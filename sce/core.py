"""
Sealed Continuation Envelope (SCE) -- reference implementation (v4 hardened)
===========================================================================

SCE binds portable AI inference state (a KV-cache slice, a state-space-model
vector, an agent's working context, or a summary) to the *exact* model-execution
environment that produced it, so that:

    * the state resumes ONLY under an identical environment, and
    * any mismatch or tampering FAILS CLOSED -- a loud, uniform error, never a
      silent, corrupted resume.

This revision hardens the construction against the issues a careful reviewer
raises about v1:

  1. Nonce-misuse resistance.  The AEAD is AES-256-GCM-SIV (RFC 8452), not plain
     GCM.  Because K_epoch is a long-lived key (derived from the master secret
     and the environment, reused across many seals), an accidental nonce repeat
     under plain GCM would be catastrophic (auth-key recovery -> forgery).  Under
     GCM-SIV a nonce repeat is not catastrophic: it degrades gracefully, at worst
     revealing that two (identical-nonce) plaintexts were equal.

  2. Key commitment.  Plain AEADs are not key-committing: one ciphertext can be
     made to open under two different keys, which would quietly defeat the
     "this state belongs to exactly one environment" guarantee.  SCE derives a
     separate commitment from the key material, stores it, binds it into the
     associated data, and verifies it in constant time before trusting a
     decryption.  A ciphertext is therefore bound to exactly one environment.

  3. Strict canonicalisation.  The environment fingerprint (MEMH) is computed
     over a rigorous, length-prefixed, NFC-normalised encoding of the manifest,
     not over `json.dumps`.  This removes the cross-platform ambiguity (Unicode
     normalisation, integer/float rendering, key ordering) that could otherwise
     cause spurious refusals or mask a real difference.

  4. Uniform failure.  `unseal_state` raises a single exception with a single
     message for every cryptographic failure (wrong environment, wrong secret,
     tampering).  It does not leak *why* it failed.  A separate, opt-in
     `explain_mismatch()` is provided for trusted debugging only.

  5. Key separation / blast radius.  A `context` label and an `epoch_id` feed the
     key derivation, so keys can be separated per deployment/tenant and rotated,
     bounding the damage from any single key compromise.

  6. Unlinkable at rest (v4).  Earlier wire versions carried the environment
     fingerprint (MEMH), the epoch, and a *deterministic* key commitment in the
     cleartext header, so any party merely *holding* an envelope could cluster
     envelopes by that stable (MEMH, epoch, commitment) tuple -- exactly the
     linkage an untrusted relay in LDDP must not be able to perform.  v4 removes
     all three from cleartext: MEMH and epoch are re-derived by the unsealer and
     bound only through the key and the associated data, and a fresh per-seal
     salt feeds the HKDF extract so the derived key *and* the commitment are
     unique to every seal.  Two seals of the same state under the same key now
     share no linkable field.  The salt doubles as genuine per-seal key
     separation, so a nonce repeat is a non-event even before GCM-SIV's own
     nonce-misuse resistance is considered.

Scope
-----
This module implements ONLY the fail-closed, committing, version-binding seal.
By design it has no transport, no mixnet, no anonymity layer, and no network
code.  It is meant to sit *underneath* those systems.

That boundary bears directly on point 6 above: the unlinkability property is a
property of the BYTES, not of the CHANNEL.  An adversary who can correlate
network identity -- source IP, TLS session, account credential, connection
timing -- links a user's envelopes no matter how clean the envelope is, and no
wire format can prevent it.  Unlinkability at rest is NECESSARY BUT NOT
SUFFICIENT for anonymity: it only pays off when composed with an anonymising
transport (a mixnet, onion routing, or a true dead drop).  SCE seals the
capsule; it does not disguise the courier.  See README "Boundaries" and SPEC
section 11.2.

The public API deliberately does NOT let callers supply raw AEAD keys or nonces:
nonces are always generated internally, and keys are always derived internally
from the master secret.  Versatility is meant to live in *where it plugs in*, not
in *how many ways it can be mis-configured*.

Status
------
Reference / proof-of-concept.  Correct and tested, built on standard primitives.
NOT yet independently audited, NOT hardened against every side channel, and NOT
yet integrated with a production inference engine's state-export path.  See
README.md for the honest boundary list.  "Infallible" is not claimed and is not
achievable; the achievable and intended property is: no silent, catastrophic
failure mode.
"""

from __future__ import annotations

import os
import hmac
import struct
import hashlib
import unicodedata
from types import MappingProxyType
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

__all__ = [
    "ModelManifest",
    "compute_memh",
    "seal_state",
    "unseal_state",
    "describe_envelope",
    "explain_mismatch",
    "SCEError",
    "StateSealMismatch",
    "MalformedEnvelope",
    "SEAL_COUNT_CEILING_PER_KEY",
]

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
_MAGIC = b"SCE4"
_VERSION = 4
_NONCE_LEN = 12          # AES-GCM-SIV nonce
_SALT_LEN = 16           # per-seal HKDF-extract salt (also de-links key + commitment)
_TAG_LEN = 16            # AES-GCM-SIV authentication tag (128-bit)
_MEMH_LEN = 32           # SHA3-256
_COMMIT_LEN = 32         # SHA3-256 key commitment
_KEY_LEN = 32            # AES-256
_DOMAIN = b"LDDP-SCE-v4"  # domain-separation label
_KDF_INFO_PREFIX = b"LDDP-SCE|kdf-v4|"      # fixed prefix on the HKDF info string
_KDF_CANON_TAG = b"LDDP-SCE|kdf-canon-v4"   # tag on the length-prefixed info canonical form
_MANIFEST_TAG = b"SCEMAN1"  # canonical-manifest format tag (unchanged: MEMH is stable)

# Optional per-key seal ceiling. In v4 a fresh per-seal salt feeds the HKDF
# extract, so every seal uses a unique encryption key and nonce collisions are a
# non-event; this ceiling is therefore no longer about nonce reuse but is kept as
# opt-in rotation hygiene (bounding how much rides under one master secret).
SEAL_COUNT_CEILING_PER_KEY = 1 << 40

# Envelope layout (big-endian). v4 deliberately carries NO environment metadata
# in cleartext -- MEMH and epoch are re-derived by the unsealer and bound only
# through the key and the associated data, so a mere holder cannot link envelopes.
#   -- header prefix (all of it is bound into the AEAD associated data) --
#   4s  magic       b"SCE4"
#   B   version     4
#   12s nonce       AES-GCM-SIV nonce     (random per seal)
#   16s salt        HKDF-extract salt     (random per seal; de-links key + commitment)
#   32s commitment  key commitment        (unique per seal via the salt)
#   -- framing (not in AAD; ciphertext integrity covered by the AEAD tag) --
#   I   ct_len      length of the ciphertext+tag
#   .   ciphertext
# MEMH and epoch are folded into the AAD (see _aad), re-derived on unseal, so they
# still bind in two independent ways (key + AAD) without appearing on the wire.
_HEADER_PREFIX = struct.Struct(">4sB12s16s32s")    # magic, ver, nonce, salt, commitment
_CTLEN = struct.Struct(">I")

# The uint32 ct_len frame bounds a single sealed payload. Enforced in seal_state so
# an oversize state fails with a clean SCEError, not a raw struct.error deep in the
# pack call. (The AEAD's own 2**36-byte limit is far higher; this frame binds first.)
_MAX_STATE = (1 << 32) - 1 - _TAG_LEN     # ciphertext = plaintext + 16-byte tag

_MISMATCH_MESSAGE = "sealed state could not be opened under the presented environment"


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class SCEError(Exception):
    """Base class for all SCE errors."""


class StateSealMismatch(SCEError):
    """The fail-closed guarantee.

    Raised whenever sealed state cannot be cryptographically opened under the
    presented environment/epoch/context/secret -- whether because the
    environment changed, the epoch or context differ, the master secret is
    wrong, or the bytes were tampered with. The message is intentionally uniform
    and does NOT reveal which of these was the cause (that would be an oracle).

    When raised, plaintext is NEVER returned. Discard the sealed state and
    rebuild from an authoritative source (e.g. re-prefill from the transcript).
    """

    def __init__(self, message: str = _MISMATCH_MESSAGE):
        super().__init__(message)


class MalformedEnvelope(SCEError):
    """The bytes are not a structurally valid SCE envelope (bad magic,
    unsupported version, truncated, or internally inconsistent length).

    Structural validity is public information (the wire format is not secret),
    so distinguishing it from a cryptographic mismatch leaks nothing about keys.
    """


# --------------------------------------------------------------------------- #
# Manifest and MEMH  (strict, deterministic canonicalisation)
# --------------------------------------------------------------------------- #
def _enc_str(label: str, value: Any) -> bytes:
    """NFC-normalise a required string and length-prefix its UTF-8 bytes.

    Rejects non-strings so the fingerprint can never depend on how a JSON
    library happened to render a number, bool, or null.
    """
    if not isinstance(value, str):
        raise SCEError(f"manifest field {label!r} must be a str, got {type(value).__name__}")
    b = unicodedata.normalize("NFC", value).encode("utf-8")
    return len(b).to_bytes(4, "big") + b


@dataclass(frozen=True)
class ModelManifest:
    """A fingerprint of everything that changes numerical inference behaviour.

    All core fields are strings; `extra` is a flat mapping of str -> str for
    forward-compatible factors (LoRA adapter hash, RoPE scaling, sampler build,
    etc.). Types are validated on construction so canonicalisation is rigorous.
    """

    weights_hash: str        # hash/identifier of the exact weight file(s)
    quantization: str        # e.g. "bf16", "fp8-e4m3", "gptq-int4"
    kernel_build_id: str     # inference kernel / runtime build id
    tensor_parallel: str     # topology, e.g. "tp=1,pp=1"
    numerics_mode: str       # e.g. "bf16", "fp16", "fp32"
    extra: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        for name in ("weights_hash", "quantization", "kernel_build_id",
                     "tensor_parallel", "numerics_mode"):
            if not isinstance(getattr(self, name), str):
                raise SCEError(f"manifest field {name!r} must be a str")
        if not isinstance(self.extra, Mapping):
            raise SCEError("manifest field 'extra' must be a mapping of str -> str")
        for k, v in self.extra.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise SCEError("manifest 'extra' must map str -> str")
        # Reject keys that collide after NFC normalisation. Two distinct-but-
        # normalisation-equal keys would make canonical_bytes order-dependent and
        # ambiguous, defeating the injectivity the fingerprint relies on.
        seen_norm = set()
        for k in self.extra:
            nk = unicodedata.normalize("NFC", k)
            if nk in seen_norm:
                raise SCEError(
                    "manifest 'extra' has keys that collide after NFC normalisation "
                    f"({k!r}); de-duplicate them before constructing the manifest so "
                    "the fingerprint stays unambiguous."
                )
            seen_norm.add(nk)

        # `frozen=True` is only SHALLOW: it stops rebinding the attribute, not
        # mutation of the dict behind it. Take a private snapshot (so the caller's
        # dict cannot alias ours) and expose it read-only, so a constructed
        # manifest -- and therefore its MEMH -- can never change afterwards.
        # Determinism is the whole basis of the fingerprint; without this, a live
        # manifest's identity could shift under the caller's feet.
        object.__setattr__(self, "extra", MappingProxyType(dict(self.extra)))

        # The manifest is now genuinely immutable, so its fingerprint is fixed for
        # the life of the object -- compute it once. Besides being correct only
        # BECAUSE of the immutability above, this removes an O(n) redundancy on the
        # chunked path, where seal_state re-derived the MEMH for every segment
        # (~9% of a 1024-segment seal, ~17% of a small single seal).
        object.__setattr__(self, "_memh",
                           hashlib.sha3_256(self.canonical_bytes()).digest())

    def __hash__(self) -> int:
        """Hash by fingerprint. A frozen dataclass holding a mapping is otherwise
        unhashable; hashing the MEMH is well-defined now that the manifest cannot
        change, and lets manifests be used as dict/set keys (e.g. per-environment
        caches). Consistent with __eq__: equal manifests canonicalise identically,
        so they share a MEMH."""
        return hash(self._memh)

    def __reduce__(self):
        """Pickle / deepcopy support.

        The read-only `extra` proxy cannot be pickled, so reconstruct from a plain
        dict and let __post_init__ re-validate and re-freeze. Without this, making
        the manifest immutable would have silently broken sending one across a
        process boundary (multiprocessing, task queues) -- a regression, not a
        hardening.
        """
        return (
            self.__class__,
            (self.weights_hash, self.quantization, self.kernel_build_id,
             self.tensor_parallel, self.numerics_mode, dict(self.extra)),
        )

    def canonical_bytes(self) -> bytes:
        """Strict, deterministic serialisation: a format tag, then each core
        field length-prefixed in a FIXED order, then the `extra` entries sorted
        by NFC-UTF-8 key and length-prefixed. No whitespace, no JSON, no
        ambiguity -- identical manifests serialise identically on every stack.
        """
        parts = [_MANIFEST_TAG]
        for name in ("weights_hash", "quantization", "kernel_build_id",
                     "tensor_parallel", "numerics_mode"):
            parts.append(_enc_str(name, getattr(self, name)))
        items = sorted(
            self.extra.items(),
            key=lambda kv: unicodedata.normalize("NFC", kv[0]).encode("utf-8"),
        )
        parts.append(len(items).to_bytes(4, "big"))
        for k, v in items:
            parts.append(_enc_str("extra-key", k))
            parts.append(_enc_str("extra-value", v))
        return b"".join(parts)

    def memh(self) -> bytes:
        """Model Execution Manifest Hash: 32-byte SHA3-256 over the manifest.

        Computed once at construction and cached. That is safe ONLY because the
        manifest is genuinely immutable (see __post_init__): a cached fingerprint
        on a mutable object would be a correctness bug, not an optimisation.
        """
        return self._memh


def _require_manifest(manifest: Any) -> None:
    """Every public entry point that takes a manifest validates it here, so a
    wrong type raises SCEError rather than leaking a raw AttributeError from deep
    inside. Callers can then rely on `except SCEError` catching everything."""
    if not isinstance(manifest, ModelManifest):
        raise SCEError(
            f"manifest must be a ModelManifest, got {type(manifest).__name__}"
        )


def _require_envelope_bytes(blob: Any, what: str) -> bytes:
    """Same contract for the untrusted blob: a wrong type is a MalformedEnvelope,
    not a raw TypeError. bytearray/memoryview are accepted and normalised; the
    common `bytes` path is not copied."""
    if isinstance(blob, bytes):
        return blob
    if isinstance(blob, (bytearray, memoryview)):
        return bytes(blob)
    raise MalformedEnvelope(
        f"{what} must be bytes, got {type(blob).__name__}"
    )


def compute_memh(manifest: ModelManifest) -> bytes:
    """Convenience wrapper: return the 32-byte MEMH for a manifest."""
    _require_manifest(manifest)
    return manifest.memh()


# --------------------------------------------------------------------------- #
# Key derivation + commitment
# --------------------------------------------------------------------------- #
def _check_epoch(epoch_id: int) -> None:
    if not isinstance(epoch_id, int) or isinstance(epoch_id, bool) \
            or not (0 <= epoch_id < (1 << 64)):
        raise SCEError("epoch_id must be an integer in [0, 2**64)")


def _lp(b: bytes) -> bytes:
    """Length-prefix arbitrary bytes with a 4-byte big-endian length.

    The same discipline used by the manifest canonicaliser. Applying it to every
    field of a composite input makes that input unambiguous by construction: no
    two distinct field tuples can serialise to the same byte string.
    """
    return len(b).to_bytes(4, "big") + b


def _kdf_info(context: bytes, epoch_id: int, memh: bytes) -> bytes:
    """Build the HKDF `info` string unambiguously.

    Every field is length-prefixed and folded through SHA3-256, so the info
    channel inherits the same non-ambiguity guarantee as the manifest encoding.
    This removes any reliance on incidental properties (such as MEMH being
    fixed-width and last) and keeps one canonicalisation discipline to audit.
    """
    canonical = (
        _KDF_CANON_TAG
        + _lp(context)
        + _lp(epoch_id.to_bytes(8, "big"))
        + _lp(memh)
    )
    return _KDF_INFO_PREFIX + hashlib.sha3_256(canonical).digest()


def _derive_key_material(master_secret: bytes, memh: bytes, epoch_id: int,
                         context: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """Derive (K_enc, commitment) from the master secret, the environment, and a
    fresh per-seal `salt`.

    Both outputs are HKDF-SHA3-256 material over the SAME inputs, so a change to
    the environment (MEMH), epoch, context, or secret changes both:

        info         = "LDDP-SCE|kdf-v4|" || SHA3-256( LP(context)|LP(epoch)|LP(MEMH) )
        material     = HKDF(secret, salt=salt, info=info, len=64)
        K_enc        = material[:32]
        commitment   = SHA3-256(DOMAIN|"|commit|"|material[32:])

    `salt` is the per-seal random salt carried in the envelope header. Using it as
    the HKDF-extract salt (its RFC 5869 role) makes K_enc unique to each seal,
    which (a) removes any dependence on GCM-SIV nonce uniqueness for safety and
    (b) makes the commitment fresh per seal -- so the commitment is no longer a
    stable, linkable tag, while remaining a binding, hiding commitment to the key
    material:
      * hiding   -- the committed half is independent of K_enc, so publishing the
                    commitment reveals nothing usable about the encryption key;
      * binding  -- a different environment yields different HKDF output, hence a
                    different commitment; one ciphertext opening under two
                    environments would need a SHA3-256 collision on the committed
                    half (infeasible). This is what makes the scheme key-committing.
    The environment (MEMH/epoch/context) binds through `info`; the salt only adds
    freshness and binds nothing about the environment, so unlinkability does not
    weaken the fail-closed guarantee.
    """
    if not isinstance(master_secret, (bytes, bytearray)):
        raise SCEError(
            f"master_secret must be bytes, got {type(master_secret).__name__}; "
            "pass raw key bytes (e.g. os.urandom(32)), not a str"
        )
    if len(master_secret) < 16:
        raise SCEError(
            "master_secret must be >= 16 bytes of high-entropy key material. Note "
            "that LENGTH IS NOT ENTROPY: this must be random bytes from a CSPRNG "
            "(os.urandom / secrets.token_bytes) or a KMS/HSM key, NOT a password or "
            "passphrase. If you only have a password, stretch it with a memory-hard "
            "KDF (Argon2id/scrypt) first -- SCE does not do that for you."
        )
    master_secret = bytes(master_secret)
    info = _kdf_info(context, epoch_id, memh)
    material = HKDF(
        algorithm=hashes.SHA3_256(),
        length=_KEY_LEN * 2,
        salt=salt,
        info=info,
    ).derive(master_secret)
    k_enc = material[:_KEY_LEN]
    k_com_half = material[_KEY_LEN:]
    commitment = hashlib.sha3_256(_DOMAIN + b"|commit|" + k_com_half).digest()
    return k_enc, commitment


def _aad(header_prefix: bytes, memh: bytes, epoch_id: int) -> bytes:
    """Associated data = domain label + the cleartext header prefix (magic,
    version, nonce, salt, commitment) + the re-derived MEMH and epoch.

    MEMH and epoch are authenticated here but are NOT part of the on-wire header:
    the unsealer reconstructs them from the caller-supplied manifest and epoch.
    This gives the environment two independent bindings (it derives the key AND is
    authenticated data) while keeping it off the wire, so a holder cannot read or
    link it. Any change to the header, MEMH, or epoch fails closed.
    """
    return _DOMAIN + b"|hdr|" + header_prefix + memh + epoch_id.to_bytes(8, "big")


# --------------------------------------------------------------------------- #
# Seal / unseal
# --------------------------------------------------------------------------- #
def seal_state(
    state: bytes,
    manifest: ModelManifest,
    *,
    master_secret: bytes,
    epoch_id: int = 0,
    context: bytes = b"",
    seal_count: int | None = None,
) -> bytes:
    """Seal `state` so it can only be reopened under an identical `manifest`
    (and matching epoch, context, and master secret).

    Returns an opaque, self-describing, tamper-evident, key-committing envelope.
    Safe to hand to an untrusted holder: it reveals nothing about the plaintext
    and cannot be modified or re-bound to another environment without detection.

    `seal_count` is optional, opt-in blast-radius control. SCE is stateless and
    cannot count seals itself; if the caller passes a monotonic per-(secret,
    epoch) count, seal_state refuses once it reaches SEAL_COUNT_CEILING_PER_KEY,
    prompting a master-secret rotation or an epoch bump. Passing None (the
    default) disables the check, and the caller then owns nonce-collision risk.
    """
    _require_manifest(manifest)
    if not isinstance(state, (bytes, bytearray)):
        raise SCEError("state must be bytes; serialise your tensors/objects first")
    if len(state) > _MAX_STATE:
        raise SCEError(
            f"state is {len(state)} bytes; SCE's uint32 length frame caps a single "
            f"sealed payload at {_MAX_STATE} bytes (~4 GiB). Chunk a large KV-cache, "
            "or seal a compact / summarised state instead."
        )
    if not isinstance(context, (bytes, bytearray)):
        raise SCEError("context must be bytes")
    if seal_count is not None:
        if not isinstance(seal_count, int) or isinstance(seal_count, bool) or seal_count < 0:
            raise SCEError("seal_count must be a non-negative integer or None")
        if seal_count >= SEAL_COUNT_CEILING_PER_KEY:
            raise SCEError(
                f"seal_count {seal_count} has reached SEAL_COUNT_CEILING_PER_KEY "
                f"({SEAL_COUNT_CEILING_PER_KEY}); rotate the master secret or bump the "
                "epoch. SCE is stateless and cannot track this for you -- the caller "
                "must pass and persist a monotonic per-(secret, epoch) count."
            )
    _check_epoch(epoch_id)

    memh = manifest.memh()
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    k_enc, commitment = _derive_key_material(master_secret, memh, epoch_id, bytes(context), salt)
    prefix = _HEADER_PREFIX.pack(_MAGIC, _VERSION, nonce, salt, commitment)
    ciphertext = AESGCMSIV(k_enc).encrypt(nonce, bytes(state), _aad(prefix, memh, epoch_id))
    return prefix + _CTLEN.pack(len(ciphertext)) + ciphertext


def _parse(sealed: bytes):
    """Structural parse only. Raises MalformedEnvelope on any structural fault.
    Returns (prefix_bytes, fields_tuple, ciphertext)."""
    sealed = _require_envelope_bytes(sealed, "sealed envelope")
    if len(sealed) < _HEADER_PREFIX.size + _CTLEN.size:
        raise MalformedEnvelope("sealed blob is shorter than the SCE header")
    prefix = sealed[: _HEADER_PREFIX.size]
    fields = _HEADER_PREFIX.unpack(prefix)
    magic, version = fields[0], fields[1]
    if magic != _MAGIC:
        raise MalformedEnvelope("bad magic: not an SCE v4 envelope")
    if version != _VERSION:
        raise MalformedEnvelope(f"unsupported SCE envelope version {version}")
    off = _HEADER_PREFIX.size
    (ct_len,) = _CTLEN.unpack(sealed[off: off + _CTLEN.size])
    ciphertext = sealed[off + _CTLEN.size:]
    if len(ciphertext) != ct_len:
        raise MalformedEnvelope("declared ciphertext length does not match envelope")
    if len(ciphertext) < _TAG_LEN:
        # A valid AEAD ciphertext must contain at least the 16-byte tag. The tag
        # length is public, so rejecting this structurally leaks nothing.
        raise MalformedEnvelope("ciphertext shorter than the authentication tag")
    return prefix, fields, ciphertext


def unseal_state(
    sealed: bytes,
    manifest: ModelManifest,
    *,
    master_secret: bytes,
    epoch_id: int = 0,
    context: bytes = b"",
) -> bytes:
    """Attempt to reopen `sealed` under the CURRENT environment `manifest`.

    On success: returns the original plaintext state.
    On ANY cryptographic mismatch (environment/epoch/context/secret changed, or
    tampering): raises `StateSealMismatch` with a uniform message and returns
    nothing. Structural faults raise `MalformedEnvelope`.
    """
    _require_manifest(manifest)
    if not isinstance(context, (bytes, bytearray)):
        raise SCEError("context must be bytes")
    _check_epoch(epoch_id)

    prefix, fields, ciphertext = _parse(sealed)
    _magic, _ver, nonce, salt, commit_stored = fields

    # Everything security-relevant is recomputed from the caller-supplied
    # environment; the header carries no environment metadata to trust. The salt
    # is the only per-seal input read from the header, and it binds nothing about
    # the environment -- it only adds freshness both sides agree on.
    memh_present = manifest.memh()
    k_enc, commit_expected = _derive_key_material(
        master_secret, memh_present, epoch_id, bytes(context), salt
    )

    # Key-commitment check, constant time. If the environment (or epoch/context/
    # secret) differs, commit_expected differs and this fails -- binding the
    # ciphertext to exactly one key/environment.
    commitment_ok = hmac.compare_digest(commit_stored, commit_expected)

    # Always attempt the AEAD open too, so timing does not distinguish the two
    # failure modes; combine the outcomes into one uniform result. The re-derived
    # MEMH and epoch enter through the associated data.
    try:
        plaintext = AESGCMSIV(k_enc).decrypt(
            nonce, ciphertext, _aad(prefix, memh_present, epoch_id)
        )
        aead_ok = True
    except InvalidTag:
        plaintext = None
        aead_ok = False

    if not (commitment_ok and aead_ok):
        raise StateSealMismatch()
    return plaintext


# --------------------------------------------------------------------------- #
# Inspection (no secrets) and opt-in diagnosis (trusted contexts only)
# --------------------------------------------------------------------------- #
def describe_envelope(sealed: bytes) -> Dict[str, Any]:
    """Return the non-secret, structural header fields of a sealed envelope.

    Reveals nothing about the plaintext and needs no key. By design (v4) it also
    reveals nothing about the environment, epoch, or context the state was sealed
    under -- those are not on the wire -- so its output cannot be used to link or
    cluster a holder's envelopes. Only the format identity and sizes are exposed.
    """
    _prefix, fields, _ct = _parse(sealed)
    magic, version, _nonce, _salt, _commit = fields
    return {
        "magic": magic.decode("ascii", "replace"),
        "version": version,
        "ciphertext_bytes": len(_ct),
        "total_envelope_bytes": len(sealed),
    }


def explain_mismatch(sealed: bytes, manifest: ModelManifest) -> str:
    """Opt-in, human-readable note for a refusal, for TRUSTED debugging/logs only.

    In v4 the envelope records nothing in cleartext about the environment, epoch,
    or context it was sealed under -- that is what stops an untrusted holder from
    linking envelopes -- so, unlike earlier versions, this helper CANNOT identify
    the specific cause of a refusal from the envelope alone. It confirms structural
    validity and echoes the presented environment's MEMH for an out-of-band check.
    It still MUST NOT be exposed to untrusted callers, and `unseal_state` never
    calls it.
    """
    _require_manifest(manifest)
    try:
        _parse(sealed)
    except MalformedEnvelope as e:
        return f"not a valid SCE envelope: {e}"
    memh_present = manifest.memh()
    return (
        "refused under the presented environment (MEMH "
        f"{memh_present.hex()[:16]}...). SCE v4 does not record the sealing "
        "environment/epoch/context in the envelope -- by design, to keep envelopes "
        "unlinkable -- so the specific cause cannot be recovered from the bytes. "
        "Verify the manifest, epoch, context, and master secret against the "
        "sealing side out of band."
    )
