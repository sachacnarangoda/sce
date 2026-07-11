"""
Test suite for the Sealed Continuation Envelope (v4).

Runs WITHOUT pytest:  python tests/test_core.py

Sections:
  A. Core correctness ....... round-trip, determinism, structure
  B. Fail-closed binding .... every environment factor, epoch, context, secret
  C. Tamper-evidence ........ ciphertext and every header field
  D. Adversarial hardening .. nonce-misuse, key-commitment/cross-key, canonical
                              ambiguity, oracle-free uniform failure, v4 de-link
                              (unlinkability at rest), cross-version rejection
  E. Robustness ............. malformed input, large state, type validation
  F. Regression ............. one guard per code-review finding
"""

import os
import sys
import struct
import logging
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest,
    compute_memh,
    seal_state,
    unseal_state,
    describe_envelope,
    explain_mismatch,
    SCEError,
    StateSealMismatch,
    MalformedEnvelope,
)
import sce.core as core  # noqa: E402

MASTER = b"\x11" * 32
MASTER2 = b"\x22" * 32


def base_manifest(**overrides):
    fields = dict(
        weights_hash="sha3:aaaa1111",
        quantization="bf16",
        kernel_build_id="vllm-0.6.3+abc123",
        tensor_parallel="tp=1,pp=1",
        numerics_mode="bf16",
    )
    fields.update(overrides)
    return ModelManifest(**fields)


# ===================== A. CORE CORRECTNESS ============================ #
def test_round_trip_identical_environment():
    m = base_manifest()
    state = b"conversation-state: turn=7; kv-cache-slice=<...>"
    sealed = seal_state(state, m, master_secret=MASTER, epoch_id=0)
    assert unseal_state(sealed, m, master_secret=MASTER, epoch_id=0) == state


def test_memh_is_deterministic_and_order_independent():
    a = ModelManifest("w", "q", "k", "tp=1,pp=1", "bf16", extra={"b": "2", "a": "1"})
    b = ModelManifest("w", "q", "k", "tp=1,pp=1", "bf16", extra={"a": "1", "b": "2"})
    assert compute_memh(a) == compute_memh(b)
    assert compute_memh(a) == compute_memh(a)
    assert len(compute_memh(a)) == 32


def test_describe_envelope_reveals_no_plaintext_or_environment():
    m = base_manifest()
    secret = b"THE-SECRET-STATE-SHOULD-NOT-APPEAR"
    sealed = seal_state(secret, m, master_secret=MASTER, epoch_id=5)
    info = describe_envelope(sealed)
    assert secret not in repr(info).encode()
    assert info["magic"] == "SCE4"
    assert info["version"] == 4
    # v4 de-link: the envelope exposes NOTHING about the sealing environment/epoch
    assert "sealed_under_memh" not in info
    assert "sealed_under_epoch" not in info
    # and the MEMH itself never appears in the envelope bytes
    assert m.memh() not in sealed


# ===================== B. FAIL-CLOSED BINDING ======================== #
def test_fails_closed_on_weight_change():
    sealed = seal_state(b"state", base_manifest(), master_secret=MASTER)
    changed = base_manifest(weights_hash="sha3:bbbb2222")
    try:
        unseal_state(sealed, changed, master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: stale state opened after weight change")


def test_every_environment_field_is_bound():
    sealed = seal_state(b"state", base_manifest(), master_secret=MASTER)
    for f, v in [("quantization", "fp8-e4m3"), ("kernel_build_id", "vllm-0.6.4+x"),
                 ("tensor_parallel", "tp=2,pp=1"), ("numerics_mode", "fp16"),
                 ("weights_hash", "sha3:cccc3333")]:
        try:
            unseal_state(sealed, base_manifest(**{f: v}), master_secret=MASTER)
        except StateSealMismatch:
            continue
        raise AssertionError(f"SECURITY FAILURE: opened despite changed {f}")


def test_extra_field_is_bound():
    sealed = seal_state(b"state", base_manifest(extra={"lora": "none"}), master_secret=MASTER)
    try:
        unseal_state(sealed, base_manifest(extra={"lora": "adapter-42"}), master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: opened despite changed extra field")


def test_fails_closed_on_epoch_change():
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER, epoch_id=0)
    try:
        unseal_state(sealed, m, master_secret=MASTER, epoch_id=1)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: opened under a different epoch")


def test_fails_closed_on_context_change():
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER, context=b"tenant-A")
    try:
        unseal_state(sealed, m, master_secret=MASTER, context=b"tenant-B")
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: opened under a different context")


def test_fails_closed_on_wrong_master_secret():
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER)
    try:
        unseal_state(sealed, m, master_secret=MASTER2)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: opened with the wrong master secret")


# ===================== C. TAMPER-EVIDENCE ============================ #
def test_tamper_in_ciphertext_is_detected():
    m = base_manifest()
    sealed = bytearray(seal_state(b"a-secret-payload-of-some-length", m, master_secret=MASTER))
    sealed[-1] ^= 0x01
    try:
        unseal_state(bytes(sealed), m, master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: tampered ciphertext accepted")


def test_tamper_in_every_header_byte_is_detected():
    """Flip a byte in each region of the authenticated header (magic excluded,
    since that is a structural check) and confirm each fails closed."""
    m = base_manifest()
    good = seal_state(b"state", m, master_secret=MASTER)
    # v4 layout: magic[0:4] ver[4] nonce[5:17] salt[17:33] commitment[33:65] ...ct
    for off in (6, 20, 40, 70):  # inside nonce, salt, commitment, ciphertext
        sealed = bytearray(good)
        sealed[off] ^= 0x01
        try:
            unseal_state(bytes(sealed), m, master_secret=MASTER)
        except (StateSealMismatch, MalformedEnvelope):
            continue
        raise AssertionError(f"SECURITY FAILURE: tampered byte {off} accepted")


# ===================== D. ADVERSARIAL HARDENING ====================== #
def test_nonce_reuse_is_not_catastrophic():
    """Force a repeated nonce under the SAME key with DIFFERENT plaintexts.

    Under plain GCM this leaks the auth key. Under GCM-SIV it must not: both
    ciphertexts must still decrypt correctly to their own plaintexts, and the
    ciphertexts for different plaintexts must differ.
    """
    m = base_manifest()
    memh = m.memh()
    # In v4 the key is derived with a per-seal salt, so a nonce repeat alone does
    # not even reuse the key. To exercise GCM-SIV's nonce-misuse resistance we pin
    # BOTH the salt and the nonce (same key AND same nonce).
    fixed_salt = b"\x05" * core._SALT_LEN
    fixed_nonce = b"\x07" * core._NONCE_LEN
    k_enc, commitment = core._derive_key_material(MASTER, memh, 0, b"", fixed_salt)
    prefix = core._HEADER_PREFIX.pack(core._MAGIC, core._VERSION, fixed_nonce, fixed_salt, commitment)
    aad = core._aad(prefix, memh, 0)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    c1 = AESGCMSIV(k_enc).encrypt(fixed_nonce, b"plaintext-ONE", aad)
    c2 = AESGCMSIV(k_enc).encrypt(fixed_nonce, b"plaintext-TWO", aad)
    assert c1 != c2, "different plaintexts under a reused nonce produced equal ciphertext"
    assert AESGCMSIV(k_enc).decrypt(fixed_nonce, c1, aad) == b"plaintext-ONE"
    assert AESGCMSIV(k_enc).decrypt(fixed_nonce, c2, aad) == b"plaintext-TWO"


def test_key_commitment_blocks_cross_environment_open():
    """A ciphertext sealed under environment A must never open under a large set
    of distinct environments B -- the key-commitment property in practice."""
    state = b"committed-state"
    sealed = seal_state(state, base_manifest(), master_secret=MASTER)
    opened_elsewhere = 0
    for i in range(200):
        other = base_manifest(weights_hash=f"sha3:variant-{i}")
        try:
            unseal_state(sealed, other, master_secret=MASTER)
            opened_elsewhere += 1
        except StateSealMismatch:
            pass
    assert opened_elsewhere == 0, f"state opened under {opened_elsewhere} foreign environments"


def test_commitment_tamper_fails_closed():
    """Directly corrupting the stored commitment must fail closed (and not be
    silently ignored)."""
    m = base_manifest()
    sealed = bytearray(seal_state(b"state", m, master_secret=MASTER))
    # v4: commitment occupies bytes [33:65]
    sealed[40] ^= 0xFF
    try:
        unseal_state(bytes(sealed), m, master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError("SECURITY FAILURE: tampered commitment accepted")


def test_commitment_is_unlinkable_across_seals():
    """v4 de-link: two seals of the SAME state under the SAME (secret, manifest,
    epoch, context) must NOT share the stored commitment. A stable commitment
    would let a holder link a user's envelopes. Both must still round-trip."""
    m = base_manifest()
    s1 = seal_state(b"identical-state", m, master_secret=MASTER, epoch_id=3, context=b"tenant-A")
    s2 = seal_state(b"identical-state", m, master_secret=MASTER, epoch_id=3, context=b"tenant-A")
    lo = core._HEADER_PREFIX.size - core._COMMIT_LEN
    hi = core._HEADER_PREFIX.size
    assert s1[lo:hi] != s2[lo:hi], "commitment is a stable, linkable tag across seals"
    assert s1 != s2
    assert unseal_state(s1, m, master_secret=MASTER, epoch_id=3, context=b"tenant-A") == b"identical-state"
    assert unseal_state(s2, m, master_secret=MASTER, epoch_id=3, context=b"tenant-A") == b"identical-state"


def test_envelope_exposes_no_environment_metadata():
    """v4 de-link: the MEMH must not appear anywhere in the envelope bytes, and
    describe_envelope must expose no sealed-under environment/epoch fields. The
    per-seal nonce and salt must differ across seals so nothing is stable."""
    m = base_manifest()
    memh = m.memh()
    s1 = seal_state(b"state-one", m, master_secret=MASTER, epoch_id=7, context=b"ctx")
    s2 = seal_state(b"state-two", m, master_secret=MASTER, epoch_id=7, context=b"ctx")
    assert memh not in s1 and memh not in s2, "MEMH leaked into the envelope cleartext"
    info = describe_envelope(s1)
    assert "sealed_under_memh" not in info and "sealed_under_epoch" not in info
    # nonce[5:17] and salt[17:33] are random per seal
    assert s1[5:17] != s2[5:17], "nonce is not fresh per seal"
    assert s1[17:33] != s2[17:33], "salt is not fresh per seal"


def test_v3_envelope_is_rejected_by_v4():
    """Cross-version safety: a v3-magic envelope must be refused by v4 code (fail
    closed), never mis-parsed. Magic separation makes this automatic."""
    faux_v3 = b"SCE3" + os.urandom(120)   # right shape, wrong version
    try:
        unseal_state(faux_v3, base_manifest(), master_secret=MASTER)
    except (MalformedEnvelope, StateSealMismatch):
        return
    raise AssertionError("a v3-magic envelope was not rejected by v4")


def test_manifest_theft_and_brute_force_fails():
    """Scenario: an attacker copies the (public) manifest to a cloned address and
    brute-forces the secret over many attempts. Because the manifest is NOT a
    secret, and the master secret has 256-bit entropy, every attempt must fail.
    """
    m = base_manifest()
    sealed = seal_state(b"private-state", m, master_secret=MASTER, context=b"prod")
    opened = 0
    for _ in range(3000):  # stand-in for sustained brute forcing
        try:
            unseal_state(sealed, m, master_secret=os.urandom(32), context=b"prod")
            opened += 1
        except StateSealMismatch:
            pass
    assert opened == 0, "a guessed secret opened the envelope"
    # The manifest by itself (correct manifest, no secret) also opens nothing:
    try:
        unseal_state(sealed, m, master_secret=os.urandom(32), context=b"prod")
        raise AssertionError("opened with a random secret despite correct manifest")
    except StateSealMismatch:
        pass


def test_channel_binding_isolates_sessions():
    """The 'cloned address' replay variant is defeated by binding each session to
    a distinct `context`: a valid envelope from one context must not open under
    another, even with the correct secret."""
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER, context=b"session-A")
    try:
        unseal_state(sealed, m, master_secret=MASTER, context=b"session-B")
    except StateSealMismatch:
        # and the right context still works
        assert unseal_state(sealed, m, master_secret=MASTER, context=b"session-A") == b"state"
        return
    raise AssertionError("SECURITY FAILURE: envelope opened under a foreign context")


def test_canonicalisation_is_unicode_normalised():
    """Composed vs decomposed Unicode forms of the same string must produce the
    same MEMH (NFC), so 'the same' manifest never spuriously fails to resume."""
    composed = "café"          # U+00E9
    decomposed = "cafe\u0301"  # e + combining acute
    assert composed != decomposed
    a = base_manifest(extra={"note": composed})
    b = base_manifest(extra={"note": decomposed})
    assert compute_memh(a) == compute_memh(b), "NFC normalisation not applied"


def test_canonicalisation_has_no_delimiter_ambiguity():
    """Length-prefixing must prevent field-boundary confusion: moving a
    character across a field boundary must change the MEMH."""
    a = base_manifest(weights_hash="ab", quantization="cd")
    b = base_manifest(weights_hash="abc", quantization="d")
    assert compute_memh(a) != compute_memh(b), "delimiter/boundary ambiguity present"


def test_kdf_info_is_unambiguous():
    """The HKDF info string must be injective in (context, epoch, MEMH). This
    guards against reintroducing a delimiter ambiguity in the key-derivation
    encoding: distinct inputs — including contexts of different lengths and
    contexts containing the historical delimiter byte — must yield distinct info
    strings and therefore distinct derived keys, with no reliance on MEMH being
    fixed-width or terminal.
    """
    memh_x = b"\x01" * 32
    memh_y = b"\x02" * 32
    triples = [
        (b"", 0, memh_x),
        (b"a", 0, memh_x),
        (b"a|", 0, memh_x),          # context containing the old delimiter
        (b"|a", 0, memh_x),
        (b"a", 1, memh_x),           # epoch differs
        (b"a", 0, memh_y),           # MEMH differs
        (b"aa", 0, memh_x),          # length differs
    ]
    infos = [core._kdf_info(c, e, m) for (c, e, m) in triples]
    assert len(set(infos)) == len(infos), "kdf info string is not injective"
    fixed_salt = b"\x00" * core._SALT_LEN
    keys = [core._derive_key_material(MASTER, m, e, c, fixed_salt)[0] for (c, e, m) in triples]
    assert len(set(keys)) == len(keys), "distinct inputs produced a colliding key"


def test_non_string_manifest_fields_are_rejected():
    """Numbers/bools/None must be rejected so the fingerprint can't depend on
    how they would have been rendered."""
    for bad in [{"weights_hash": 123}, {"quantization": None}, {"numerics_mode": True}]:
        try:
            base_manifest(**bad)
        except SCEError:
            continue
        raise AssertionError(f"non-string field accepted: {bad}")
    # extra must be str -> str
    try:
        base_manifest(extra={"k": 5})
        raise AssertionError("non-string extra value accepted")
    except SCEError:
        pass


def test_failure_is_uniform_no_oracle():
    """Environment-change, wrong-secret, and tamper must raise the SAME
    exception type with the SAME message, so nothing leaks WHY it failed."""
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER)

    msgs = set()
    # (1) environment changed
    try:
        unseal_state(sealed, base_manifest(numerics_mode="fp16"), master_secret=MASTER)
    except StateSealMismatch as e:
        msgs.add(str(e))
    # (2) wrong secret
    try:
        unseal_state(sealed, m, master_secret=MASTER2)
    except StateSealMismatch as e:
        msgs.add(str(e))
    # (3) tampered ciphertext
    bad = bytearray(sealed); bad[-1] ^= 0x01
    try:
        unseal_state(bytes(bad), m, master_secret=MASTER)
    except StateSealMismatch as e:
        msgs.add(str(e))

    assert len(msgs) == 1, f"failure messages differ (oracle): {msgs}"


def test_explain_mismatch_is_opt_in_only():
    """The detailed reason must come only from the explicit helper, never from
    the exception raised by unseal_state. In v4 the helper is deliberately
    non-diagnostic (the envelope carries no environment metadata); it echoes the
    presented MEMH for an out-of-band check."""
    m = base_manifest()
    sealed = seal_state(b"state", m, master_secret=MASTER)
    drifted = base_manifest(weights_hash="sha3:different")
    # unseal exception stays generic...
    try:
        unseal_state(sealed, drifted, master_secret=MASTER)
    except StateSealMismatch as e:
        assert "MEMH" not in str(e) and "weights" not in str(e)
    # ...the opt-in helper returns a by-design note referencing the presented env
    exp = explain_mismatch(sealed, drifted)
    assert drifted.memh().hex()[:16] in exp


# ===================== E. ROBUSTNESS ================================ #
def test_malformed_envelope_raises_cleanly():
    for junk in [b"", b"x", b"SCE3short", os.urandom(50), os.urandom(500),
                 b"SCE1" + os.urandom(120)]:
        try:
            unseal_state(junk, base_manifest(), master_secret=MASTER)
        except (MalformedEnvelope, StateSealMismatch):
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"uncontrolled error on junk input: {exc!r}")


def test_declared_length_mismatch_is_malformed():
    m = base_manifest()
    sealed = bytearray(seal_state(b"state", m, master_secret=MASTER))
    # corrupt the ct_len field (immediately after the header prefix)
    off = core._HEADER_PREFIX.size
    sealed[off:off + 4] = struct.pack(">I", 999999)
    try:
        unseal_state(bytes(sealed), m, master_secret=MASTER)
    except MalformedEnvelope:
        return
    except StateSealMismatch:
        return
    raise AssertionError("length mismatch not caught")


def test_short_master_secret_rejected():
    try:
        seal_state(b"state", base_manifest(), master_secret=b"tooshort")
    except SCEError:
        return
    raise AssertionError("short master secret accepted")


def test_large_state_round_trip():
    m = base_manifest()
    big = os.urandom(1_000_000)
    sealed = seal_state(big, m, master_secret=MASTER)
    assert unseal_state(sealed, m, master_secret=MASTER) == big


def test_empty_state_round_trip():
    m = base_manifest()
    sealed = seal_state(b"", m, master_secret=MASTER)
    assert unseal_state(sealed, m, master_secret=MASTER) == b""


def test_out_of_range_epoch_rejected():
    m = base_manifest()
    for bad in [-1, 1 << 64, "0", 1.0, True]:
        try:
            seal_state(b"state", m, master_secret=MASTER, epoch_id=bad)
        except SCEError:
            continue
        raise AssertionError(f"bad epoch accepted: {bad!r}")


def test_tiny_ciphertext_is_malformed_not_crash():
    """A crafted envelope whose ciphertext is shorter than the tag must be
    rejected structurally, never reach the AEAD, and never crash."""
    m = base_manifest()
    sealed = bytearray(seal_state(b"state", m, master_secret=MASTER))
    off = core._HEADER_PREFIX.size
    # rewrite ct_len = 4 and truncate ciphertext to 4 bytes (< 16-byte tag)
    sealed[off:off + 4] = struct.pack(">I", 4)
    sealed = bytes(sealed[: off + 4 + 4])
    try:
        unseal_state(sealed, m, master_secret=MASTER)
    except MalformedEnvelope:
        return
    except StateSealMismatch:
        return
    raise AssertionError("tiny ciphertext not handled cleanly")


def test_fuzz_core_invariant():
    """Randomised property test of the central invariant, over many trials:

        unseal returns exactly the sealed plaintext  IFF  the environment
        matches and the bytes are untampered;  otherwise it fails closed.

    The failure that must NEVER happen: silently returning data that is wrong
    (either different plaintext, or a success under a changed environment).
    """
    import random
    rng = random.Random(1234)
    trials = 1500
    silent_corruptions = 0

    def rand_manifest():
        return ModelManifest(
            weights_hash="w" + str(rng.randrange(10_000)),
            quantization=rng.choice(["bf16", "fp8-e4m3", "int4", "fp16"]),
            kernel_build_id="k" + str(rng.randrange(10_000)),
            tensor_parallel=rng.choice(["tp=1,pp=1", "tp=2,pp=1", "tp=4,pp=2"]),
            numerics_mode=rng.choice(["bf16", "fp16", "fp32"]),
            extra={} if rng.random() < 0.5 else {"lora": "a" + str(rng.randrange(100))},
        )

    for _ in range(trials):
        secret = bytes(rng.randrange(256) for _ in range(32))
        m = rand_manifest()
        epoch = rng.randrange(0, 5)
        ctx = rng.choice([b"", b"prod", b"tenant-x"])
        state = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        sealed = seal_state(state, m, master_secret=secret, epoch_id=epoch, context=ctx)

        roll = rng.random()
        if roll < 0.34:
            # correct open -> must return exactly the state
            out = unseal_state(sealed, m, master_secret=secret, epoch_id=epoch, context=ctx)
            if out != state:
                silent_corruptions += 1
        elif roll < 0.67:
            # change something about the environment/epoch/context/secret -> must fail
            what = rng.choice(["manifest", "epoch", "ctx", "secret"])
            try:
                if what == "manifest":
                    unseal_state(sealed, rand_manifest_diff(m, rng),
                                 master_secret=secret, epoch_id=epoch, context=ctx)
                elif what == "epoch":
                    unseal_state(sealed, m, master_secret=secret, epoch_id=(epoch + 1) % 6, context=ctx)
                elif what == "ctx":
                    unseal_state(sealed, m, master_secret=secret, epoch_id=epoch, context=ctx + b"!")
                else:
                    bad = bytes(b ^ 0x01 for b in secret[:1]) + secret[1:]
                    unseal_state(sealed, m, master_secret=bad, epoch_id=epoch, context=ctx)
                # if we reach here without exception, an env change opened -> corruption
                silent_corruptions += 1
            except StateSealMismatch:
                pass
        else:
            # flip a random byte -> must fail closed (crypto mismatch or malformed)
            pos = rng.randrange(len(sealed))
            tampered = bytearray(sealed); tampered[pos] ^= (1 << rng.randrange(8))
            try:
                out = unseal_state(bytes(tampered), m, master_secret=secret,
                                   epoch_id=epoch, context=ctx)
                # a tampered envelope that returns the ORIGINAL state is acceptable only
                # if the flipped byte was in a non-authenticated position -- but every
                # byte of this envelope is either structural or authenticated, so any
                # successful return of non-identical data is a corruption.
                if out != state:
                    silent_corruptions += 1
            except (StateSealMismatch, MalformedEnvelope):
                pass

    assert silent_corruptions == 0, f"{silent_corruptions} silent corruptions in {trials} trials"


def rand_manifest_diff(m, rng):
    """Return a manifest guaranteed to differ from m in exactly one field."""
    fields = dict(
        weights_hash=m.weights_hash, quantization=m.quantization,
        kernel_build_id=m.kernel_build_id, tensor_parallel=m.tensor_parallel,
        numerics_mode=m.numerics_mode, extra=dict(m.extra),
    )
    key = rng.choice(["weights_hash", "quantization", "kernel_build_id",
                      "tensor_parallel", "numerics_mode"])
    fields[key] = fields[key] + "-DIFF"
    return ModelManifest(**fields)


# ===================== F. REGRESSION (review fixes) ================= #
# Each test here corresponds to a specific finding from the code review and
# would have caught the bug it guards against.

def test_oversize_state_is_rejected_cleanly():
    """Fix #3: a state larger than the uint32 length frame must raise SCEError,
    NOT a raw struct.error. The cap is shrunk here to avoid allocating ~4 GiB."""
    m = base_manifest()
    saved = core._MAX_STATE
    try:
        core._MAX_STATE = 64                       # pretend the frame is tiny
        try:
            seal_state(b"x" * 65, m, master_secret=MASTER)
        except SCEError:
            pass
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"oversize state raised non-SCE error: {exc!r}")
        else:
            raise AssertionError("oversize state was not rejected")
        # a state within the (shrunk) cap still seals and round-trips
        sealed = seal_state(b"x" * 64, m, master_secret=MASTER)
        assert unseal_state(sealed, m, master_secret=MASTER) == b"x" * 64
    finally:
        core._MAX_STATE = saved
    # the real cap is exactly the uint32 frame minus the AEAD tag
    assert core._MAX_STATE == (1 << 32) - 1 - core._TAG_LEN


def test_non_bytes_master_secret_rejected():
    """Fix #4: a str (or other non-bytes) master_secret must raise SCEError, not a
    low-level TypeError from inside HKDF -- including the >=16-char case that used
    to slip past the length check."""
    m = base_manifest()
    for bad in ["sixteencharacter", "short", 12345, None]:
        try:
            seal_state(b"state", m, master_secret=bad)
        except SCEError:
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"non-bytes secret raised non-SCE error: {exc!r}")
        raise AssertionError(f"non-bytes master_secret accepted: {bad!r}")
    # a bytearray of sufficient length is still accepted and round-trips
    sealed = seal_state(b"state", m, master_secret=bytearray(b"\x11" * 32))
    assert unseal_state(sealed, m, master_secret=bytearray(b"\x11" * 32)) == b"state"


def test_nfc_colliding_extra_keys_rejected():
    """Fix #5: two extra keys that are distinct strings but equal under NFC must be
    rejected at construction, so the fingerprint stays unambiguous and
    order-independent."""
    composed = "caf\u00e9"        # e-acute as one code point
    decomposed = "cafe\u0301"     # e + combining acute
    assert composed != decomposed
    for order in ({composed: "1", decomposed: "2"}, {decomposed: "2", composed: "1"}):
        try:
            base_manifest(extra=order)
        except SCEError:
            continue
        raise AssertionError("NFC-colliding extra keys were accepted")
    # a single normalised form is of course fine
    assert len(compute_memh(base_manifest(extra={composed: "1"}))) == 32


def test_seal_count_ceiling_is_enforced_when_supplied():
    """Fix #8: an opt-in seal_count must fail closed at the per-key ceiling and
    proceed below it. SCE stays stateless -- the caller owns the counter."""
    from sce import SEAL_COUNT_CEILING_PER_KEY
    m = base_manifest()
    # below the ceiling: seals normally and round-trips
    sealed = seal_state(b"state", m, master_secret=MASTER, seal_count=0)
    assert unseal_state(sealed, m, master_secret=MASTER) == b"state"
    # at the ceiling: refused
    try:
        seal_state(b"state", m, master_secret=MASTER,
                   seal_count=SEAL_COUNT_CEILING_PER_KEY)
    except SCEError:
        pass
    else:
        raise AssertionError("seal_count at the ceiling was not refused")
    # bad seal_count values are rejected (bool is not an int here)
    for bad in [-1, 1.0, "0", True]:
        try:
            seal_state(b"state", m, master_secret=MASTER, seal_count=bad)
        except SCEError:
            continue
        raise AssertionError(f"bad seal_count accepted: {bad!r}")
    # None (the default) disables the check
    assert unseal_state(seal_state(b"s", m, master_secret=MASTER, seal_count=None),
                        m, master_secret=MASTER) == b"s"


def test_serving_adapter_refusal_carries_no_reason():
    """Fix #1 (oracle leak): the serving adapter's fail-closed response must NOT
    include explain_mismatch output -- or any 'why' -- on the wire."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "examples", "serving_adapter.py")
    if not os.path.exists(path):
        return  # example not present in this checkout; nothing to guard
    spec = importlib.util.spec_from_file_location("serving_adapter", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    logging.disable(logging.CRITICAL)   # keep the server-side warning out of test output
    try:
        server = mod.MockInferenceServer()
        first = server.chat({"message": "hello", "continuation": None})
        server.update_model()           # model changes underneath -> unseal fails closed
        refused = server.chat({"message": "again", "continuation": first["continuation"]})
    finally:
        logging.disable(logging.NOTSET)

    assert refused.get("error") == "state_epoch_mismatch"
    assert "detail" not in refused, "adapter leaked a refusal reason key on the wire"
    blob = repr(refused)
    for leak in ("MEMH", "environment", "quantis", "sealed under"):
        assert leak not in blob, f"adapter response leaks '{leak}'"


# ===================== runner ======================================= #
def main():
    tests = [obj for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    print(f"\nRunning {len(tests)} SCE hardening tests\n" + "-" * 62)
    failures = 0
    for t in tests:
        label = t.__name__.replace("test_", "").replace("_", " ")
        try:
            t()
            print(f"  PASS  {label}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL  {label}\n         -> {exc}")
        except Exception:  # noqa: BLE001
            failures += 1
            print(f"  ERROR {label}")
            traceback.print_exc()
    print("-" * 62)
    if failures:
        print(f"{failures} of {len(tests)} tests FAILED\n")
        sys.exit(1)
    print(f"All {len(tests)} tests passed.\n")


if __name__ == "__main__":
    main()
