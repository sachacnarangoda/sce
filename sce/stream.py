"""
Chunked stream container for the Sealed Continuation Envelope (SCES v1)
======================================================================

`seal_state` produces a single SCE4 envelope. A single AES-256-GCM-SIV message
is capped at ~4 GiB by SCE's uint32 length frame, and by the algorithm itself at
2**36 bytes (~64 GiB). For states larger than that -- e.g. a long-context
transformer KV-cache, when compact SSM / summarised state is not an option --
this module seals the state as an ordered sequence of bounded SCE4 envelopes and
binds the sequence together so that reordering, dropping, truncating, extending,
or splicing segments (including from another stream) all fail closed.

Design
------
The sequence binding reuses the primitive's existing `context` channel rather
than adding new cryptography. For a state S split into `n` segments of nominal
size C, with total length L and a fresh random `stream_id`:

    seg_context(i) = "LDDP-SCE|stream-v1"
                     || LP(user_context) || LP(stream_id)
                     || u64(i) || u64(n) || u64(L) || u64(C)
    env_i          = seal_state(S[i*C:(i+1)*C], manifest, master_secret,
                                epoch_id, context=seg_context(i))

Because `context` feeds the key derivation, a segment sealed at index i of n can
only be opened when the unsealer reconstructs that exact
(user_context, stream_id, i, n, L, C). The container header carries stream_id,
n, C and L in the clear; it needs no separate MAC, because any change to those
values makes every segment fail to derive its key -- the header is authenticated
"by consequence". The envelope wire format (SCE4) is unchanged: each segment is a
normal, unlinkable v4 envelope, so this layer required no re-audit of the seal.

Memory
------
This returns the whole container as `bytes`, so peak memory is ~L for the
container plus the per-segment transient (~2C). That removes the AEAD size
ceiling and avoids ever holding 2-3x the *whole* state for one AEAD pass, but it
does not yet stream to disk. A file-backed streaming variant is the natural
follow-up for states too large to hold assembled in memory.
"""

from __future__ import annotations

import os
import struct
from typing import Any, Dict, List, Tuple

from .core import (
    ModelManifest,
    seal_state,
    unseal_state,
    SCEError,
    StateSealMismatch,
    MalformedEnvelope,
    _MAX_STATE,
    _require_manifest,
    _require_envelope_bytes,
)

__all__ = [
    "seal_state_chunked",
    "unseal_state_chunked",
    "describe_stream",
    "DEFAULT_SEGMENT_SIZE",
]

_STREAM_MAGIC = b"SCES"
_STREAM_VERSION = 1
_STREAM_DOMAIN = b"LDDP-SCE|stream-v1"   # domain separation for the per-segment context
_STREAM_ID_LEN = 16

# Container header: magic, version, stream_id, num_segments, segment_size, total_len
_STREAM_HEADER = struct.Struct(">4sB16sQQQ")     # 4+1+16+8+8+8 = 45 bytes
_SEG_FRAME = struct.Struct(">Q")                 # 8-byte big-endian length prefix per segment

# Default nominal segment size: large enough that the 85-byte per-segment envelope
# overhead is negligible, small enough to bound the per-segment AEAD memory
# transient (~2 * segment_size while one segment is being sealed).
DEFAULT_SEGMENT_SIZE = 64 * 1024 * 1024          # 64 MiB


def _lp(b: bytes) -> bytes:
    """Length-prefix bytes with a 4-byte big-endian length (the same discipline
    the core canonicaliser uses), so the per-segment context is unambiguous."""
    return len(b).to_bytes(4, "big") + b


def _seg_context(user_context: bytes, stream_id: bytes, index: int,
                 num_segments: int, total_len: int, segment_size: int) -> bytes:
    """Deterministic, injective per-segment context.

    Binds a segment to its exact position in its exact stream. Any change to the
    index, segment count, total length, segment size, stream id, or the caller's
    context yields a different context, hence a different key, hence a fail-closed
    open. The two variable-length fields are length-prefixed; the integers are
    fixed-width, so distinct tuples never serialise to the same bytes.
    """
    return (
        _STREAM_DOMAIN
        + _lp(user_context)
        + _lp(stream_id)
        + index.to_bytes(8, "big")
        + num_segments.to_bytes(8, "big")
        + total_len.to_bytes(8, "big")
        + segment_size.to_bytes(8, "big")
    )


def seal_state_chunked(
    state: bytes,
    manifest: ModelManifest,
    *,
    master_secret: bytes,
    epoch_id: int = 0,
    context: bytes = b"",
    segment_size: int = DEFAULT_SEGMENT_SIZE,
) -> bytes:
    """Seal an arbitrarily large `state` as an ordered sequence of bounded SCE4
    envelopes, bound together so the sequence itself is tamper-evident.

    Returns an SCES container (opaque `bytes`), safe to hand to an untrusted
    holder. Reordering, dropping, truncating, extending, or splicing segments --
    including a segment from another stream -- all fail closed on
    `unseal_state_chunked`, as does any change to the environment, epoch, context,
    or master secret, or a flipped byte anywhere.

    `segment_size` is the nominal per-segment plaintext size (the last segment may
    be shorter). It must be a positive int within a single envelope's capacity
    (`seal_state` enforces the ~4 GiB per-envelope frame). The default is 64 MiB.
    """
    _require_manifest(manifest)
    if not isinstance(state, (bytes, bytearray)):
        raise SCEError("state must be bytes; serialise your tensors/objects first")
    if not isinstance(context, (bytes, bytearray)):
        raise SCEError("context must be bytes")
    if not isinstance(segment_size, int) or isinstance(segment_size, bool) or segment_size <= 0:
        raise SCEError("segment_size must be a positive integer")
    if segment_size > _MAX_STATE:
        # segment_size is packed into a u64 header field, and a single segment can
        # never exceed one envelope's payload capacity anyway. Bounding it here
        # keeps the "only SCEError escapes" contract instead of letting an oversize
        # value surface as a raw struct.error from the header pack.
        raise SCEError("segment_size exceeds the maximum sealable payload (~4 GiB)")

    state = bytes(state)
    user_context = bytes(context)
    total_len = len(state)

    # At least one segment, so an empty state still produces a well-formed stream.
    if total_len == 0:
        bounds: List[Tuple[int, int]] = [(0, 0)]
    else:
        bounds = [(o, min(o + segment_size, total_len))
                  for o in range(0, total_len, segment_size)]
    num_segments = len(bounds)

    stream_id = os.urandom(_STREAM_ID_LEN)
    header = _STREAM_HEADER.pack(
        _STREAM_MAGIC, _STREAM_VERSION, stream_id,
        num_segments, segment_size, total_len,
    )

    out = bytearray(header)
    for i, (lo, hi) in enumerate(bounds):
        seg_ctx = _seg_context(user_context, stream_id, i, num_segments, total_len, segment_size)
        env = seal_state(state[lo:hi], manifest, master_secret=master_secret,
                         epoch_id=epoch_id, context=seg_ctx)
        out += _SEG_FRAME.pack(len(env))
        out += env
    return bytes(out)


def _parse_stream_header(container: bytes):
    """Structural parse of the container header only. Raises MalformedEnvelope on
    any structural fault. Returns (stream_id, num_segments, segment_size, total_len)."""
    container = _require_envelope_bytes(container, "stream container")
    if len(container) < _STREAM_HEADER.size:
        raise MalformedEnvelope("blob is shorter than the SCES stream header")
    magic, version, stream_id, n, seg_size, total_len = _STREAM_HEADER.unpack(
        container[:_STREAM_HEADER.size]
    )
    if magic != _STREAM_MAGIC:
        raise MalformedEnvelope("bad magic: not an SCES stream container")
    if version != _STREAM_VERSION:
        raise MalformedEnvelope(f"unsupported SCES stream version {version}")
    return stream_id, n, seg_size, total_len


def unseal_state_chunked(
    container: bytes,
    manifest: ModelManifest,
    *,
    master_secret: bytes,
    epoch_id: int = 0,
    context: bytes = b"",
) -> bytes:
    """Reopen an SCES container produced by `seal_state_chunked`.

    Returns the original plaintext state, or fails closed: `StateSealMismatch` for
    any cryptographic / sequence-binding failure (wrong environment, epoch,
    context, or secret; tampering; reordering; dropping; cross-stream splicing),
    and `MalformedEnvelope` for a structurally invalid container. Never returns
    partial or reordered data.

    Note: on a tampered stream this stops at the first failing segment, which is a
    timing signal about *where* the first fault is -- but that position is not
    secret (the attacker chose it, and the segment count is in the cleartext
    header), and no plaintext or key material is revealed. Each segment still fails
    with the envelope's own uniform, oracle-free error.
    """
    _require_manifest(manifest)
    if not isinstance(context, (bytes, bytearray)):
        raise SCEError("context must be bytes")
    user_context = bytes(context)

    container = _require_envelope_bytes(container, "stream container")
    stream_id, n, seg_size, total_len = _parse_stream_header(container)

    # A valid container always seals at least one segment -- the producer forces
    # this, and SPEC 9.2 requires L == 0 to be carried by exactly one segment
    # sealing an empty state. Without this guard a header-only blob claiming
    # n == 0 would return b"" having performed NO cryptographic verification: an
    # unauthenticated forgery of the fail-closed contract. Reject it structurally.
    if n == 0:
        raise MalformedEnvelope("container declares zero segments")
    if total_len == 0 and n != 1:
        raise MalformedEnvelope("an empty state must be carried by exactly one segment")

    # Guard against an absurd declared segment count forcing a long loop: each
    # segment needs at least its length frame plus one byte.
    max_possible = (len(container) - _STREAM_HEADER.size) // (_SEG_FRAME.size + 1)
    if n > max_possible:
        raise MalformedEnvelope("declared segment count exceeds what the container can hold")

    off = _STREAM_HEADER.size
    parts: List[bytes] = []
    assembled = 0
    for i in range(n):
        if off + _SEG_FRAME.size > len(container):
            raise MalformedEnvelope("stream truncated: missing a segment length prefix")
        (env_len,) = _SEG_FRAME.unpack(container[off:off + _SEG_FRAME.size])
        off += _SEG_FRAME.size
        if env_len > len(container) - off:
            raise MalformedEnvelope("stream truncated: segment shorter than declared")
        env = container[off:off + env_len]
        off += env_len
        seg_ctx = _seg_context(user_context, stream_id, i, n, total_len, seg_size)
        # Any binding mismatch (position, stream, count, length, environment, ...)
        # surfaces here as StateSealMismatch; structural faults as MalformedEnvelope.
        segment = unseal_state(env, manifest, master_secret=master_secret,
                               epoch_id=epoch_id, context=seg_ctx)
        parts.append(segment)
        assembled += len(segment)

    if off != len(container):
        raise MalformedEnvelope("trailing bytes after the declared segments")
    if assembled != total_len:
        # Every segment opened, yet the total does not match the header's claim.
        # This cannot happen for an untampered stream; treat it as a binding failure.
        raise StateSealMismatch()
    return b"".join(parts)


def describe_stream(container: bytes) -> Dict[str, Any]:
    """Return the non-secret, structural header fields of an SCES container.

    Needs no key and reveals nothing about the plaintext beyond its size (which
    the container length already implies). Does not expose the stream id.
    """
    _stream_id, n, seg_size, total_len = _parse_stream_header(container)
    return {
        "magic": _STREAM_MAGIC.decode("ascii"),
        "version": _STREAM_VERSION,
        "num_segments": n,
        "segment_size": seg_size,
        "total_plaintext_bytes": total_len,
        "total_container_bytes": len(container),
    }
