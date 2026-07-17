"""
Test suite for the SCES chunked stream container (sce.stream).

Runs WITHOUT pytest:  python tests/test_stream.py

Covers round-trip across many segment sizes, and fail-closed behaviour under
every structural attack on the sequence: reorder, drop, drop-with-header-fixup,
truncate, trailing bytes, cross-stream splice, per-segment tamper, and header
tamper -- plus the inherited environment/epoch/context/secret bindings.
"""

import os
import sys
import struct
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest,
    seal_state,
    unseal_state,
    seal_state_chunked,
    unseal_state_chunked,
    describe_stream,
    SCEError,
    StateSealMismatch,
    MalformedEnvelope,
)
import sce.stream as stream  # noqa: E402

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


def _segment_spans(container):
    """Return (offset, length) of each segment's framed envelope in a container,
    for tests that surgically tamper with individual segments."""
    off = stream._STREAM_HEADER.size
    _sid, n, _c, _l = stream._parse_stream_header(container)
    spans = []
    for _ in range(n):
        (env_len,) = stream._SEG_FRAME.unpack(container[off:off + stream._SEG_FRAME.size])
        spans.append((off + stream._SEG_FRAME.size, env_len))
        off += stream._SEG_FRAME.size + env_len
    return spans


# ===================== round-trip ===================================== #
def test_chunked_round_trip_many_segment_sizes():
    m = base_manifest()
    payload = os.urandom(2000)
    for seg in (1, 13, 128, 999, 2000, 5000):
        c = seal_state_chunked(payload, m, master_secret=MASTER, segment_size=seg)
        out = unseal_state_chunked(c, m, master_secret=MASTER)
        assert out == payload, f"round-trip failed at segment_size={seg}"


def test_chunked_round_trip_larger_state():
    m = base_manifest()
    payload = os.urandom(200_000)
    c = seal_state_chunked(payload, m, master_secret=MASTER, segment_size=8192)
    assert describe_stream(c)["num_segments"] == 25
    assert unseal_state_chunked(c, m, master_secret=MASTER) == payload


def test_chunked_round_trip_with_context_and_epoch():
    m = base_manifest()
    payload = os.urandom(5000)
    c = seal_state_chunked(payload, m, master_secret=MASTER, epoch_id=9,
                           context=b"tenant-A", segment_size=512)
    assert unseal_state_chunked(c, m, master_secret=MASTER, epoch_id=9,
                                context=b"tenant-A") == payload


def test_chunked_empty_state_round_trip():
    m = base_manifest()
    c = seal_state_chunked(b"", m, master_secret=MASTER, segment_size=1024)
    assert describe_stream(c)["num_segments"] == 1
    assert unseal_state_chunked(c, m, master_secret=MASTER) == b""


def test_chunked_single_segment_when_state_fits():
    m = base_manifest()
    payload = b"small-enough-for-one-segment"
    c = seal_state_chunked(payload, m, master_secret=MASTER, segment_size=1 << 20)
    assert describe_stream(c)["num_segments"] == 1
    assert unseal_state_chunked(c, m, master_secret=MASTER) == payload


def test_describe_stream_counts_and_hides_plaintext():
    m = base_manifest()
    payload = os.urandom(10_000)
    c = seal_state_chunked(payload, m, master_secret=MASTER, segment_size=1000)
    info = describe_stream(c)
    assert info["magic"] == "SCES"
    assert info["num_segments"] == 10
    assert info["total_plaintext_bytes"] == 10_000
    assert "stream_id" not in info
    assert payload not in c        # plaintext is encrypted, never appears in the container


# ===================== inherited fail-closed binding ================= #
def test_chunked_fails_on_wrong_environment():
    m = base_manifest()
    c = seal_state_chunked(os.urandom(4000), m, master_secret=MASTER, segment_size=500)
    try:
        unseal_state_chunked(c, base_manifest(numerics_mode="fp16"), master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError("stream opened under a changed environment")


def test_chunked_fails_on_wrong_secret():
    m = base_manifest()
    c = seal_state_chunked(os.urandom(4000), m, master_secret=MASTER, segment_size=500)
    try:
        unseal_state_chunked(c, m, master_secret=MASTER2)
    except StateSealMismatch:
        return
    raise AssertionError("stream opened under a wrong master secret")


def test_chunked_fails_on_wrong_context():
    m = base_manifest()
    c = seal_state_chunked(os.urandom(4000), m, master_secret=MASTER,
                           context=b"session-A", segment_size=500)
    try:
        unseal_state_chunked(c, m, master_secret=MASTER, context=b"session-B")
    except StateSealMismatch:
        return
    raise AssertionError("stream opened under a foreign context")


# ===================== structural tamper ============================= #
def test_chunked_segment_reorder_fails_closed():
    m = base_manifest()
    # equal-length segments so a swap keeps the framing structurally valid
    c = bytearray(seal_state_chunked(os.urandom(6000), m, master_secret=MASTER, segment_size=1000))
    spans = _segment_spans(bytes(c))
    (o0, l0), (o1, l1) = spans[0], spans[1]
    assert l0 == l1
    seg0 = bytes(c[o0:o0 + l0])
    seg1 = bytes(c[o1:o1 + l1])
    c[o1:o1 + l1] = seg0
    c[o0:o0 + l0] = seg1
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("reordered segments opened")


def test_chunked_segment_drop_fails_closed():
    m = base_manifest()
    c = bytearray(seal_state_chunked(os.urandom(6000), m, master_secret=MASTER, segment_size=1000))
    spans = _segment_spans(bytes(c))
    o, l = spans[-1]
    del c[o - stream._SEG_FRAME.size: o + l]   # remove last segment, leave header n unchanged
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("dropped segment opened")


def test_chunked_drop_with_header_fixup_fails_closed():
    """Drop a segment AND decrement n / total_len in the header. Must still fail:
    the remaining segments were bound to the ORIGINAL n and L."""
    m = base_manifest()
    c = bytearray(seal_state_chunked(os.urandom(6000), m, master_secret=MASTER, segment_size=1000))
    sid, n, seg_size, total_len = stream._parse_stream_header(bytes(c))
    spans = _segment_spans(bytes(c))
    o, l = spans[-1]
    del c[o - stream._SEG_FRAME.size: o + l]
    fixed = stream._STREAM_HEADER.pack(stream._STREAM_MAGIC, stream._STREAM_VERSION,
                                       sid, n - 1, seg_size, total_len - 1000)
    c[:stream._STREAM_HEADER.size] = fixed
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("drop-with-header-fixup opened")


def test_chunked_cross_stream_splice_fails_closed():
    """A segment from one stream spliced into another at the same index fails,
    because each segment is bound to its stream_id."""
    m = base_manifest()
    payload = os.urandom(6000)
    a = bytearray(seal_state_chunked(payload, m, master_secret=MASTER, segment_size=1000))
    b = bytearray(seal_state_chunked(payload, m, master_secret=MASTER, segment_size=1000))
    (oa, la) = _segment_spans(bytes(a))[2]
    (ob, lb) = _segment_spans(bytes(b))[2]
    assert la == lb
    a[oa:oa + la] = bytes(b[ob:ob + lb])
    try:
        unseal_state_chunked(bytes(a), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("cross-stream spliced segment opened")


def test_chunked_per_segment_tamper_fails_closed():
    m = base_manifest()
    c = bytearray(seal_state_chunked(os.urandom(6000), m, master_secret=MASTER, segment_size=1000))
    o, l = _segment_spans(bytes(c))[3]
    c[o + 10] ^= 0x01
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("tampered segment opened")


def test_chunked_header_stream_id_tamper_fails_closed():
    m = base_manifest()
    c = bytearray(seal_state_chunked(os.urandom(4000), m, master_secret=MASTER, segment_size=1000))
    c[6] ^= 0x01   # header: magic[0:4] ver[4] stream_id[5:21] -> flip inside stream_id
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("stream_id tamper opened")


def test_chunked_total_len_tamper_fails_closed():
    m = base_manifest()
    c = bytearray(seal_state_chunked(os.urandom(4000), m, master_secret=MASTER, segment_size=1000))
    off = stream._STREAM_HEADER.size - 8        # total_len is the last 8 header bytes
    (tl,) = struct.unpack(">Q", bytes(c[off:off + 8]))
    c[off:off + 8] = struct.pack(">Q", tl + 1)
    try:
        unseal_state_chunked(bytes(c), m, master_secret=MASTER)
    except (StateSealMismatch, MalformedEnvelope):
        return
    raise AssertionError("total_len tamper opened")


def test_chunked_trailing_bytes_rejected():
    m = base_manifest()
    c = seal_state_chunked(os.urandom(3000), m, master_secret=MASTER, segment_size=1000)
    try:
        unseal_state_chunked(c + b"\x00", m, master_secret=MASTER)
    except MalformedEnvelope:
        return
    raise AssertionError("trailing bytes not rejected")


# ===================== format separation / robustness =============== #
def test_chunked_not_a_stream_is_malformed():
    m = base_manifest()
    env = seal_state(b"hello", m, master_secret=MASTER)   # a single SCE4 envelope
    try:
        unseal_state_chunked(env, m, master_secret=MASTER)
    except MalformedEnvelope:
        pass
    else:
        raise AssertionError("single envelope accepted as a stream")
    for junk in [b"", b"x", b"SCES", os.urandom(30), os.urandom(200)]:
        try:
            unseal_state_chunked(junk, m, master_secret=MASTER)
        except (MalformedEnvelope, StateSealMismatch):
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"uncontrolled error on junk: {exc!r}")


def test_stream_container_rejected_by_single_unseal():
    m = base_manifest()
    c = seal_state_chunked(os.urandom(3000), m, master_secret=MASTER, segment_size=1000)
    try:
        unseal_state(c, m, master_secret=MASTER)
    except MalformedEnvelope:
        return
    raise AssertionError("stream container accepted by single-envelope unseal")


def test_bad_segment_size_rejected():
    m = base_manifest()
    for bad in [0, -1, 1.5, "1024", True]:
        try:
            seal_state_chunked(b"data", m, master_secret=MASTER, segment_size=bad)
        except SCEError:
            continue
        raise AssertionError(f"bad segment_size accepted: {bad!r}")


# ===================== runner ======================================= #
def test_forged_zero_segment_container_is_rejected():
    """Regression: a header-only container claiming n=0, built with NO secret,
    must NOT be accepted. Before the fix it returned b"" after performing zero
    cryptographic verification -- an unauthenticated forgery of the fail-closed
    contract (and a violation of SPEC 9.2)."""
    forged = stream._STREAM_HEADER.pack(
        stream._STREAM_MAGIC, stream._STREAM_VERSION, b"\x00" * 16, 0, 0, 0)
    for secret in (b"\x00" * 32, b"\x99" * 32, MASTER):
        try:
            unseal_state_chunked(forged, base_manifest(), master_secret=secret)
        except MalformedEnvelope:
            continue
        raise AssertionError("SECURITY FAILURE: zero-segment container accepted")


def test_forged_empty_container_with_wrong_n_is_rejected():
    """An empty state (L=0) must be carried by exactly one segment. A container
    claiming L=0 with n != 1 is structurally invalid and must be refused."""
    for n in (0, 2, 5):
        forged = stream._STREAM_HEADER.pack(
            stream._STREAM_MAGIC, stream._STREAM_VERSION, b"\x00" * 16, n, 0, 0)
        try:
            unseal_state_chunked(forged, base_manifest(), master_secret=MASTER)
        except MalformedEnvelope:
            continue
        raise AssertionError(f"empty container with n={n} accepted")


def test_genuine_empty_state_still_round_trips():
    """The fix must not break the legitimate empty-state case: a properly sealed
    empty state (which the producer carries as exactly one segment) still opens."""
    c = seal_state_chunked(b"", base_manifest(), master_secret=MASTER, segment_size=1000)
    assert unseal_state_chunked(c, base_manifest(), master_secret=MASTER) == b""


def test_oversize_segment_size_raises_sceerror_not_struct_error():
    """Regression: segment_size at or above 2**64 (or above the max sealable
    payload) is packed into a u64 header field and previously escaped as a raw
    struct.error, violating the 'only SCEError escapes a public entry point'
    contract asserted in the README and SPEC 10. It must now raise SCEError."""
    import struct
    for ss in (1 << 64, 1 << 70, (1 << 32)):   # >= 2**64, huge, and > _MAX_STATE
        try:
            seal_state_chunked(b"hello", base_manifest(), master_secret=MASTER, segment_size=ss)
        except SCEError:
            continue
        except struct.error as e:
            raise AssertionError(f"segment_size={ss} leaked raw struct.error: {e}")
        raise AssertionError(f"segment_size={ss} was accepted")


def test_oversize_context_raises_sceerror_not_overflow():
    """Regression: an oversized length-prefixed field must raise SCEError, not a
    raw OverflowError, upholding the 'only SCEError escapes' contract. We assert
    the guard directly against the length-prefix helper (allocating 4 GiB is not
    feasible in a test)."""
    import sce.core as core

    class _HugeLen(bytes):
        def __len__(self):  # pretend to be > 2**32 bytes without allocating
            return (1 << 32) + 1

    try:
        core._lp(_HugeLen())
    except SCEError:
        pass
    else:
        raise AssertionError("oversize length-prefixed field did not raise SCEError")


def test_wrong_segment_index_derivation_fails_closed():
    """Semantic-mutation test for the stream layer: if the per-segment context
    were derived with the WRONG index (a plausible off-by-one maintenance error),
    a validly-sealed container must fail closed on unseal rather than silently
    accept. The sabotage suite mutates core.py only, so this models the same class
    of 'wrong logic, not missing logic' error in the stream binding directly, by
    monkeypatching the index that goes into the segment context at unseal time.
    """
    container = seal_state_chunked(b"A" * 500, base_manifest(),
                                   master_secret=MASTER, segment_size=150)
    # sanity: it opens correctly with the real derivation
    assert unseal_state_chunked(container, base_manifest(), master_secret=MASTER) == b"A" * 500

    real = stream._seg_context

    def wrong_index(user_context, stream_id, index, num_segments, total_len, segment_size):
        # off-by-one on the index -- exactly the maintenance error being modelled
        return real(user_context, stream_id, index + 1, num_segments, total_len, segment_size)

    stream._seg_context = wrong_index
    try:
        try:
            unseal_state_chunked(container, base_manifest(), master_secret=MASTER)
        except StateSealMismatch:
            pass  # correct: wrong index -> wrong key -> fails closed
        else:
            raise AssertionError("wrong segment index did not fail closed")
    finally:
        stream._seg_context = real
    # and the real derivation still works afterwards (no global corruption)
    assert unseal_state_chunked(container, base_manifest(), master_secret=MASTER) == b"A" * 500


def main():
    tests = [obj for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    print(f"\nRunning {len(tests)} SCES stream tests\n" + "-" * 62)
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
