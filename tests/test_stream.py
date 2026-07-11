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
