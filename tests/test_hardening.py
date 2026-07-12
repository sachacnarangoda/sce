"""
Hardening harness for SCE -- stdlib only, no external dependencies.

Runs WITHOUT pytest:  python tests/test_hardening.py

This is the automated security-verification layer. Where test_core.py asserts the
designed behaviour, this file attacks the implementation:

  1. Exhaustive mutation ..... every bit of every byte of an envelope and of a
                               stream container must fail closed -- not a sample.
  2. Exhaustive truncation ... every prefix length must fail closed.
  3. Error-model fuzz ........ for ARBITRARY input to ANY public entry point,
                               only SCEError subclasses may escape. A raw
                               TypeError/struct.error/AttributeError is a bug:
                               callers cannot write `except SCEError` safely.
  4. Isolating tests ......... prove the key-commitment check and the AEAD
                               associated-data binding are each LOAD-BEARING and
                               not merely redundant with the other bindings.
  5. Known-answer vectors .... the Python side reproduces test_vectors.json, so a
                               silent change to canonicalisation or key derivation
                               is caught here, not only by the JS verifier.
  6. Immutability ............ a constructed manifest cannot be mutated, and its
                               fingerprint is therefore stable.
  7. Scaling ................. the chunked layer stays sub-quadratic.
"""

import copy
import dataclasses
import gc
import json
import os
import pickle
import random
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest,
    compute_memh,
    seal_state,
    unseal_state,
    describe_envelope,
    explain_mismatch,
    seal_state_chunked,
    unseal_state_chunked,
    describe_stream,
    SCEError,
    StateSealMismatch,
    MalformedEnvelope,
)
import sce.core as core        # noqa: E402
import sce.stream as stream    # noqa: E402

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASTER = b"\x11" * 32

# Every public entry point, as (name, callable, kwargs-builder). Used by the
# error-model tests to assert a single, uniform exception contract.
FAIL_CLOSED = (StateSealMismatch, MalformedEnvelope)


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


# =============================== 1. exhaustive mutation ==================== #
def test_every_single_bit_flip_in_an_envelope_fails_closed():
    """Not a spot check: flip EVERY bit of EVERY byte, one at a time, and require
    that the envelope never opens. An envelope of ~93 bytes gives ~744 mutants."""
    m = base_manifest()
    good = seal_state(b"payload-under-test", m, master_secret=MASTER,
                      epoch_id=3, context=b"ctx")
    accepted = []
    for off in range(len(good)):
        for bit in range(8):
            mutant = bytearray(good)
            mutant[off] ^= (1 << bit)
            try:
                unseal_state(bytes(mutant), m, master_secret=MASTER,
                             epoch_id=3, context=b"ctx")
                accepted.append((off, bit))
            except FAIL_CLOSED:
                pass
    assert not accepted, f"SECURITY FAILURE: mutated envelope accepted at {accepted[:5]}"


def test_every_truncation_of_an_envelope_fails_closed():
    """Every proper prefix of a valid envelope must be refused."""
    m = base_manifest()
    good = seal_state(b"payload", m, master_secret=MASTER)
    for n in range(len(good)):
        try:
            unseal_state(good[:n], m, master_secret=MASTER)
        except FAIL_CLOSED:
            continue
        raise AssertionError(f"SECURITY FAILURE: {n}-byte truncation accepted")


def test_every_extension_of_an_envelope_fails_closed():
    """Appending bytes must be refused (the declared length must be exact)."""
    m = base_manifest()
    good = seal_state(b"payload", m, master_secret=MASTER)
    for extra in (b"\x00", b"\xff", os.urandom(1), os.urandom(17)):
        try:
            unseal_state(good + extra, m, master_secret=MASTER)
        except FAIL_CLOSED:
            continue
        raise AssertionError("SECURITY FAILURE: extended envelope accepted")


def test_every_single_bit_flip_in_a_stream_container_fails_closed():
    """Same exhaustive treatment for the SCES container (kept small on purpose)."""
    m = base_manifest()
    good = seal_state_chunked(b"A" * 24, m, master_secret=MASTER, segment_size=8)
    accepted = []
    for off in range(len(good)):
        for bit in range(8):
            mutant = bytearray(good)
            mutant[off] ^= (1 << bit)
            try:
                unseal_state_chunked(bytes(mutant), m, master_secret=MASTER)
                accepted.append((off, bit))
            except FAIL_CLOSED:
                pass
    assert not accepted, f"SECURITY FAILURE: mutated container accepted at {accepted[:5]}"


def test_every_truncation_of_a_stream_container_fails_closed():
    m = base_manifest()
    good = seal_state_chunked(b"A" * 24, m, master_secret=MASTER, segment_size=8)
    for n in range(len(good)):
        try:
            unseal_state_chunked(good[:n], m, master_secret=MASTER)
        except FAIL_CLOSED:
            continue
        raise AssertionError(f"SECURITY FAILURE: {n}-byte container truncation accepted")


# =============================== 2. error model =========================== #
WRONG_TYPES = (None, 0, 1, -1, 1.5, True, "a string", ["list"], {"dict": 1}, object())


def test_public_api_never_leaks_a_non_library_exception_on_wrong_types():
    """Every public entry point must reject a wrong-typed argument with an
    SCEError. A raw TypeError/AttributeError means `except SCEError` is unsafe."""
    m = base_manifest()
    good = seal_state(b"x", m, master_secret=MASTER)
    container = seal_state_chunked(b"x", m, master_secret=MASTER)
    leaks = []

    def probe(label, fn):
        try:
            fn()
        except SCEError:
            pass                      # the contract
        except Exception as exc:      # noqa: BLE001 -- this is the bug we hunt
            leaks.append(f"{label}: {type(exc).__name__}: {exc}")

    for bad in WRONG_TYPES:
        probe(f"seal_state(state={bad!r})",
              lambda b=bad: seal_state(b, m, master_secret=MASTER))
        probe(f"seal_state(manifest={bad!r})",
              lambda b=bad: seal_state(b"x", b, master_secret=MASTER))
        probe(f"seal_state(master_secret={bad!r})",
              lambda b=bad: seal_state(b"x", m, master_secret=b))
        probe(f"seal_state(epoch_id={bad!r})",
              lambda b=bad: seal_state(b"x", m, master_secret=MASTER, epoch_id=b))
        probe(f"seal_state(context={bad!r})",
              lambda b=bad: seal_state(b"x", m, master_secret=MASTER, context=b))
        probe(f"unseal_state(sealed={bad!r})",
              lambda b=bad: unseal_state(b, m, master_secret=MASTER))
        probe(f"unseal_state(manifest={bad!r})",
              lambda b=bad: unseal_state(good, b, master_secret=MASTER))
        probe(f"unseal_state(master_secret={bad!r})",
              lambda b=bad: unseal_state(good, m, master_secret=b))
        probe(f"unseal_state(epoch_id={bad!r})",
              lambda b=bad: unseal_state(good, m, master_secret=MASTER, epoch_id=b))
        probe(f"unseal_state(context={bad!r})",
              lambda b=bad: unseal_state(good, m, master_secret=MASTER, context=b))
        probe(f"describe_envelope({bad!r})", lambda b=bad: describe_envelope(b))
        probe(f"explain_mismatch({bad!r})", lambda b=bad: explain_mismatch(b, m))
        probe(f"compute_memh({bad!r})", lambda b=bad: compute_memh(b))
        probe(f"seal_state_chunked(state={bad!r})",
              lambda b=bad: seal_state_chunked(b, m, master_secret=MASTER))
        probe(f"seal_state_chunked(manifest={bad!r})",
              lambda b=bad: seal_state_chunked(b"x", b, master_secret=MASTER))
        probe(f"seal_state_chunked(epoch_id={bad!r})",
              lambda b=bad: seal_state_chunked(b"x", m, master_secret=MASTER, epoch_id=b))
        probe(f"unseal_state_chunked(container={bad!r})",
              lambda b=bad: unseal_state_chunked(b, m, master_secret=MASTER))
        probe(f"unseal_state_chunked(manifest={bad!r})",
              lambda b=bad: unseal_state_chunked(container, b, master_secret=MASTER))
        probe(f"describe_stream({bad!r})", lambda b=bad: describe_stream(b))
        probe(f"ModelManifest(extra={bad!r})",
              lambda b=bad: ModelManifest("w", "q", "k", "t", "n", extra=b))

    assert not leaks, (
        f"{len(leaks)} non-SCEError leaks from the public API:\n  "
        + "\n  ".join(sorted(set(leaks))[:12])
    )


def test_arbitrary_bytes_never_leak_a_non_library_exception():
    """Seeded, reproducible byte fuzz across every bytes-consuming entry point."""
    m = base_manifest()
    rng = random.Random(20260712)
    leaks = []
    for _ in range(4000):
        n = rng.choice([0, 1, 2, 63, 64, 65, 66, 92, 93, 94, rng.randrange(0, 300)])
        blob = bytes(rng.randrange(256) for _ in range(n))
        if rng.random() < 0.5:                      # bias toward plausible shapes
            blob = core._MAGIC + blob
        for fn in (
            lambda b: unseal_state(b, m, master_secret=MASTER),
            lambda b: describe_envelope(b),
            lambda b: explain_mismatch(b, m),
            lambda b: unseal_state_chunked(b, m, master_secret=MASTER),
            lambda b: describe_stream(b),
        ):
            try:
                fn(blob)
            except SCEError:
                pass
            except Exception as exc:  # noqa: BLE001
                leaks.append(f"{type(exc).__name__}: {exc} on {blob[:16].hex()}")
    assert not leaks, f"{len(leaks)} non-SCEError leaks:\n  " + "\n  ".join(sorted(set(leaks))[:8])


def test_structured_mutation_fuzz_never_leaks_and_never_opens():
    """Mutate VALID envelopes (the interesting region of the input space) and
    require: never a raw exception, and never a successful open."""
    m = base_manifest()
    rng = random.Random(987654321)
    good = seal_state(b"the-quick-brown-fox", m, master_secret=MASTER)
    for _ in range(3000):
        mutant = bytearray(good)
        for _ in range(rng.randrange(1, 4)):
            op = rng.randrange(4)
            if op == 0 and mutant:                       # bit flip
                i = rng.randrange(len(mutant))
                mutant[i] ^= 1 << rng.randrange(8)
            elif op == 1 and mutant:                     # byte set
                mutant[rng.randrange(len(mutant))] = rng.randrange(256)
            elif op == 2 and len(mutant) > 1:            # truncate
                del mutant[rng.randrange(len(mutant)):]
            else:                                        # extend
                mutant += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
        blob = bytes(mutant)
        if blob == good:
            continue
        try:
            unseal_state(blob, m, master_secret=MASTER)
        except FAIL_CLOSED:
            continue
        except Exception as exc:  # noqa: BLE001
            raise AssertionError(f"raw {type(exc).__name__} from mutated envelope: {exc}")
        raise AssertionError(f"SECURITY FAILURE: mutated envelope opened: {blob[:24].hex()}")


# ===================== 3. isolating tests (defence-in-depth) ============== #
def test_commitment_check_is_load_bearing():
    """Prove the explicit key-commitment check does real work.

    Craft an envelope whose AEAD is perfectly valid (encrypted under the correct
    key, with the AAD over the header we actually ship) but whose stored
    commitment is wrong. The AEAD alone would ACCEPT this. Only the commitment
    check refuses it -- so if that check is ever removed, this test fails.
    """
    m = base_manifest()
    memh = m.memh()
    salt = os.urandom(core._SALT_LEN)
    nonce = os.urandom(core._NONCE_LEN)
    k_enc, _real_commitment = core._derive_key_material(MASTER, memh, 0, b"", salt)
    bogus_commitment = os.urandom(core._COMMIT_LEN)
    prefix = core._HEADER_PREFIX.pack(core._MAGIC, core._VERSION, nonce, salt, bogus_commitment)
    ct = AESGCMSIV(k_enc).encrypt(nonce, b"secret-state", core._aad(prefix, memh, 0))
    envelope = prefix + core._CTLEN.pack(len(ct)) + ct
    try:
        unseal_state(envelope, m, master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError(
        "SECURITY FAILURE: envelope with a valid AEAD but a WRONG key commitment "
        "was accepted -- the key-commitment check is not being enforced"
    )


def test_aad_binding_is_load_bearing():
    """Prove the AEAD associated data actually binds MEMH/epoch.

    Craft an envelope with a correct key, correct commitment, correct nonce --
    but encrypted under an AAD built from a DIFFERENT MEMH. Everything except the
    AAD checks out, so only the AAD binding can refuse it. If MEMH/epoch are ever
    dropped from the AAD, this test fails.
    """
    m = base_manifest()
    memh = m.memh()
    other_memh = base_manifest(numerics_mode="fp16").memh()
    salt = os.urandom(core._SALT_LEN)
    nonce = os.urandom(core._NONCE_LEN)
    k_enc, commitment = core._derive_key_material(MASTER, memh, 0, b"", salt)
    prefix = core._HEADER_PREFIX.pack(core._MAGIC, core._VERSION, nonce, salt, commitment)
    ct = AESGCMSIV(k_enc).encrypt(nonce, b"secret-state", core._aad(prefix, other_memh, 0))
    envelope = prefix + core._CTLEN.pack(len(ct)) + ct
    try:
        unseal_state(envelope, m, master_secret=MASTER)
    except StateSealMismatch:
        return
    raise AssertionError(
        "SECURITY FAILURE: envelope whose AAD was built from a foreign MEMH was "
        "accepted -- the associated-data binding is not being enforced"
    )


def test_constant_time_commitment_compare_is_present():
    """Static guard. A variable-time comparison is a timing leak that NO
    functional test can observe, so it is asserted at the source level."""
    src = open(os.path.join(REPO_ROOT, "sce", "core.py"), encoding="utf-8").read()
    assert "hmac.compare_digest(commit_stored, commit_expected)" in src, (
        "the key-commitment comparison is no longer constant-time "
        "(hmac.compare_digest); a variable-time compare leaks the commitment"
    )


# =============================== 4. known-answer vectors ================== #
def test_python_reproduces_the_known_answer_vectors():
    """The Python implementation must reproduce test_vectors.json exactly.

    Without this, a silent change to canonicalisation or key derivation would
    still round-trip (both sides change together) and only the JS verifier would
    notice. This makes the Python suite self-sufficient.
    """
    with open(os.path.join(REPO_ROOT, "test_vectors.json"), encoding="utf-8") as f:
        vectors = json.load(f)
    assert vectors["envelope_magic"] == core._MAGIC.decode()
    for i, case in enumerate(vectors["cases"]):
        man = ModelManifest(**case["manifest"])
        assert man.canonical_bytes().hex() == case["canonical_manifest_hex"], \
            f"case {i}: canonical manifest bytes drifted"
        assert man.memh().hex() == case["memh_sha3_256_hex"], f"case {i}: MEMH drifted"
        k_enc, commitment = core._derive_key_material(
            bytes.fromhex(case["master_secret_hex"]),
            man.memh(),
            case["epoch_id"],
            case["context_utf8"].encode("utf-8"),
            bytes.fromhex(case["salt_hex"]),
        )
        assert k_enc.hex() == case["k_enc_hex"], f"case {i}: K_enc drifted"
        assert commitment.hex() == case["key_commitment_hex"], f"case {i}: commitment drifted"


# =============================== 5. immutability ========================== #
def test_manifest_extra_cannot_be_mutated_after_construction():
    """A frozen dataclass holding a plain dict is only SHALLOWLY immutable. If
    `extra` can be mutated, the fingerprint of a live manifest can change under
    the caller's feet -- breaking determinism and making any cached MEMH unsafe."""
    m = base_manifest(extra={"lora": "none"})
    before = m.memh()
    try:
        m.extra["lora"] = "adapter-42"
    except (TypeError, AttributeError):
        pass                                   # correctly rejected
    else:
        raise AssertionError(
            "SECURITY FAILURE: manifest.extra was mutated after construction; "
            f"MEMH changed {before.hex()[:12]} -> {m.memh().hex()[:12]}"
        )
    assert m.memh() == before, "MEMH changed after an attempted mutation"


def test_manifest_is_isolated_from_the_callers_dict():
    """Mutating the dict the caller passed in must not change the manifest."""
    caller_dict = {"lora": "none"}
    m = base_manifest(extra=caller_dict)
    before = m.memh()
    caller_dict["lora"] = "adapter-42"
    caller_dict["injected"] = "yes"
    assert m.memh() == before, (
        "SECURITY FAILURE: the manifest aliases the caller's dict; mutating it "
        "changed the environment fingerprint"
    )


def test_memh_is_stable_across_repeated_calls():
    m = base_manifest(extra={"b": "2", "a": "1"})
    assert len({m.memh() for _ in range(50)}) == 1


def test_spec_constants_match_the_implementation():
    """SPEC.md is normative, so it must not drift from the code.

    A specification that quietly disagrees with the implementation is worse than
    no specification: it gives a third-party implementer false confidence and
    guarantees an interop failure. So the normative constants block in SPEC.md is
    parsed and checked against the real values on every CI run.
    """
    spec_path = os.path.join(REPO_ROOT, "SPEC.md")
    with open(spec_path, encoding="utf-8") as f:
        text = f.read()
    assert "SCE-CONSTANTS-v4" in text, "SPEC.md has no normative constants block"
    block = text.split("SCE-CONSTANTS-v4", 1)[1].split("```", 1)[0]

    declared = {}
    for line in block.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        name, value = (p.strip() for p in line.split("=", 1))
        declared[name] = value

    actual = {
        "MAGIC": core._MAGIC.hex(),
        "VERSION": f"{core._VERSION:02x}",
        "NONCE_LEN": str(core._NONCE_LEN),
        "SALT_LEN": str(core._SALT_LEN),
        "TAG_LEN": str(core._TAG_LEN),
        "MEMH_LEN": str(core._MEMH_LEN),
        "COMMIT_LEN": str(core._COMMIT_LEN),
        "KEY_LEN": str(core._KEY_LEN),
        "HEADER_LEN": str(core._HEADER_PREFIX.size),
        "MAX_STATE": str(core._MAX_STATE),
        "DOMAIN": core._DOMAIN.hex(),
        "KDF_INFO_PREFIX": core._KDF_INFO_PREFIX.hex(),
        "KDF_CANON_TAG": core._KDF_CANON_TAG.hex(),
        "MANIFEST_TAG": core._MANIFEST_TAG.hex(),
        "STREAM_MAGIC": stream._STREAM_MAGIC.hex(),
        "STREAM_VERSION": f"{stream._STREAM_VERSION:02x}",
        "STREAM_HEADER_LEN": str(stream._STREAM_HEADER.size),
        "STREAM_ID_LEN": str(stream._STREAM_ID_LEN),
        "STREAM_DOMAIN": stream._STREAM_DOMAIN.hex(),
    }

    missing = set(actual) - set(declared)
    assert not missing, f"SPEC.md does not declare: {sorted(missing)}"
    drifted = {k: (declared[k], actual[k]) for k in actual if declared[k] != actual[k]}
    assert not drifted, f"SPEC.md disagrees with the implementation: {drifted}"

    # The spec also states the exact header layout; check the offsets it claims.
    assert core._HEADER_PREFIX.size == 65, "spec §6 claims a 65-byte header"
    assert core._CTLEN.size == 4, "spec §6 claims a 4-byte ct_len"
    assert stream._SEG_FRAME.size == 8, "spec §9.1 claims an 8-byte segment frame"


def test_manifest_survives_the_object_protocol_intact():
    """Immutability must not cost picklability.

    A read-only mapping is not picklable, so freezing `extra` could silently break
    sending a manifest across a process boundary (multiprocessing, task queues) --
    a regression, not a hardening. Every standard object operation must round-trip
    and preserve the fingerprint EXACTLY, or the environment binding is not
    portable.
    """
    m = base_manifest(extra={"lora": "none", "rope": "linear-2x"})
    memh = m.memh()

    assert pickle.loads(pickle.dumps(m)).memh() == memh, "pickle changed the MEMH"
    assert copy.deepcopy(m).memh() == memh, "deepcopy changed the MEMH"
    assert copy.copy(m).memh() == memh, "copy changed the MEMH"
    assert dataclasses.replace(m, numerics_mode="bf16").memh() == memh, \
        "a no-op replace() changed the MEMH"
    # a real replace must change it
    assert dataclasses.replace(m, numerics_mode="fp16").memh() != memh

    # a round-tripped manifest is still immutable (post_init re-froze it)
    revived = pickle.loads(pickle.dumps(m))
    try:
        revived.extra["lora"] = "adapter-42"
    except (TypeError, AttributeError):
        pass
    else:
        raise AssertionError("a pickled/unpickled manifest came back MUTABLE")


def test_manifests_are_hashable_and_usable_as_keys():
    """A frozen dataclass holding a mapping is unhashable by default. Now that the
    manifest cannot change, hashing by fingerprint is well-defined -- and equal
    manifests must hash equally, or dict/set lookups would silently miss."""
    a = base_manifest(extra={"x": "1", "y": "2"})
    b = base_manifest(extra={"y": "2", "x": "1"})     # same content, other order
    c = base_manifest(numerics_mode="fp16")
    assert a == b and hash(a) == hash(b), "equal manifests must hash equally"
    assert hash(a) != hash(c)
    cache = {a: "env-A", c: "env-C"}
    assert cache[b] == "env-A", "lookup by an equal manifest missed"


# =============================== 6. scaling =============================== #
def test_chunked_sealing_is_not_quadratic():
    """Guard against a future refactor introducing O(n^2) behaviour in the stream
    layer (e.g. `out = out + segment` on bytes instead of a bytearray/join).

    Timing on shared CI runners is noisy, so this asserts an ASYMPTOTIC ratio with
    a generous bound rather than an absolute budget: doubling the segment count
    should roughly double the work (ratio ~2). Quadratic growth gives ~4.
    """
    m = base_manifest()
    seg = 512

    def timed(nsegs):
        payload = b"\x5a" * (seg * nsegs)
        best = float("inf")
        for _ in range(5):
            gc.disable()
            t0 = time.perf_counter()
            c = seal_state_chunked(payload, m, master_secret=MASTER, segment_size=seg)
            unseal_state_chunked(c, m, master_secret=MASTER)
            best = min(best, time.perf_counter() - t0)
            gc.enable()
        return best

    base = timed(256)
    if base < 0.005:                 # too fast to time reliably; scale up
        base = timed(512)
        doubled = timed(1024)
    else:
        doubled = timed(512)
    ratio = doubled / base if base > 0 else 0.0
    assert ratio < 3.0, (
        f"chunked sealing scales super-linearly (ratio {ratio:.2f} for a 2x input; "
        "quadratic would be ~4). Check for bytes concatenation in a loop."
    )


# =============================== runner ================================== #
def main():
    tests = [obj for name, obj in sorted(globals().items())
             if name.startswith("test_") and callable(obj)]
    print(f"\nRunning {len(tests)} SCE hardening tests\n" + "-" * 66)
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
    print("-" * 66)
    if failures:
        print(f"{failures} of {len(tests)} tests FAILED\n")
        sys.exit(1)
    print(f"All {len(tests)} tests passed.\n")


if __name__ == "__main__":
    main()
