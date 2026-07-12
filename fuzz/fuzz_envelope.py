#!/usr/bin/env python3
"""
SCE fuzz target -- stdlib driver, Atheris-compatible entry point.

    python fuzz/fuzz_envelope.py                  # replay corpus + 20k generated inputs
    python fuzz/fuzz_envelope.py --runs 200000    # longer soak
    python fuzz/fuzz_envelope.py --seed 7         # different deterministic stream

THE PROPERTY UNDER TEST
-----------------------
SCE promises callers a single, uniform error model: everything it raises is an
`SCEError` (StateSealMismatch / MalformedEnvelope). If ANY other exception can
escape a public entry point -- a raw TypeError, struct.error, AttributeError,
OverflowError -- then `except SCEError:` is not a safe way to call this library,
and an application built on it can be crashed by a malicious envelope. So:

    for arbitrary bytes, into any public entry point, only SCEError may escape.

Plus, for the round-trip path: seal-then-unseal must return the input exactly.

(The complementary property -- that a *tampered* envelope must never open -- is
covered exhaustively in tests/test_hardening.py, which flips every bit of every
byte. This target is about the exception contract and about hangs/crashes.)

CORPUS
------
`fuzz/corpus.json` holds hex-encoded regression seeds. Every input that has ever
broken SCE belongs there: it is replayed on every run, so a fixed bug cannot
silently come back. Hex (rather than binary files) keeps the corpus reviewable in
a diff and pasteable through a web editor.

RUNNING UNDER ATHERIS / OSS-FUZZ
--------------------------------
`TestOneInput` is already the standard libFuzzer-shaped entry point, so adopting
a coverage-guided engine later needs no rewrite -- just a driver:

    import atheris, sys
    from fuzz.fuzz_envelope import TestOneInput
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

Note that OSS-Fuzz itself accepts only established, widely-depended-on projects;
until SCE qualifies, this stdlib driver plus the CI job is the practical
equivalent, and the corpus is the part that carries the lasting value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest,
    seal_state,
    unseal_state,
    describe_envelope,
    explain_mismatch,
    seal_state_chunked,
    unseal_state_chunked,
    describe_stream,
    SCEError,
)

CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus.json")

MASTER = b"\x11" * 32
MANIFEST = ModelManifest(
    weights_hash="sha3:aaaa1111",
    quantization="bf16",
    kernel_build_id="vllm-0.6.3+abc123",
    tensor_parallel="tp=1,pp=1",
    numerics_mode="bf16",
)

_ENTRY_POINTS = 6


class FuzzFailure(AssertionError):
    """A property violation found by the fuzzer."""


def TestOneInput(data: bytes) -> None:
    """libFuzzer/Atheris-shaped entry point. Raises only on a real finding."""
    if not data:
        return
    selector = data[0] % _ENTRY_POINTS
    payload = data[1:]

    try:
        if selector == 0:
            unseal_state(payload, MANIFEST, master_secret=MASTER)
        elif selector == 1:
            describe_envelope(payload)
        elif selector == 2:
            explain_mismatch(payload, MANIFEST)
        elif selector == 3:
            unseal_state_chunked(payload, MANIFEST, master_secret=MASTER)
        elif selector == 4:
            describe_stream(payload)
        elif selector == 5:
            # Round-trip property on the seal path, with fuzzer-chosen epoch/context.
            epoch = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else 0
            ctx = payload[2:6]
            body = payload[6:]
            sealed = seal_state(body, MANIFEST, master_secret=MASTER,
                                epoch_id=epoch, context=ctx)
            out = unseal_state(sealed, MANIFEST, master_secret=MASTER,
                               epoch_id=epoch, context=ctx)
            if out != body:
                raise FuzzFailure(
                    f"round-trip mismatch: sealed {len(body)} bytes, recovered {len(out)}"
                )
    except SCEError:
        return                       # the documented contract -- fine
    except FuzzFailure:
        raise
    except Exception as exc:         # noqa: BLE001 -- THIS is the bug class we hunt
        raise FuzzFailure(
            f"non-SCEError escaped entry point {selector}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


# --------------------------------------------------------------------------- #
# stdlib driver
# --------------------------------------------------------------------------- #
def load_corpus() -> list[bytes]:
    if not os.path.exists(CORPUS_PATH):
        return []
    with open(CORPUS_PATH, encoding="utf-8") as f:
        doc = json.load(f)
    return [bytes.fromhex(h) for h in doc.get("seeds", [])]


def record_finding(data: bytes) -> str:
    """Print the failing input as hex so it can be pasted into fuzz/corpus.json."""
    digest = hashlib.sha3_256(data).hexdigest()[:12]
    print("\n" + "=" * 70)
    print(f"FINDING {digest} -- add this hex to the 'seeds' list in fuzz/corpus.json")
    print(f'  "{data.hex()}"')
    print("=" * 70)
    return digest


def seeds_for_generation() -> list[bytes]:
    """Valid artefacts to mutate: the interesting region of the input space."""
    return [
        seal_state(b"seed-state", MANIFEST, master_secret=MASTER),
        seal_state(b"", MANIFEST, master_secret=MASTER, epoch_id=7, context=b"ctx"),
        seal_state_chunked(b"A" * 40, MANIFEST, master_secret=MASTER, segment_size=8),
    ]


def mutate(rng: random.Random, base: bytes) -> bytes:
    out = bytearray(base)
    for _ in range(rng.randrange(1, 5)):
        op = rng.randrange(5)
        if op == 0 and out:
            out[rng.randrange(len(out))] ^= 1 << rng.randrange(8)
        elif op == 1 and out:
            out[rng.randrange(len(out))] = rng.randrange(256)
        elif op == 2 and len(out) > 1:
            del out[rng.randrange(len(out)):]
        elif op == 3:
            out += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 16)))
        elif op == 4 and len(out) > 2:
            i = rng.randrange(len(out) - 1)
            out[i], out[i + 1] = out[i + 1], out[i]
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="SCE stdlib fuzz driver")
    ap.add_argument("--runs", type=int, default=20000, help="generated inputs to try")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed (deterministic)")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    t0 = time.perf_counter()

    corpus = load_corpus()
    print(f"Replaying {len(corpus)} regression seed(s) from fuzz/corpus.json")
    for blob in corpus:
        try:
            TestOneInput(blob)
        except FuzzFailure as exc:
            record_finding(blob)
            print(f"REGRESSION: a previously-fixed input fails again -- {exc}")
            return 1

    bases = seeds_for_generation()
    print(f"Fuzzing {args.runs} generated inputs (seed={args.seed})")
    for i in range(args.runs):
        r = rng.random()
        if r < 0.30:                                   # pure random bytes
            n = rng.randrange(0, 200)
            blob = bytes(rng.randrange(256) for _ in range(n))
        elif r < 0.55:                                 # random with a valid magic
            blob = bytes([rng.randrange(256)]) + b"SCE4" + bytes(
                rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        else:                                          # mutate a valid artefact
            blob = bytes([rng.randrange(256)]) + mutate(rng, rng.choice(bases))
        try:
            TestOneInput(blob)
        except FuzzFailure as exc:
            record_finding(blob)
            print(f"FAILURE after {i} inputs: {exc}")
            return 1

    dt = time.perf_counter() - t0
    total = len(corpus) + args.runs
    print(f"OK -- {total} inputs, no property violations "
          f"({dt:.2f}s, {total / dt:,.0f} inputs/s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
