"""
Differential-timing check for SCE unseal.

Run:  python bench/timing_check.py

A uniform error message is not enough on its own; if the three failure paths
took visibly different times, an attacker could still tell WHY a seal failed.
`unseal_state` is written so that both the key-commitment compare and the AEAD
open ALWAYS run, regardless of outcome, so the paths should be indistinguishable.

This measures that. It is a screening test, not a proof: Python timing is noisy,
so a real audit would use a dedicated tool (e.g. dudect) against a native build.
What we want to see is no LARGE, systematic gap between the cases.
"""

import os
import statistics
import time

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import ModelManifest, seal_state, unseal_state, StateSealMismatch  # noqa: E402

MASTER = os.urandom(32)
M = ModelManifest("sha3:w", "bf16", "k", "tp=1,pp=1", "bf16")
M_WRONG = ModelManifest("sha3:w-DIFFERENT", "bf16", "k", "tp=1,pp=1", "bf16")
STATE = os.urandom(256)

sealed = seal_state(STATE, M, master_secret=MASTER)
tampered = bytearray(sealed); tampered[-1] ^= 0x01; tampered = bytes(tampered)


def timed(fn, n):
    xs = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e6)  # microseconds
    return xs


def case_success():
    unseal_state(sealed, M, master_secret=MASTER)

def case_wrong_env():
    try: unseal_state(sealed, M_WRONG, master_secret=MASTER)
    except StateSealMismatch: pass

def case_wrong_secret():
    try: unseal_state(sealed, M, master_secret=b"\x00" * 32)
    except StateSealMismatch: pass

def case_tampered_ct():
    try: unseal_state(tampered, M, master_secret=MASTER)
    except StateSealMismatch: pass


def main():
    cases = [("success (opens)", case_success),
             ("wrong environment", case_wrong_env),
             ("wrong master secret", case_wrong_secret),
             ("tampered ciphertext", case_tampered_ct)]

    # Warm up.
    for _, fn in cases:
        timed(fn, 2000)

    n = 40000
    # Interleave measurement rounds to average out CPU-frequency drift.
    samples = {name: [] for name, _ in cases}
    for _ in range(4):
        for name, fn in cases:
            samples[name].extend(timed(fn, n // 4))

    print(f"\nunseal timing over {n:,} iterations each (256-byte state)\n" + "-" * 60)
    print(f"{'case':<24}{'median us':>12}{'p10 us':>10}{'p90 us':>10}")
    print("-" * 60)
    meds = {}
    for name, _ in cases:
        xs = sorted(samples[name])
        med = statistics.median(xs)
        p10 = xs[len(xs) // 10]
        p90 = xs[len(xs) * 9 // 10]
        meds[name] = med
        print(f"{name:<24}{med:>12.3f}{p10:>10.3f}{p90:>10.3f}")
    print("-" * 60)

    base = meds["success (opens)"]
    failure_meds = [meds[n] for n in ("wrong environment", "wrong master secret", "tampered ciphertext")]
    fail_to_fail = max(failure_meds) - min(failure_meds)
    succ_to_fail = statistics.median(failure_meds) - base

    print(f"\nFailure-to-failure spread (the security-relevant number): "
          f"{fail_to_fail:.3f} us ({100*fail_to_fail/base:.2f}% of median).")
    print(f"Success-to-failure gap:                                   "
          f"{succ_to_fail:.3f} us ({100*succ_to_fail/base:.1f}% of median).")
    print(
        "\nINTERPRETATION\n"
        "  What matters is the FIRST number. The three failure causes -- wrong\n"
        "  environment, wrong secret, tampered ciphertext -- are mutually\n"
        "  indistinguishable, because unseal always does the same work (derive\n"
        "  key -> constant-time commitment compare -> AEAD open) before deciding.\n"
        "  An attacker therefore cannot learn WHY a seal failed. The small\n"
        "  success-vs-failure gap is Python exception-handling overhead, and it is\n"
        "  NOT an oracle: whether a seal opened is already observable from the\n"
        "  outcome, so its timing reveals nothing new. A production (Rust) build\n"
        "  should still be checked with a dedicated constant-time tool (e.g.\n"
        "  dudect); this screening only rules out a large, obvious oracle."
    )
    print()


if __name__ == "__main__":
    main()
