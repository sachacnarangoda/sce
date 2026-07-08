"""
Adversarial simulation: manifest theft + cloned address + brute force.

Run:  python examples/attack_sim.py

Threat modelled (as posed):
    A hacker copies the SCE *manifest*, stands up a separate "cloned" address,
    and brute-forces it over several sessions to try to open an intercepted
    sealed envelope.

The whole answer turns on one fact, so we make it explicit and then prove it:

    THE MANIFEST IS NOT A SECRET.

The manifest is a *description* of the model-execution environment (weights
hash, quantisation, kernel, topology, numerics). It is meant to be published so
clients can compute the MEMH. The only secret in SCE is the master_secret.
Copying the manifest is copying public configuration -- not a key.

We simulate four things:
  1. The literal attack: clone the manifest, brute-force without the secret.
  2. The keyspace maths (why "a couple of sessions" is hopeless vs a real key).
  3. The crown jewel: the same envelope opens instantly WITH the secret.
  4. The honest caveat: if the operator used a WEAK master secret, brute force
     wins -- because no AEAD can protect a guessable key. Then: the replay
     boundary, and how channel-binding defeats the cloned-address variant.
"""

import os
import time
import math
import hashlib

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest, seal_state, unseal_state, describe_envelope, StateSealMismatch,
)


def rule(t=""):
    print("\n" + "=" * 70)
    if t:
        print(t); print("=" * 70)


def main():
    # -- The legitimate provider -------------------------------------- #
    provider_master = os.urandom(32)          # lives in an HSM; never leaves
    manifest = ModelManifest(                 # PUBLIC environment descriptor
        weights_hash="sha3:7b-instruct-v1-9f2a",
        quantization="bf16",
        kernel_build_id="vllm-0.6.3+build.a1b2c3",
        tensor_parallel="tp=1,pp=1",
        numerics_mode="bf16",
    )
    secret_state = b"PRIVATE conversation state the attacker wants to read"
    sealed = seal_state(secret_state, manifest, master_secret=provider_master,
                        context=b"prod")

    rule("WHAT THE ATTACKER STEALS")
    print("  - the sealed envelope (intercepted on the wire)")
    print("  - the manifest (they 'copied' it -- but it is public anyway):")
    for k, v in describe_envelope(sealed).items():
        print(f"        {k:22}: {v}")
    print("  NOTE: none of the above is the master secret. The manifest only")
    print("        describes the environment; it is not a credential.")

    # -- 1. Literal attack: clone + brute force WITHOUT the secret ------ #
    rule("ATTACK 1  Clone the manifest, brute-force over 'several sessions'")
    attempts = 200_000            # stand-in for sustained brute forcing
    t0 = time.time()
    successes = 0
    for _ in range(attempts):
        guess = os.urandom(32)    # attacker has no idea of the real secret
        try:
            unseal_state(sealed, manifest, master_secret=guess, context=b"prod")
            successes += 1
        except StateSealMismatch:
            pass
    dt = time.time() - t0
    rate = attempts / dt
    print(f"  {attempts:,} brute-force attempts against the cloned address")
    print(f"  time: {dt:.1f}s   rate: {rate:,.0f} attempts/sec")
    print(f"  envelopes opened: {successes}")
    assert successes == 0
    print("  -> The clone cannot open anything. The manifest gave zero help.")

    # -- 2. The maths ------------------------------------------------- #
    rule("ATTACK 1  Why more sessions do not help (the keyspace)")
    keyspace = 2 ** 256           # a 32-byte high-entropy master secret
    years = keyspace / rate / (60 * 60 * 24 * 365)
    print(f"  master-secret keyspace         : 2^256  (~10^77)")
    print(f"  at this machine's {rate:,.0f}/sec :")
    print(f"     expected time to exhaust    : ~10^{math.log10(years):.0f} years")
    print(f"  age of the universe            : ~1.4 x 10^10 years")
    print("  Each attempt is independent with success probability 2^-256, so")
    print("  running 'a couple of sessions' -- or a billion of them -- changes")
    print("  nothing. Brute force against a proper key is not a viable path.")

    # -- 3. The crown jewel: WITH the secret it opens at once ---------- #
    rule("ATTACK 1  What actually protects the state (the secret, not the manifest)")
    opened = unseal_state(sealed, manifest, master_secret=provider_master, context=b"prod")
    print(f"  With the real master secret, the SAME envelope opens instantly:")
    print(f"     recovered == original : {opened == secret_state}")
    print("  So the security rests entirely on the master secret. The attack")
    print("  targeted the wrong thing -- the public manifest, not the key.")

    # -- 4. The honest caveat: a WEAK master secret is crackable ------- #
    rule("ATTACK 2  The real risk: a WEAK / low-entropy master secret")
    # A provider who (badly) derives the master secret from a guessable value.
    def weak_secret(pin: int) -> bytes:
        return hashlib.sha3_256(f"master-pin-{pin:06d}".encode()).digest()

    real_pin = 428_913
    weak_master = weak_secret(real_pin)
    sealed_weak = seal_state(secret_state, manifest, master_secret=weak_master, context=b"prod")

    print("  Suppose the provider derived the secret from a 6-digit value")
    print("  (only ~10^6 possibilities) instead of 32 random bytes.")
    t0 = time.time()
    found = None
    for pin in range(1_000_000):
        cand = weak_secret(pin)
        try:
            unseal_state(sealed_weak, manifest, master_secret=cand, context=b"prod")
            found = pin
            break
        except StateSealMismatch:
            pass
    dt = time.time() - t0
    print(f"  attacker cracked it at pin={found} in {dt:.1f}s")
    assert found == real_pin
    print("  VERDICT: SCE's guarantee is only as strong as the master secret's")
    print("  entropy. No AEAD can protect a guessable key. High-entropy secret")
    print("  generation + HSM custody is a REQUIREMENT, not an optional extra.")

    # -- 5. Replay boundary + channel binding ------------------------- #
    rule("ATTACK 3  Replay of a VALID envelope (the one genuine adjacent gap)")
    # SCE is a stateless primitive: it does not remember what it has seen, so a
    # valid envelope, replayed with the correct secret, opens again.
    again = unseal_state(sealed, manifest, master_secret=provider_master, context=b"prod")
    print(f"  A valid envelope replayed with the correct secret opens again: {again == secret_state}")
    print("  -> SCE alone does NOT prevent replay. Freshness is the transport's")
    print("     job (e.g. LDDP carrier-IDs / a seen-nonce cache).")
    print()
    print("  BUT the 'separate cloned address' variant is defeated by CHANNEL")
    print("  BINDING via the existing `context` parameter. Bind each session to")
    print("  a value the clone cannot reproduce:")
    real_ctx = b"session:" + os.urandom(16).hex().encode()
    sealed_bound = seal_state(secret_state, manifest, master_secret=provider_master,
                              context=real_ctx)
    # The clone (even if it somehow had the secret) uses a different context:
    try:
        unseal_state(sealed_bound, manifest, master_secret=provider_master,
                     context=b"session:clone-guessed-value")
        print("     clone opened it -- unexpected")
    except StateSealMismatch:
        print("     replay into a different session/context: REFUSED (fail-closed)")
    # The legitimate endpoint, with the right context, still works:
    ok = unseal_state(sealed_bound, manifest, master_secret=provider_master, context=real_ctx)
    print(f"     legitimate session with the right context: opens ({ok == secret_state})")

    # -- Verdict ------------------------------------------------------ #
    rule("VERDICT")
    print(
        "  The scenario as posed -- copy the manifest, clone the address, brute\n"
        "  force over sessions -- FAILS against SCE, because it targets the\n"
        "  public manifest rather than the secret. The manifest is not a key;\n"
        "  cloning it grants nothing; brute-forcing a 256-bit secret is hopeless.\n\n"
        "  The two things that DO matter, both already known and documented:\n"
        "    * master-secret entropy + custody -- a weak key is crackable; use\n"
        "      high-entropy generation and an HSM (this is on the operator);\n"
        "    * replay/freshness -- out of scope for the stateless primitive, and\n"
        "      the cloned-endpoint variant is closed by `context` channel-binding.\n\n"
        "  No change to the construction is required to pass this scenario."
    )
    print()


if __name__ == "__main__":
    main()
