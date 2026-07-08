"""
SCE demo: what happens when the model changes underneath saved inference state.

Run:  python examples/demo.py

This walks through the exact scenario the primitive exists for:
a piece of inference state is saved under one model, the model is then updated,
and the state is presented again. Without SCE, the stale state would be resumed
silently and the model would produce a confident, wrong answer. With SCE, the
resume is refused, loudly and unambiguously.

We use a small numpy array to stand in for a KV-cache slice so the "state" is a
real tensor rather than an abstract blob.
"""

import os
import sys
import hashlib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sce import (  # noqa: E402
    ModelManifest,
    compute_memh,
    seal_state,
    unseal_state,
    describe_envelope,
    explain_mismatch,
    StateSealMismatch,
)


def rule(title=""):
    print("\n" + "=" * 68)
    if title:
        print(title)
        print("=" * 68)


def manifest_for(weight_bytes: bytes, *, quantization: str) -> ModelManifest:
    """Build a manifest whose weights_hash is computed from actual bytes, so the
    fingerprint is grounded in a real artifact rather than a made-up string."""
    return ModelManifest(
        weights_hash="sha3:" + hashlib.sha3_256(weight_bytes).hexdigest()[:16],
        quantization=quantization,
        kernel_build_id="vllm-0.6.3+build.a1b2c3",
        tensor_parallel="tp=1,pp=1",
        numerics_mode="bf16",
    )


def main():
    # A server-side master secret. In LDDP this lives in an HSM and never leaves
    # the provider; K_epoch is derived from it and the MEMH, and is never sent.
    master_secret = os.urandom(32)

    # ------------------------------------------------------------------ #
    # 1. Model v1 produces some inference state that we want to carry.
    # ------------------------------------------------------------------ #
    rule("STEP 1  Model v1 runs and we save its inference state")
    weights_v1 = b"<pretend these are the 7B model weight tensors, version 1>"
    model_v1 = manifest_for(weights_v1, quantization="bf16")
    print("  model v1 MEMH :", compute_memh(model_v1).hex())

    # A realistic-ish KV-cache slice: a float tensor. We serialise it to bytes.
    kv_cache_slice = np.random.default_rng(0).standard_normal((8, 64)).astype("float32")
    state_bytes = kv_cache_slice.tobytes()
    print(f"  saved state   : {kv_cache_slice.shape} float32 tensor "
          f"({len(state_bytes)} bytes) standing in for a KV-cache slice")

    sealed = seal_state(state_bytes, model_v1, master_secret=master_secret, epoch_id=0)
    print("  sealed        :", describe_envelope(sealed))

    # ------------------------------------------------------------------ #
    # 2. Later, the SAME model v1 resumes the state. This must succeed.
    # ------------------------------------------------------------------ #
    rule("STEP 2  Model v1 resumes the saved state  (environment unchanged)")
    recovered = unseal_state(sealed, model_v1, master_secret=master_secret, epoch_id=0)
    tensor_back = np.frombuffer(recovered, dtype="float32").reshape(kv_cache_slice.shape)
    ok = np.array_equal(tensor_back, kv_cache_slice)
    print(f"  resume        : SUCCESS; recovered tensor identical = {ok}")

    # ------------------------------------------------------------------ #
    # 3. The model is updated overnight (re-quantised bf16 -> fp8). The
    #    weights and quantisation change, so the MEMH changes.
    # ------------------------------------------------------------------ #
    rule("STEP 3  Overnight the model is updated (re-quantised bf16 -> fp8)")
    weights_v2 = b"<same architecture, re-quantised weights, version 2>"
    model_v2 = manifest_for(weights_v2, quantization="fp8-e4m3")
    print("  model v2 MEMH :", compute_memh(model_v2).hex())
    print("  -> different fingerprint from v1, as it must be")

    # ------------------------------------------------------------------ #
    # 4. The v1 state is presented to v2. This MUST fail closed.
    # ------------------------------------------------------------------ #
    rule("STEP 4  The v1 state is presented to model v2")
    try:
        unseal_state(sealed, model_v2, master_secret=master_secret, epoch_id=0)
        print("  !!! resume succeeded -- THIS WOULD BE THE BUG SCE PREVENTS")
    except StateSealMismatch as exc:
        # unseal_state itself gives only a uniform, oracle-free message...
        print(f"  resume        : REFUSED (fail-closed) -> \"{exc}\"")
        # ...and in a trusted context you can ask WHY, via the opt-in helper:
        print("  explanation   :", explain_mismatch(sealed, model_v2))

    # ------------------------------------------------------------------ #
    # 5. The contrast, stated plainly.
    # ------------------------------------------------------------------ #
    rule("WHAT JUST HAPPENED")
    print(
        "  Without SCE, the v1 state would have been handed to v2 and resumed\n"
        "  silently. The model would keep generating -- fluently, confidently,\n"
        "  and wrong -- with nothing to signal that its working memory no longer\n"
        "  matches the model reading it. Nobody would see an error; they would\n"
        "  see a plausible answer that happens to be corrupted.\n\n"
        "  With SCE, the mismatch is caught the instant the state is presented.\n"
        "  The failure is loud and specific. The caller discards the stale state\n"
        "  and rebuilds from the transcript -- paying a re-computation cost, but\n"
        "  never shipping a silent wrong answer.\n\n"
        "  A loud crash is safe. A silent wrong answer is the dangerous one."
    )
    print()


if __name__ == "__main__":
    main()
