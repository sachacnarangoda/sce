# Sealed Continuation Envelope (SCE)

**A small cryptographic primitive that makes portable AI inference state fail *closed* when the model changes underneath it — instead of resuming into silent, undetectable corruption.**

Status: **reference / proof-of-concept (hardened v2).** Correct and tested (29 tests, including adversarial, a manifest-theft/brute-force simulation, and a 1,500-trial randomised property test), built on standard cryptography: **AES-256-GCM-SIV** (RFC 8452), HKDF-SHA3-256, SHA3-256. Not yet independently audited and not yet wired into a production inference engine. See [Boundaries](#boundaries). "Infallible" is not claimed and is not achievable; the achievable, intended property is **no silent, catastrophic failure mode**.

> **Part of a larger effort.** SCE is the first open component of the **Linked Dead-Drop Protocol (LDDP)** — a design for private, provider-independent AI inference in which providers compute without becoming long-term custodians of identity, history, or session state. SCE is the foundation-stone primitive: the piece that makes portable inference state safe to carry. It is released openly on its own so it can be used, reviewed, and built upon. The broader LDDP protocol is a separate and continuing work. If SCE is useful to you, or you're working on adjacent problems (reproducibility, runtime attestation, private inference, agent-state safety), contact and collaboration are welcome.

---

## The problem

Portable inference state already exists — systems like LMCache move a model's KV-cache between servers so it doesn't have to be recomputed. But that state is bound to the exact weights, quantisation, kernel build, tensor-parallel topology, and numeric precision that produced it. Reuse it after any of those change and you don't get a clean error. You get a **confident, fluent, wrong answer** that nothing flags.

In a chatbot that's an annoyance. In a stateful agent doing medical, legal, financial, or industrial work, a silent wrong answer is a safety and liability event that surfaces only after it has caused harm. The pattern recurs across self-hosted stacks (llama.cpp, MLX, LM Studio, agent frameworks), where developers hand-roll ad-hoc checks because there is no shared, principled primitive for it.

Second problem: for inference state to be held by a party that is **neither the user nor the model provider** — which is what a privacy-preserving transport needs to carry a multi-turn session without the provider retaining it — the state must be tamper-evident and impossible to misuse against the wrong model. Plain portable state is neither.

## What SCE does

- **Fail-closed version binding.** If the environment changes, the state will not load — it raises a loud, uniform error instead of resuming into corruption.
- **Key commitment.** A sealed envelope is cryptographically bound to exactly one environment; it cannot be made to open under a second one. (Plain AEADs do not give this.)
- **Tamper-evidence.** Any modification to any byte of the envelope is detected.
- **Confidentiality at rest.** The sealed blob reveals nothing about the plaintext.
- **Oracle-free failure.** Every cryptographic failure (wrong environment, wrong secret, tampering) returns one identical error, so nothing leaks about *why* it failed.

## How it works

```
MEMH       = SHA3-256( canonical(manifest) )               # 32-byte environment fingerprint
material   = HKDF-SHA3-256(master_secret, salt=epoch, info=DOMAIN|context|MEMH, len=64)
K_enc      = material[:32]
commitment = SHA3-256(DOMAIN|"commit"|material[32:])        # binds the ciphertext to one environment
sealed     = AES-256-GCM-SIV.encrypt(K_enc, nonce, state,
                                     aad = magic|version|MEMH|epoch|commitment|nonce)
```

- **MEMH** (Model Execution Manifest Hash) is computed over a **strict, length-prefixed, NFC-normalised** encoding of the manifest — not `json.dumps` — so "the same" manifest hashes identically on every machine, with no Unicode/ordering/type ambiguity.
- **AES-256-GCM-SIV** is nonce-misuse-resistant: because `K_enc` is a long-lived key, an accidental nonce repeat under plain GCM would be catastrophic (auth-key recovery → forgery); under GCM-SIV it degrades gracefully.
- The environment binds in **two independent ways** — it derives the key *and* it is authenticated data — and the **key commitment** is checked in constant time. Unsealing re-derives everything from the **caller-supplied** manifest; the header is authenticated but never trusted as the source of truth.
- Nonces and keys are **never caller-supplied** — nonces are generated internally, keys are derived internally from the master secret. Versatility is meant to live in *where it plugs in*, not in *how many ways it can be mis-configured*.

## Where it fits

SCE is deliberately narrow — **one component** meant to sit underneath larger privacy systems, not to replace them:

- On top of an anonymity network such as **Nym**, or an anonymous-inference design such as the academic *funion*/Echomix work, SCE provides the piece they don't: a safe, version-consistent, tamper-evident way to carry **multi-turn stateful sessions** over the anonymous channel — without re-sending the whole transcript each turn, and without an intermediary holding linkable, mutable state.
- In the **Linked Dead-Drop Protocol (LDDP)**, SCE is the continuation-state primitive: it lets a provider stay stateless while the client (or an untrusted relay) carries the sealed session forward.

## What it is *not*

- **Not an anonymity system.** It hides nothing about *who* is asking — that is the transport's job (Nym, a mixnet, LDDP).
- **Not confidential inference.** The model still reads plaintext to run. Hiding the query *from the model itself* needs a TEE (e.g. Phala) or homomorphic encryption — out of scope. SCE protects state **at rest and in transit between turns**, not **in use**.
- **Not a retention control.** Zero-data-retention already covers "the provider keeps nothing." SCE makes the state that *leaves* the provider safe to carry and resume.
- **Not a replay-prevention mechanism.** A holder can resubmit a valid envelope; freshness/replay is a transport-layer concern (e.g. LDDP carrier IDs).
- **Not a model or an inference engine.** It sits alongside whatever you already run.

## Install and run

```bash
pip install "cryptography>=43" numpy     # AES-GCM-SIV needs cryptography >= 43 (OpenSSL >= 3.2); numpy is only for the demo

python tests/test_core.py                # full suite: 29 tests, incl. adversarial + fuzz
python examples/demo.py                  # narrated walkthrough of the fail-closed behaviour
```

## API

```python
from sce import ModelManifest, seal_state, unseal_state, StateSealMismatch

manifest = ModelManifest(
    weights_hash="sha3:...", quantization="bf16",
    kernel_build_id="vllm-0.6.3+abc123", tensor_parallel="tp=1,pp=1",
    numerics_mode="bf16", extra={},          # extra is a flat dict of str -> str
)

sealed = seal_state(state_bytes, manifest, master_secret=SECRET,
                    epoch_id=0, context=b"tenant-A")   # epoch + context bound into the key

try:
    state = unseal_state(sealed, manifest, master_secret=SECRET,
                         epoch_id=0, context=b"tenant-A")
except StateSealMismatch:
    # uniform, oracle-free failure: environment/epoch/context/secret changed, or tampering.
    # discard the sealed state and rebuild from the transcript.
    ...
```

- `ModelManifest(...)` — the environment fingerprint (validated str fields); `.memh()` returns 32 bytes.
- `seal_state(...) -> bytes` — produce a sealed, committing envelope.
- `unseal_state(...) -> bytes` — resume, or raise `StateSealMismatch` (uniform message).
- `describe_envelope(sealed) -> dict` — inspect non-secret header fields (no key needed).
- `explain_mismatch(sealed, manifest) -> str` — **opt-in, trusted-context-only** human-readable reason for a refusal. Never call this on untrusted input paths: revealing *why* a seal failed is an oracle. `unseal_state` never calls it.
- Exceptions: `SCEError` (base), `StateSealMismatch`, `MalformedEnvelope`.

## Test vectors

`test_vectors.json` contains deterministic known-answer values — the canonical manifest bytes, the MEMH, and (for a fixed master secret) the derived `K_enc` and key commitment — so an independent implementation in another language can verify canonicalisation, MEMH, key derivation, and commitment. Nonce and ciphertext are randomised per seal and are therefore not part of the KAT.

## Boundaries

This is a reference implementation meant to demonstrate the construction and anchor discussion — **not** a production library. Honest limitations:

- **Not independently audited.** The construction is standard and tested, but it has not had external cryptographic review. That review is a prerequisite for production use.
- **In-use plaintext.** SCE protects state at rest and between turns, not while the model computes on it. Defeating in-use exposure requires a TEE or homomorphic encryption.
- **Memory hygiene.** This is Python; key material and plaintext live in immutable `bytes` that cannot be reliably zeroised. A production port (e.g. Rust) should wipe secrets after use.
- **No forward secrecy by itself.** If the master secret leaks, envelopes under it become openable/forgeable. `epoch_id` and `context` bound blast radius and support rotation; a full ratchet is a system-level concern, out of scope for the primitive.
- **No replay protection** (see "What it is not").
- **Side channels.** The AEAD tag check and the constant-time commitment compare are constant-time; surrounding Python is not audited for timing, and the environment fingerprint is not secret.
- **Integration.** It is not yet wired to a specific inference engine's state-export path. That is where the compact-state fit matters — state-space models or summarised context, rather than a full transformer KV-cache, which is often larger than the text that produced it.

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for the full text.
Apache-2.0 is a permissive licence with an explicit patent grant: you are free to use, modify, and build on this work, including commercially, provided you preserve the copyright and licence notices.
---
Developed as the first open component of the Linked Dead-Drop Protocol (LDDP) effort. Contributions and critique welcome, particularly from the anonymity-network, CFRG, and confidential-/anonymous-inference communities — most of all on the manifest's completeness and on the keying/commitment construction.
