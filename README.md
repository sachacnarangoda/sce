# Sealed Continuation Envelope (SCE)
![tests](https://github.com/sachacnarangoda/sce/actions/workflows/tests.yml/badge.svg)

**A small cryptographic primitive that makes portable AI inference state fail *closed* when the model changes underneath it — instead of resuming into silent, undetectable corruption.**

## The idea in one picture

A homing pigeon carries a message capsule between two parties who never meet. It doesn't know who sent the message, it can't read what it carries, and it has nothing worth selling.

**SCE is the capsule — not the pigeon.**

- **It opens under exactly one environment.** Not "for the right person," but under a byte-identical model, quantisation, kernel build, topology and numerics. Change any of them and the state does not open. It doesn't half-open. It doesn't hand back plausible-looking corruption. It refuses, loudly, every time.
- **No two envelopes look alike.** Seal the same state twice and the two envelopes share no field — no environment fingerprint, no epoch, no stable tag. A relay holding a thousand of them cannot tell which two are yours.
- **The carrier holds nothing worth having.** It cannot read the state, alter it, or re-bind it to a different environment. Any tampering fails closed.

And one thing SCE deliberately does **not** do:

- **It doesn't hide the pigeon.** Unmarked bytes buy you nothing if someone can see which loft the bird left from. Concealing the *route* is the transport's job, not the envelope's — and that is what the wider **Linked Dead-Drop Protocol (LDDP)** is for. Read [Boundaries](#boundaries) before relying on this.

> **SCE seals the capsule. LDDP hides the flight.**

---

Status: **reference / proof-of-concept (v4).** Correct and tested (**77 tests**: a 38-test envelope suite, a 20-test chunked-stream suite, and a 19-test hardening harness, plus a sabotage suite that verifies the tests actually catch security regressions and a fuzz target with a replayed regression corpus — covering adversarial cases, a manifest-theft/brute-force simulation, unlinkability regressions, exhaustive single-bit mutation of every envelope and container byte, and a 1,500-trial randomised property test), built on standard cryptography: **AES-256-GCM-SIV** (RFC 8452), HKDF-SHA3-256, SHA3-256. Not yet independently audited and not yet wired into a production inference engine. See [Boundaries](#boundaries). "Infallible" is not claimed and is not achievable; the achievable, intended property is **no silent, catastrophic failure mode**.

**[`SPEC.md`](SPEC.md)** is the normative wire-format and algorithm specification: an implementation written from that document alone, in any language, must interoperate byte-for-byte and reproduce the test vectors. `tools/verify_vectors.js` is a second, from-scratch JavaScript implementation of the deterministic parts, sharing no code with the Python package — and it reproduces every vector exactly.

**Be precise about what that does and does not prove.** A second implementation in a different language catches transcription, encoding, endianness and canonicalisation errors — a real and common class of bug, and the class most likely to break interoperability. It is **not** a substitute for third-party review, because it was written by the same author and therefore inherits any conceptual misunderstanding the Python has. Only an independent audit closes that gap, and this project has not had one. The specification exists precisely so that a *stranger* can build the genuinely independent implementation this repository cannot provide for itself.

> **v4 wire change.** The envelope no longer carries the environment fingerprint (MEMH), the epoch, or a deterministic commitment in cleartext — so a party merely *holding* an envelope can no longer link or cluster a user's sessions by a stable tag. Those fields are re-derived on unseal and bound through the key and the AEAD associated data instead. v4 envelopes and older (SCE3) envelopes deliberately refuse to open under each other. See [How it works](#how-it-works).

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
- **Unlinkable at rest, by content (v4).** The envelope carries no environment/epoch metadata and no stable per-key tag — beyond the constant format identifiers, two seals of the same state under the same key share no field — so an untrusted holder or relay has no *content* to cluster a user's envelopes on. This is what lets the state be carried by a party that is neither the user nor the provider. Envelope **size** is still visible, and is the residual linkage vector — see [Boundaries](#boundaries).

## How it works

```
MEMH       = SHA3-256( canonical(manifest) )               # 32-byte environment fingerprint
salt       = random 16 bytes                               # fresh per seal, carried in the header
material   = HKDF-SHA3-256(master_secret, salt=salt, info=DOMAIN|context|epoch|MEMH, len=64)
K_enc      = material[:32]
commitment = SHA3-256(DOMAIN|"commit"|material[32:])        # fresh per seal -> unlinkable, still binding
header     = magic | version | nonce | salt | commitment    # NO MEMH/epoch on the wire
sealed     = header | ct_len | AES-256-GCM-SIV.encrypt(
                 K_enc, nonce, state,
                 aad = header | MEMH | epoch)               # MEMH+epoch re-derived on unseal, not transmitted
```

- **MEMH** (Model Execution Manifest Hash) is computed over a **strict, length-prefixed, NFC-normalised** encoding of the manifest — not `json.dumps` — so "the same" manifest hashes identically on every machine, with no Unicode/ordering/type ambiguity.
- **A fresh per-seal salt** feeds the HKDF extract, so both `K_enc` and the commitment are **unique to each seal**. That is what makes the commitment a *non-stable* tag: two seals of the same state under the same key produce different envelopes with no field in common, so a holder cannot link them. It also gives genuine per-seal key separation.
- **AES-256-GCM-SIV** is nonce-misuse-resistant and kept as defence-in-depth. Because the per-seal salt already makes `K_enc` unique to each seal, a nonce repeat is a non-event on its own; GCM-SIV additionally protects against an RNG failure that repeats a `(salt, nonce)` pair, where it degrades gracefully rather than catastrophically.
- The environment binds in **two independent ways** — it derives the key *and* it is authenticated data — yet appears **nowhere in the envelope**: the unsealer re-derives MEMH (from the caller-supplied manifest) and the epoch, and folds them into the AEAD associated data. The **key commitment** is checked in constant time. The header is authenticated but is never the source of truth.
- Nonces, salts, and keys are **never caller-supplied** — nonces and salts are generated internally, keys are derived internally from the master secret. Versatility is meant to live in *where it plugs in*, not in *how many ways it can be mis-configured*.

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

python tests/test_core.py                # envelope suite: 38 tests, incl. adversarial + fuzz
python tests/test_stream.py              # chunked-stream suite: 20 tests, incl. structural tamper
python tests/test_hardening.py           # hardening harness: 19 tests, exhaustive mutation + KAT
python tests/test_sabotage.py            # "who tests the tests?" -- 9 sabotages must be caught
python fuzz/fuzz_envelope.py             # corpus replay + generated inputs (stdlib driver)
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
- `seal_state(...) -> bytes` — produce a sealed, committing envelope. An optional `seal_count` enables opt-in, per-key blast-radius control (SCE is stateless, so the caller supplies and persists the monotonic count).
- `unseal_state(...) -> bytes` — resume, or raise `StateSealMismatch` (uniform message).
- `describe_envelope(sealed) -> dict` — inspect non-secret header fields (no key needed). In v4 this is only the format identity and sizes; by design it exposes **no** environment/epoch metadata, so it cannot be used to link a holder's envelopes.
- `explain_mismatch(sealed, manifest) -> str` — **opt-in, trusted-context-only** note for a refusal. In v4 it is deliberately **non-diagnostic**: because the envelope records nothing about the sealing environment, it can only confirm structural validity and echo the *presented* MEMH for an out-of-band check — it cannot recover the specific cause. Still never call it on untrusted paths, and `unseal_state` never calls it.
- Exceptions: `SCEError` (base), `StateSealMismatch`, `MalformedEnvelope`.

### Large states (chunked stream)

A single envelope is capped at ~4 GiB (and by AES-GCM-SIV itself at ~64 GiB). For a state larger than that — a long-context transformer KV-cache, when compact SSM/summarised state isn't an option — seal it as a bound sequence of segments:

```python
from sce import seal_state_chunked, unseal_state_chunked, describe_stream

container = seal_state_chunked(big_state, manifest, master_secret=SECRET,
                               context=b"tenant-A", segment_size=64*1024*1024)  # 64 MiB default
state = unseal_state_chunked(container, manifest, master_secret=SECRET, context=b"tenant-A")
```

Each segment is a normal SCE4 envelope; the sequence is bound via the `context` channel with a fresh per-container `stream_id`, so **reordering, dropping, truncating, extending, or splicing segments — including from another stream — all fail closed**, as does any environment/epoch/context/secret change or a flipped byte. This is a container layer *above* the envelope: the SCE4 wire format is unchanged. `describe_stream(container) -> dict` reports the non-secret header (segment count and sizes; no `stream_id`, no plaintext). It returns `bytes`, so peak memory is ~state size plus a per-segment transient; a file-backed streaming variant is the natural follow-up for states too large to hold assembled in memory.

## Test vectors

`test_vectors.json` contains deterministic known-answer values — the canonical manifest bytes, the MEMH, and (for a fixed master secret and a **fixed per-seal salt**) the derived `K_enc` and key commitment — so an independent implementation in another language can verify canonicalisation, MEMH, key derivation, and commitment. The salt is normally random per seal; it is pinned per case here purely so the derived values are reproducible. Nonce and ciphertext are randomised per seal and are therefore not part of the KAT. An independent JavaScript reimplementation (`tools/verify_vectors.js`) reproduces every value, which is the interoperability check.

## Verification

Beyond the behavioural suites, SCE carries an automated security-verification layer that attacks its own implementation. It needs no dependencies beyond the library itself, and runs in CI on every push.

- **Exhaustive mutation, not sampling.** Every bit of every byte of an envelope — and of a chunked stream container — is flipped, one at a time, and must fail closed. Every truncation and extension likewise.
- **A single, uniform error model.** For arbitrary bytes into any public entry point, only `SCEError` may escape. If a raw `TypeError` could get out, `except SCEError:` would not be a safe way to call this library and a malformed envelope could crash a caller — so that is asserted, not assumed.
- **Known-answer vectors, checked from Python too.** A silent change to canonicalisation or key derivation would still round-trip (both sides change together) and would previously have been caught only by the JavaScript verifier. Now the Python suite catches it as well.
- **"Who tests the tests?"** `tests/test_sabotage.py` deliberately breaks nine security mechanisms in `core.py` — disabling the key-commitment check, gutting the associated data, pinning the nonce or salt, dropping domain separation, and so on — and asserts the suite catches each one. It runs an unmutated control first, so it cannot pass vacuously. One mutation (downgrading the constant-time compare to `==`) is *not* functionally detectable, because the behaviour is identical and only the timing changes; it is documented as an expected survivor and guarded at the source level instead. This is how the suite's teeth are kept honest rather than assumed.
- **The spec cannot silently drift.** `SPEC.md` carries a normative constants block that is parsed and checked against the implementation on every CI run. A specification that quietly disagrees with the code is worse than none — it hands a third-party implementer false confidence and guarantees an interop failure.
- **Fuzzing with a regression corpus.** `fuzz/fuzz_envelope.py` exposes a libFuzzer-shaped `TestOneInput(data)` entry point with a dependency-free driver; `fuzz/corpus.json` holds hex-encoded regression seeds replayed on every run, so a fixed bug cannot quietly return. Adopting a coverage-guided engine (Atheris) later is a five-line driver, not a rewrite.

## Boundaries

This is a reference implementation meant to demonstrate the construction and anchor discussion — **not** a production library. Honest limitations:

- **SCE binds to the manifest you give it, not to the real environment — and it can't tell the difference.** This is the one that matters most, because it's the assumption every other guarantee rests on, and it's on *you*, not on the cryptography. The environment fingerprint is a hash of a manifest *you* enumerate. If something that actually changes the numbers is missing from that manifest — a cuBLAS/cuDNN point-release, an A100-vs-H100 difference hidden under the same tensor-parallel string, a driver update, a flash-attention-vs-eager swap — then two genuinely different environments hash to the *same* fingerprint, derive the *same* key, and stale state resumes **silently**: the exact failure this whole primitive exists to prevent. SCE cannot see the real environment, so it cannot catch a factor you left out. "Resumes only under an identical environment" is, stated honestly, "resumes only under an identical *manifest*" — and closing the gap between those two is your job, not SCE's. (Related: `weights_hash` is just a label you pass in; SCE never checks it against the actual loaded weights, so a wrong or reused label produces a false match.) Get the manifest right, or none of the rest holds.

- **No transport-level anonymity — the unlinkability claim is about bytes, not about the channel.** v4 went to the trouble of a breaking wire change to strip every linkable field from the envelope, so a relay cannot cluster your sessions *from the envelopes themselves*. That is worth having, and it is **not enough on its own**: a relay that sees network identity — your source IP, your TLS session, your account credential, even your connection timing — links your envelopes anyway, and no wire format can stop it. Unlinkability at rest is **necessary but not sufficient**; it only pays off when composed with an anonymising transport (a mixnet, onion routing, or a genuine dead drop where sender and recipient never connect directly). Ship SCE over an ordinary logged-in HTTPS session to a provider and you get *none* of the unlinkability benefit, however clean the bytes are. **SCE seals the capsule; it does not disguise the pigeon.** That layer is what LDDP is for, and it is not in this repository.
- **Not independently audited.** The construction is standard and tested, but it has not had external cryptographic review. That review is a prerequisite for production use.
- **In-use plaintext.** SCE protects state at rest and between turns, not while the model computes on it. Defeating in-use exposure requires a TEE or homomorphic encryption.
- **State must already be in host memory to be sealed.** SCE is a payload-format primitive: it seals a byte string that has already been exported to host memory. In an accelerator-served deployment the continuation state lives in device memory (GPU HBM), and materialising it for the seal necessarily places plaintext in host RAM. Sealing in place on the device — so plaintext never crosses the PCIe bus — is a deployment-architecture problem outside this primitive, and it is not one this format either provides or precludes.
- **Memory hygiene.** This is Python; key material and plaintext live in immutable `bytes` that cannot be reliably zeroised. A production port (e.g. Rust) should wipe secrets after use.
- **Not forward-secret in this reference form.** The reference implementation seals under a *static* `master_secret`, so a provider that is compromised or compelled (e.g. by subpoena) could retroactively decrypt every envelope sealed under that key. For zero-trust deployments this is the central limitation — and it is a property of the static-key reference design, not of the sealing logic. The known remediation sits one layer above the primitive: derive the sealing key ephemerally *per transaction* by using a client–server Diffie-Hellman shared secret as the HKDF input keying material, keeping the environment fingerprint (MEMH), epoch, and context in the HKDF `info`. The encryption key then depends on both the client's transient cryptographic presence and the exact environment — either changing fails closed — and it exists only transiently on the server, so a provider holding sealed envelopes alone has nothing decryptable. In the static form, `epoch_id` and `context` still bound blast radius and support rotation.
- **No replay protection** (see "What it is not").
- **Side channels.** The AEAD tag check and the constant-time commitment compare are constant-time; surrounding Python is not audited for timing, and the environment fingerprint is not secret.
- **Metadata at rest — size is the residual leak, and it is the significant one.** v4 removes the cleartext environment fingerprint, epoch, and stable commitment, so an envelope no longer carries a *content* tag a holder could link on. One channel remains by construction: the envelope length is a deterministic function of the payload size (fixed overhead is 85 bytes = 65-byte header + 4-byte length + 16-byte tag). This is worth stating plainly rather than burying, because it is the correlation signal that survives everything else — a relay can cluster envelopes by exact byte length, and because session state usually grows monotonically across turns, that size sequence is a strong session fingerprint on its own. Content-unlinkability does not defeat it. Mitigate by padding into fixed-size buckets before sealing, or (better) by composing with a transport that normalises packet size — a Sphinx-style mixnet does this by construction. The chunked container partially quantises length, since all but the final segment are exactly `segment_size` bytes.
- **Bounded payload size (per envelope).** A single sealed envelope is capped at ~4 GiB by the uint32 length frame (and by AES-GCM-SIV itself at ~64 GiB); oversize input is refused with a clean error, never truncated. For larger states, `seal_state_chunked` seals a bound sequence of segments with no total-size limit (see [Large states](#large-states-chunked-stream)). SCE's intended home is still compact state (recurrent/SSM state or a summary), where the single-envelope path is more efficient — see `bench/kv_cache_reality.py`.
- **Integration.** It is not yet wired to a specific inference engine's state-export path. That is where the compact-state fit matters — state-space models or summarised context, rather than a full transformer KV-cache, which is often larger than the text that produced it.

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for the full text.

Apache-2.0 is a permissive licence with an explicit patent grant: you are free to use, modify, and build on this work, including commercially, provided you preserve the copyright and licence notices.

---

Developed as the first open component of the Linked Dead-Drop Protocol (LDDP) effort. Contributions and critique welcome, particularly from the anonymity-network, CFRG, and confidential-/anonymous-inference communities — most of all on the manifest's completeness and on the keying/commitment construction.
