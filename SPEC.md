# Sealed Continuation Envelope — Specification

**Wire version:** SCE4 (envelope) · SCES v1 (chunked container)
**Status:** stable for the 0.4.x series · reference implementation, not independently audited
**Document version:** 1.0 (2026-07-12)

This document specifies the SCE wire format and algorithms **normatively and completely**: an independent implementation written from this document alone, in any language, must interoperate byte-for-byte with the reference implementation and reproduce `test_vectors.json`.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in RFC 2119.

Where a requirement is marked **MUST**, removing it is a security defect, not a simplification. Section 12 records which requirements were empirically shown to be load-bearing, and how.

---

## 1. Purpose and threat model

SCE seals portable inference state (a KV-cache, a recurrent/SSM state, or a summary) so that it can be reopened **only** under a byte-identical model execution environment, and only by a holder of the master secret. It is designed for the Linked Dead-Drop Protocol (LDDP), where the sealed state is carried by an **untrusted relay** that is neither the user nor the inference provider.

The adversary is assumed to:

- hold arbitrarily many envelopes, indefinitely;
- choose, reorder, truncate, extend, splice and corrupt the bytes of any envelope;
- observe the size and timing of every envelope it carries;
- **not** know the master secret.

Against this adversary SCE guarantees (§11): confidentiality and integrity of the state; that an envelope opens under exactly one environment; that failure is uniform and reveals nothing about its cause; and that envelopes are **unlinkable** — two envelopes sealed from identical inputs share no common field.

SCE does **not** provide forward secrecy, does not hide the payload size, and does not authenticate the *holder*. See §11.2.

---

## 2. Notation

| Notation | Meaning |
|---|---|
| `‖` | concatenation |
| `u32(n)` | `n` as a 4-byte unsigned big-endian integer |
| `u64(n)` | `n` as an 8-byte unsigned big-endian integer |
| `LP(b)` | length-prefixed bytes: `u32(len(b)) ‖ b` |
| `SHA3(b)` | SHA3-256 of `b` (32 bytes) |
| `NFC(s)` | Unicode Normalization Form C of string `s` |
| `UTF8(s)` | UTF-8 encoding of `s` |
| `random(n)` | `n` bytes from a cryptographically secure RNG |

All integers on the wire are **unsigned big-endian**. All lengths are in bytes.

### 2.1 Primitives

| Role | Algorithm |
|---|---|
| AEAD | AES-256-GCM-SIV (RFC 8452), 12-byte nonce, 16-byte tag |
| KDF | HKDF (RFC 5869) with SHA3-256 |
| Hash | SHA3-256 (FIPS 202) |
| Constant-time compare | any equal-time byte comparison |

Implementations MUST use exactly these primitives. AES-256-GCM-SIV is chosen for nonce-misuse resistance: it degrades gracefully rather than catastrophically if an RNG ever repeats a `(salt, nonce)` pair.

---

## 3. Constants

The following block is normative and is machine-checked against the implementation by `tests/test_hardening.py::test_spec_constants_match_the_implementation`. Byte strings are hex; lengths are decimal byte counts.

```
SCE-CONSTANTS-v4
MAGIC                = 53434534                                     # "SCE4"
VERSION              = 04                                           # 4
NONCE_LEN            = 12
SALT_LEN             = 16
TAG_LEN              = 16
MEMH_LEN             = 32
COMMIT_LEN           = 32
KEY_LEN              = 32
HEADER_LEN           = 65
MAX_STATE            = 4294967279
DOMAIN               = 4c4444502d5343452d7634                       # "LDDP-SCE-v4"
KDF_INFO_PREFIX      = 4c4444502d5343457c6b64662d76347c             # "LDDP-SCE|kdf-v4|"
KDF_CANON_TAG        = 4c4444502d5343457c6b64662d63616e6f6e2d7634   # "LDDP-SCE|kdf-canon-v4"
MANIFEST_TAG         = 5343454d414e31                               # "SCEMAN1"
STREAM_MAGIC         = 53434553                                     # "SCES"
STREAM_VERSION       = 01                                           # 1
STREAM_HEADER_LEN    = 45
STREAM_ID_LEN        = 16
STREAM_DOMAIN        = 4c4444502d5343457c73747265616d2d7631         # "LDDP-SCE|stream-v1"
```

---

## 4. The manifest and its canonical encoding (`SCEMAN1`)

A **manifest** describes everything that changes numerical inference behaviour. It has five required string fields, in this **fixed order**, plus an `extra` mapping of `str → str` for forward-compatible factors (LoRA adapter hash, RoPE scaling, sampler build, …):

1. `weights_hash`
2. `quantization`
3. `kernel_build_id`
4. `tensor_parallel`
5. `numerics_mode`

### 4.1 Requirements

- All five core fields MUST be strings. A non-string MUST be rejected. (Rationale: the fingerprint must never depend on how a JSON library rendered a number, bool, or null.)
- Every key and value of `extra` MUST be a string.
- If two `extra` keys are distinct but **equal after NFC normalisation**, the manifest MUST be rejected. Such a pair would make the encoding order-dependent and therefore ambiguous.
- A manifest MUST be immutable once constructed. An implementation that permits `extra` to be mutated afterwards is non-conforming: the fingerprint of a live manifest could change, and any cached fingerprint would be wrong.

### 4.2 Encoding

Define `enc(s) = LP(UTF8(NFC(s)))`.

```
canonical(M) = MANIFEST_TAG
             ‖ enc(M.weights_hash)
             ‖ enc(M.quantization)
             ‖ enc(M.kernel_build_id)
             ‖ enc(M.tensor_parallel)
             ‖ enc(M.numerics_mode)
             ‖ u32(count(M.extra))
             ‖ for each (k, v) of M.extra, sorted ascending by UTF8(NFC(k)):
                   enc(k) ‖ enc(v)
```

Sorting is by the **NFC-normalised UTF-8 key bytes**, ascending. Every field is length-prefixed, so the encoding is unambiguous by construction — no delimiter can be forged by a field's contents.

Implementations MUST NOT use JSON, YAML, or any whitespace-bearing or key-order-dependent serialisation to compute this.

### 4.3 MEMH

```
MEMH = SHA3(canonical(M))                          # 32 bytes
```

MEMH is the **Model Execution Manifest Hash** — the environment fingerprint. It is deterministic across machines, languages, and processes.

`MANIFEST_TAG` is `SCEMAN1`, not versioned with the envelope: the manifest encoding is unchanged from SCE3, so MEMH values are stable across that wire bump.

---

## 5. Key derivation

Inputs: `master_secret` (bytes), `MEMH` (32 bytes), `epoch_id` (integer), `context` (bytes), `salt` (16 bytes).

```
info      = KDF_INFO_PREFIX ‖ SHA3( KDF_CANON_TAG
                                  ‖ LP(context)
                                  ‖ LP(u64(epoch_id))
                                  ‖ LP(MEMH) )

material  = HKDF-SHA3-256(ikm = master_secret,
                          salt = salt,
                          info = info,
                          length = 64)

K_enc      = material[0:32]
K_com      = material[32:64]
commitment = SHA3( DOMAIN ‖ "|commit|" ‖ K_com )    # 32 bytes
```

(`"|commit|"` is the 8 ASCII bytes `7c636f6d6d69747c`.)

### 5.1 Requirements

- `master_secret` MUST be at least 16 bytes of **high-entropy** key material — output of a CSPRNG, or a KMS/HSM key. Length is not entropy: an implementation MUST NOT accept a password or passphrase as a master secret. If only a password is available, it MUST first be stretched with a memory-hard KDF (Argon2id, scrypt).
- `epoch_id` MUST satisfy `0 ≤ epoch_id < 2^64`.
- `salt` MUST be exactly 16 fresh bytes from a CSPRNG **for every seal**. It MUST NOT be derived from, or correlated with, any other field. (§11.1 — this is what makes envelopes unlinkable.)
- The three variable-length inputs to the canonical hash are length-prefixed. An implementation MUST NOT concatenate them unprefixed; doing so makes the `info` channel ambiguous, so distinct `(context, epoch, MEMH)` triples could derive the same key.
- The environment binds through `info`, **never** through `salt`. This is why per-seal freshness does not weaken the environment binding.

---

## 6. Envelope format (`SCE4`)

Total length: `65 + 4 + len(ciphertext)`.

```
offset  size  field        description
------  ----  -----------  --------------------------------------------------
     0     4  magic        MAGIC ("SCE4")
     4     1  version      VERSION (4)
     5    12  nonce        AEAD nonce; fresh random per seal
    17    16  salt         HKDF-extract salt; fresh random per seal
    33    32  commitment   key commitment (§5)
------  ----  -----------  --------------------------------------------------  header = bytes[0:65]
    65     4  ct_len       u32, length of ciphertext ‖ tag
    69   ...  ciphertext   AEAD output, including the 16-byte tag
```

The envelope carries **no** environment metadata: MEMH, `epoch_id` and `context` do not appear on the wire in any form. This is a requirement, not an optimisation (§11.1).

An implementation MUST NOT add fields to the header. Any field that is stable across a user's seals re-introduces a linkable tag.

### 6.1 Associated data

```
AAD = DOMAIN ‖ "|hdr|" ‖ header ‖ MEMH ‖ u64(epoch_id)
```

(`"|hdr|"` is the 5 ASCII bytes `7c6864727c`.)

MEMH and `epoch_id` are **authenticated but not transmitted**: the unsealer recomputes them from the manifest and epoch it was given. This binds the environment a second time, independently of the key derivation, without putting anything linkable on the wire.

---

## 7. Seal

```
seal(state, M, master_secret, epoch_id, context) -> envelope

  1. reject if state is not a byte string
  2. reject if len(state) > MAX_STATE
  3. reject if context is not a byte string
  4. reject unless 0 <= epoch_id < 2^64
  5. MEMH        = SHA3(canonical(M))
  6. salt        = random(16)
  7. nonce       = random(12)
  8. K_enc, commitment = derive(master_secret, MEMH, epoch_id, context, salt)
  9. header      = MAGIC ‖ VERSION ‖ nonce ‖ salt ‖ commitment
 10. ciphertext  = AES-256-GCM-SIV.Encrypt(K_enc, nonce, state,
                                           AAD = DOMAIN ‖ "|hdr|" ‖ header
                                                 ‖ MEMH ‖ u64(epoch_id))
 11. return header ‖ u32(len(ciphertext)) ‖ ciphertext
```

`nonce`, `salt` and `K_enc` MUST NOT be caller-supplied. Generating them internally removes an entire class of misuse.

---

## 8. Unseal

```
unseal(envelope, M, master_secret, epoch_id, context) -> state | FAIL

  1. reject if envelope is not a byte string             -> MALFORMED
  2. reject if len(envelope) < 69                        -> MALFORMED
  3. parse magic, version, nonce, salt, commitment
  4. reject if magic != MAGIC                            -> MALFORMED
  5. reject if version != VERSION                        -> MALFORMED
  6. ct_len = u32 at offset 65
  7. ciphertext = envelope[69:]
  8. reject if len(ciphertext) != ct_len                 -> MALFORMED
  9. reject if len(ciphertext) < TAG_LEN                 -> MALFORMED
 10. MEMH = SHA3(canonical(M))                    # from the CALLER's manifest
 11. K_enc, expected = derive(master_secret, MEMH, epoch_id, context, salt)
 12. commitment_ok = constant_time_equal(commitment, expected)
 13. aead_ok, plaintext = AES-256-GCM-SIV.Decrypt(K_enc, nonce, ciphertext,
                                                  AAD = ... as in §6.1)
 14. if not (commitment_ok AND aead_ok):               -> MISMATCH
 15. return plaintext
```

### 8.1 Requirements

- Step 12 MUST use a constant-time comparison. A variable-time compare is a timing oracle on the commitment. **This defect is not observable by any functional test** (behaviour is identical); implementations SHOULD guard it by review or static check.
- Step 13 MUST be attempted **even when step 12 already failed**, and the two results combined at step 14. Short-circuiting on the commitment check turns the difference in work into a timing oracle that distinguishes *why* a seal failed.
- Every cryptographic failure — wrong environment, wrong epoch, wrong context, wrong secret, tampering — MUST produce **one identical error**. An implementation MUST NOT report which factor mismatched, MUST NOT return partial plaintext, and MUST NOT return unauthenticated plaintext.
- Structural faults (steps 1–9) MAY be distinguished from cryptographic failure (step 14). They reveal only public framing facts an adversary already controls. Implementations SHOULD document this.
- The header is authenticated but MUST NEVER be treated as the source of truth. Everything security-relevant is recomputed from the caller's manifest, epoch and context.

---

## 9. Chunked stream container (`SCES` v1)

A single envelope is capped at `MAX_STATE` (~4 GiB) by `ct_len`, and by AES-GCM-SIV itself at 2^36 bytes (~64 GiB) per message. For larger state — a long-context KV-cache — a stream container seals an ordered sequence of bounded envelopes.

**This is a layer above §6–§8. The envelope format is unchanged; each segment is an ordinary, unlinkable SCE4 envelope.**

### 9.1 Container format

```
offset  size  field           description
------  ----  --------------  -----------------------------------------------
     0     4  stream_magic    STREAM_MAGIC ("SCES")
     4     1  stream_version  STREAM_VERSION (1)
     5    16  stream_id       fresh random per container
    21     8  num_segments    u64, n
    29     8  segment_size    u64, C (nominal plaintext bytes per segment)
    37     8  total_len       u64, L (total plaintext bytes)
------  ----  --------------  -----------------------------------------------  header = bytes[0:45]
    45   ...  segments        n × ( u64(len(envelope_i)) ‖ envelope_i )
```

### 9.2 Sequence binding

The binding introduces **no new cryptography**. Segment `i` is sealed with a derived context:

```
seg_context(i) = STREAM_DOMAIN
               ‖ LP(context) ‖ LP(stream_id)
               ‖ u64(i) ‖ u64(n) ‖ u64(L) ‖ u64(C)

envelope_i = seal(state[i·C : min((i+1)·C, L)], M, master_secret,
                  epoch_id, context = seg_context(i))
```

Because `context` feeds the key derivation (§5), a segment opens **only** when the unsealer reconstructs its exact position in its exact stream. Consequently, reordering, dropping, duplicating, truncating, extending, or splicing a segment from another stream all fail closed.

The container header therefore needs **no MAC of its own**: it is authenticated *by consequence*. Any change to `stream_id`, `n`, `C` or `L` makes every segment fail to derive its key.

- A container with `L = 0` MUST contain exactly one segment, itself sealing an empty state.
- `segment_size` MUST be a positive integer not exceeding a single envelope's capacity.
- On unseal, the implementation MUST reject trailing bytes after the declared segments, and MUST reject a declared `num_segments` larger than the container could physically hold (a guard against a length field forcing an unbounded loop).
- On unseal, the sum of the recovered segment lengths MUST equal `L`, or the container MUST fail closed.

### 9.3 Note on failure position

`unseal` of a container stops at the first failing segment, which reveals *where* the first fault is. That position is not secret — the adversary chose it, and `num_segments` is in the cleartext header — and no plaintext or key material is revealed. Each segment still fails with the uniform error of §8.1.

---

## 10. Error model

An implementation MUST expose exactly two failure classes, and MUST NOT let any other error escape a public entry point:

| Class | Raised when |
|---|---|
| **MalformedEnvelope** | structural fault: wrong type, too short, bad magic, unsupported version, declared length mismatch, trailing bytes |
| **StateSealMismatch** | any cryptographic failure, with a **uniform** message |

Both MUST derive from a single library error type, so a caller can catch everything with one handler. Leaking a native `TypeError`, `struct.error`, `AttributeError` or equivalent from a public entry point is a **conformance failure**: it means a malformed envelope can crash a caller that correctly handles the documented errors.

Diagnostic helpers MAY exist for trusted operators, but MUST NOT be reachable from an untrusted path, and MUST NOT be invoked by `unseal`. Because SCE4 records nothing about the sealing environment, such a helper cannot in any case recover the cause of a refusal from an envelope alone — by design.

---

## 11. Security properties

### 11.1 Guaranteed

1. **Confidentiality and integrity.** From AES-256-GCM-SIV under `K_enc`.
2. **Environment binding, twice, independently.** The environment derives the key (§5) *and* is authenticated data (§6.1). A change to any manifest field, the epoch, or the context changes `K_enc` and the commitment, and the seal fails.
3. **Key commitment.** The explicit commitment binds the ciphertext to exactly one key. A plain AEAD is *not* key-committing; without this, an adversary who can choose keys could construct a ciphertext that opens validly under two, which is the basis of partitioning-oracle attacks (Albertini et al., USENIX Security 2022; Bellare–Hoang). The commitment is *hiding* (its input half is independent of `K_enc`) and *binding* (a second opening would require a SHA3-256 collision on that half).
4. **Fail-closed, oracle-free.** One uniform error for every cryptographic failure; both checks always performed (§8.1).
5. **Unlinkability at rest.** Two envelopes sealed from identical inputs share **no** common field: `nonce`, `salt`, `commitment` and ciphertext all differ, and no environment metadata is present. A holder or relay has nothing to cluster on. This is what permits an untrusted third party to carry the state.
6. **Per-seal key separation.** The fresh salt makes `K_enc` unique to every seal, so a repeated nonce is not even a repeated key. GCM-SIV's own nonce-misuse resistance is retained as defence-in-depth behind that.

### 11.2 Not provided

- **No forward secrecy.** Compromise of the master secret retroactively opens every envelope sealed under it. Mitigation requires an ephemeral key-agreement layer above SCE, which is out of scope for this document.
- **No size privacy.** The envelope length reveals the payload size (fixed overhead: 85 bytes = 65 header + 4 length + 16 tag). Pad at the transport layer if size correlation matters.
- **No holder authentication.** SCE authenticates the *environment and secret*, not who is presenting the bytes.
- **The environment fingerprint is not secret.** MEMH is a hash of public build facts; it is kept off the wire for *unlinkability*, not for confidentiality.
- **Not audited.** This is a reference implementation.

---

## 12. Conformance: which requirements are load-bearing

A requirement is only meaningful if its removal is detectable. `tests/test_sabotage.py` removes each mechanism from the reference implementation and records which test catches it. Results:

| Requirement | Removing it is caught by |
|---|---|
| Constant-time commitment compare (§8.1) | **nothing functional** — timing-only; static guard required |
| Key-commitment check (§8, step 12) | an envelope with a valid AEAD but a wrong stored commitment |
| AAD binds MEMH/epoch (§6.1) | an envelope whose AAD was built from a foreign MEMH |
| Fresh per-seal salt (§5.1) | two seals sharing a commitment (linkability) |
| Fresh per-seal nonce (§7) | two seals sharing a nonce |
| Epoch in the KDF `info` (§5) | known-answer vectors |
| Domain separation in the commitment (§5) | known-answer vectors |
| Length-prefixing in the KDF canonical hash (§5.1) | known-answer vectors |
| Sorted `extra` keys (§4.2) | order-independence of the fingerprint |

Implementers SHOULD port these checks. Three of them are the *sole* detector of their mechanism: without the commitment-isolation test, the AAD-isolation test, and known-answer vectors, those requirements could be silently dropped while a test suite stayed green.

---

## 13. Test vectors

`test_vectors.json` contains six known-answer cases. Each gives a manifest and the expected `canonical(M)`, `MEMH`, and — for a fixed `master_secret`, `epoch_id`, `context` and a **pinned** `salt` — the derived `K_enc` and `commitment`.

The salt is random per seal in normal operation; it is pinned per case so the derived values are reproducible. `nonce` and `ciphertext` are randomised per seal and are therefore **not** part of the known-answer set.

A conforming implementation MUST reproduce every value in `test_vectors.json`. `tools/verify_vectors.js` is an independent JavaScript implementation that does so, and is the interoperability check for this specification.

---

## 14. Versioning and compatibility

- The envelope `magic` and `version` are bumped together on any change to the header layout, the key derivation, or the AAD. SCE3 and SCE4 envelopes therefore refuse to open under each other's implementations; magic separation makes this automatic and fail-closed.
- The manifest encoding (`SCEMAN1`) is versioned **independently** and is unchanged from SCE3, so MEMH values are stable across that bump.
- The stream container (`SCES`) is versioned independently of the envelope, because it adds no cryptography of its own.
- An implementation MUST reject an envelope whose version it does not implement. It MUST NOT attempt a best-effort parse.
