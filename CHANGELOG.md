# Changelog

All notable changes to SCE are recorded here. This project uses semantic-ish
versioning; the envelope wire version (e.g. `SCE3`) is bumped whenever the
on-wire format or the key derivation changes, so envelopes from different
versions are intentionally incompatible and fail closed rather than mixing.

## [0.4.0] — 2026-07-11

### Changed (wire + key derivation — this is a wire bump)
This release makes the envelope **unlinkable at rest**. It changes the on-wire
format and the key derivation, so **`SCE3` and `SCE4` envelopes intentionally
refuse to open under each other** (magic separation makes this automatic and
fail-closed). Envelopes sealed by 0.3.x cannot be read by 0.4.0 and vice versa.

- **Environment metadata removed from cleartext.** Earlier versions carried the
  environment fingerprint (`MEMH`), the `epoch`, and a *deterministic* key
  commitment in the cleartext header. Because the commitment was a fixed function
  of `(master_secret, MEMH, epoch, context)`, it was a **stable per-key tag**: any
  party merely *holding* an envelope could cluster a user's sessions by it, and
  `MEMH`/`epoch` were in the clear too. v4 removes all three from the wire. The
  header is now `magic | version | nonce | salt | commitment` (**65 bytes, down
  from 89**). `MEMH` and `epoch` are re-derived by the unsealer from the
  caller-supplied manifest and epoch and folded into the AEAD **associated data**,
  so the environment still binds in two independent ways (key + AAD) without
  appearing anywhere in the envelope.
- **Fresh per-seal salt in the HKDF extract.** A random 16-byte `salt`, carried in
  the header, is now the HKDF-extract salt (replacing the previous `epoch`-as-salt,
  which was redundant since `epoch` is already in the `info`). This makes both
  `K_enc` and the commitment **unique to every seal**.

### Security rationale
- **Why it is now unlinkable.** The only per-seal-stable value that used to leak —
  the commitment — is now randomised by the salt, and the two other cleartext
  identifiers (`MEMH`, `epoch`) are gone. Two seals of the same state under the
  same key now share **no** common field: `nonce`, `salt`, `commitment`, and the
  ciphertext all differ. A holder or relay has nothing to cluster on.
- **Why it is still key-committing.** The commitment remains an explicit,
  constant-time-verified `SHA3-256` over an independent HKDF half; the salt only
  randomises it. It is still *binding* — a different environment yields a different
  committed half, so one ciphertext opening under two environments would still
  require a `SHA3-256` collision on that half — and still *hiding*. Crucially, the
  environment binds through the HKDF `info` (which carries `context`, `epoch`,
  `MEMH`), **not** through the salt, so making the commitment unlinkable does not
  weaken the fail-closed guarantee. This keeps the explicit-commitment design that
  the partitioning-oracle literature (Albertini et al., *USENIX Security* 2022;
  Bellare–Hoang, committing AE) recommends, rather than resting key-commitment on
  the AEAD alone.
- **Why nonce handling is now stronger.** Because the per-seal salt makes `K_enc`
  unique to each seal, a repeated nonce is a non-event on its own — it is no longer
  even the same key. AES-256-GCM-SIV is retained as defence-in-depth against an RNG
  failure that repeats a `(salt, nonce)` pair.

### Wire / version
- Envelope magic `SCE3` → `SCE4`; domain-separation label `LDDP-SCE-v3` →
  `LDDP-SCE-v4`; KDF tags `LDDP-SCE|kdf-v3|`/`LDDP-SCE|kdf-canon-v3` → `…v4`.
- The manifest canonicalisation (`SCEMAN1`) and the `MEMH` computation are
  **unchanged**, so the canonical-manifest bytes and MEMH values in the vectors are
  identical to v3; only the derived `K_enc`/commitment change (new salt input).
- Package version `0.3.1` → `0.4.0`.

### Costs (intended)
- `describe_envelope` no longer reports `sealed_under_memh`/`sealed_under_epoch`/
  `key_commitment` — only the format identity and sizes. Exposing any of those
  would re-introduce a linkable tag.
- `explain_mismatch` is now deliberately **non-diagnostic**: with no environment
  metadata in the envelope, it can only confirm structural validity and echo the
  *presented* MEMH for an out-of-band check, not recover the specific cause.

### Tests / tooling
- Added 3 tests: commitment is unlinkable across seals, the envelope exposes no
  environment metadata (and `MEMH` never appears in the bytes), and a `SCE3`
  envelope is rejected by v4. Updated the header-tamper offsets, the nonce-reuse
  test, the KDF-injectivity test, and the `describe`/`explain` tests for the new
  layout — **38 tests total**.
- Regenerated `test_vectors.json` for v4 (adds a `salt_hex` per case) and updated
  the independent JavaScript verifier (`tools/verify_vectors.js`); all 6 vectors
  reproduce exactly across the Python and JS implementations.
- Resolves review findings **#2** (linkable cleartext state) and **#10**
  (redundant `epoch`-as-HKDF-salt).

## [0.3.1] — 2026-07-10

### Fixed (review hardening — no wire change)
This is a patch-level release; envelopes sealed
by 0.3.0 remain readable.

- **Oversize input now fails cleanly.** `seal_state` rejects a state larger than
  the uint32 length frame (~4 GiB) with a clear `SCEError`, instead of letting
  `struct.pack` raise an uncontrolled `struct.error` deep in the call. New
  internal constant `_MAX_STATE`.
- **`master_secret` type is validated.** A non-`bytes` secret (e.g. a `str`) now
  raises a clear `SCEError` up front, rather than a low-level `TypeError` from
  inside HKDF (which a `>= 16`-character string previously reached) or a
  misleading "must be >= 16 bytes" message.
- **NFC-colliding `extra` keys are rejected.** Two manifest keys that are
  distinct strings but equal under NFC normalisation previously made the
  fingerprint order-dependent and ambiguous; `ModelManifest` now refuses them at
  construction, preserving the injectivity guarantee.
- **`SEAL_COUNT_CEILING_PER_KEY` is now enforceable.** `seal_state` takes an
  optional `seal_count`; when supplied, it refuses at the ceiling and prompts a
  rotation. SCE remains stateless, so the caller owns the counter — but the
  constant is no longer purely decorative.
- **`examples/serving_adapter.py` no longer leaks the refusal reason.** The
  fail-closed response previously carried `explain_mismatch()` output over the
  wire to the client, contradicting that helper's trusted-only contract and
  re-introducing the very oracle `unseal_state` is written to avoid. The reason
  is now logged server-side only; the client receives a uniform error code.

### Tests / docs
- Added 5 regression tests (oversize state, non-`bytes` secret, NFC-colliding
  keys, opt-in seal-count enforcement, and an adapter no-leak guard) — **35
  tests total**.
- Corrected stale "v2" version strings that referred to the current v3 code
  (module and test docstring headers, the bad-magic error message, README
  status line). CI step no longer hardcodes a test count.
- Package version `0.3.0` → `0.3.1`; `CITATION.cff` synced from `0.2.0` to
  `0.3.1`.

## [0.3.0] — 2026-07-10

### Changed (hardening)
- **Key-derivation `info` string is now unambiguous by construction.** The HKDF
  `info` input is built by length-prefixing every field (`context`, `epoch`,
  `MEMH`) and folding them through SHA3-256, using the same strict encoding
  discipline as the manifest canonicaliser:

  ```
  info = "LDDP-SCE|kdf-v3|" || SHA3-256( LP(context) || LP(epoch) || LP(MEMH) )
  ```

  The previous encoding concatenated these fields with byte delimiters. That
  encoding was **not** exploitable in practice — `MEMH` is fixed-width (32 bytes)
  and terminal, which made the concatenation injective — but its safety relied on
  that incidental property. The new encoding removes the reliance entirely and
  is robust to any future field addition or reordering. Defense-in-depth, no
  known prior vulnerability, zero performance cost.

### Wire / version
- Envelope magic bumped `SCE2` → `SCE3`; domain-separation label
  `LDDP-SCE-v2` → `LDDP-SCE-v3`. Because the derivation changed, v2 and v3
  envelopes are incompatible; a v2 envelope presented to v3 code fails closed.
- Package version `0.2.0` → `0.3.0`.

### Tests / tooling
- Added `test_kdf_info_is_unambiguous`, a regression guard proving the `info`
  string is injective in `(context, epoch, MEMH)` (30 tests total).
- Regenerated `test_vectors.json` for v3 and updated the independent JavaScript
  verifier (`tools/verify_vectors.js`) to match; all vectors reproduce exactly
  across the Python and JS implementations.

## [0.2.0] — 2026-07-08
- Hardened reference implementation: AES-256-GCM-SIV (nonce-misuse resistant),
  explicit key commitment, strict length-prefixed NFC-normalised manifest
  canonicalisation, uniform (oracle-free) failure, per-deployment key
  separation via `context`. 29 tests including adversarial, a manifest-theft
  brute-force simulation, and a 1,500-trial randomised property test.
