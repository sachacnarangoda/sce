# Changelog

All notable changes to SCE are recorded here. This project uses semantic-ish
versioning; the envelope wire version (e.g. `SCE3`) is bumped whenever the
on-wire format or the key derivation changes, so envelopes from different
versions are intentionally incompatible and fail closed rather than mixing.

## [0.3.1] — 2026-07-10

### Fixed (review hardening, no wire change)
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
