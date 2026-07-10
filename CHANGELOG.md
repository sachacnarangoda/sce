# Changelog

All notable changes to SCE are recorded here. This project uses semantic-ish
versioning; the envelope wire version (e.g. `SCE3`) is bumped whenever the
on-wire format or the key derivation changes, so envelopes from different
versions are intentionally incompatible and fail closed rather than mixing.

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
