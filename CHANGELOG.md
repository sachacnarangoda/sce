# Changelog

All notable changes to SCE are recorded here. This project uses semantic-ish
versioning; the envelope wire version (e.g. `SCE3`) is bumped whenever the
on-wire format or the key derivation changes, so envelopes from different
versions are intentionally incompatible and fail closed rather than mixing.

## [0.4.5] — 2026-07-13

A conformance fix and two interoperability/precision improvements. 
**No wire change and no key-derivation change** — the
magic stays `SCE4` and every existing derived value in `test_vectors.json` is
byte-identical; the vectors only *gain* pinned fields. Patch release.

### Fixed — uniform-error-model violation (distinct from the 0.4.4 fix)
- **`segment_size` above the u64 range now raises `SCEError`, not a raw
  `struct.error`.** A `segment_size >= 2**64` (or above the maximum sealable
  payload) was packed into the SCES header's u64 field and escaped as a bare
  `struct.error`, violating the "only `SCEError` escapes a public entry point"
  contract asserted in the README and SPEC §10. This is a *different* chokepoint
  from the length-prefix `OverflowError` sites fixed in 0.4.4 — it is the header
  `struct.pack`. Producer-side and caller-controlled (no false-accept or leak),
  but it falsified a stated invariant. Bounded with `SCEError` and covered by a
  regression test. (`sce/stream.py`, `tests/test_stream.py`.)

### Improved — the test vectors now pin the AEAD/AAD (closes an interop gap)
- **The AAD and the full envelope are now known answers.** Previously the six
  vectors stopped at `K_enc` and `commitment`; the associated data affects only
  the ciphertext/tag, so an implementation that mis-built the AAD (wrong domain
  label, `MEMH`/epoch transposed, dropped separator, wrong header order) could
  reproduce every vector, be internally self-consistent, and still emit envelopes
  the reference cannot open. Each case now also **pins the nonce** and publishes
  `aad_hex` and `envelope_hex` for a fixed plaintext. The Python known-answer
  test verifies the AAD and the whole envelope end-to-end; the JS verifier (Node
  has no AES-256-GCM-SIV) reproduces the **AAD bytes** cross-language, which is
  the component that was unpinned. (`test_vectors.json`, `tools/verify_vectors.js`,
  `tests/test_hardening.py`, `SPEC.md` §13.)

### Fixed — NFC normalisation was version-dependent and unpinned
- **A normative Unicode version is now named (Unicode 15.0.0).** `NFC` depends on
  the Unicode Character Database version, and two implementations bundling
  different versions could compute different `MEMH` for a manifest containing an
  affected codepoint — a **fail-closed** interop defect (a spurious refusal, never
  a false accept), but a real one, and every prior KAT was ASCII so it was never
  exercised. `SPEC.md` §2.1 now pins Unicode 15.0.0 as normative, and a seventh
  KAT case uses a decomposed non-ASCII string and a two-key `extra`, locking both
  normalisation and key-ordering to a known answer. (`SPEC.md`, `test_vectors.json`.)



A security fix plus an error-model fix and documentation precisions surfaced by
two independent cold reviews. **No wire change and no key-derivation change** —
the magic stays `SCE4`, `test_vectors.json` is unchanged, and the cross-language
verifier still reproduces every vector byte-for-byte, so every legitimately
sealed envelope and container round-trips exactly as before. This is therefore a
patch release: the only behavioural change is that a previously-accepted forgery
is now correctly refused.

### Fixed — a no-secret forgery of the stream layer's fail-closed contract
- **A zero-segment container is no longer accepted.** `unseal_state_chunked`
  previously returned `b""` for a header-only container claiming `num_segments = 0`
  **having performed no cryptographic verification** — an attacker with no key
  could manufacture a byte string the unsealer accepted, and it violated the SPEC
  §9.2 rule that an empty state (`L = 0`) is carried by exactly one segment. The
  producer always honoured that rule; the unsealer never enforced it. It now
  rejects `n == 0`, and rejects `L == 0` with `n != 1`, as `MalformedEnvelope`.
  Regression tests reproduce the forgery attempt and confirm it is refused, while
  a legitimately sealed empty state still round-trips. (`sce/stream.py`,
  `tests/test_stream.py`.)

### Fixed — uniform-error-model violation
- **Oversized length-prefixed fields now raise `SCEError`, not a raw
  `OverflowError`.** A `context` (or manifest field, or stream context) at or above
  2³² bytes hit `len(b).to_bytes(4, "big")` and escaped as a bare `OverflowError`,
  breaking the "only `SCEError` escapes a public entry point" contract that callers'
  `except SCEError` handling relies on. Guarded at both length-prefix chokepoints —
  the manifest-field encoder and the generic helper — plus an explicit bound on
  `context` at the seal/unseal entry points. Practically unreachable (~4 GiB), but
  the contract now holds on every length-prefixed path. (`sce/core.py`.)

### Documentation — corrected claims and a promoted boundary
- **Manifest completeness is now a first-class security boundary**, not a usability
  aside. SCE binds to the *manifest it is given*, not to the true execution
  environment, and cannot detect a numerics-affecting factor (a cuBLAS/cuDNN
  point-release, an A100-vs-H100 difference folded under one `tensor_parallel`
  string, a driver flag, a flash-attention-vs-eager swap) that the caller omitted —
  in which case two different environments hash to the same fingerprint and stale
  state resumes silently, the exact failure SCE exists to prevent. Stated in
  `SPEC.md` §11.2 (leading bullet) and the README **Boundaries** section, including
  that `weights_hash` is an unverified caller-supplied label.
- **The key commitment is scoped honestly** as defence-in-depth under the shipped
  static-secret design (the AAD already binds the environment independently, and
  callers cannot choose keys), becoming load-bearing only under the planned
  DH-derived keying. Stated in `sce/core.py` and `SPEC.md` §11.1(3).
- **Wording precisions:** the commitment is *computationally* hiding (a PRF
  assumption, not information-theoretic); the GCM-SIV nonce-repeat characterisation
  now cites RFC 8452 §9's usage limits rather than an under-stated "at worst";
  the chunked container is noted to expose *exact* plaintext length in its header
  (a richer shape fingerprint than a bare envelope); and a reimplementer note makes
  explicit that `ciphertext = envelope[69:]` (all trailing bytes), never
  `envelope[69:69+ct_len]`.



Documentation only. No code behaviour change, no wire change, no API change, no
change to `test_vectors.json`. **It corrects an over-stated security claim**, which
is why it is recorded as a release rather than an untagged commit.

### Fixed — an over-claimed security property
- **Unlinkability is a property of the bytes, not of the channel.** v4 made a
  breaking wire change to strip every linkable field from the envelope, and the
  documentation then implied — in `SPEC.md` §11.1 most explicitly ("this is what
  permits an untrusted third party to carry the state") — that this was sufficient
  for an untrusted relay to carry state without linking a user's sessions. **It is
  not.** A relay that observes network identity (source IP, TLS session, account
  credential, connection timing) links a user's envelopes regardless of how clean
  the envelope bytes are, and no wire format can prevent that. Unlinkability at rest
  is **necessary but not sufficient**: it only yields real-world anonymity when
  composed with an anonymising transport — a mixnet, onion routing, or a genuine
  dead drop in which sender and recipient never connect directly. That layer is what
  LDDP is for, and it is not in this repository.
- The correction is stated in three places a reader can actually reach it:
  `SPEC.md` §1 (threat model — the guarantees are properties of the bytes, not the
  channel), §11.1(5) (the claim is now marked necessary-but-not-sufficient), and a
  new leading bullet in §11.2 (*Not provided*); the README **Boundaries** section,
  as its first entry; and the `sce/core.py` module docstring, so a developer reading
  the source hits it too.
- Concretely: shipping SCE over an ordinary logged-in HTTPS session to a provider
  yields **none** of the unlinkability benefit. Anyone relying on that property
  needed to be told so plainly.

### Added — README framing
- An opening metaphor, so the design is legible in thirty seconds.

## [0.4.2] — 2026-07-12

Robustness and verification release. **No wire change, no API change, no change to
`test_vectors.json`** — SCE4 envelopes sealed by 0.4.x remain readable, and the
cross-language vectors are byte-identical. This adds an automated security
verification harness, and fixes the defects that harness found on its first run.

### Fixed
- **`ModelManifest` is now genuinely immutable.** `@dataclass(frozen=True)` is only
  *shallowly* immutable: the `extra` dict behind it could still be mutated after
  construction, which silently changed a live manifest's MEMH — breaking the
  determinism the whole fingerprint rests on, and making any cached MEMH unsafe.
  `extra` is now validated, snapshotted (so it cannot alias the caller's dict), and
  exposed read-only via `MappingProxyType`. The canonical bytes and MEMH of any
  given manifest are unchanged, so this is wire- and vector-safe.
  *Behaviour change:* mutating `manifest.extra` now raises instead of silently
  corrupting the fingerprint. `extra` accepts any `Mapping` on input.
- **Uniform error model at every public entry point.** 11 of 20 entry-point/argument
  combinations could leak a raw, non-`SCEError` exception (`TypeError` from an
  unchecked `sealed`/`container`; `AttributeError` from an unchecked `manifest`),
  which meant `except SCEError:` was *not* a safe way to call this library and a
  malicious or malformed input could crash a caller. All public entry points now
  validate their arguments and raise `SCEError` (`MalformedEnvelope` for a
  non-bytes envelope, `SCEError` for a non-manifest). `bytes`, `bytearray`, and
  `memoryview` envelopes are accepted; the common `bytes` path is not copied.
- **Sharper `master_secret` guidance.** The minimum stays 16 bytes (128 bits of
  *random* key material is not weak, and a higher floor would reject legitimate
  128-bit KMS/HSM keys while still admitting a long password). The error now states
  plainly that length is not entropy: use a CSPRNG or a KMS key, and stretch a
  password with Argon2id/scrypt first if that is all you have.

- **Manifest pickling / deep-copying restored.** Freezing `extra` into a read-only
  mapping (above) silently broke `pickle` and `copy.deepcopy`, so a manifest could
  no longer cross a process boundary (multiprocessing, task queues) — a regression,
  not a hardening. `ModelManifest.__reduce__` now reconstructs from a plain dict and
  re-freezes on the way in. This was found while closing the remaining gaps, *not*
  by the new harness, which tested the security contract but not the object
  protocol; tests for `pickle`/`deepcopy`/`copy`/`replace` round-trips now exist.

### Added — normative specification
- **`SPEC.md`.** The complete wire format and algorithms, written so that an
  independent implementation in any language can be built from that document alone
  and interoperate byte-for-byte. Covers the threat model, the `SCEMAN1` manifest
  canonicalisation and MEMH, key derivation and the commitment, the SCE4 envelope
  and its associated data, seal/unseal (including the requirements that make failure
  uniform and oracle-free), the SCES stream container, the error model, and an
  explicit statement of what is *not* provided (no forward secrecy, no size privacy,
  no holder authentication). `tools/verify_vectors.js` is a working demonstration
  that the spec is implementable: it is an independent implementation and it
  reproduces every vector.
- **§12 of the spec records which requirements are load-bearing**, using the sabotage
  suite's evidence: for each mechanism, the test that catches its removal. Three
  requirements have exactly one detector, so an implementer who skips those tests can
  drop those mechanisms without noticing. That is stated in the spec rather than left
  as folklore.
- **The spec is machine-checked against the code.** Its normative constants block is
  parsed and compared to the implementation on every CI run
  (`test_spec_constants_match_the_implementation`). A specification that quietly
  disagrees with the code is worse than no specification.

### Performance
- **MEMH is computed once per manifest and cached.** This is correct *only* because
  the manifest is now genuinely immutable — a cached fingerprint on a mutable object
  would be a correctness bug, not an optimisation. `manifest.memh()` drops from
  ~6.7 µs to ~0.09 µs; a small `seal_state` is ~30% faster (38.6 µs → 27.1 µs); and
  the chunked path no longer re-derives the MEMH once per segment (~9% of a
  1024-segment seal).
- **`ModelManifest` is now hashable**, by fingerprint. A frozen dataclass holding a
  mapping is unhashable by default; hashing the MEMH is well-defined now that the
  manifest cannot change, and lets manifests be used as dict/set keys for
  per-environment caches. Equal manifests hash equally.

### Added — automated security verification harness (stdlib only, no new dependencies)
- **`tests/test_hardening.py` (19 tests).** Exhaustive single-bit mutation of every
  byte of an envelope *and* of a stream container (not a spot check); exhaustive
  truncation; a wrong-type matrix over every public entry point; seeded byte fuzz
  and structured mutation fuzz asserting only `SCEError` escapes and no mutant ever
  opens; a Python-side known-answer test against `test_vectors.json`; immutability
  and MEMH-stability properties; and a sub-quadratic scaling guard on the chunked
  layer (an asymptotic ratio test, not a wall-clock budget, so it does not flake on
  shared runners).
- **`tests/test_sabotage.py` — "who tests the tests?"** Applies 9 targeted source
  mutations to `sce/core.py` (disable the commitment check, gut the associated data,
  pin the nonce, pin the salt, drop the epoch from the KDF info, drop domain
  separation, remove length-prefixing, remove manifest key sorting, downgrade the
  constant-time compare), loads each mutant in isolation, and asserts the canaries
  catch it. Includes an unmutated **control** run, so the suite cannot pass
  vacuously. Every functionally detectable sabotage is caught. The constant-time
  downgrade is *not* functionally detectable — identical behaviour, timing-only — so
  it is documented as an expected survivor and guarded statically instead.
- **`fuzz/fuzz_envelope.py` + `fuzz/corpus.json`.** A libFuzzer-shaped
  `TestOneInput(data)` entry point with a dependency-free driver and a hex-encoded
  regression corpus that is replayed on every run. Adopting Atheris/OSS-Fuzz later
  needs a five-line driver, not a rewrite. (OSS-Fuzz itself only accepts established,
  widely-depended-on projects, so the CI job plus the corpus is the practical
  equivalent until SCE qualifies.)
- **Three of the new tests are load-bearing, not decorative** — the sabotage suite
  proves it. `disable_commitment_check` is caught *only* by the new
  commitment-isolation test (an envelope with a valid AEAD but a wrong stored
  commitment); `gut_the_associated_data` *only* by the new AAD-isolation test (a
  correct key and commitment, but an AAD built from a foreign MEMH); and three KDF
  sabotages *only* by the new Python-side KAT. Without them, those mechanisms were
  redundant under test and a refactor could have silently dropped them with CI green.
- CI now runs the hardening harness, the sabotage suite, and a 50k-input fuzz round
  (deterministic seed) on every push.

### Not changed, deliberately
- No `max_*` input-bound configuration knobs were added. The untrusted party controls
  the envelope bytes, and those are already length-checked, so there is no
  amplification to bound; `context`/`manifest` come from the *calling* provider, not
  the holder. Adding knobs would enlarge the misconfiguration surface the design
  explicitly tries to avoid, and any default generous enough not to break the chunked
  large-state path would protect nobody by default.
- `core.py` was not split into serialization/KDF/crypto/envelope modules. A single
  auditable file of this size is easier to review in one pass than four, and
  fragmenting working cryptographic code carries more risk than the maintainability
  it would buy at this scale. Worth revisiting if the module grows substantially or
  ahead of a formal audit.

## [0.4.1] — 2026-07-11

### Added — chunked stream container (SCES v1), no envelope wire change
`seal_state_chunked` / `unseal_state_chunked` seal an arbitrarily large state as
an ordered sequence of bounded SCE4 envelopes, lifting the single-envelope size
ceiling (the uint32 ~4 GiB frame, and AES-GCM-SIV's own ~64 GiB per-message
limit) for states like a long-context transformer KV-cache when compact
SSM/summarised state is not an option. **The SCE4 envelope format is unchanged** —
this is a container layer *above* the envelope, so it required no re-audit of the
seal and no wire bump; `SCE4` envelopes and vectors are untouched.

- **New public API** (in a new `sce.stream` module, re-exported from `sce`):
  `seal_state_chunked(...)`, `unseal_state_chunked(...)`, `describe_stream(...)`,
  and `DEFAULT_SEGMENT_SIZE` (64 MiB). The single-envelope API is unaffected.
- **Sequence binding reuses `context`, adds no new cryptography.** Each segment is
  sealed under a per-segment context
  `"LDDP-SCE|stream-v1" || LP(context) || LP(stream_id) || u64(i) || u64(n) || u64(L) || u64(C)`,
  where `stream_id` is fresh-random per container. Because `context` feeds the key
  derivation, a segment opens only when the unsealer reconstructs its exact
  position in its exact stream.
- **Fail-closed against sequence tampering.** Reordering, dropping, truncating,
  extending, duplicating, or splicing segments (including from another stream) all
  fail closed, as do environment/epoch/context/secret changes and any flipped
  byte. The `SCES` header (`stream_id`, `n`, segment size, total length) carries no
  MAC of its own — it is authenticated by consequence, since any change to it makes
  every segment fail to derive its key.
- **Format separation.** A stream container (`SCES` magic) and a single envelope
  (`SCE4` magic) each reject the other's decoder, so the two cannot be confused.

### Security notes
- `describe_stream` exposes only the container's format identity, segment count,
  and sizes — no `stream_id`, no plaintext. As with a single envelope, the
  container length reveals the payload size (the inherent size-metadata channel).
- On a tampered stream, `unseal_state_chunked` stops at the first failing segment.
  That is a timing signal about the *position* of the first fault, which is not
  secret (the attacker chose it; the segment count is in the cleartext header) and
  leaks no plaintext or key material; each segment still fails with the envelope's
  own uniform, oracle-free error.

### Memory
Returns the whole container as `bytes`: peak memory is ~L (the container) plus a
per-segment transient (~2·segment_size), which removes the AEAD size ceiling and
avoids holding 2–3× the *whole* state for one AEAD pass, but does not yet stream
to disk. A file-backed streaming variant is the natural follow-up for states too
large to hold assembled in memory.

### Tests / tooling
- New `tests/test_stream.py` (**20 tests**): round-trip across many segment sizes,
  a larger multi-segment state, empty/single-segment states, and fail-closed
  coverage of reorder, drop, drop-with-header-fixup, truncate, trailing bytes,
  cross-stream splice, per-segment tamper, and header (`stream_id`/`total_len`)
  tamper, plus format-separation and input-validation guards. Wired into CI.
- Package version `0.4.0` → `0.4.1`. No changes to `sce/core.py`,
  `test_vectors.json`, or the JavaScript verifier.

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
This release addresses findings from an external code review. **None of it
changes the wire format or the key derivation** — `SCE3` envelopes and the v3
test vectors are unaffected, and the independent JavaScript verifier still
reproduces every vector exactly. It is a patch-level release; envelopes sealed
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
