# Security Policy

## Status

SCE is a **reference / proof-of-concept** implementation. It is correct and
tested, and built on standard cryptography (AES-256-GCM-SIV, HKDF-SHA3-256,
SHA3-256), but it has **not** had an independent cryptographic audit and is not
yet hardened for production (see the Boundaries section of the README).

"Infallible" is not claimed. The intended and achievable property is **no
silent, catastrophic failure mode** — a mismatch or tampering is refused, never
resumed into corruption.

## Known limitations (by design, documented)

- **Static-key reference form.** The reference seals under a static
  `master_secret`; a compromised or compelled provider could retroactively
  decrypt state sealed under it. The remediation (ephemeral per-transaction key
  derivation) is described in the README and the design notes.
- **Not an anonymity, confidentiality-in-use, retention, or replay control.**
  SCE protects portable computed state at rest and between turns, and binds it
  to its execution environment. It does not hide *who* is asking, does not hide
  the query from the model during computation, and does not prevent replay of a
  valid envelope. Those belong to other layers.
- **Memory hygiene.** In Python, key material and plaintext cannot be reliably
  zeroised; a production port should address this.

## Reporting a vulnerability

If you believe you have found a cryptographic weakness or an implementation flaw
— for example, a way to open sealed state under a *different* environment, to
have a mismatch resume instead of fail closed, or a timing/oracle distinction
between failure causes — please report it.

- Open a GitHub issue for non-sensitive reports, **or**
- For anything you consider sensitive, contact the maintainer directly (see the
  profile on the repository owner's GitHub account) rather than filing a public
  issue.

Please include: what you did, what you observed, what you expected, and (ideally)
a minimal reproduction. Critique of the manifest's completeness and of the
keying/commitment construction is especially welcome.
