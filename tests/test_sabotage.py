"""
Sabotage suite -- "who tests the tests?"  (stdlib only)

Runs WITHOUT pytest:  python tests/test_sabotage.py

Every other test asks "is the implementation correct?". This one asks the
question that actually decides whether the suite is worth anything:

    IF someone silently broke a security mechanism, would we notice?

It takes the real `sce/core.py`, applies a targeted source mutation that removes
or weakens ONE security mechanism, loads the mutated module in isolation (never
importing it into the package, never shipping it), and runs a set of canary
properties against it. A mutation is CAUGHT if at least one canary fails.

A mutation that survives every canary is a hole in the test suite, not
necessarily a hole in the code -- it means the mechanism is currently redundant
under test, so a future refactor could silently drop it and CI would stay green.

Note the honest limit: a constant-time compare downgraded to `==` is a TIMING
defect with identical functional behaviour, so NO functional canary can catch it.
That one is guarded statically in test_hardening.py instead, and is asserted here
to be un-catchable so nobody later mistakes its absence for coverage.
"""

import importlib.util
import json
import os
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_PATH = os.path.join(REPO_ROOT, "sce", "core.py")
VECTORS_PATH = os.path.join(REPO_ROOT, "test_vectors.json")
MASTER = b"\x11" * 32

with open(CORE_PATH, encoding="utf-8") as _f:
    CORE_SRC = _f.read()


def load_mutant(source: str, name: str):
    """Load a mutated copy of core.py as an isolated module. Never installed into
    the package; the file is deleted immediately after import."""
    fd, path = tempfile.mkstemp(suffix=".py", prefix=f"sce_mutant_{name}_")
    modname = f"sce_mutant_{name}"
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(source)
        spec = importlib.util.spec_from_file_location(modname, path)
        mod = importlib.util.module_from_spec(spec)
        # @dataclass resolves its own module via sys.modules while processing the
        # class, so the module MUST be registered before exec_module or the import
        # dies with an unrelated AttributeError -- which would look like a "caught"
        # sabotage and silently make this whole suite vacuous.
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)
        return mod
    finally:
        os.unlink(path)


def manifest(mod, **overrides):
    fields = dict(
        weights_hash="sha3:aaaa1111",
        quantization="bf16",
        kernel_build_id="vllm-0.6.3+abc123",
        tensor_parallel="tp=1,pp=1",
        numerics_mode="bf16",
    )
    fields.update(overrides)
    return mod.ModelManifest(**fields)


# ------------------------------ canary properties -------------------------- #
# Each canary raises AssertionError if the property it defends is broken.

def canary_round_trip(mod):
    m = manifest(mod)
    s = mod.seal_state(b"state", m, master_secret=MASTER, epoch_id=1, context=b"c")
    assert mod.unseal_state(s, m, master_secret=MASTER, epoch_id=1, context=b"c") == b"state"


def canary_wrong_environment_fails_closed(mod):
    m = manifest(mod)
    s = mod.seal_state(b"state", m, master_secret=MASTER)
    try:
        mod.unseal_state(s, manifest(mod, numerics_mode="fp16"), master_secret=MASTER)
    except mod.SCEError:
        return
    raise AssertionError("opened under a changed environment")


def canary_tamper_is_detected(mod):
    m = manifest(mod)
    good = mod.seal_state(b"state", m, master_secret=MASTER)
    for off in range(len(good)):
        bad = bytearray(good)
        bad[off] ^= 0x01
        try:
            mod.unseal_state(bytes(bad), m, master_secret=MASTER)
        except mod.SCEError:
            continue
        raise AssertionError(f"tampered byte {off} accepted")


def canary_commitment_is_enforced(mod):
    """Valid AEAD, wrong stored commitment -> only the commitment check refuses."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    m = manifest(mod)
    memh = m.memh()
    salt = os.urandom(mod._SALT_LEN)
    nonce = os.urandom(mod._NONCE_LEN)
    k_enc, _real = mod._derive_key_material(MASTER, memh, 0, b"", salt)
    prefix = mod._HEADER_PREFIX.pack(mod._MAGIC, mod._VERSION, nonce, salt,
                                     os.urandom(mod._COMMIT_LEN))
    ct = AESGCMSIV(k_enc).encrypt(nonce, b"x", mod._aad(prefix, memh, 0))
    env = prefix + mod._CTLEN.pack(len(ct)) + ct
    try:
        mod.unseal_state(env, m, master_secret=MASTER)
    except mod.SCEError:
        return
    raise AssertionError("wrong key commitment accepted")


def canary_aad_is_enforced(mod):
    """Correct key/commitment/nonce, AAD built from a foreign MEMH."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
    m = manifest(mod)
    memh = m.memh()
    other = manifest(mod, numerics_mode="fp16").memh()
    salt = os.urandom(mod._SALT_LEN)
    nonce = os.urandom(mod._NONCE_LEN)
    k_enc, commitment = mod._derive_key_material(MASTER, memh, 0, b"", salt)
    prefix = mod._HEADER_PREFIX.pack(mod._MAGIC, mod._VERSION, nonce, salt, commitment)
    ct = AESGCMSIV(k_enc).encrypt(nonce, b"x", mod._aad(prefix, other, 0))
    env = prefix + mod._CTLEN.pack(len(ct)) + ct
    try:
        mod.unseal_state(env, m, master_secret=MASTER)
    except mod.SCEError:
        return
    raise AssertionError("envelope with a foreign-MEMH AAD accepted")


def canary_commitment_is_unlinkable(mod):
    m = manifest(mod)
    lo = mod._HEADER_PREFIX.size - mod._COMMIT_LEN
    hi = mod._HEADER_PREFIX.size
    a = mod.seal_state(b"s", m, master_secret=MASTER)
    b = mod.seal_state(b"s", m, master_secret=MASTER)
    assert a[lo:hi] != b[lo:hi], "commitment is a stable, linkable tag across seals"


def canary_nonce_and_salt_are_fresh(mod):
    m = manifest(mod)
    a = mod.seal_state(b"s", m, master_secret=MASTER)
    b = mod.seal_state(b"s", m, master_secret=MASTER)
    assert a[5:17] != b[5:17], "nonce is not fresh per seal"
    assert a[17:33] != b[17:33], "salt is not fresh per seal"


def canary_canonicalisation_is_order_independent(mod):
    a = manifest(mod, extra={"alpha": "1", "beta": "2"})
    b = manifest(mod, extra={"beta": "2", "alpha": "1"})
    assert a.memh() == b.memh(), "manifest fingerprint depends on dict insertion order"


def canary_known_answer_vectors(mod):
    with open(VECTORS_PATH, encoding="utf-8") as f:
        vectors = json.load(f)
    for i, case in enumerate(vectors["cases"]):
        man = mod.ModelManifest(**case["manifest"])
        assert man.canonical_bytes().hex() == case["canonical_manifest_hex"], f"case {i} canon"
        assert man.memh().hex() == case["memh_sha3_256_hex"], f"case {i} memh"
        k_enc, commitment = mod._derive_key_material(
            bytes.fromhex(case["master_secret_hex"]), man.memh(), case["epoch_id"],
            case["context_utf8"].encode("utf-8"), bytes.fromhex(case["salt_hex"]),
        )
        assert k_enc.hex() == case["k_enc_hex"], f"case {i} k_enc"
        assert commitment.hex() == case["key_commitment_hex"], f"case {i} commitment"


CANARIES = (
    canary_round_trip,
    canary_wrong_environment_fails_closed,
    canary_tamper_is_detected,
    canary_commitment_is_enforced,
    canary_aad_is_enforced,
    canary_commitment_is_unlinkable,
    canary_nonce_and_salt_are_fresh,
    canary_canonicalisation_is_order_independent,
    canary_known_answer_vectors,
)


# ------------------------------ the mutations ------------------------------ #
# (name, old_source, new_source, functionally_catchable)
MUTATIONS = [
    (
        "disable_commitment_check",
        "commitment_ok = hmac.compare_digest(commit_stored, commit_expected)",
        "commitment_ok = True",
        True,
    ),
    (
        "gut_the_associated_data",
        'return _DOMAIN + b"|hdr|" + header_prefix + memh + epoch_id.to_bytes(8, "big")',
        "return _DOMAIN",
        True,
    ),
    (
        "pin_the_nonce",
        "nonce = os.urandom(_NONCE_LEN)",
        'nonce = b"\\x00" * _NONCE_LEN',
        True,
    ),
    (
        "pin_the_salt",
        "salt = os.urandom(_SALT_LEN)",
        'salt = b"\\x00" * _SALT_LEN',
        True,
    ),
    (
        "drop_epoch_from_kdf_info",
        '        + _lp(epoch_id.to_bytes(8, "big"))\n',
        "",
        True,
    ),
    (
        "drop_domain_separation_from_commitment",
        'commitment = hashlib.sha3_256(_DOMAIN + b"|commit|" + k_com_half).digest()',
        "commitment = hashlib.sha3_256(k_com_half).digest()",
        True,
    ),
    (
        "remove_length_prefixing_in_kdf",
        'return len(b).to_bytes(4, "big") + b',
        "return b",
        True,
    ),
    (
        "remove_manifest_key_sorting",
        "items = sorted(",
        "items = (lambda x, key=None: list(x))(",
        True,
    ),
    (
        "downgrade_constant_time_compare",
        "commitment_ok = hmac.compare_digest(commit_stored, commit_expected)",
        "commitment_ok = (commit_stored == commit_expected)",
        False,   # timing-only: functionally identical, NOT catchable by any canary
    ),
]


def run_canaries(mod):
    """Return the list of canaries that FAILED (i.e. detected the sabotage)."""
    caught_by = []
    for canary in CANARIES:
        try:
            canary(mod)
        except AssertionError:
            caught_by.append(canary.__name__)
        except Exception:  # noqa: BLE001 -- a crash also counts as detection
            caught_by.append(canary.__name__ + " (crashed)")
    return caught_by


def main():
    print(f"\nSabotaging sce/core.py in {len(MUTATIONS)} ways; "
          f"{len(CANARIES)} canaries must catch each one\n" + "-" * 74)
    failures = 0

    # CONTROL. If the UNMUTATED source does not load and pass every canary, then
    # any "CAUGHT" below is meaningless -- the canaries would be firing on a
    # broken harness rather than on the sabotage. This guards against a vacuous
    # green run, which is the failure mode that makes a suite like this dangerous.
    try:
        control = load_mutant(CORE_SRC, "control")
    except Exception as exc:  # noqa: BLE001
        print(f"  CONTROL FAILED TO LOAD ({type(exc).__name__}: {exc}) -- the suite "
              "would report every mutation as caught for the wrong reason.")
        sys.exit(1)
    control_failures = run_canaries(control)
    if control_failures:
        print(f"  CONTROL FAILED canaries {control_failures} on UNMUTATED source -- "
              "the harness is broken, not the code.")
        sys.exit(1)
    print(f"  CONTROL  unmutated core.py passes all {len(CANARIES)} canaries "
          "(the suite is not vacuous)")
    print("-" * 74)

    for name, old, new, catchable in MUTATIONS:
        if CORE_SRC.count(old) < 1:
            print(f"  ERROR {name}: mutation anchor not found in core.py "
                  "(the source moved -- update this suite)")
            failures += 1
            continue
        mutated = CORE_SRC.replace(old, new, 1)
        try:
            mod = load_mutant(mutated, name)
        except Exception as exc:  # noqa: BLE001 -- refusing to import is detection
            print(f"  CAUGHT {name:38s} <- module failed to load ({type(exc).__name__})")
            continue
        caught_by = run_canaries(mod)
        if catchable and caught_by:
            print(f"  CAUGHT {name:38s} <- {', '.join(c[7:] for c in caught_by[:3])}")
        elif catchable and not caught_by:
            failures += 1
            print(f"  SURVIVED {name:36s} !! no canary detected this -- the suite "
                  "has a blind spot")
        elif not catchable and not caught_by:
            print(f"  EXPECTED-SURVIVOR {name:27s} (timing-only; guarded statically "
                  "in test_hardening.py)")
        else:
            print(f"  NOTE  {name:38s} unexpectedly caught by "
                  f"{', '.join(c[7:] for c in caught_by[:2])}")
    print("-" * 74)
    if failures:
        print(f"{failures} sabotage(s) went undetected -- the test suite is not "
              "strong enough.\n")
        sys.exit(1)
    print("Every functionally-detectable sabotage was caught by the suite.\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
