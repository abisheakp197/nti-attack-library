# NTI Attack Library — Full Audit Report

## Summary
- Total issues found: 5
- Critical: 0
- High: 1
- Medium: 1
- Low: 3

## Category 1: API Mismatch
No issues found.
- Checked `nti_attack/signing.py`: `PqcKeyPair` constructor `PqcKeyPair()` and `key.sign(message)` returning hex string directly match the `ube_foundation` API specification.
- Checked `TrustEngine`: No mismatched calls found in codebase.

## Category 2: Import Errors
No issues found.
- Verified `from ube_foundation import PqcKeyPair` in `nti_attack/signing.py` resolves to valid `ube_foundation` module.
- Verified all internal module import paths in `nti_attack`, `cli`, `attacks`, and `tests`.
- Verified no circular imports exist.

## Category 3: Type Mismatch
No issues found.
- Verified string and bytes conversions: `_canonical_bytes` produces `bytes` via `encode("utf-8")`, which is passed to `key.sign(message: bytes)`.
- Verified no `.hex()` calls on string return values.

## Category 4: Exception Handling
### Finding 4.1 [LOW]
- File: `nti_attack/adapters/http_adapter.py`
- Line: 33
- Issue: Bare `except:` in `reset()` silently swallows all exceptions without specific exception handling or logging.
- Fix: `except httpx.HTTPError:`

### Finding 4.2 [LOW]
- File: `attacks/_registry.py`
- Line: 17, 34
- Issue: Broad `except Exception:` swallows module import and attack class instantiation failures without logging or narrow exception types.
- Fix: Catch `(ImportError, AttributeError, TypeError)` specifically.

## Category 5: Dependency Declaration
### Finding 5.1 [HIGH]
- File: `pyproject.toml`
- Line: 8
- Issue: `ube-foundation` is required at runtime by `nti_attack/signing.py` (`from ube_foundation import PqcKeyPair`) but is missing from `dependencies` in `pyproject.toml`.
- Fix: Add `"ube-foundation>=0.1.0"` to `dependencies` list in `pyproject.toml`.

## Category 6: Test Quality
### Finding 6.1 [LOW]
- File: `tests/failure/test_cold_start.py`
- Line: 14
- Issue: Unconditional `assert True` assertion used at the end of import test.
- Fix: `assert nti_attack is not None`

## Category 7: Security
### Finding 7.1 [MEDIUM]
- File: `nti_attack/signing.py`
- Line: 36
- Issue: `sign_payload()` generates a Dilithium5 signature (`key.sign(message)`), but `verify_cert_integrity()` only checks `compute_cert_hash(payload) == payload["cert_hash"]`, leaving the signature unverified.
- Fix: Ensure `verify_cert_integrity()` or attestation verification validates signature integrity alongside `cert_hash`.

## Category 8: Crypto Correctness
No issues found.
- Verified canonical JSON formatting (`json.dumps(..., sort_keys=True)`) is consistently used for payload hashing.
- Verified `issuer_pubkey` is set in the canonical payload before computing `cert_hash` and Dilithium5 signature.

## Category 9: Logic Bugs
No issues found.
- Checked for mutable default arguments (`def f(x=[])`), reversed boolean logic, off-by-one errors, and shadowed variables. None found.

## Category 10: Build/Packaging
No issues found.
- Verified `pyproject.toml` contains `[project]` table with name, version, requires-python, dependencies, and `[project.scripts]`.
- Verified package discovery (`tool.setuptools.packages.find`) matches directory structure (`nti_attack*`, `attacks*`, `cli*`).
- Verified `README.md` and `LICENSE` files are present.

## Non-issues verified
- `nti_attack/signing.py` PqcKeyPair API usage (`PqcKeyPair()` constructor, `key.sign(message)` returning hex string).
- Canonical byte encoding (`encode("utf-8")`) and hashlib SHA256 digest handling.
- CLI entrypoint binding `cli.main:main` in `pyproject.toml`.
- Attack registry auto-discovery mechanics in `attacks/_registry.py`.
