# Contributing to NTI Attack Library

## Adding a New Attack
1. Create a subclass of `nti_attack.core.Attack` in the appropriate category under `attacks/`.
2. Ensure all required metadata fields (`id`, `name`, `category`, `severity`, `cwe`, `pillar`, `detection_rule`) are set.
3. Implement `build_payload()`, `check(response, adapter)`, and `remediation()`.
4. Run tests with `pytest`.
