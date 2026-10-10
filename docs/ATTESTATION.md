# Attestation Protocol

## Attestation Format
Report specifications follow `NTI-Attack-Report/1`.

Reports contain cryptographic proof signed via post-quantum signature schemes (Dilithium5).

## Verification
Reports can be verified offline via:
```bash
nti-attack verify path/to/report.json
```
Verification checks message integrity against `cert_hash` and validates the resistance score calculation.
