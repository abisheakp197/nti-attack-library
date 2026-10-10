# NTI Attack Library vs Existing Work

## Table 1: Positioning

| Existing | NTI Attack Library |
|---|---|
| **OWASP AI**: general guidance | Dilithium5-signed, machine-readable |
| **MITRE ATLAS**: threat model only | Live API + federation-mirrorable |
| **NIST AI RMF**: framework | Consumed directly by nti-scanner rules |
| Static docs | Federated — anyone can mirror |
| No provenance | Every entry cryptographically signed |
| English only | JSON + YAML + MD |

## Table 2: Attack Database Model

| CVE / NVD / OWASP | NTI Attack Library |
|---|---|
| Human-curated by central authority | Federated — any node contributes |
| Prose descriptions | Signed, machine-executable PoCs |
| No cryptographic proof | Every attack Dilithium5-signed |
| No link to detection | Every attack maps to an nti-scanner rule |
| Single vendor holds it | Anyone can mirror, verify offline |
| Published once, edited silently | Append-only with signed history |

## What No Other System Has

1. **Executable attacks, not documents.** MITRE publishes PDFs. Ours are Python
classes you run.
2. **Framework-agnostic adapters.** One attack runs against LangChain, CrewAI, A
utoGen, MAF, HTTP, or a plain callable.
3. **Signed attestations.** Every test run produces a Dilithium5-signed report v
erifiable offline.
4. **Detection-rule binding.** Every attack links to a specific nti-scanner rule
. Offense and defense are coupled.
5. **Federated contributions.** No gatekeeper. Any node can host. Any contributo
r can submit. Signatures are the only authority.
6. **Append-only history.** Every change is a new signed artifact. Nobody can ed
it a past attack silently.
7. **Consumer-ready.** nti-scanner, CI pipelines, insurers, and auditors can all
 consume the JSON directly.

## What This Means

Before NTI: "Prove your AI agent is safe" was answered with a PDF.
After NTI: it is answered with a signed, offline-verifiable attack report bound
to a specific commit.

That is what makes this the first insurance-grade attack framework for AI agents
.
