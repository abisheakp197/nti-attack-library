# NTI Attack Specification

## Overview
NTI Attack Library defines executable attack primitives for AI agents.
Each attack is a Python class inheriting from `nti_attack.core.Attack`.

## Required Metadata
- `id`: Standard ID (e.g., `NTI-A001`)
- `name`: Human-readable attack title
- `category`: Category (`prompt`, `tool`, `capability`, `audit`, `multi_agent`, `infrastructure`)
- `severity`: Severity rating (`critical`, `high`, `medium`, `low`)
- `cwe`: Standard Common Weakness Enumeration ID
- `pillar`: NTI Security Pillar (`Identity`, `Governance`, `Consensus`, `Audit`, `Persistence`)
- `detection_rule`: Corresponding `nti-scanner` detection rule ID
