# NTI Attack Library Federation

## Model

Any node can host a mirror. Nodes sync attacks from each other. No master node.
No central authority.

## Node Endpoints

- GET /api/attacks — list all attack IDs on this node
- GET /api/attack?id=X — fetch one attack's full definition
- GET /api/manifest — node metadata + signature

## Sync Protocol

A node syncs from another by:
1. GET /api/attacks to list IDs
2. For each ID not present locally, GET /api/attack?id=X
3. Verify the attack's signature (Dilithium5)
4. Store the verified attack

## Trust Model

Nodes do not trust each other. Every attack is signed by its contributor. Nodes
forward, never vouch.

## Why This Beats MITRE

- MITRE has one authoritative source. Ours has many.
- Ours cannot be shut down.
- Ours cannot be poisoned — signatures break on tamper.
- Ours cannot be edited retroactively — every change is a new signed artifact.

## Bounties

The NTI Foundation maintains a public bounty board. Top contributors earn signed
 recognition. Reputation is provable, not claimed.
