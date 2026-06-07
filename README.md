# Distributed Consensus Engine

A production-grade distributed state machine implementing both **Paxos** (crash-fault tolerance) and **PBFT** (Byzantine-fault tolerance) across a 6-node Docker cluster with full chaos testing via Toxiproxy.

---

## Architecture Overview

The system runs a 5-node honest cluster plus 1 Byzantine adversary node, orchestrated via Docker Compose. All inter-node communication uses raw TCP sockets with `asyncio`. Two operational modes are supported:

| Mode | Protocol | Fault Model | Max Faults |
|------|----------|-------------|------------|
| A | Bully Election + Basic Paxos | Crash faults | f = 2 |
| B | Bully Election + PBFT | Byzantine faults | f = 1 |

### Component Diagram

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│  node1  │   │  node2  │   │  node3  │   │  node4  │   │  node5  │
│  :5001  │◄──│  :5002  │◄──│  :5003  │◄──│  :5004  │◄──│  :5005  │
└────▲────┘   └────▲────┘   └────▲────┘   └────▲────┘   └────▲────┘
     │              │              │              │              │
     └──────────────┴──────────────┴──────────────┴─────────────┘
                                   │
                            ┌──────▼──────┐        ┌──────────┐
                            │  Toxiproxy  │        │  node6   │
                            │    :8474    │        │ adversary│
                            └─────────────┘        └──────────┘
                                   │
                            ┌──────▼──────┐
                            │   client    │
                            └─────────────┘
```

---

## File Structure

```
distributed-consensus-engine/
├── src/
│   ├── node.py           # Main daemon — Leader Election, Paxos, PBFT
│   ├── adversary.py      # Byzantine adversary node (subclasses Node)
│   ├── client.py         # Concurrent transaction generator
│   └── crypto_utils.py   # RSA key generation and message signing
├── tests/
│   └── chaos_test.sh     # Toxiproxy fault injection script
├── Dockerfile
├── docker-compose.yml    # 5 honest nodes + 1 adversary + Toxiproxy + client
├── requirements.txt
└── README.md
```

---

## Protocol Details

### Leader Election (Bully Algorithm)
- Each node broadcasts heartbeats every 1 second when it is the leader
- Followers timeout after 3 seconds of missing heartbeats and trigger an election
- A candidate sends `ELECTION` to all nodes with higher IDs; if none respond within 5 seconds, it declares itself leader via `LEADER_ANNOUNCE`
- Prevents split-brain: a node yields leadership if it receives `ELECTION_OK` from a higher-ID peer

### Mode A — Basic Paxos
- **Phase 1 (Prepare/Promise):** Leader sends `PREPARE(slot, proposal_id)` to all peers; acceptors reply with `PROMISE` or `NACK`
- **Phase 2 (Accept/Accepted):** On quorum of promises, leader sends `ACCEPT(slot, value)`; acceptors log and reply `ACCEPTED`
- Transactions are written to disk (`/data/ledger_node_N.jsonl`) only after a quorum of `ACCEPTED` messages
- Tolerates up to **f = 2** simultaneous node crashes in a 5-node cluster

### Mode B — PBFT
- **Pre-prepare:** Primary broadcasts request with RSA-2048 signature and SHA-256 digest
- **Prepare:** Each replica verifies signature, checks digest consistency, and broadcasts its own signed `PREPARE`
- **Commit:** On 2f+1 prepare votes, each replica broadcasts `COMMIT`; on 2f+1 commit votes, the transaction is committed to ledger
- All messages carry RSA-PSS signatures; invalid signatures are silently dropped
- Tolerates up to **f = 1** Byzantine node in a 5-node cluster (requires n ≥ 3f+1)

### Byzantine Adversary (node6)
Six concurrent attack behaviours, all configurable via environment variables:

| Behaviour | Env Var | Description |
|-----------|---------|-------------|
| Message Suppression | `ADV_SUPPRESS_RATE` | Randomly drops PREPARE/COMMIT to subsets of peers |
| Equivocation | `ADV_EQUIVOCATE` | Sends different digests to different peer halves |
| Signature Forgery | `ADV_FORGE_SIG` | Corrupts RSA signatures on outgoing messages |
| Paxos Poisoning | `ADV_POISON_PAXOS` | Fabricates high-ballot PROMISE to hijack Proposer |
| Fake Leader | `ADV_FAKE_LEADER` | Periodically claims itself as leader |
| Commit Suppression | `ADV_COMMIT_SUPPRESS` | Never forwards COMMIT messages |

---

## Quick Start

### Prerequisites
- Docker >= 24.0
- Docker Compose v2

### Setup

```bash
git clone https://github.com/priyanships31/distributed-consensus-engine-assignment-1.git
cd distributed-consensus-engine-assignment-1
mkdir -p data keys
```

### Run Mode B (PBFT) — Default

```bash
docker compose up --build
```

### Run Mode A (Paxos)

```bash
MODE=A docker compose up --build
```

### Stop

```bash
docker compose down
```

---

## Chaos Testing

The `chaos_test.sh` script uses Toxiproxy's REST API to inject network faults at runtime while the client continuously submits transactions:

```bash
# Run inside the cluster (after compose up)
docker exec node1 bash /app/tests/chaos_test.sh
```

Faults injected include latency spikes, packet loss, and full network partitions between node pairs. The system is expected to maintain consensus throughout.

---

## Cryptography

- Each node generates a fresh **RSA-2048** key pair on startup
- Public keys are exchanged via `KEY_EXCHANGE` messages at boot
- All PBFT messages (Pre-prepare, Prepare, Commit) are signed with **RSA-PSS / SHA-256**
- The adversary's forged signatures are detected and dropped by honest nodes
- HMAC-SHA256 is used for cluster-internal authentication (`CLUSTER_HMAC_SECRET`)

---

## Configuration

All parameters are set via environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `MODE` | `B` | `A` for Paxos, `B` for PBFT |
| `KEY_DIR` | `/keys` | Directory for key storage |
| `CLUSTER_HMAC_SECRET` | — | Shared HMAC secret |
| `ADV_SUPPRESS_RATE` | `0.65` | Probability of message suppression |
| `ADV_FAKE_LEADER_INTERVAL` | `10` | Seconds between fake leader announcements |

---

## Ledger

Each node maintains an append-only transaction ledger at `/data/ledger_node_N.jsonl`. Entries are written only after consensus is reached:

```json
{"slot": 0, "value": {"tx": "tx_001", "amount": 42}, "ts": 1717123456.789}
{"slot": 1, "value": {"tx": "tx_002", "amount": 17}, "ts": 1717123457.001}
```

---

## Dependencies

```
cryptography
requests
pytest
pytest-asyncio
```

---

## Course Info

**Indian Institute of Technology Jodhpur**
Fundamentals of Distributed Systems — Assignment 1
Total Marks: 20 (Question 1)
