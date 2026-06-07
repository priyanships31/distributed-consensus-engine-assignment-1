# Distributed Consensus Engine


A production-grade distributed state machine implementing **Basic Paxos** (crash-fault tolerance) and **PBFT** (Byzantine-fault tolerance) across a 6-container Docker cluster, with full chaos testing via Toxiproxy.

---

## Repository Structure

```
distributed-consensus-engine/
├── src/
│   ├── node.py           # Main daemon — Leader Election, Paxos, PBFT
│   ├── adversary.py      # Byzantine adversary node (subclasses Node)
│   ├── client.py         # Concurrent transaction generator
│   └── crypto_utils.py   # RSA-2048 key generation, signing, verification
├── tests/
│   └── chaos_test.sh     # Toxiproxy fault injection — 9 chaos scenarios
├── data/                 # Ledger files (populated at runtime)
├── keys/                 # RSA key pairs (populated at runtime)
├── Dockerfile            # Two-stage Python 3.14 build
├── docker-compose.yml    # 5 honest nodes + 1 adversary + client + Toxiproxy
├── requirements.txt      # cryptography, requests, pytest
└── README.md
```

---

## Architecture Overview

The system runs **5 honest consensus nodes** (node1–node5) plus **1 Byzantine adversary** (node6), all orchestrated via Docker Compose on a shared bridge network. All inter-node communication uses raw TCP sockets with Python `asyncio`. No external message broker is used.

```
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│  node1  │  │  node2  │  │  node3  │  │  node4  │  │  node5  │
│  :5001  │◄─│  :5002  │◄─│  :5003  │◄─│  :5004  │◄─│  :5005  │
└────▲────┘  └────▲────┘  └────▲────┘  └────▲────┘  └────▲────┘
     └─────────────┴─────────────┴─────────────┴──────────┘
                                 │
              ┌──────────────────┤──────────────┐
              │                  │              │
       ┌──────▼──────┐    ┌──────▼──────┐ ┌────▼─────┐
       │  Toxiproxy  │    │   client    │ │  node6   │
       │  REST :8474 │    │ tx generator│ │adversary │
       └─────────────┘    └─────────────┘ └──────────┘
```

Two operational modes are supported, switchable via `MODE` environment variable:

| Mode | Protocol | Fault Model | Max Faults | Quorum |
|------|----------|-------------|------------|--------|
| A | Bully Election + Basic Paxos | Crash faults | f = 2 | ⌊n/2⌋ + 1 = 3 |
| B | Bully Election + PBFT | Byzantine faults | f = 1 | 2f + 1 = 3 |

---

## Protocol Details

### 1. Leader Election — Bully Algorithm

- Each node sends **heartbeats every 1 second** when it is the leader
- Followers declare the leader dead after **3 seconds** of no heartbeat and start an election
- A candidate sends `ELECTION` only to nodes with **higher IDs**; if none respond within 5 seconds it declares itself leader via `LEADER_ANNOUNCE`
- **Anti-split-brain:** nodes only accept `LEADER_ANNOUNCE` from IDs in their known peer list — fake announcements from the adversary are rejected with a warning log
- The highest-ID honest node (node5) wins in a clean election

### 2. Mode A — Basic Paxos

```
Phase 1 — Prepare / Promise
  Leader  →  PREPARE(slot, proposal_id)  →  All peers
  Acceptor →  PROMISE(slot, highest_accepted)  →  Leader
  (On NACK: bump proposal_id and retry)

Phase 2 — Accept / Accepted
  Leader  →  ACCEPT(slot, value)  →  All peers
  Acceptor →  ACCEPTED(slot, value)  →  Leader
  (On quorum of ACCEPTED: write to /data/ledger_node_N.jsonl)
```

- Transactions are written to disk **only after a quorum of ACCEPTED messages**
- Tolerates up to **f = 2** simultaneous node crashes in a 5-node cluster
- Proposal IDs are `(counter, node_id)` tuples — globally unique and totally ordered

### 3. Mode B — PBFT

```
PRE-PREPARE  (Primary only)
  Primary  →  {view, seq, digest, request, RSA-sig}  →  All replicas

PREPARE  (All replicas)
  Replica  →  {view, seq, digest, RSA-sig}  →  All replicas
  (After 2f+1 matching PREPARE votes → enter COMMIT phase)

COMMIT  (All replicas)
  Replica  →  {view, seq, digest, RSA-sig}  →  All replicas
  (After 2f+1 COMMIT votes → write to ledger)
```

- Every message carries an **RSA-PSS / SHA-256 signature**
- Receivers verify signatures via the sender's public key; invalid signatures are **silently dropped**
- The digest `d(m)` is a SHA-256 hash of the canonical JSON request
- Tolerates up to **f = 1** Byzantine node (system requires n ≥ 3f + 1 = 4; we have 5 honest)

### 4. Byzantine Adversary (node6)

Six concurrent attack behaviours, all configurable via environment variables:

| # | Behaviour | Env Var | What it does |
|---|-----------|---------|--------------|
| 1 | Message Suppression | `ADV_SUPPRESS_RATE` | Drops PREPARE/COMMIT to random peer subsets |
| 2 | Equivocation | `ADV_EQUIVOCATE` | Sends different digests to different peer halves |
| 3 | Signature Forgery | `ADV_FORGE_SIG` | Corrupts RSA signatures — rejected by honest nodes |
| 4 | Paxos Poisoning | `ADV_POISON_PAXOS` | Fabricates high-ballot PROMISE in Mode A |
| 5 | Fake Leader | `ADV_FAKE_LEADER` | Broadcasts LEADER_ANNOUNCE every 10s — blocked |
| 6 | Commit Suppression | `ADV_COMMIT_SUPPRESS` | Never sends COMMIT votes |

**Defence:** honest nodes filter `LEADER_ANNOUNCE` / `HEARTBEAT` against their peer list. PBFT signature verification neutralises Behaviours 1–3 and 6.

---

## Cryptography

- Each node generates an **RSA-2048 key pair** on first boot and saves it to `/keys/node_<id>_priv.pem` + `node_<id>_pub.pem` (Docker volume — persists across restarts)
- Public keys are exchanged via `KEY_EXCHANGE` messages at boot time
- All PBFT messages are signed with **RSA-PSS / SHA-256** using Python's `cryptography` library
- **HMAC-SHA256** is used for fast cluster-internal heartbeat authentication (`CLUSTER_HMAC_SECRET`)
- `crypto_utils.py` exposes `KeyStore`, `MessageSigner`, `HMACAuthenticator`, `DigestUtils`, and `KeyRing` as standalone reusable classes

---

## Quick Start

### Prerequisites

- Docker ≥ 24.0
- Docker Compose v2 (comes with Docker Desktop)
- Python 3.14+ (for local development only)

### Clone and run

```bash
git clone https://github.com/priyanships31/distributed-consensus-engine-assignment-1.git
cd distributed-consensus-engine-assignment-1

# Create required runtime directories
mkdir -p data keys

# Start the full cluster in Mode B (PBFT) — default
docker compose up --build

# OR start in Mode A (Paxos)
MODE=A docker compose up --build
```

### Verify it's working

In a second terminal:

```bash
# Check leader status and committed ledger
echo '{"type":"STATUS","from":0}' | nc localhost 5005

# Watch ledger entries accumulating
docker exec node5 tail -f /data/ledger_node_5.jsonl

# Confirm adversary is being blocked
docker logs node1 2>&1 | grep "Ignoring"

# Check RSA keys were generated
ls keys/
```

### Expected output after ~15 seconds

```
node5 | *** Node 5 is now the LEADER ***
node1 | Ignoring LEADER_ANNOUNCE from unknown/adversary node 6
node5 | [PBFT] Committed seq=1 slot=0
node5 | [PBFT] Committed seq=2 slot=1
...
```

### Stop

```bash
docker compose down
```

---

## Chaos Testing

`tests/chaos_test.sh` uses the Toxiproxy REST API to inject 9 fault scenarios while the client continuously submits transactions:

| Scenario | Fault injected | Assertion |
|----------|---------------|-----------|
| 0 | Warm-up | Leader elected within 20s |
| 1 | Baseline (no faults) | ≥ 95% success rate |
| 2 | Single non-leader crash | Cluster continues at ≥ 80% |
| 3 | 800ms latency + 200ms jitter | Consensus progresses at ≥ 65% |
| 4 | Node4 all links blackholed | Majority continues at ≥ 60% |
| 5 | Network partition {1,2} \| {3,4,5} | No split-brain after heal |
| 6 | Leader crash → re-election | New leader within 20s |
| 7 | Double crash (max f=2) | Ledger consistent after restore |
| 8 | Byzantine adversary active | No poisoned txns in honest ledgers |
| 9 | Full recovery | ≥ 90% success, all ledgers consistent |

```bash
# Run chaos tests against the live cluster
docker compose exec client bash /app/tests/chaos_test.sh --mode B

# Quick run (shorter sleep intervals)
docker compose exec client bash /app/tests/chaos_test.sh --mode B --quick
```

---

## Configuration Reference

All parameters are set via environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `MODE` | `B` | `A` = Paxos, `B` = PBFT |
| `KEY_DIR` | `/keys` | RSA key pair storage directory |
| `CLUSTER_HMAC_SECRET` | — | Shared HMAC secret for heartbeat auth |
| `ADV_SUPPRESS_RATE` | `0.65` | Probability of message suppression (adversary) |
| `ADV_EQUIVOCATE` | `true` | Enable equivocation attack |
| `ADV_FORGE_SIG` | `true` | Enable signature forgery |
| `ADV_POISON_PAXOS` | `true` | Enable Paxos promise poisoning |
| `ADV_FAKE_LEADER` | `true` | Enable fake leader announcements |
| `ADV_COMMIT_SUPPRESS` | `true` | Enable commit suppression |
| `ADV_FAKE_LEADER_INTERVAL` | `10` | Seconds between fake leader broadcasts |

---

## Ledger Format

Each node maintains an append-only ledger at `/data/ledger_node_N.jsonl`. Entries are written **only after consensus is reached**:

```json
{"slot": 0, "value": {"tx_id": "e75aa9f0-...", "tx_type": "WITHDRAW", "from_account": "ACC0007", "to_account": "ACC0008", "amount": 6834.0, "currency": "INR"}, "ts": 1780850910.728}
{"slot": 1, "value": {"tx_id": "5dd7afd9-...", "tx_type": "QUERY",    "from_account": "ACC0010", "to_account": "ACC0002", "amount": 5918.39, "currency": "INR"}, "ts": 1780850911.235}
```

The running system committed **237+ ledger entries** across multiple client runs, demonstrating sustained PBFT consensus under adversarial conditions.

---

## Proof of Execution

The `data/` folder in this repository contains live ledger output captured from the running cluster demonstrating:

- Continuous transaction commitment via PBFT (slots 0–237+)
- Adversary node6 actively attacking (fake leader, equivocation, signature forgery)
- All honest nodes (1–5) rejecting adversary messages and maintaining correct state

Key log evidence:
```
node1 | [CryptoManager[1]] Generated new key pair → /keys
node5 | *** Node 5 is now the LEADER ***
node1 | Ignoring LEADER_ANNOUNCE from unknown/adversary node 6
node6 | [ADV] FAKE_LEADER – broadcasting self (6) as leader
node5 | [PBFT] Committed seq=100 slot=99
```

---

## Dependencies

```
cryptography>=42.0.8   # RSA-PSS signing, key serialisation
requests>=2.32.3       # HTTP (Toxiproxy REST API calls)
pytest>=8.2.2          # Testing framework
pytest-asyncio>=0.23.7 # Async test support
```


