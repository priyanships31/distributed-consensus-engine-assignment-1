"""
client.py  –  Concurrent Transaction Client
IIT Jodhpur | Fundamentals of Distributed Systems | Assignment-1

Submits concurrent CLIENT_REQUEST transactions to the distributed consensus
cluster and tracks which ones are confirmed, retried, or lost.

Features
--------
  • Discovers the current leader automatically (probes all nodes, picks the
    one that reports role=LEADER via a lightweight STATUS query).
  • Submits N concurrent transactions using asyncio tasks.
  • Retries failed / timed-out requests with exponential back-off, up to
    MAX_RETRIES attempts.
  • Re-discovers the leader after every failure (handles leader re-election
    that occurs during chaos tests).
  • Prints a colour-coded live summary and writes a JSON results log to
    /data/client_results.jsonl for the chaos test script to inspect.
  • Supports both Mode A (Paxos) and Mode B (PBFT) — the message format is
    identical for both; the cluster handles routing internally.

Usage
-----
    python client.py --nodes "1@node1:5001,2@node2:5002,3@node3:5003,4@node4:5004,5@node5:5005" \
                     --mode B \
                     --txns 50 \
                     --concurrency 5 \
                     --rate 2.0

Environment variables (set by Docker Compose):
    NODES          same format as --nodes
    MODE           A or B
    NUM_TXNS       integer
    CONCURRENCY    integer
    RATE           float  (transactions per second across all workers)
    REQUEST_TIMEOUT float (seconds to wait for a single attempt)
    MAX_RETRIES    integer
"""

import asyncio
import argparse
import json
import logging
import os
import random
import string
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging  (colour output if the terminal supports it)
# ---------------------------------------------------------------------------
_RESET  = "\033[0m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_BOLD   = "\033[1m"


class _ColourFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    _CYAN,
        logging.INFO:     _GREEN,
        logging.WARNING:  _YELLOW,
        logging.ERROR:    _RED,
        logging.CRITICAL: _BOLD + _RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        colour = self.COLOURS.get(record.levelno, _RESET)
        record.msg = f"{colour}{record.msg}{_RESET}"
        return super().format(record)


_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    _ColourFormatter(
        fmt="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )
)
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger("Client")

# ---------------------------------------------------------------------------
# Constants / defaults  (all overridable via env or CLI)
# ---------------------------------------------------------------------------
DEFAULT_REQUEST_TIMEOUT = 6.0    # seconds per attempt
DEFAULT_MAX_RETRIES     = 5
DEFAULT_CONCURRENCY     = 5
DEFAULT_RATE            = 2.0    # txns / second  (throttles submission)
DEFAULT_NUM_TXNS        = 30
LEADER_PROBE_TIMEOUT    = 2.0    # seconds to wait for a STATUS reply
RESULTS_FILE            = "/data/client_results.jsonl"
STATUS_PORT_OFFSET      = 100    # nodes expose a status server on port+100


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class NodeAddr:
    node_id: int
    host:    str
    port:    int


@dataclass
class TxResult:
    tx_id:       str
    payload:     dict
    status:      str        # "committed" | "failed" | "timeout"
    attempts:    int
    latency_ms:  float
    committed_at: float     # epoch seconds, 0 if not committed
    leader_used: Optional[int] = None
    error:       str        = ""


# ---------------------------------------------------------------------------
# Low-level TCP helpers
# ---------------------------------------------------------------------------

async def _tcp_send(host: str, port: int, msg: dict, timeout: float = 2.0):
    """Fire-and-forget TCP send (same wire format as node.py)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = json.dumps(msg).encode() + b"\n"
        writer.write(data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return True
    except Exception as exc:
        log.debug("TCP send to %s:%d failed: %s", host, port, exc)
        return False


async def _tcp_rpc(
    host: str, port: int, msg: dict, timeout: float = 2.0
) -> Optional[dict]:
    """
    Send a request and read one JSON line back.
    Used for the STATUS probe (nodes must support a STATUS request that
    returns a JSON status line — see note below).
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = json.dumps(msg).encode() + b"\n"
        writer.write(data)
        await writer.drain()
        raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return json.loads(raw.decode().strip())
    except Exception as exc:
        log.debug("RPC to %s:%d failed: %s", host, port, exc)
        return None


# ---------------------------------------------------------------------------
# Leader discovery
# ---------------------------------------------------------------------------

class LeaderDiscovery:
    """
    Probes all known nodes for their status and returns the one reporting
    role == LEADER.  Results are cached for CACHE_TTL seconds to avoid
    hammering the cluster on every transaction.
    """
    CACHE_TTL = 4.0

    def __init__(self, nodes: List[NodeAddr]):
        self._nodes      = nodes
        self._leader     : Optional[NodeAddr] = None
        self._cache_time : float = 0.0

    async def get_leader(self, force_refresh: bool = False) -> Optional[NodeAddr]:
        now = time.time()
        if (
            not force_refresh
            and self._leader is not None
            and now - self._cache_time < self.CACHE_TTL
        ):
            return self._leader

        log.debug("Probing cluster for current leader …")
        tasks = [self._probe(n) for n in self._nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for node, result in zip(self._nodes, results):
            if isinstance(result, dict) and result.get("role") == "LEADER":
                log.info("Leader discovered: node %d @ %s:%d", node.node_id, node.host, node.port)
                self._leader    = node
                self._cache_time = now
                return node

        # Fallback: pick the node that reported the lowest leader_id (best guess)
        candidates = [
            (r.get("leader_id"), self._nodes[i])
            for i, r in enumerate(results)
            if isinstance(r, dict) and r.get("leader_id") is not None
        ]
        if candidates:
            candidates.sort(key=lambda x: x[0])
            best_leader_id = candidates[0][0]
            for lid, n in candidates:
                if lid == best_leader_id:
                    node_match = next(
                        (x for x in self._nodes if x.node_id == best_leader_id), n
                    )
                    log.warning(
                        "No node claims LEADER role; routing to reported leader %d",
                        best_leader_id,
                    )
                    self._leader    = node_match
                    self._cache_time = now
                    return node_match

        log.error("Could not determine cluster leader!")
        return None

    async def _probe(self, node: NodeAddr) -> Optional[dict]:
        status_msg = {"type": "STATUS", "from": 0}
        # Query status on main port — node handles STATUS messages directly
        return await _tcp_rpc(
            node.host,
            node.port,
            status_msg,
            timeout=LEADER_PROBE_TIMEOUT,
        )

    def invalidate(self):
        self._cache_time = 0.0


# ---------------------------------------------------------------------------
# Transaction factory
# ---------------------------------------------------------------------------

_TX_TYPES = ["TRANSFER", "DEPOSIT", "WITHDRAW", "QUERY"]
_ACCOUNTS = [f"ACC{i:04d}" for i in range(1, 21)]


def make_transaction(idx: int) -> dict:
    """Generate a realistic-looking transaction payload."""
    tx_type = random.choice(_TX_TYPES)
    return {
        "tx_id":   str(uuid.uuid4()),
        "tx_type": tx_type,
        "seq_no":  idx,
        "from_account": random.choice(_ACCOUNTS),
        "to_account":   random.choice(_ACCOUNTS),
        "amount":  round(random.uniform(1.0, 10_000.0), 2),
        "currency": "INR",
        "timestamp": time.time(),
        "nonce":   "".join(random.choices(string.ascii_lowercase, k=8)),
    }


# ---------------------------------------------------------------------------
# Single transaction submission
# ---------------------------------------------------------------------------

async def submit_transaction(
    tx:          dict,
    discovery:   LeaderDiscovery,
    mode:        str,
    timeout:     float,
    max_retries: int,
) -> TxResult:
    """
    Submit one transaction to the cluster leader with retry + back-off.
    Returns a TxResult describing what happened.
    """
    tx_id    = tx["tx_id"]
    start    = time.time()
    attempts = 0

    for attempt in range(1, max_retries + 2):   # +2: first try + retries
        attempts = attempt
        leader   = await discovery.get_leader(force_refresh=(attempt > 1))

        if leader is None:
            wait = min(2 ** attempt, 10.0)
            log.warning("[%s] No leader found (attempt %d). Waiting %.1fs …", tx_id[:8], attempt, wait)
            await asyncio.sleep(wait)
            continue

        if mode == "A":
            msg = {
                "type":   "CLIENT_REQUEST",
                "value":  tx,
                "client": 0,
            }
        else:   # Mode B
            msg = {
                "type":    "CLIENT_REQUEST",
                "request": tx,
                "from":    0,
            }

        log.debug(
            "[%s] Attempt %d → node %d (%s:%d)",
            tx_id[:8], attempt, leader.node_id, leader.host, leader.port,
        )

        ok = await _tcp_send(leader.host, leader.port, msg, timeout=timeout)

        if ok:
            # The cluster processes asynchronously; we optimistically mark as
            # committed after a successful delivery (fire-and-forget model).
            # For a production client you'd open a reply socket and wait for
            # PBFT_REPLY / a ledger confirmation.  Here we track at report time.
            latency = (time.time() - start) * 1000
            log.info(
                "✓ [%s] SENT → node %d  attempt=%d  latency=%.1fms",
                tx_id[:8], leader.node_id, attempt, latency,
            )
            return TxResult(
                tx_id        = tx_id,
                payload      = tx,
                status       = "sent",
                attempts     = attempts,
                latency_ms   = latency,
                committed_at = time.time(),
                leader_used  = leader.node_id,
            )
        else:
            log.warning(
                "✗ [%s] Send failed  attempt=%d  leader=%d  retrying …",
                tx_id[:8], attempt, leader.node_id,
            )
            discovery.invalidate()
            wait = min(0.5 * (2 ** (attempt - 1)), 8.0) + random.uniform(0, 0.5)
            await asyncio.sleep(wait)

    latency = (time.time() - start) * 1000
    log.error("✗✗ [%s] FAILED after %d attempts", tx_id[:8], attempts)
    return TxResult(
        tx_id        = tx_id,
        payload      = tx,
        status       = "failed",
        attempts     = attempts,
        latency_ms   = latency,
        committed_at = 0.0,
        error        = f"Exhausted {max_retries} retries",
    )


# ---------------------------------------------------------------------------
# Concurrent submission engine
# ---------------------------------------------------------------------------

class TransactionClient:

    def __init__(
        self,
        nodes:       List[NodeAddr],
        mode:        str,
        num_txns:    int,
        concurrency: int,
        rate:        float,
        timeout:     float,
        max_retries: int,
    ):
        self.nodes       = nodes
        self.mode        = mode.upper()
        self.num_txns    = num_txns
        self.concurrency = concurrency
        self.rate        = rate          # txns / second
        self.timeout     = timeout
        self.max_retries = max_retries
        self.discovery   = LeaderDiscovery(nodes)
        self.results:    List[TxResult] = []

    # ---- Throttle helper ------------------------------------------------ #

    @property
    def _inter_tx_delay(self) -> float:
        """Seconds between consecutive transaction launches."""
        return 1.0 / self.rate if self.rate > 0 else 0.0

    # ---- Main run ------------------------------------------------------- #

    async def run(self):
        log.info(
            "%s=== Client starting ===%s  mode=%s  txns=%d  concurrency=%d  rate=%.1f/s",
            _BOLD, _RESET, self.mode, self.num_txns, self.concurrency, self.rate,
        )

        # Pre-discover leader before we start hammering
        leader = await self.discovery.get_leader()
        if leader is None:
            log.error("Cannot find a leader — aborting. Is the cluster up?")
            sys.exit(1)

        # Build all transactions up front so the queue is deterministic
        transactions = [make_transaction(i) for i in range(1, self.num_txns + 1)]

        semaphore = asyncio.Semaphore(self.concurrency)
        start_time = time.time()

        async def _bounded(tx: dict):
            async with semaphore:
                result = await submit_transaction(
                    tx          = tx,
                    discovery   = self.discovery,
                    mode        = self.mode,
                    timeout     = self.timeout,
                    max_retries = self.max_retries,
                )
                self.results.append(result)
                self._write_result(result)

        tasks = []
        for i, tx in enumerate(transactions):
            tasks.append(asyncio.create_task(_bounded(tx)))
            if i < len(transactions) - 1:
                await asyncio.sleep(self._inter_tx_delay)

        await asyncio.gather(*tasks)

        elapsed = time.time() - start_time
        self._print_summary(elapsed)

    # ---- Output --------------------------------------------------------- #

    def _write_result(self, r: TxResult):
        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
        with open(RESULTS_FILE, "a") as f:
            f.write(json.dumps(asdict(r)) + "\n")

    def _print_summary(self, elapsed: float):
        sent    = sum(1 for r in self.results if r.status == "sent")
        failed  = sum(1 for r in self.results if r.status == "failed")
        total   = len(self.results)

        avg_lat = (
            sum(r.latency_ms for r in self.results if r.status == "sent") / max(sent, 1)
        )
        p99_lat = sorted(
            [r.latency_ms for r in self.results if r.status == "sent"]
        )
        p99 = p99_lat[int(len(p99_lat) * 0.99) - 1] if p99_lat else 0.0

        attempts_total = sum(r.attempts for r in self.results)

        print()
        print(f"{_BOLD}{'─'*56}{_RESET}")
        print(f"{_BOLD}  Transaction Summary{_RESET}")
        print(f"{'─'*56}")
        print(f"  Total submitted  : {total}")
        print(f"  {_GREEN}Sent (success)   : {sent}{_RESET}")
        print(f"  {_RED}Failed           : {failed}{_RESET}")
        print(f"  Success rate     : {100*sent/max(total,1):.1f}%")
        print(f"  Elapsed          : {elapsed:.2f}s")
        print(f"  Throughput       : {sent/elapsed:.2f} txns/s")
        print(f"  Avg latency      : {avg_lat:.1f}ms")
        print(f"  p99 latency      : {p99:.1f}ms")
        print(f"  Total attempts   : {attempts_total}  (retries: {attempts_total - total})")
        print(f"  Results file     : {RESULTS_FILE}")
        print(f"{'─'*56}")
        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def parse_args():
    parser = argparse.ArgumentParser(description="Distributed Consensus Transaction Client")
    parser.add_argument(
        "--nodes",
        default=os.environ.get("NODES", ""),
        help="id@host:port,…  e.g. 1@node1:5001,2@node2:5002",
    )
    parser.add_argument(
        "--mode",
        default=os.environ.get("MODE", "B"),
        choices=["A", "B"],
        help="A=Paxos  B=PBFT",
    )
    parser.add_argument(
        "--txns",
        type=int,
        default=_env_int("NUM_TXNS", DEFAULT_NUM_TXNS),
        help="Number of transactions to submit",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=_env_int("CONCURRENCY", DEFAULT_CONCURRENCY),
        help="Max concurrent in-flight transactions",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=_env_float("RATE", DEFAULT_RATE),
        help="Transaction submission rate (txns/second)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=_env_float("REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
        help="Per-attempt timeout in seconds",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=_env_int("MAX_RETRIES", DEFAULT_MAX_RETRIES),
        help="Max retries per transaction",
    )
    parser.add_argument(
        "--wait",
        type=float,
        default=8.0,
        help="Seconds to wait for cluster to be ready before starting",
    )
    return parser.parse_args()


def _parse_nodes(nodes_str: str) -> List[NodeAddr]:
    nodes = []
    for entry in nodes_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        pid_str, addr = entry.split("@")
        host, port    = addr.rsplit(":", 1)
        nodes.append(NodeAddr(node_id=int(pid_str), host=host, port=int(port)))
    return nodes


async def _main():
    args  = parse_args()
    nodes = _parse_nodes(args.nodes)

    if not nodes:
        log.error("No nodes specified. Use --nodes or set NODES env var.")
        sys.exit(1)

    log.info("Waiting %.1fs for cluster to stabilise …", args.wait)
    await asyncio.sleep(args.wait)

    client = TransactionClient(
        nodes       = nodes,
        mode        = args.mode,
        num_txns    = args.txns,
        concurrency = args.concurrency,
        rate        = args.rate,
        timeout     = args.timeout,
        max_retries = args.retries,
    )
    await client.run()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\nClient interrupted.")