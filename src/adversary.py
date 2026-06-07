"""
adversary.py  –  Byzantine Adversary Node

Subclasses Node and selectively overrides protocol methods to simulate
a malicious Byzantine participant.  Six distinct attack behaviours are
implemented and can be combined via environment variables or CLI flags:

  BEHAVIOUR 1  – Message Suppression
                 Randomly drop outgoing PBFT_PREPARE / PBFT_COMMIT messages
                 to different subsets of peers (selective silence).

  BEHAVIOUR 2  – Equivocation (split-brain attack)
                 During the PBFT PREPARE phase, send *different* digests to
                 different halves of the peer set, attempting to prevent honest
                 nodes from reaching a consistent quorum.

  BEHAVIOUR 3  – Signature Forgery Attempt
                 Attach a randomly corrupted signature on every outgoing PBFT
                 message, testing whether honest nodes correctly reject it.

  BEHAVIOUR 4  – Paxos Promise Poisoning
                 In Mode A, reply to PREPARE with a fabricated higher-ballot
                 PROMISE that claims a previously accepted value, trying to
                 hijack the Proposer's choice of value.

  BEHAVIOUR 5  – Fake Leader Announcement
                 Periodically broadcast a LEADER_ANNOUNCE claiming the
                 adversary is the leader, regardless of the actual election
                 result, attempting to cause split-brain in leader election.

  BEHAVIOUR 6  – Commit Suppression
                 Never forward PBFT_COMMIT messages, stalling consensus
                 (only effective if f≥2; with f=1 honest nodes still commit).

Environment variables (all optional, default shown):
  ADV_SUPPRESS_RATE   float  0.6    prob. of dropping any single PREPARE/COMMIT
  ADV_EQUIVOCATE      bool   true   enable equivocation on PREPARE
  ADV_FORGE_SIG       bool   true   send garbage signatures
  ADV_POISON_PAXOS    bool   true   poison Paxos PROMISE replies
  ADV_FAKE_LEADER     bool   true   broadcast fake LEADER_ANNOUNCE
  ADV_COMMIT_SUPPRESS bool   true   never send COMMIT messages
  ADV_FAKE_LEADER_INTERVAL float 8.0  seconds between fake announcements

Usage (Docker Compose sets these via environment):
    python adversary.py --id 6 --port 5006 \
        --peers "1@node1:5001,2@node2:5002,3@node3:5003,4@node4:5004,5@node5:5005" \
        --mode B
"""

import asyncio
import copy
import json
import logging
import os
import random
import string
import sys
import time
import argparse
import base64
from typing import Dict, List, Optional, Tuple

# Re-use everything from node.py
sys.path.insert(0, os.path.dirname(__file__))
from node import (
    Node, NodeRole, MsgType,
    CryptoManager, PeerComm,
    HEARTBEAT_INTERVAL, HEARTBEAT_TIMEOUT,
    ELECTION_TIMEOUT, PAXOS_QUORUM_WAIT, PBFT_TIMEOUT,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name, "").lower()
    if val in ("1", "true", "yes"):
        return True
    if val in ("0", "false", "no"):
        return False
    return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _corrupt_signature(sig: str) -> str:
    """Flip random bytes inside a base64-encoded signature."""
    try:
        raw  = bytearray(base64.b64decode(sig))
        for _ in range(max(1, len(raw) // 16)):
            idx      = random.randint(0, len(raw) - 1)
            raw[idx] = raw[idx] ^ random.randint(1, 255)
        return base64.b64encode(bytes(raw)).decode()
    except Exception:
        return "BADSIG===="


def _fake_digest() -> str:
    """Return a random 64-hex-char string that looks like a SHA-256 digest."""
    return "".join(random.choices("0123456789abcdef", k=64))


# ---------------------------------------------------------------------------
# Adversary node
# ---------------------------------------------------------------------------

class AdversaryNode(Node):
    """
    A Byzantine node that inherits all normal node behaviour and selectively
    overrides send/handler methods to inject protocol violations.
    Every attack is logged with an [ADV] prefix so the chaos tests can grep
    for evidence that the adversary was active.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # ---- Configuration ------------------------------------------------
        self.suppress_rate   = _env_float("ADV_SUPPRESS_RATE",   0.6)
        self.do_equivocate   = _env_bool ("ADV_EQUIVOCATE",       True)
        self.do_forge_sig    = _env_bool ("ADV_FORGE_SIG",        True)
        self.do_poison_paxos = _env_bool ("ADV_POISON_PAXOS",     True)
        self.do_fake_leader  = _env_bool ("ADV_FAKE_LEADER",      True)
        self.do_suppress_commit = _env_bool("ADV_COMMIT_SUPPRESS", True)
        self.fake_leader_interval = _env_float("ADV_FAKE_LEADER_INTERVAL", 8.0)

        self.adv_log = logging.getLogger(f"Adversary[{self.id}]")
        self.adv_log.info(
            "Adversary node online  suppress_rate=%.2f  equivocate=%s  "
            "forge_sig=%s  poison_paxos=%s  fake_leader=%s  suppress_commit=%s",
            self.suppress_rate, self.do_equivocate, self.do_forge_sig,
            self.do_poison_paxos, self.do_fake_leader, self.do_suppress_commit,
        )

    # ======================================================================
    # Bootstrap: add adversary-specific background tasks
    # ======================================================================

    async def start(self):
        # Kick off parent startup; adds heartbeat + election watchdog tasks.
        # We inject our own tasks right after.
        asyncio.ensure_future(self._adv_background())
        await super().start()

    async def _adv_background(self):
        """Runs adversary-specific periodic attacks."""
        await asyncio.sleep(5.0)   # let the cluster settle first
        while True:
            tasks = []
            if self.do_fake_leader:
                tasks.append(self._attack_fake_leader())
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(self.fake_leader_interval)

    # ======================================================================
    # BEHAVIOUR 5 – Fake Leader Announcement
    # ======================================================================

    async def _attack_fake_leader(self):
        """
        Broadcast LEADER_ANNOUNCE claiming self as leader, regardless of the
        real election outcome.  Honest nodes that received the legitimate
        leader's heartbeat recently will ignore this (their last_heartbeat is
        fresh), but nodes that just restarted or are partitioned may be fooled
        temporarily.
        """
        self.adv_log.warning(
            "[ADV] FAKE_LEADER – broadcasting self (%d) as leader", self.id
        )
        fake_msg = {
            "type":      MsgType.LEADER_ANNOUNCE,
            "leader_id": self.id,
            "ADVERSARY": True,
        }
        await self._broadcast(fake_msg)

    # ======================================================================
    # BEHAVIOUR 4 – Paxos Promise Poisoning  (Mode A)
    # ======================================================================

    async def _on_prepare(self, msg: dict):
        """
        Override the Acceptor's PREPARE handler.
        Instead of returning an honest PROMISE, fabricate one that claims
        we previously accepted a junk value at a very high ballot number,
        tricking the Proposer into adopting our value.
        """
        if not self.do_poison_paxos or self.mode != "A":
            await super()._on_prepare(msg)
            return

        slot    = msg["slot"]
        prop_id = msg["prop_id"]
        sender  = msg["from"]

        if sender == self.id:
            # self-send during proposal – handle normally to avoid breaking self
            await super()._on_prepare(msg)
            return

        # Fabricate a PROMISE with a sky-high accepted ballot and a junk value
        fake_ballot = [9999, self.id]
        fake_value  = {
            "tx":    "ADV_POISON_TX",
            "amount": -1,
            "adv":   True,
        }
        poisoned_promise = {
            "type":           MsgType.PROMISE,
            "slot":           slot,
            "prop_id":        prop_id,
            "accepted_id":    fake_ballot,
            "accepted_value": fake_value,
            "from":           self.id,
            "ADVERSARY":      True,
        }
        self.adv_log.warning(
            "[ADV] PAXOS_POISON – sending fake PROMISE to %d  slot=%d  "
            "fake_ballot=%s  fake_value=%s",
            sender, slot, fake_ballot, fake_value,
        )
        await self._send_to(sender, poisoned_promise)

    # ======================================================================
    # BEHAVIOUR 2 – Equivocation during PBFT PREPARE
    # ======================================================================

    async def _on_pre_prepare(self, msg: dict):
        """
        Override PREPARE broadcast.
        Split peers into two halves and send each half a *different* digest,
        hoping to create conflicting prepare-certificate sets.
        """
        if not self.do_equivocate or self.mode != "B":
            await super()._on_pre_prepare(msg)
            return

        view   = msg["view"]
        seq    = msg["seq"]
        sender = msg["from"]

        # Store the real request
        self.pbft.log[seq] = msg.get("request", {})

        real_digest = msg["digest"]
        fake_digest = _fake_digest()

        # Split peer list in two halves
        half = len(self.peer_ids) // 2
        group_a = self.peer_ids[:half]      # gets real digest
        group_b = self.peer_ids[half:]      # gets fake digest

        self.adv_log.warning(
            "[ADV] EQUIVOCATE  seq=%d  group_A=%s (real digest %.8s) "
            "group_B=%s (fake digest %.8s)",
            seq, group_a, real_digest, group_b, fake_digest,
        )

        async def _send_prepare(target_id: int, digest: str):
            payload = {"view": view, "seq": seq, "digest": digest, "from": self.id}
            sig = self.crypto.sign(payload)
            if self.do_forge_sig:
                sig = _corrupt_signature(sig)
            prepare_msg = {
                "type":   MsgType.PBFT_PREPARE,
                "view":   view,
                "seq":    seq,
                "digest": digest,
                "from":   self.id,
                "sig":    sig,
                "ADVERSARY": True,
            }
            await self._send_to(target_id, prepare_msg)

        tasks = []
        for pid in group_a:
            tasks.append(_send_prepare(pid, real_digest))
        for pid in group_b:
            tasks.append(_send_prepare(pid, fake_digest))
        await asyncio.gather(*tasks, return_exceptions=True)

    # ======================================================================
    # BEHAVIOUR 1 + 3 – Selective Suppression & Signature Forgery on PREPARE
    # ======================================================================

    async def _on_pbft_prepare(self, msg: dict):
        """
        When we receive a PREPARE from an honest node:
        – With probability suppress_rate, drop it entirely (Behaviour 1).
        – Otherwise forward it onward but with a corrupted signature
          if do_forge_sig is set (Behaviour 3).
        If equivocation is on, we already broadcast our own prepare in
        _on_pre_prepare, so we skip the honest flow here too.
        """
        if self.mode != "B":
            await super()._on_pbft_prepare(msg)
            return

        seq    = msg["seq"]
        sender = msg["from"]

        if random.random() < self.suppress_rate:
            self.adv_log.warning(
                "[ADV] SUPPRESS PREPARE  seq=%d  from=%d", seq, sender
            )
            return   # drop – do not process or forward

        # Tamper with signature before passing up
        if self.do_forge_sig and sender != self.id:
            self.adv_log.warning(
                "[ADV] FORGE_SIG on PREPARE  seq=%d  from=%d", seq, sender
            )
            msg = dict(msg)
            msg["sig"] = _corrupt_signature(msg.get("sig", ""))

        await super()._on_pbft_prepare(msg)

    # ======================================================================
    # BEHAVIOUR 6 – Commit Suppression
    # ======================================================================

    async def _on_pbft_commit(self, msg: dict):
        """
        Never forward COMMIT messages we generate or receive.
        We still count them locally (so we can observe what honest nodes do)
        but we refuse to contribute our own COMMIT vote to the network.
        """
        if not self.do_suppress_commit or self.mode != "B":
            await super()._on_pbft_commit(msg)
            return

        seq    = msg["seq"]
        sender = msg["from"]

        if sender == self.id:
            self.adv_log.warning(
                "[ADV] COMMIT_SUPPRESS – refusing to send own COMMIT  seq=%d", seq
            )
            # Do NOT call super; our vote is withheld.
            return

        # We received a COMMIT from an honest node – suppress re-broadcast
        self.adv_log.warning(
            "[ADV] COMMIT_SUPPRESS – dropping COMMIT from %d  seq=%d", sender, seq
        )
        # Still record locally so we can see what's happening, but don't help quorum
        votes = self.pbft.commit_votes.setdefault(seq, {})
        votes[sender] = msg

    # ======================================================================
    # Helper: override _broadcast to randomly skip peers (Behaviour 1 general)
    # ======================================================================

    async def _broadcast(self, msg: dict, exclude: int = -1):
        """
        Wrap parent _broadcast so that for PBFT PREPARE / COMMIT messages we
        randomly skip peers according to suppress_rate, creating asymmetric
        message delivery.
        """
        t = msg.get("type")
        targeted_types = {MsgType.PBFT_PREPARE, MsgType.PBFT_COMMIT}

        if t not in targeted_types:
            await super()._broadcast(msg, exclude=exclude)
            return

        # Send to each peer independently with probability (1 - suppress_rate)
        tasks = []
        for i, pid in enumerate(self.peer_ids):
            if pid == exclude:
                continue
            if random.random() < self.suppress_rate:
                self.adv_log.debug(
                    "[ADV] SUPPRESS broadcast of %s to peer %d", t, pid
                )
                continue
            tasks.append(self._send(i, msg))

        await asyncio.gather(*tasks, return_exceptions=True)

    # ======================================================================
    # Status override
    # ======================================================================

    def status(self) -> dict:
        base = super().status()
        base.update({
            "adversary":        True,
            "suppress_rate":    self.suppress_rate,
            "do_equivocate":    self.do_equivocate,
            "do_forge_sig":     self.do_forge_sig,
            "do_poison_paxos":  self.do_poison_paxos,
            "do_fake_leader":   self.do_fake_leader,
            "do_suppress_commit": self.do_suppress_commit,
        })
        return base


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Byzantine Adversary Node")
    parser.add_argument("--id",    type=int, required=True)
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, required=True)
    parser.add_argument(
        "--peers",
        required=True,
        help="id@host:port,…",
    )
    parser.add_argument("--mode", default="B", choices=["A", "B"])
    return parser.parse_args()


async def _main():
    args      = parse_args()
    node_id   = int(os.environ.get("NODE_ID",   args.id))
    host      =     os.environ.get("NODE_HOST", args.host)
    port      = int(os.environ.get("NODE_PORT", args.port))
    mode      =     os.environ.get("MODE",      args.mode).upper()
    peers_str =     os.environ.get("PEERS",     args.peers)

    peers, peer_ids = [], []
    for entry in peers_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        pid_str, addr = entry.split("@")
        pid           = int(pid_str)
        h, p          = addr.rsplit(":", 1)
        peer_ids.append(pid)
        peers.append((h, int(p)))

    node = AdversaryNode(
        node_id  = node_id,
        host     = host,
        port     = port,
        peers    = peers,
        peer_ids = peer_ids,
        mode     = mode,
    )

    logging.getLogger("Main").info(
        "Starting ADVERSARY node %d  mode=%s  peers=%s",
        node_id, mode,
        [f"{pid}@{h}:{p}" for pid, (h, p) in zip(peer_ids, peers)],
    )
    await node.start()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass