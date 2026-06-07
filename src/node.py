"""
node.py  -  Distributed Consensus Node
IIT Jodhpur | Fundamentals of Distributed Systems | Assignment-1

Implements:
  - Bully-style Leader Election with heartbeat failure detection
  - Mode A: Basic Paxos  (crash-fault tolerance, up to f=2 failures in 5-node cluster)
  - Mode B: PBFT         (Byzantine-fault tolerance, up to f=1 Byzantine node)

Each node is started as:
    python node.py --id <NODE_ID> --peers <id@host:port,...> --mode <A|B>

Environment variables (set by docker-compose):
    NODE_ID, NODE_PORT, PEERS, MODE
"""

import asyncio
import json
import logging
import os
import sys
import time
import argparse
import hashlib
import base64
from enum import Enum, auto
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HEARTBEAT_INTERVAL   = 1.0
HEARTBEAT_TIMEOUT    = 3.0
ELECTION_TIMEOUT     = 5.0
PAXOS_QUORUM_WAIT    = 2.0
PBFT_TIMEOUT         = 4.0
LEDGER_FILE_TEMPLATE = "/data/ledger_node_{}.jsonl"
STATUS_PORT_OFFSET   = 100   # status sidecar listens on main_port + 100


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------
class MsgType(str, Enum):
    HEARTBEAT        = "HEARTBEAT"
    ELECTION         = "ELECTION"
    ELECTION_OK      = "ELECTION_OK"
    LEADER_ANNOUNCE  = "LEADER_ANNOUNCE"
    PREPARE          = "PREPARE"
    PROMISE          = "PROMISE"
    ACCEPT           = "ACCEPT"
    ACCEPTED         = "ACCEPTED"
    PAXOS_NACK       = "PAXOS_NACK"
    CLIENT_REQUEST   = "CLIENT_REQUEST"
    PRE_PREPARE      = "PRE_PREPARE"
    PBFT_PREPARE     = "PBFT_PREPARE"
    PBFT_COMMIT      = "PBFT_COMMIT"
    PBFT_REPLY       = "PBFT_REPLY"
    KEY_EXCHANGE     = "KEY_EXCHANGE"
    STATUS           = "STATUS"


# ---------------------------------------------------------------------------
# Cryptographic utilities
# ---------------------------------------------------------------------------
KEY_DIR = os.environ.get("KEY_DIR", "/keys")


class CryptoManager:
    """
    RSA-2048 key pair per node — persisted to KEY_DIR so keys survive
    container restarts and are visible to the host via the bind-mount volume.

    Key files written to KEY_DIR:
        node_<id>_priv.pem   — private key (PKCS8, no passphrase)
        node_<id>_pub.pem    — public key  (SubjectPublicKeyInfo)
    """

    def __init__(self, node_id: int):
        self.node_id    = node_id
        self._peer_keys: Dict[int, object] = {}
        self._priv_key, self._pub_key = self._load_or_generate()

    def _load_or_generate(self):
        os.makedirs(KEY_DIR, exist_ok=True)
        priv_path = os.path.join(KEY_DIR, f"node_{self.node_id}_priv.pem")
        pub_path  = os.path.join(KEY_DIR, f"node_{self.node_id}_pub.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            # Load existing keys from the shared volume
            try:
                with open(priv_path, "rb") as f:
                    priv = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
                with open(pub_path, "rb") as f:
                    pub = serialization.load_pem_public_key(
                        f.read(), backend=default_backend()
                    )
                logging.getLogger(f"CryptoManager[{self.node_id}]").info(
                    "Loaded existing key pair from %s", KEY_DIR
                )
                return priv, pub
            except Exception as e:
                logging.getLogger(f"CryptoManager[{self.node_id}]").warning(
                    "Failed to load keys (%s) — regenerating", e
                )

        # Generate fresh key pair and save to volume
        priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        pub = priv.public_key()

        with open(priv_path, "wb") as f:
            f.write(priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
        with open(pub_path, "wb") as f:
            f.write(pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

        logging.getLogger(f"CryptoManager[{self.node_id}]").info(
            "Generated new key pair → %s", KEY_DIR
        )
        return priv, pub

    def public_key_pem(self) -> str:
        return self._pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def load_peer_key(self, peer_id: int, pem: str):
        self._peer_keys[peer_id] = serialization.load_pem_public_key(
            pem.encode(), backend=default_backend()
        )

    def sign(self, payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True).encode()
        sig = self._priv_key.sign(
            canonical,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(sig).decode()

    def verify(self, payload: dict, signature: str, sender_id: int) -> bool:
        pub = self._peer_keys.get(sender_id)
        if pub is None:
            return False
        canonical = json.dumps(payload, sort_keys=True).encode()
        try:
            pub.verify(
                base64.b64decode(signature),
                canonical,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def digest(payload: dict) -> str:
        canonical = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Ledger (append-only, disk-backed)
# ---------------------------------------------------------------------------
class Ledger:
    def __init__(self, node_id: int):
        self.path = LEDGER_FILE_TEMPLATE.format(node_id)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._entries: List[dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        self._entries.append(json.loads(line))

    def append(self, slot: int, value: dict):
        entry = {"slot": slot, "value": value, "ts": time.time()}
        self._entries.append(entry)
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        logging.getLogger(f"Ledger[{self.path}]").info(
            "Committed slot %d: %s", slot, value
        )

    def last_slot(self) -> int:
        return self._entries[-1]["slot"] if self._entries else -1

    def entries(self) -> List[dict]:
        return list(self._entries)


# ---------------------------------------------------------------------------
# Peer communication helper
# ---------------------------------------------------------------------------
class PeerComm:
    @staticmethod
    async def send(host: str, port: int, message: dict, timeout: float = 2.0):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            data = json.dumps(message).encode() + b"\n"
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except Exception as exc:
            logging.getLogger("PeerComm").debug(
                "send to %s:%d failed: %s", host, port, exc
            )


# ---------------------------------------------------------------------------
# Node state dataclasses
# ---------------------------------------------------------------------------
class NodeRole(Enum):
    FOLLOWER  = auto()
    CANDIDATE = auto()
    LEADER    = auto()


@dataclass
class PaxosState:
    proposal_id:        int  = 0
    accepted_proposals: Dict = field(default_factory=dict)
    promises_rcvd:      Dict = field(default_factory=dict)
    accepted_rcvd:      Dict = field(default_factory=dict)
    pending_slots:      Dict = field(default_factory=dict)


@dataclass
class PBFTState:
    view:            int  = 0
    seq:             int  = 0
    log:             Dict = field(default_factory=dict)
    prepare_votes:   Dict = field(default_factory=dict)
    commit_votes:    Dict = field(default_factory=dict)
    committed:       Dict = field(default_factory=dict)
    pending_futures: Dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main Node class
# ---------------------------------------------------------------------------
class Node:
    def __init__(
        self,
        node_id:  int,
        host:     str,
        port:     int,
        peers:    List[Tuple[str, int]],
        peer_ids: List[int],
        mode:     str = "A",
    ):
        self.id       = node_id
        self.host     = host
        self.port     = port
        self.peers    = peers
        self.peer_ids = peer_ids
        self.mode     = mode.upper()
        self.n        = len(peers) + 1
        self.f        = (self.n - 1) // 3 if self.mode == "B" else (self.n - 1) // 2

        self.crypto = CryptoManager(node_id)
        self.ledger = Ledger(node_id)
        self.log    = logging.getLogger(f"Node[{node_id}]")

        self.role           : NodeRole       = NodeRole.FOLLOWER
        self.leader_id      : Optional[int]  = None
        self.last_heartbeat : float          = time.time()
        self.election_in_progress : bool     = False
        self.election_ok_rcvd     : bool     = False

        self.paxos = PaxosState()
        self.pbft  = PBFTState()

        self._keys_received: set = set()
        self._server: Optional[asyncio.AbstractServer] = None
        self._status_server: Optional[asyncio.AbstractServer] = None

    # ======================================================================
    # Bootstrap
    # ======================================================================

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        # Status sidecar — used by client leader discovery and chaos_test.sh
        self._status_server = await asyncio.start_server(
            self._handle_status, self.host, self.port + STATUS_PORT_OFFSET
        )
        self.log.info(
            "Listening on %s:%d  status=%d  mode=%s",
            self.host, self.port, self.port + STATUS_PORT_OFFSET, self.mode,
        )

        await asyncio.sleep(1.0)
        await self._broadcast_key()

        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._election_watchdog())

        async with self._server, self._status_server:
            await self._server.serve_forever()

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            raw = await reader.readline()
            msg = json.loads(raw.decode().strip())
            # STATUS requests get an inline reply on the main port
            if msg.get("type") == MsgType.STATUS or msg.get("type") == "STATUS":
                resp = json.dumps(self.status()) + "\n"
                writer.write(resp.encode())
                await writer.drain()
            else:
                await self._dispatch(msg)
        except Exception as exc:
            self.log.debug("Connection error: %s", exc)
        finally:
            writer.close()

    async def _handle_status(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Lightweight status sidecar — replies with JSON status and closes."""
        try:
            await reader.readline()   # consume the request line
            resp = json.dumps(self.status()) + "\n"
            writer.write(resp.encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def _dispatch(self, msg: dict):
        t = msg.get("type")
        handlers = {
            MsgType.HEARTBEAT:       self._on_heartbeat,
            MsgType.ELECTION:        self._on_election,
            MsgType.ELECTION_OK:     self._on_election_ok,
            MsgType.LEADER_ANNOUNCE: self._on_leader_announce,
            MsgType.KEY_EXCHANGE:    self._on_key_exchange,
            MsgType.PREPARE:         self._on_prepare,
            MsgType.PROMISE:         self._on_promise,
            MsgType.ACCEPT:          self._on_accept,
            MsgType.ACCEPTED:        self._on_accepted,
            MsgType.PAXOS_NACK:      self._on_paxos_nack,
            MsgType.CLIENT_REQUEST:  self._on_client_request,
            MsgType.PRE_PREPARE:     self._on_pre_prepare,
            MsgType.PBFT_PREPARE:    self._on_pbft_prepare,
            MsgType.PBFT_COMMIT:     self._on_pbft_commit,
        }
        handler = handlers.get(t)
        if handler:
            await handler(msg)
        else:
            self.log.warning("Unknown message type: %s", t)

    # ======================================================================
    # Key Exchange
    # ======================================================================

    async def _broadcast_key(self):
        msg = {
            "type":    MsgType.KEY_EXCHANGE,
            "sender":  self.id,
            "pub_key": self.crypto.public_key_pem(),
        }
        await self._broadcast(msg)

    async def _on_key_exchange(self, msg: dict):
        pid = msg["sender"]
        pem = msg["pub_key"]
        self.crypto.load_peer_key(pid, pem)
        self._keys_received.add(pid)
        self.log.debug("Stored public key for node %d", pid)

    # ======================================================================
    # Peer helpers
    # ======================================================================

    async def _send(self, peer_idx: int, msg: dict):
        host, port = self.peers[peer_idx]
        await PeerComm.send(host, port, msg)

    async def _broadcast(self, msg: dict, exclude: int = -1):
        tasks = []
        for i, pid in enumerate(self.peer_ids):
            if pid != exclude:
                tasks.append(self._send(i, msg))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_to(self, target_id: int, msg: dict):
        if target_id not in self.peer_ids:
            return
        idx = self.peer_ids.index(target_id)
        await self._send(idx, msg)

    # ======================================================================
    # Leader Election  (Bully Algorithm)
    # ======================================================================

    async def _heartbeat_loop(self):
        while True:
            if self.role == NodeRole.LEADER:
                msg = {
                    "type":      MsgType.HEARTBEAT,
                    "leader_id": self.id,
                    "ts":        time.time(),
                }
                await self._broadcast(msg)
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    async def _election_watchdog(self):
        await asyncio.sleep(HEARTBEAT_TIMEOUT + 2.0)
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self.role != NodeRole.LEADER:
                elapsed = time.time() - self.last_heartbeat
                if elapsed > HEARTBEAT_TIMEOUT and not self.election_in_progress:
                    self.log.warning(
                        "Heartbeat timeout (%.1fs). Starting election.", elapsed
                    )
                    await self._start_election()

    async def _start_election(self):
        self.election_in_progress = True
        self.election_ok_rcvd     = False
        self.role                 = NodeRole.CANDIDATE
        self.log.info("=== ELECTION STARTED by node %d ===", self.id)

        msg = {"type": MsgType.ELECTION, "candidate_id": self.id}
        for i, pid in enumerate(self.peer_ids):
            if pid > self.id:
                await self._send(i, msg)

        await asyncio.sleep(ELECTION_TIMEOUT)

        if not self.election_ok_rcvd:
            await self._become_leader()
        else:
            self.role = NodeRole.FOLLOWER
        self.election_in_progress = False

    async def _become_leader(self):
        self.role      = NodeRole.LEADER
        self.leader_id = self.id
        self.log.info("*** Node %d is now the LEADER ***", self.id)
        announce = {"type": MsgType.LEADER_ANNOUNCE, "leader_id": self.id}
        await self._broadcast(announce)

    async def _on_heartbeat(self, msg: dict):
        lid = msg["leader_id"]
        # Reject heartbeats from nodes not in our peer list (adversary defence)
        if lid != self.id and lid not in self.peer_ids:
            self.log.debug("Ignoring heartbeat from unknown/adversary node %d", lid)
            return
        if self.role != NodeRole.LEADER:
            self.last_heartbeat = time.time()
            self.leader_id      = lid
            self.role           = NodeRole.FOLLOWER

    async def _on_election(self, msg: dict):
        cid = msg["candidate_id"]
        if cid < self.id:
            reply = {"type": MsgType.ELECTION_OK, "from": self.id}
            await self._send_to(cid, reply)
            if not self.election_in_progress:
                asyncio.create_task(self._start_election())

    async def _on_election_ok(self, msg: dict):
        self.election_ok_rcvd = True

    async def _on_leader_announce(self, msg: dict):
        lid = msg["leader_id"]
        # Reject fake LEADER_ANNOUNCE from adversary nodes not in our peer list
        if lid != self.id and lid not in self.peer_ids:
            self.log.warning(
                "Ignoring LEADER_ANNOUNCE from unknown/adversary node %d", lid
            )
            return
        self.leader_id            = lid
        self.last_heartbeat       = time.time()
        self.election_in_progress = False
        if self.id != self.leader_id:
            self.role = NodeRole.FOLLOWER
        self.log.info("Leader is node %d", self.leader_id)

    # ======================================================================
    # Mode A - Basic Paxos
    # ======================================================================

    async def propose(self, value: dict) -> bool:
        if self.mode != "A":
            raise RuntimeError("propose() only valid in Mode A")
        if self.role != NodeRole.LEADER:
            if self.leader_id is not None:
                fwd = {"type": MsgType.CLIENT_REQUEST, "value": value, "client": self.id}
                await self._send_to(self.leader_id, fwd)
            return False
        return await self._paxos_propose(value)

    async def _paxos_propose(self, value: dict) -> bool:
        slot = self.ledger.last_slot() + 1
        self.paxos.proposal_id += 1
        prop_id = (self.paxos.proposal_id, self.id)

        self.log.info("[Paxos] Phase-1 PREPARE  slot=%d prop_id=%s", slot, prop_id)
        self.paxos.promises_rcvd[slot] = []

        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self.paxos.pending_slots[slot] = fut

        prepare_msg = {
            "type":    MsgType.PREPARE,
            "slot":    slot,
            "prop_id": prop_id,
            "from":    self.id,
        }
        await self._on_prepare(prepare_msg)
        await self._broadcast(prepare_msg)

        try:
            highest_accepted = await asyncio.wait_for(fut, timeout=PAXOS_QUORUM_WAIT)
        except asyncio.TimeoutError:
            self.log.warning("[Paxos] Phase-1 timed out for slot %d", slot)
            self.paxos.pending_slots.pop(slot, None)
            return False

        chosen_value = highest_accepted if highest_accepted else value
        self.log.info("[Paxos] Phase-2 ACCEPT   slot=%d value=%s", slot, chosen_value)
        self.paxos.accepted_rcvd[slot] = []

        loop2 = asyncio.get_event_loop()
        fut2  = loop2.create_future()
        self.paxos.pending_slots[slot] = fut2

        accept_msg = {
            "type":    MsgType.ACCEPT,
            "slot":    slot,
            "prop_id": prop_id,
            "value":   chosen_value,
            "from":    self.id,
        }
        await self._on_accept(accept_msg)
        await self._broadcast(accept_msg)

        try:
            await asyncio.wait_for(fut2, timeout=PAXOS_QUORUM_WAIT)
        except asyncio.TimeoutError:
            self.log.warning("[Paxos] Phase-2 timed out for slot %d", slot)
            self.paxos.pending_slots.pop(slot, None)
            return False

        self.ledger.append(slot, chosen_value)
        self.log.info("[Paxos] CONSENSUS reached slot=%d", slot)
        return True

    async def _on_prepare(self, msg: dict):
        slot    = msg["slot"]
        prop_id = tuple(msg["prop_id"])
        sender  = msg["from"]

        highest = self.paxos.accepted_proposals.get(slot, (None, None))
        if highest[0] is not None and tuple(highest[0]) >= prop_id:
            nack = {
                "type":       MsgType.PAXOS_NACK,
                "slot":       slot,
                "highest_id": list(highest[0]),
                "from":       self.id,
            }
            if sender != self.id:
                await self._send_to(sender, nack)
            return

        self.paxos.accepted_proposals[slot] = (list(prop_id), None)
        promise = {
            "type":           MsgType.PROMISE,
            "slot":           slot,
            "prop_id":        list(prop_id),
            "accepted_id":    list(highest[0]) if highest[0] else None,
            "accepted_value": highest[1],
            "from":           self.id,
        }
        if sender == self.id:
            await self._on_promise(promise)
        else:
            await self._send_to(sender, promise)

    async def _on_promise(self, msg: dict):
        slot   = msg["slot"]
        quorum = self.n // 2 + 1

        promises = self.paxos.promises_rcvd.setdefault(slot, [])
        promises.append(msg)

        if len(promises) >= quorum and slot in self.paxos.pending_slots:
            fut = self.paxos.pending_slots.pop(slot)
            if not fut.done():
                best_id, best_val = None, None
                for p in promises:
                    aid = p.get("accepted_id")
                    av  = p.get("accepted_value")
                    if aid and (best_id is None or tuple(aid) > tuple(best_id)):
                        best_id, best_val = aid, av
                fut.set_result(best_val)

    async def _on_accept(self, msg: dict):
        slot    = msg["slot"]
        prop_id = tuple(msg["prop_id"])
        value   = msg["value"]
        sender  = msg["from"]

        current = self.paxos.accepted_proposals.get(slot, (None, None))
        if current[0] is not None and tuple(current[0]) > prop_id:
            nack = {
                "type":       MsgType.PAXOS_NACK,
                "slot":       slot,
                "highest_id": list(current[0]),
                "from":       self.id,
            }
            if sender != self.id:
                await self._send_to(sender, nack)
            return

        self.paxos.accepted_proposals[slot] = (list(prop_id), value)
        accepted = {
            "type":    MsgType.ACCEPTED,
            "slot":    slot,
            "prop_id": list(prop_id),
            "value":   value,
            "from":    self.id,
        }
        if sender == self.id:
            await self._on_accepted(accepted)
        else:
            await self._send_to(sender, accepted)

    async def _on_accepted(self, msg: dict):
        slot   = msg["slot"]
        quorum = self.n // 2 + 1

        accepted_list = self.paxos.accepted_rcvd.setdefault(slot, [])
        accepted_list.append(msg)

        if len(accepted_list) >= quorum and slot in self.paxos.pending_slots:
            fut = self.paxos.pending_slots.pop(slot)
            if not fut.done():
                fut.set_result(True)

    async def _on_paxos_nack(self, msg: dict):
        self.paxos.proposal_id = max(
            self.paxos.proposal_id, msg["highest_id"][0] + 1
        )

    # ======================================================================
    # Mode B - PBFT
    # ======================================================================

    async def pbft_request(self, request: dict) -> bool:
        if self.mode != "B":
            raise RuntimeError("pbft_request() only valid in Mode B")
        if self.role != NodeRole.LEADER:
            if self.leader_id is not None:
                fwd = {"type": MsgType.CLIENT_REQUEST, "request": request, "from": self.id}
                await self._send_to(self.leader_id, fwd)
            return False
        return await self._pbft_primary_initiate(request)

    async def _pbft_primary_initiate(self, request: dict) -> bool:
        seq    = self.pbft.seq + 1
        self.pbft.seq = seq
        digest = CryptoManager.digest(request)

        payload = {"view": self.pbft.view, "seq": seq, "digest": digest}
        sig = self.crypto.sign(payload)

        pp_msg = {
            "type":    MsgType.PRE_PREPARE,
            "view":    self.pbft.view,
            "seq":     seq,
            "digest":  digest,
            "request": request,
            "from":    self.id,
            "sig":     sig,
        }
        self.log.info("[PBFT] PRE-PREPARE  seq=%d digest=%.8s", seq, digest)
        self.pbft.log[seq] = request

        loop = asyncio.get_event_loop()
        fut  = loop.create_future()
        self.pbft.pending_futures[seq] = fut

        await self._on_pre_prepare(pp_msg)
        await self._broadcast(pp_msg)

        try:
            await asyncio.wait_for(fut, timeout=PBFT_TIMEOUT)
            self.log.info("[PBFT] COMMIT reached seq=%d", seq)
            return True
        except asyncio.TimeoutError:
            self.log.warning("[PBFT] Timeout waiting for commit seq=%d", seq)
            return False

    async def _on_client_request(self, msg: dict):
        if self.mode == "A":
            await self._paxos_propose(msg.get("value", msg))
        else:
            await self._pbft_primary_initiate(msg.get("request", msg))

    async def _on_pre_prepare(self, msg: dict):
        view   = msg["view"]
        seq    = msg["seq"]
        digest = msg["digest"]
        sender = msg["from"]

        payload = {"view": view, "seq": seq, "digest": digest}
        if sender != self.id:
            if not self.crypto.verify(payload, msg.get("sig", ""), sender):
                self.log.warning("[PBFT] PRE-PREPARE signature invalid from node %d", sender)
                return

        existing = self.pbft.log.get(seq)
        if existing and CryptoManager.digest(existing) != digest:
            self.log.warning("[PBFT] Conflicting PRE-PREPARE for seq=%d. Ignoring.", seq)
            return

        self.pbft.log[seq] = msg["request"]

        prep_payload = {"view": view, "seq": seq, "digest": digest, "from": self.id}
        sig = self.crypto.sign(prep_payload)
        prepare_msg = {
            "type":   MsgType.PBFT_PREPARE,
            "view":   view,
            "seq":    seq,
            "digest": digest,
            "from":   self.id,
            "sig":    sig,
        }
        self.log.debug("[PBFT] PREPARE  seq=%d from=%d", seq, self.id)
        await self._on_pbft_prepare(prepare_msg)
        await self._broadcast(prepare_msg, exclude=self.id)

    async def _on_pbft_prepare(self, msg: dict):
        view   = msg["view"]
        seq    = msg["seq"]
        digest = msg["digest"]
        sender = msg["from"]

        payload = {"view": view, "seq": seq, "digest": digest, "from": sender}
        if sender != self.id:
            if not self.crypto.verify(payload, msg.get("sig", ""), sender):
                self.log.warning("[PBFT] PREPARE signature invalid from node %d", sender)
                return

        votes  = self.pbft.prepare_votes.setdefault(seq, {})
        votes[sender] = msg

        quorum = 2 * self.f + 1
        self.log.debug("[PBFT] PREPARE votes seq=%d: %d/%d", seq, len(votes), quorum)

        if len(votes) >= quorum and seq not in self.pbft.commit_votes:
            commit_payload = {"view": view, "seq": seq, "digest": digest, "from": self.id}
            sig = self.crypto.sign(commit_payload)
            commit_msg = {
                "type":   MsgType.PBFT_COMMIT,
                "view":   view,
                "seq":    seq,
                "digest": digest,
                "from":   self.id,
                "sig":    sig,
            }
            self.pbft.commit_votes[seq] = {}
            await self._on_pbft_commit(commit_msg)
            await self._broadcast(commit_msg, exclude=self.id)

    async def _on_pbft_commit(self, msg: dict):
        view   = msg["view"]
        seq    = msg["seq"]
        digest = msg["digest"]
        sender = msg["from"]

        payload = {"view": view, "seq": seq, "digest": digest, "from": sender}
        if sender != self.id:
            if not self.crypto.verify(payload, msg.get("sig", ""), sender):
                self.log.warning("[PBFT] COMMIT signature invalid from node %d", sender)
                return

        votes = self.pbft.commit_votes.setdefault(seq, {})
        votes[sender] = msg

        quorum = 2 * self.f + 1
        self.log.debug("[PBFT] COMMIT votes seq=%d: %d/%d", seq, len(votes), quorum)

        if len(votes) >= quorum and seq not in self.pbft.committed:
            request = self.pbft.log.get(seq)
            if request is None:
                self.log.error("[PBFT] No request for seq=%d at commit time!", seq)
                return
            slot = self.ledger.last_slot() + 1
            self.ledger.append(slot, request)
            self.pbft.committed[seq] = request
            self.log.info("[PBFT] Committed seq=%d slot=%d", seq, slot)

            fut = self.pbft.pending_futures.get(seq)
            if fut and not fut.done():
                fut.set_result(True)

    # ======================================================================
    # Status
    # ======================================================================

    def status(self) -> dict:
        return {
            "node_id":   self.id,
            "role":      self.role.name,
            "leader_id": self.leader_id,
            "mode":      self.mode,
            "ledger":    self.ledger.entries(),
            "f":         self.f,
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Distributed Consensus Node")
    parser.add_argument("--id",    type=int, required=True)
    parser.add_argument("--host",  default="0.0.0.0")
    parser.add_argument("--port",  type=int, required=True)
    parser.add_argument("--peers", required=True,
                        help="id@host:port,... e.g. 2@node2:5002,3@node3:5003")
    parser.add_argument("--mode",  default="A", choices=["A", "B"])
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

    node = Node(
        node_id  = node_id,
        host     = host,
        port     = port,
        peers    = peers,
        peer_ids = peer_ids,
        mode     = mode,
    )

    logging.getLogger("Main").info(
        "Starting node %d  mode=%s  peers=%s", node_id, mode,
        [f"{pid}@{h}:{p}" for pid, (h, p) in zip(peer_ids, peers)]
    )
    await node.start()


if __name__ == "__main__":
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass