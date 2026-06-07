"""
crypto_utils.py  –  Cryptographic Utilities
IIT Jodhpur | Fundamentals of Distributed Systems | Assignment-1

Standalone cryptographic toolkit used by node.py, adversary.py, and
client.py.  Provides:

  KeyStore          – Generate, persist, load, and distribute RSA-2048 key
                      pairs per node.  Keys are stored as PEM files under a
                      configurable key directory so they survive container
                      restarts and can be pre-shared via a Docker volume.

  MessageSigner     – Sign and verify arbitrary dict payloads using
                      RSA-PSS / SHA-256.  Wraps the raw cryptography calls
                      from node.py into a cleaner, reusable API.

  HMACAuthenticator – Lightweight HMAC-SHA256 for fast message authentication
                      codes (MACs) used in heartbeat / leader-election messages
                      where the full RSA overhead is unnecessary.

  DigestUtils       – Canonical SHA-256 digests over dict payloads, used as
                      the PBFT message digest (d(m) in the paper).

  CertificateBundle – Bundles a node's public key + node_id into a self-signed
                      certificate-like structure for exchange during the
                      KEY_EXCHANGE handshake.

  KeyRing           – In-memory registry mapping node_id → public key,
                      with thread-safe load/store.  Shared singleton used by
                      MessageSigner.verify().

CLI (run directly)
------------------
    # Generate key pairs for all 6 nodes into ./keys/
    python crypto_utils.py generate --nodes 1,2,3,4,5,6 --keydir ./keys

    # Print the public key for node 2
    python crypto_utils.py show --node 2 --keydir ./keys

    # Verify a signed JSON file produced by the test harness
    python crypto_utils.py verify --file signed_msg.json --keydir ./keys

Environment variables
---------------------
    KEY_DIR    path to the key directory  (default: /keys)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
import threading
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log = logging.getLogger("crypto_utils")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_KEY_DIR   = os.environ.get("KEY_DIR", "/keys")
RSA_KEY_BITS      = 2048
RSA_PUBLIC_EXPON  = 65537
HMAC_DIGEST       = hashlib.sha256
_PRIV_FILE_TMPL   = "node_{node_id}_priv.pem"
_PUB_FILE_TMPL    = "node_{node_id}_pub.pem"
_BUNDLE_FILE_TMPL = "node_{node_id}_bundle.json"


# ===========================================================================
# DigestUtils
# ===========================================================================

class DigestUtils:
    """
    Canonical SHA-256 digests over arbitrary Python dicts.

    The canonical form is deterministic JSON with sorted keys and no extra
    whitespace.  This matches the digest used in the PBFT PRE-PREPARE message
    (d(m) in the Castro & Liskov paper).
    """

    @staticmethod
    def canonical_bytes(payload: dict) -> bytes:
        """Return the canonical UTF-8 JSON encoding of *payload*."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def sha256_hex(payload: dict) -> str:
        """Return the hex-encoded SHA-256 digest of the canonical encoding."""
        return hashlib.sha256(DigestUtils.canonical_bytes(payload)).hexdigest()

    @staticmethod
    def sha256_b64(payload: dict) -> str:
        """Return the base64-encoded SHA-256 digest (URL-safe, no padding)."""
        raw = hashlib.sha256(DigestUtils.canonical_bytes(payload)).digest()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @staticmethod
    def verify_digest(payload: dict, expected_hex: str) -> bool:
        """Return True iff sha256_hex(payload) == expected_hex."""
        return secrets.compare_digest(
            DigestUtils.sha256_hex(payload), expected_hex
        )

    @staticmethod
    def chain_hash(previous_hash: str, payload: dict) -> str:
        """
        Combine the previous ledger entry hash with the current payload
        to create a tamper-evident hash chain (used by the Ledger).
        """
        combined = previous_hash + DigestUtils.sha256_hex(payload)
        return hashlib.sha256(combined.encode()).hexdigest()


# ===========================================================================
# KeyStore
# ===========================================================================

class KeyStore:
    """
    Manages RSA-2048 key pair generation, PEM persistence, and loading for a
    single node.

    File layout under key_dir:
        node_<id>_priv.pem      – PKCS8 PEM, no passphrase (container-internal)
        node_<id>_pub.pem       – SubjectPublicKeyInfo PEM
        node_<id>_bundle.json   – {node_id, pub_pem, fingerprint, generated_at}
    """

    def __init__(self, node_id: int, key_dir: str = DEFAULT_KEY_DIR):
        self.node_id  = node_id
        self.key_dir  = Path(key_dir)
        self._priv    : Optional[RSAPrivateKey]  = None
        self._pub     : Optional[RSAPublicKey]   = None

    # ------------------------------------------------------------------ #
    # Private paths
    # ------------------------------------------------------------------ #

    def _priv_path(self) -> Path:
        return self.key_dir / _PRIV_FILE_TMPL.format(node_id=self.node_id)

    def _pub_path(self) -> Path:
        return self.key_dir / _PUB_FILE_TMPL.format(node_id=self.node_id)

    def _bundle_path(self) -> Path:
        return self.key_dir / _BUNDLE_FILE_TMPL.format(node_id=self.node_id)

    # ------------------------------------------------------------------ #
    # Generation
    # ------------------------------------------------------------------ #

    def generate(self, overwrite: bool = False) -> "KeyStore":
        """
        Generate a fresh RSA-2048 key pair and persist it to disk.
        Raises FileExistsError if the key already exists and overwrite=False.
        """
        self.key_dir.mkdir(parents=True, exist_ok=True)

        if self._priv_path().exists() and not overwrite:
            raise FileExistsError(
                f"Key for node {self.node_id} already exists at "
                f"{self._priv_path()}.  Pass overwrite=True to regenerate."
            )

        log.info("Generating RSA-%d key pair for node %d …", RSA_KEY_BITS, self.node_id)
        priv = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPON,
            key_size=RSA_KEY_BITS,
            backend=default_backend(),
        )
        pub = priv.public_key()

        # Write private key
        self._priv_path().write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Write public key
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._pub_path().write_bytes(pub_pem)

        # Write bundle
        bundle = {
            "node_id":      self.node_id,
            "pub_pem":      pub_pem.decode(),
            "fingerprint":  _fingerprint(pub),
            "generated_at": time.time(),
            "key_bits":     RSA_KEY_BITS,
        }
        self._bundle_path().write_text(json.dumps(bundle, indent=2))

        self._priv = priv
        self._pub  = pub
        log.info(
            "Key pair saved  fingerprint=%s", bundle["fingerprint"]
        )
        return self

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #

    def load(self) -> "KeyStore":
        """
        Load an existing key pair from disk.
        If keys do not exist, generate them automatically.
        """
        if not self._priv_path().exists():
            log.warning(
                "No key found for node %d; generating on-the-fly.", self.node_id
            )
            return self.generate()

        self._priv = serialization.load_pem_private_key(
            self._priv_path().read_bytes(),
            password=None,
            backend=default_backend(),
        )
        self._pub = serialization.load_pem_public_key(
            self._pub_path().read_bytes(),
            backend=default_backend(),
        )
        log.debug("Loaded key pair for node %d  fp=%s", self.node_id, self.fingerprint)
        return self

    # ------------------------------------------------------------------ #
    # Properties
    # ------------------------------------------------------------------ #

    @property
    def private_key(self) -> RSAPrivateKey:
        if self._priv is None:
            self.load()
        return self._priv  # type: ignore[return-value]

    @property
    def public_key(self) -> RSAPublicKey:
        if self._pub is None:
            self.load()
        return self._pub  # type: ignore[return-value]

    @property
    def public_key_pem(self) -> str:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.public_key)

    def bundle(self) -> "CertificateBundle":
        """Return a CertificateBundle for the KEY_EXCHANGE handshake."""
        return CertificateBundle(
            node_id     = self.node_id,
            pub_pem     = self.public_key_pem,
            fingerprint = self.fingerprint,
        )


# ===========================================================================
# CertificateBundle
# ===========================================================================

class CertificateBundle:
    """
    Lightweight self-signed certificate exchanged during the KEY_EXCHANGE
    handshake.  Carries the node's public key, its ID, and a fingerprint so
    receivers can sanity-check the key they received.

    Wire format (JSON dict included in KEY_EXCHANGE message):
        {
            "node_id":     <int>,
            "pub_pem":     "<PEM string>",
            "fingerprint": "<SHA-256 hex of DER-encoded public key>",
            "issued_at":   <float epoch>,
        }
    """

    def __init__(self, node_id: int, pub_pem: str, fingerprint: str):
        self.node_id     = node_id
        self.pub_pem     = pub_pem
        self.fingerprint = fingerprint
        self.issued_at   = time.time()

    def to_dict(self) -> dict:
        return {
            "node_id":     self.node_id,
            "pub_pem":     self.pub_pem,
            "fingerprint": self.fingerprint,
            "issued_at":   self.issued_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CertificateBundle":
        obj = cls(
            node_id     = d["node_id"],
            pub_pem     = d["pub_pem"],
            fingerprint = d["fingerprint"],
        )
        obj.issued_at = d.get("issued_at", 0.0)
        return obj

    def verify_fingerprint(self) -> bool:
        """
        Recompute the fingerprint from the embedded PEM and compare.
        Returns False if the bundle has been tampered with.
        """
        pub = serialization.load_pem_public_key(
            self.pub_pem.encode(), backend=default_backend()
        )
        expected = _fingerprint(pub)
        return secrets.compare_digest(expected, self.fingerprint)


# ===========================================================================
# KeyRing
# ===========================================================================

class KeyRing:
    """
    Thread-safe in-memory registry of peer public keys.
    Populated during the KEY_EXCHANGE handshake; queried by MessageSigner.

    This is a module-level singleton (see _GLOBAL_KEYRING below) so all
    components in the same process share the same key set.
    """

    def __init__(self):
        self._keys  : Dict[int, RSAPublicKey] = {}
        self._lock  = threading.RLock()
        self._bundles: Dict[int, CertificateBundle] = {}

    def register(self, bundle: CertificateBundle) -> bool:
        """
        Validate and register a peer's public key from a CertificateBundle.
        Returns True on success, False if the bundle fingerprint is invalid.
        """
        if not bundle.verify_fingerprint():
            log.warning(
                "KeyRing: fingerprint mismatch for node %d — rejecting!", bundle.node_id
            )
            return False

        pub = serialization.load_pem_public_key(
            bundle.pub_pem.encode(), backend=default_backend()
        )
        with self._lock:
            self._keys[bundle.node_id]    = pub
            self._bundles[bundle.node_id] = bundle
        log.debug("KeyRing: registered node %d  fp=%s", bundle.node_id, bundle.fingerprint)
        return True

    def register_pem(self, node_id: int, pem: str) -> None:
        """Register a raw PEM string without a bundle (legacy path)."""
        pub = serialization.load_pem_public_key(
            pem.encode(), backend=default_backend()
        )
        with self._lock:
            self._keys[node_id] = pub

    def get(self, node_id: int) -> Optional[RSAPublicKey]:
        with self._lock:
            return self._keys.get(node_id)

    def known_ids(self) -> list:
        with self._lock:
            return list(self._keys.keys())

    def fingerprint(self, node_id: int) -> Optional[str]:
        with self._lock:
            pub = self._keys.get(node_id)
            return _fingerprint(pub) if pub else None

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)


# Module-level singleton
_GLOBAL_KEYRING = KeyRing()


def get_keyring() -> KeyRing:
    """Return the process-wide KeyRing singleton."""
    return _GLOBAL_KEYRING


# ===========================================================================
# MessageSigner
# ===========================================================================

class MessageSigner:
    """
    RSA-PSS / SHA-256 sign and verify for protocol messages.

    Sign:   produces a base64-encoded signature over canonical JSON.
    Verify: uses the KeyRing to look up the sender's public key.

    This is the same algorithm used inline in node.py's CryptoManager but
    extracted here so it can be tested independently and reused by
    adversary.py without duplicating logic.
    """

    def __init__(self, private_key: RSAPrivateKey, keyring: KeyRing = None):
        self._priv   = private_key
        self._ring   = keyring or _GLOBAL_KEYRING

    # ------------------------------------------------------------------ #
    # Signing
    # ------------------------------------------------------------------ #

    def sign(self, payload: dict) -> str:
        """
        Return a base64-encoded RSA-PSS signature over the canonical JSON
        encoding of *payload*.

        The signature covers the exact bytes produced by
        DigestUtils.canonical_bytes(payload), so any field reordering or
        whitespace change will invalidate it.
        """
        data = DigestUtils.canonical_bytes(payload)
        raw_sig = self._priv.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return base64.b64encode(raw_sig).decode()

    def sign_message(self, msg: dict, fields: tuple = None) -> str:
        """
        Sign a subset of *msg* fields.  If *fields* is None, sign the whole
        dict.  Useful when a message contains non-deterministic metadata
        (e.g. timestamps) that should be excluded from the signed content.

        Example:
            sig = signer.sign_message(msg, fields=("view", "seq", "digest"))
        """
        if fields is None:
            return self.sign(msg)
        subset = {k: msg[k] for k in fields if k in msg}
        return self.sign(subset)

    # ------------------------------------------------------------------ #
    # Verification
    # ------------------------------------------------------------------ #

    def verify(self, payload: dict, signature: str, sender_id: int) -> bool:
        """
        Verify that *signature* (base64) is a valid RSA-PSS signature over
        *payload* made by the node with *sender_id*.

        Returns False (not raises) on any failure so callers can log and
        continue safely.
        """
        pub = self._ring.get(sender_id)
        if pub is None:
            log.warning(
                "verify: no public key for node %d — cannot verify", sender_id
            )
            return False
        data = DigestUtils.canonical_bytes(payload)
        try:
            pub.verify(
                base64.b64decode(signature),
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except InvalidSignature:
            log.debug("verify: invalid signature from node %d", sender_id)
            return False
        except Exception as exc:
            log.warning("verify: unexpected error for node %d: %s", sender_id, exc)
            return False

    def verify_message(
        self, msg: dict, signature: str, sender_id: int, fields: tuple = None
    ) -> bool:
        """Mirror of sign_message: verify only the specified fields."""
        if fields is None:
            return self.verify(msg, signature, sender_id)
        subset = {k: msg[k] for k in fields if k in msg}
        return self.verify(subset, signature, sender_id)


# ===========================================================================
# HMACAuthenticator
# ===========================================================================

class HMACAuthenticator:
    """
    HMAC-SHA256 authenticator for fast, symmetric message authentication.

    Used for heartbeat and leader-election messages where RSA overhead is
    unacceptable.  All nodes that share the same cluster secret can verify
    each other's heartbeats.

    The shared secret is derived from an environment variable
    CLUSTER_HMAC_SECRET (or a default).  In production you would inject
    this via Docker secrets.
    """

    _DEFAULT_SECRET_ENV = "CLUSTER_HMAC_SECRET"
    _DEFAULT_SECRET     = b"iitj-ds-assignment-1-default-secret-change-me"

    def __init__(self, secret: bytes = None):
        if secret is None:
            env_val = os.environ.get(self._DEFAULT_SECRET_ENV, "")
            secret  = env_val.encode() if env_val else self._DEFAULT_SECRET
        self._secret = secret

    def mac(self, payload: dict) -> str:
        """Return base64-encoded HMAC-SHA256 of canonical payload."""
        data = DigestUtils.canonical_bytes(payload)
        tag  = hmac.new(self._secret, data, HMAC_DIGEST).digest()
        return base64.b64encode(tag).decode()

    def verify_mac(self, payload: dict, tag: str) -> bool:
        """Constant-time MAC verification.  Returns True iff valid."""
        expected = self.mac(payload)
        try:
            return secrets.compare_digest(expected, tag)
        except Exception:
            return False

    def attach(self, msg: dict, tag_field: str = "mac") -> dict:
        """
        Return a shallow copy of *msg* with an HMAC tag added under
        *tag_field*.  The tag is computed over the message *without*
        the tag field itself.
        """
        clean = {k: v for k, v in msg.items() if k != tag_field}
        tag   = self.mac(clean)
        return {**msg, tag_field: tag}

    def check(self, msg: dict, tag_field: str = "mac") -> bool:
        """
        Extract and verify the MAC from *msg[tag_field]*.
        Returns False if the field is missing or the tag is wrong.
        """
        tag = msg.get(tag_field)
        if not tag:
            return False
        clean = {k: v for k, v in msg.items() if k != tag_field}
        return self.verify_mac(clean, tag)


# ===========================================================================
# Convenience wrappers (drop-in for node.py's inline crypto)
# ===========================================================================

def generate_keypair() -> Tuple[RSAPrivateKey, RSAPublicKey]:
    """Generate and return a fresh (private_key, public_key) tuple."""
    priv = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPON,
        key_size=RSA_KEY_BITS,
        backend=default_backend(),
    )
    return priv, priv.public_key()


def private_key_to_pem(priv: RSAPrivateKey) -> str:
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def public_key_to_pem(pub: RSAPublicKey) -> str:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def public_key_from_pem(pem: str) -> RSAPublicKey:
    return serialization.load_pem_public_key(
        pem.encode(), backend=default_backend()
    )


def private_key_from_pem(pem: str) -> RSAPrivateKey:
    return serialization.load_pem_private_key(
        pem.encode(), password=None, backend=default_backend()
    )


def sign_payload(priv: RSAPrivateKey, payload: dict) -> str:
    """Standalone sign — no class needed."""
    data = DigestUtils.canonical_bytes(payload)
    raw  = priv.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(raw).decode()


def verify_payload(pub: RSAPublicKey, payload: dict, signature: str) -> bool:
    """Standalone verify — no class needed."""
    data = DigestUtils.canonical_bytes(payload)
    try:
        pub.verify(
            base64.b64decode(signature),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ===========================================================================
# Internal helpers
# ===========================================================================

def _fingerprint(pub: RSAPublicKey) -> str:
    """SHA-256 fingerprint of DER-encoded public key (colon-separated hex)."""
    der  = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw  = hashlib.sha256(der).digest()
    return ":".join(f"{b:02x}" for b in raw)


# ===========================================================================
# CLI
# ===========================================================================

def _cmd_generate(args):
    node_ids = [int(x) for x in args.nodes.split(",")]
    for nid in node_ids:
        ks = KeyStore(node_id=nid, key_dir=args.keydir)
        ks.generate(overwrite=args.force)
        print(f"Node {nid:3d}  fp={ks.fingerprint}")


def _cmd_show(args):
    ks = KeyStore(node_id=args.node, key_dir=args.keydir)
    ks.load()
    print(f"Node {args.node} public key\n{'-'*60}")
    print(ks.public_key_pem)
    print(f"Fingerprint: {ks.fingerprint}")


def _cmd_verify(args):
    with open(args.file) as f:
        msg = json.load(f)

    sender_id = msg.get("from") or msg.get("sender")
    signature = msg.get("sig")
    if sender_id is None or signature is None:
        print("ERROR: message must contain 'from'/'sender' and 'sig' fields.")
        sys.exit(1)

    ks = KeyStore(node_id=int(sender_id), key_dir=args.keydir)
    ks.load()
    ring = KeyRing()
    ring.register_pem(int(sender_id), ks.public_key_pem)
    signer = MessageSigner(private_key=ks.private_key, keyring=ring)

    # Sign payload = everything except 'sig'
    payload = {k: v for k, v in msg.items() if k != "sig"}
    ok = signer.verify(payload, signature, int(sender_id))
    if ok:
        print(f"✓  Signature VALID  (node {sender_id})")
    else:
        print(f"✗  Signature INVALID  (node {sender_id})")
        sys.exit(2)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="crypto_utils CLI — key management for the consensus cluster"
    )
    sub = p.add_subparsers(dest="command")

    # generate
    gen = sub.add_parser("generate", help="Generate RSA key pairs for nodes")
    gen.add_argument(
        "--nodes", required=True,
        help="Comma-separated node IDs, e.g. 1,2,3,4,5,6",
    )
    gen.add_argument("--keydir", default=DEFAULT_KEY_DIR)
    gen.add_argument("--force",  action="store_true", help="Overwrite existing keys")

    # show
    show = sub.add_parser("show", help="Print a node's public key and fingerprint")
    show.add_argument("--node",   type=int, required=True)
    show.add_argument("--keydir", default=DEFAULT_KEY_DIR)

    # verify
    ver = sub.add_parser("verify", help="Verify a signed JSON message file")
    ver.add_argument("--file",   required=True, help="Path to signed JSON file")
    ver.add_argument("--keydir", default=DEFAULT_KEY_DIR)

    return p


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    )
    parser = _build_parser()
    args   = parser.parse_args()

    if args.command == "generate":
        _cmd_generate(args)
    elif args.command == "show":
        _cmd_show(args)
    elif args.command == "verify":
        _cmd_verify(args)
    else:
        parser.print_help()
        sys.exit(1)