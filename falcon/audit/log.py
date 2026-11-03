"""Append-only, hash-chained audit log (JSON Lines).

hash = sha256(prev_hash + canonical_json(record without hash/prev_hash))
Editing, deleting or reordering any line breaks the chain from that point on.
"""
import hashlib
import json
import os
import threading
from datetime import datetime, timezone

from falcon.config import AUDIT_SCHEMA_VERSION

GENESIS = "0" * 64


def _canonical(d: dict) -> str:
    return json.dumps(d, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, body: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(body)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str, run_id: str):
        self.path = path
        self.run_id = run_id
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        last = GENESIS
        if os.path.exists(self.path):
            with open(self.path) as f:
                for line in f:
                    if line.strip():
                        last = json.loads(line)["hash"]
        return last

    def append(self, event, actor="falcon", attack_id=None, technique_id=None,
               target=None, params=None, outcome="ok", iocs=None) -> dict:
        body = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "run_id": self.run_id,
            "actor": actor,
            "event": event,
            "attack_id": attack_id,
            "technique_id": technique_id,
            "target": target,
            "params": params or {},
            "outcome": outcome,
            "iocs": iocs or [],
        }
        with self._lock:
            record = dict(body, prev_hash=self._last_hash, hash=_hash(self._last_hash, body))
            with open(self.path, "a") as f:
                f.write(_canonical(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._last_hash = record["hash"]
        return record


def verify_chain(path: str):
    """Return (ok, bad_line_number_or_None)."""
    prev = GENESIS
    with open(path) as f:
        for n, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, n
            if rec.get("prev_hash") != prev:
                return False, n
            body = {k: v for k, v in rec.items() if k not in ("hash", "prev_hash")}
            if _hash(prev, body) != rec.get("hash"):
                return False, n
            prev = rec["hash"]
    return True, None
