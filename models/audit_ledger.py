"""Tamper-evident, hash-chained audit ledger for every alert the system raises.

Directly addresses the problem statement's "Blockchain & Cybersecurity" theme, which nothing else
in this project touches. This is a genuine, honest implementation of blockchain's core primitive
— a hash chain where altering any past record invalidates every hash after it — run as a single
local append-only log, not a full distributed ledger with multi-party consensus. That's a
deliberate scope choice: a network-security audit trail has one writer (this system) and needs
tamper-*evidence*, not the coordination-among-mutually-distrusting-parties problem a real
multi-node blockchain with gas/wallets/consensus solves. Claiming otherwise would overclaim what's
actually running, which this project avoids elsewhere too (see the honest caveats throughout
docs/04-evaluation-real.md).

Usage:
    ledger = AuditLedger.load_or_create(path)
    ledger.append(host="10.0.0.9", peak_infiltration_prob=0.86, peak_stage="lateral_movement",
                  recommended_action="Isolate the host from internal network segments...")
    ledger.save(path)
    ok, first_bad_index = ledger.verify_integrity()
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class LedgerEntry:
    index: int
    timestamp: str
    host: str
    peak_infiltration_prob: float
    peak_stage: str
    recommended_action: str
    prev_hash: str
    record_hash: str


def _content_hash(
    index: int, timestamp: str, host: str, peak_infiltration_prob: float,
    peak_stage: str, recommended_action: str, prev_hash: str,
) -> str:
    payload = "|".join([
        str(index), timestamp, host, f"{peak_infiltration_prob:.6f}", peak_stage,
        recommended_action, prev_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLedger:
    def __init__(self, entries: list[LedgerEntry] | None = None):
        self.entries: list[LedgerEntry] = entries or []

    def append(
        self, host: str, peak_infiltration_prob: float, peak_stage: str, recommended_action: str,
    ) -> LedgerEntry:
        index = len(self.entries)
        prev_hash = self.entries[-1].record_hash if self.entries else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).isoformat()
        record_hash = _content_hash(
            index, timestamp, host, peak_infiltration_prob, peak_stage, recommended_action, prev_hash,
        )
        entry = LedgerEntry(
            index=index, timestamp=timestamp, host=host,
            peak_infiltration_prob=peak_infiltration_prob, peak_stage=peak_stage,
            recommended_action=recommended_action, prev_hash=prev_hash, record_hash=record_hash,
        )
        self.entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Walks the whole chain recomputing every hash from its own recorded content — returns
        (True, None) if every link matches, or (False, index) at the first entry whose recorded
        hash no longer matches what its content actually hashes to (or whose prev_hash no longer
        matches the previous entry's actual hash), i.e. the first point where the chain was
        broken by tampering, truncation, or reordering."""
        expected_prev = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != expected_prev:
                return False, entry.index
            recomputed = _content_hash(
                entry.index, entry.timestamp, entry.host, entry.peak_infiltration_prob,
                entry.peak_stage, entry.recommended_action, entry.prev_hash,
            )
            if recomputed != entry.record_hash:
                return False, entry.index
            expected_prev = entry.record_hash
        return True, None

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            for entry in self.entries:
                f.write(json.dumps(asdict(entry)) + "\n")

    @classmethod
    def load_or_create(cls, path: str | Path) -> "AuditLedger":
        path = Path(path)
        if not path.exists():
            return cls()
        entries = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(LedgerEntry(**json.loads(line)))
        return cls(entries)
