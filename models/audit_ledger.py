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

Concurrent writers (e.g. API request threads) MUST use ``AuditLedger.append_and_save(path, ...)``,
which holds a process-wide lock across load -> append -> atomic save; the bare
load_or_create/append/save sequence is not safe under concurrency (lost updates).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

GENESIS_HASH = "0" * 64

# Process-wide (re-entrant) lock guarding every ledger read-modify-write. It does NOT protect
# against several processes writing the same file; the API runs as one process.
LEDGER_LOCK = threading.RLock()


class LedgerCorruptError(RuntimeError):
    """Raised when appending to a ledger file that failed to parse -- saving would silently
    overwrite (destroy) the evidence of the corruption."""


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
        # Set by load_or_create when a line could not be parsed: (1-based line number, reason).
        # `entries` then holds only the valid entries BEFORE that line.
        self.load_error: tuple[int, str] | None = None

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
        """Walks the whole chain recomputing every hash from its own recorded content - returns
        (True, None) if every link matches, or (False, index) at the first entry whose recorded
        hash no longer matches what its content actually hashes to (or whose prev_hash no longer
        matches the previous entry's actual hash), i.e. the first point where the chain was
        broken by editing or reordering. A file line that could not be parsed at load time
        (garbage, extra/missing keys) is reported as (False, <index that entry would have had>)
        instead of raising; ``load_error`` holds the file line number and reason.

        LIMITATION (QC-7): TAIL TRUNCATION IS NOT DETECTED. Deleting the last N lines leaves a
        shorter chain that still verifies, because nothing outside the file records the expected
        head hash or entry count. Detecting that would need an external anchor (e.g. the head hash
        stored elsewhere); this ledger does not provide one.
        """
        if self.load_error is not None:
            return False, len(self.entries)
        expected_prev = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != expected_prev:
                return False, entry.index
            try:
                recomputed = _content_hash(
                    entry.index, entry.timestamp, entry.host, entry.peak_infiltration_prob,
                    entry.peak_stage, entry.recommended_action, entry.prev_hash,
                )
            except (TypeError, ValueError):
                return False, entry.index
            if recomputed != entry.record_hash:
                return False, entry.index
            expected_prev = entry.record_hash
        return True, None

    def save(self, path: str | Path) -> None:
        """Atomic: writes a temp file in the same directory, fsyncs, then os.replace()s it over
        `path`, so a crash or concurrent reader never sees a half-written ledger."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                for entry in self.entries:
                    f.write(json.dumps(asdict(entry)) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()

    @classmethod
    def append_and_save(
        cls, path: str | Path, host: str, peak_infiltration_prob: float, peak_stage: str,
        recommended_action: str,
    ) -> LedgerEntry:
        """Thread-safe load -> append -> atomic save under LEDGER_LOCK. Refuses (LedgerCorruptError)
        to extend a ledger whose file did not parse, so evidence is never overwritten."""
        with LEDGER_LOCK:
            ledger = cls.load_or_create(path)
            if ledger.load_error is not None:
                line, reason = ledger.load_error
                raise LedgerCorruptError(f"Ledger {path} is corrupt at line {line}: {reason}")
            entry = ledger.append(host, peak_infiltration_prob, peak_stage, recommended_action)
            ledger.save(path)
            return entry

    @classmethod
    def load_or_create(cls, path: str | Path) -> "AuditLedger":
        """Never raises on malformed content: parsing stops at the first bad line (not JSON, not an
        object, missing/extra keys) and records it in ``load_error``, so verify_integrity()
        reports not-intact instead of the caller crashing."""
        path = Path(path)
        with LEDGER_LOCK:
            ledger = cls()
            if not path.exists():
                return ledger
            expected_keys = set(LedgerEntry.__dataclass_fields__)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line_no, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if not isinstance(obj, dict):
                            raise ValueError("line is not a JSON object")
                        if set(obj) != expected_keys:
                            raise ValueError(
                                f"unexpected keys: extra={sorted(set(obj) - expected_keys)} "
                                f"missing={sorted(expected_keys - set(obj))}"
                            )
                        ledger.entries.append(LedgerEntry(**obj))
                    except (ValueError, TypeError) as exc:  # JSONDecodeError is a ValueError
                        ledger.load_error = (line_no, str(exc))
                        break
            return ledger
