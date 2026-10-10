"""QC-5/6/7: concurrency-safe, atomic, corruption-tolerant audit ledger."""
import json
import threading
from dataclasses import asdict

import pytest
from fastapi.testclient import TestClient

from models.audit_ledger import AuditLedger, LedgerCorruptError


def test_concurrent_appends_lose_no_entries(tmp_path):
    path = tmp_path / "ledger.jsonl"
    n_threads, per_thread = 8, 10
    errors = []

    def work(t):
        try:
            for i in range(per_thread):
                AuditLedger.append_and_save(path, f"10.0.{t}.{i}", 0.5, "benign", "none")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(t,)) for t in range(n_threads)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert not errors
    ledger = AuditLedger.load_or_create(path)
    assert len(ledger.entries) == n_threads * per_thread
    assert [e.index for e in ledger.entries] == list(range(n_threads * per_thread))
    assert ledger.verify_integrity() == (True, None)
    assert not list(tmp_path.glob("*.tmp"))  # no temp files left behind


def test_save_is_atomic_leaves_old_file_if_write_fails(tmp_path, monkeypatch):
    path = tmp_path / "l.jsonl"
    AuditLedger.append_and_save(path, "h", 0.1, "benign", "x")
    before = path.read_text(encoding="utf-8")
    ledger = AuditLedger.load_or_create(path)
    ledger.append("h2", 0.2, "benign", "x")
    import models.audit_ledger as al
    monkeypatch.setattr(al.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
    with pytest.raises(OSError):
        ledger.save(path)
    assert path.read_text(encoding="utf-8") == before
    assert not list(tmp_path.glob("*.tmp"))


def _good_lines(tmp_path, n=2):
    path = tmp_path / "l.jsonl"
    for i in range(n):
        AuditLedger.append_and_save(path, f"h{i}", 0.1, "benign", "x")
    return path


def test_garbage_line_verifies_as_not_intact_without_raising(tmp_path):
    path = _good_lines(tmp_path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("this is not json\n")
    ledger = AuditLedger.load_or_create(path)
    ok, bad = ledger.verify_integrity()
    assert ok is False and bad == 2
    assert ledger.load_error[0] == 3


def test_extra_key_line_verifies_as_not_intact_without_raising(tmp_path):
    path = _good_lines(tmp_path)
    entry = asdict(AuditLedger.load_or_create(path).entries[-1])
    entry["extra"] = 1
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    ok, bad = AuditLedger.load_or_create(path).verify_integrity()
    assert ok is False and bad == 2


def test_non_object_and_wrong_type_lines_do_not_raise(tmp_path):
    path = _good_lines(tmp_path, 1)
    with open(path, "a", encoding="utf-8") as f:
        f.write("[1, 2]\n")
    assert AuditLedger.load_or_create(path).verify_integrity()[0] is False


def test_append_to_corrupt_ledger_refuses_and_keeps_file(tmp_path):
    path = _good_lines(tmp_path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("garbage\n")
    before = path.read_text(encoding="utf-8")
    with pytest.raises(LedgerCorruptError):
        AuditLedger.append_and_save(path, "h", 0.1, "benign", "x")
    assert path.read_text(encoding="utf-8") == before


def test_tail_truncation_is_documented_as_undetected(tmp_path):
    path = _good_lines(tmp_path, 3)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert AuditLedger.load_or_create(path).verify_integrity() == (True, None)
    assert "TAIL TRUNCATION IS NOT DETECTED" in AuditLedger.verify_integrity.__doc__


def test_system_status_reports_not_intact_instead_of_500(tmp_path):
    import app.server as server
    path = _good_lines(tmp_path)
    with open(path, "a", encoding="utf-8") as f:
        f.write("garbage\n")
    original = server._ledger_path
    server._ledger_path = lambda: path
    try:
        resp = TestClient(server.app).get("/api/v1/system/status")
    finally:
        server._ledger_path = original
    assert resp.status_code == 200, resp.text
    assert resp.json()["ledger_intact"] is False
