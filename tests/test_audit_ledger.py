import json

from models.audit_ledger import GENESIS_HASH, AuditLedger


def test_append_chains_to_previous_hash():
    ledger = AuditLedger()
    first = ledger.append("10.0.0.9", 0.36, "benign", "No action needed")
    second = ledger.append("10.0.0.5", 0.86, "lateral_movement", "Isolate the host")

    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.record_hash
    assert first.record_hash != second.record_hash


def test_verify_integrity_passes_on_untouched_chain():
    ledger = AuditLedger()
    for i in range(5):
        ledger.append(f"10.0.0.{i}", i / 10, "benign", "No action needed")

    ok, bad_index = ledger.verify_integrity()
    assert ok is True
    assert bad_index is None


def test_verify_integrity_empty_chain_is_valid():
    ledger = AuditLedger()
    ok, bad_index = ledger.verify_integrity()
    assert ok is True
    assert bad_index is None


def test_tampering_with_a_field_is_detected():
    ledger = AuditLedger()
    ledger.append("10.0.0.9", 0.36, "benign", "No action needed")
    ledger.append("10.0.0.5", 0.86, "lateral_movement", "Isolate the host")
    ledger.append("10.0.0.7", 0.20, "benign", "No action needed")

    # Tamper with the middle entry's probability after the fact, as an attacker covering their
    # tracks might try to -- this must invalidate that entry's own hash.
    tampered = ledger.entries[1].__class__(**{**ledger.entries[1].__dict__, "peak_infiltration_prob": 0.01})
    ledger.entries[1] = tampered

    ok, bad_index = ledger.verify_integrity()
    assert ok is False
    assert bad_index == 1


def test_tampering_is_detected_even_if_attacker_recomputes_that_entrys_own_hash():
    """The stronger guarantee: even if an attacker edits a record AND recalculates its own
    record_hash to match the edited content, the NEXT entry's prev_hash still points at the old
    (correct) hash -- so the chain still breaks, just one entry later."""
    ledger = AuditLedger()
    ledger.append("10.0.0.9", 0.36, "benign", "No action needed")
    ledger.append("10.0.0.5", 0.86, "lateral_movement", "Isolate the host")

    from models.audit_ledger import _content_hash
    original = ledger.entries[0]
    forged_prob = 0.01
    forged_hash = _content_hash(
        original.index, original.timestamp, original.host, forged_prob,
        original.peak_stage, original.recommended_action, original.prev_hash,
    )
    forged = original.__class__(**{**original.__dict__, "peak_infiltration_prob": forged_prob, "record_hash": forged_hash})
    ledger.entries[0] = forged

    ok, bad_index = ledger.verify_integrity()
    assert ok is False
    assert bad_index == 1  # the second entry's prev_hash no longer matches the forged first hash


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger()
    ledger.append("10.0.0.9", 0.36, "benign", "No action needed")
    ledger.append("10.0.0.5", 0.86, "lateral_movement", "Isolate the host")
    ledger.save(path)

    reloaded = AuditLedger.load_or_create(path)
    assert len(reloaded.entries) == 2
    assert reloaded.entries == ledger.entries
    ok, _ = reloaded.verify_integrity()
    assert ok is True


def test_load_or_create_returns_empty_ledger_for_missing_file(tmp_path):
    ledger = AuditLedger.load_or_create(tmp_path / "does_not_exist.jsonl")
    assert ledger.entries == []


def test_saved_file_is_one_json_object_per_line(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger()
    ledger.append("10.0.0.9", 0.36, "benign", "No action needed")
    ledger.save(path)

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["host"] == "10.0.0.9"
    assert row["prev_hash"] == GENESIS_HASH
