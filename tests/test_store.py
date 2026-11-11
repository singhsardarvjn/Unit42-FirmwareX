import sqlite3

import pytest

from app.store import GENESIS, Store


@pytest.fixture()
def store(tmp_path):
    return Store(tmp_path / "t.sqlite3")


def test_job_lifecycle(store):
    j = store.create_job("f1", "a.bin", 10, "abc")
    assert j["status"] == "queued" and j["is_sample"] is False
    store.update_job("f1", status="running", progress=40, bogus_field="ignored")
    assert store.get_job("f1")["progress"] == 40
    store.save_report("f1", {"x": 1})
    assert store.get_report("f1") == {"x": 1}
    assert store.get_job_by_job_id(j["job_id"])["firmware_id"] == "f1"
    assert store.count_pending() == 1
    assert store.get_job("missing") is None


def test_fail_interrupted(store):
    store.create_job("f1", "a", 1, "h")
    assert store.fail_interrupted() == 1
    assert store.get_job("f1")["status"] == "failed"


def test_audit_chain_valid(store):
    assert store.verify_audit() == {"valid": True, "entries": 0, "broken_at": None}
    a = store.audit("f1", "one", {"k": 1})
    b = store.audit("f1", "two")
    ev = store.audit_events("f1")
    assert [e["action"] for e in ev] == ["two", "one"]
    assert ev[1]["prev_hash"] == GENESIS and ev[0]["prev_hash"] == a["entry_hash"] == ev[1]["entry_hash"]
    assert b["entry_hash"] == ev[0]["entry_hash"]
    assert store.verify_audit()["valid"] is True


def test_audit_is_append_only(store):
    store.audit("f1", "x")
    with sqlite3.connect(store.db_path) as c:
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("UPDATE audit_log SET action='hacked'")
        with pytest.raises(sqlite3.DatabaseError):
            c.execute("DELETE FROM audit_log")


def test_tampering_is_detected_even_if_triggers_removed(store):
    store.audit("f1", "a")
    store.audit("f1", "b")
    with sqlite3.connect(store.db_path) as c:
        c.execute("DROP TRIGGER audit_no_update")
        c.execute("UPDATE audit_log SET details_json='{\"evil\":1}' WHERE id=1")
    v = store.verify_audit()
    assert v["valid"] is False and v["broken_at"] == 1
