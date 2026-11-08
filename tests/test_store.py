import json

import pytest

from memseal.envelope import GENESIS_HASH
from memseal.store import FileStore, PrincipalScopeError, StoreError


def _w(store, content, **kw):
    args = dict(content=content, entry_class="fact", source_class="user_explicit",
                principal=store.principal, trust_tier=0)
    args.update(kw)
    return store.append(**args)


@pytest.fixture
def store(tmp_path):
    return FileStore.create(tmp_path / "s", "u-alice")


def test_create_and_reopen(store, tmp_path):
    assert store.version() == 0 and store.head_hash() == GENESIS_HASH
    _w(store, "Alice lives in Lyon")
    reopened = FileStore(tmp_path / "s")
    assert reopened.principal == "u-alice"
    assert [e.content for e in reopened.entries()] == ["Alice lives in Lyon"]


def test_create_twice_fails(store, tmp_path):
    with pytest.raises(StoreError):
        FileStore.create(tmp_path / "s", "u-alice")


def test_open_non_store_fails(tmp_path):
    with pytest.raises(StoreError):
        FileStore(tmp_path)


def test_append_chains_and_versions(store):
    a = _w(store, "one")
    b = _w(store, "two")
    assert a.seq == 0 and b.seq == 1
    assert a.prev_hash == GENESIS_HASH and b.prev_hash == a.hash
    assert store.version() == 2 and store.head_hash() == b.hash
    assert store.get(b.entry_id) == b
    assert store.verify() == ([], set())


def test_principal_scope_enforced(store):
    with pytest.raises(PrincipalScopeError):
        _w(store, "Bob's note", principal="u-bob")
    assert store.version() == 0
    # Only the policy-free baseline may bypass the scope check.
    _w(store, "Bob's note", principal="u-bob", enforce_principal=False)
    assert store.entries_for("u-alice") == []
    assert [e.content for e in store.entries_for("u-bob")] == ["Bob's note"]


def test_supersedes_hides_old_version(store):
    old = _w(store, "Lyon", slot="home_city", sealed=True)
    new = _w(store, "Paris", slot="home_city", sealed=True, supersedes=[old.entry_id])
    assert [e.entry_id for e in store.active_entries()] == [new.entry_id]
    assert len(store.entries()) == 2  # history is kept


def test_snapshot_and_rollback(store):
    _w(store, "one")
    snap = store.snapshot("before-import")
    _w(store, "poison", source_class="document", trust_tier=3, entry_class="instruction")
    assert store.version() == 2
    res = store.rollback("before-import")
    assert res["version"] == 1 and store.version() == 1
    assert store.head_hash() == snap["head_hash"]
    assert [e.content for e in store.entries()] == ["one"]
    # The removed tail is archived, not discarded.
    archived = (store.root / "archive" / res["archive"]).read_text(encoding="utf-8")
    assert "poison" in archived
    assert store.queue("audit")[-1]["event"] == "rollback"
    # Chain is valid after rollback and appends continue from the snapshot head.
    nxt = _w(store, "two")
    assert nxt.seq == 1 and nxt.prev_hash == snap["head_hash"]
    assert store.verify() == ([], set())


def test_rollback_restores_tampered_prefix(store):
    _w(store, "one")
    _w(store, "two")
    store.snapshot("good")
    lines = store.log_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["content"] = "tampered"
    lines[0] = json.dumps(rec)
    store.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert store.verify()[0]
    store.rollback("good")
    assert store.verify() == ([], set())
    assert store.entries()[0].content == "one"


def test_rollback_to_version(store):
    for c in ("a", "b", "c"):
        _w(store, c)
    store.rollback_to_version(1)
    assert [e.content for e in store.entries()] == ["a"]
    with pytest.raises(StoreError):
        store.rollback_to_version(5)


def test_snapshot_name_validation_and_duplicates(store):
    store.snapshot("s1")
    with pytest.raises(StoreError):
        store.snapshot("s1")
    with pytest.raises(StoreError):
        store.snapshot("../evil")
    with pytest.raises(StoreError):
        store.rollback("missing")
    assert store.snapshots() == ["s1"]


def test_tamper_detected_by_verify(store):
    _w(store, "one")
    _w(store, "two")
    text = store.log_path.read_text(encoding="utf-8").replace('"two"', '"evil"')
    store.log_path.write_text(text, encoding="utf-8")
    issues, bad = store.verify()
    assert {i.kind for i in issues} >= {"hash_mismatch"}
    assert len(bad) == 1


def test_malformed_line_reported(store):
    _w(store, "one")
    with open(store.log_path, "a", encoding="utf-8") as f:
        f.write("{not json\n")
    issues, _ = store.verify()
    assert any(i.kind == "malformed" for i in issues)


def test_queues(store):
    store.enqueue("quarantine", {"reasons": ["W1"]})
    store.enqueue("quarantine", {"reasons": ["W2"]})
    q = store.queue("quarantine")
    assert [r["queue_seq"] for r in q] == [0, 1]
    with pytest.raises(StoreError):
        store.enqueue("nope", {})
