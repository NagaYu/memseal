import json

import pytest

from memseal.policy import WritePolicy, raw_write
from memseal.recall import recall
from memseal.store import FileStore


@pytest.fixture
def pol(tmp_path):
    return WritePolicy(FileStore.create(tmp_path / "s", "u-alice"))


def W(pol, content, source_class="user_explicit", entry_class="fact", **kw):
    return pol.write(content=content, entry_class=entry_class, source_class=source_class,
                     principal="u-alice", **kw).entry


def _tamper(store, needle, replacement):
    p = store.log_path
    p.write_text(p.read_text(encoding="utf-8").replace(needle, replacement), encoding="utf-8")


def test_provenance_attached_to_every_entry(pol):
    a = W(pol, "Alice lives in Lyon.")
    d = W(pol, "Lyon office opens at 9.", source_class="document")
    res = recall(pol.store, "u-alice", ["lyon"])
    assert [e.entry_id for e in res.entries] == [a.entry_id, d.entry_id]
    for e in res.entries:
        assert set(e.provenance) == {"source_class", "trust_tier", "derived_from"}
    assert res.entries[1].provenance == {"source_class": "document", "trust_tier": "T3", "derived_from": []}


def test_sole_basis_flag_by_tier(pol):
    for src in ("user_explicit", "user_conversation", "agent_inference", "document", "tool_output", "external_agent"):
        W(pol, f"note from {src}", source_class=src, entry_class="episode")
    flags = {e.provenance["source_class"]: e.sole_basis_for_irreversible
             for e in recall(pol.store, "u-alice", ["note from"]).entries}
    assert flags == {"user_explicit": True, "user_conversation": True, "agent_inference": True,
                     "document": False, "tool_output": False, "external_agent": False}


def test_derived_entry_flag_follows_inherited_tier(pol):
    a = W(pol, "Alice lives in Lyon.")
    d = W(pol, "Rent goes to IBAN FR00-EVIL.", source_class="document")
    m = pol.write(content="Lyon rent IBAN FR00-EVIL", entry_class="fact", source_class="agent_inference",
                  principal="u-alice", derived_from=[a.entry_id, d.entry_id]).entry
    got = {e.entry_id: e for e in recall(pol.store, "u-alice", ["IBAN"]).entries}
    assert got[m.entry_id].sole_basis_for_irreversible is False
    assert got[m.entry_id].provenance["derived_from"] == [a.entry_id, d.entry_id]


def test_chain_failure_excluded_and_warned(pol):
    a = W(pol, "Alice's manager is Dana.")
    b = W(pol, "Alice's bank is Credit Lyonnais.")
    c = W(pol, "Alice likes tea.", entry_class="preference")
    _tamper(pol.store, "Credit Lyonnais", "Evil Bank")
    res = recall(pol.store, "u-alice")
    ids = [e.entry_id for e in res.entries]
    assert b.entry_id not in ids and a.entry_id in ids and c.entry_id in ids
    assert b.entry_id in res.excluded_ids
    assert any(w["entry_id"] == b.entry_id and w["kind"] == "hash_mismatch" for w in res.warnings)
    # The unguarded baseline returns the tampered content.
    raw = recall(pol.store, "u-alice", guarded=False)
    assert any("Evil Bank" in e.content for e in raw.entries)


def test_tampered_supersedes_cannot_hide_verified_entry(pol):
    a = W(pol, "Lyon", slot="home_city", sealed=True)
    b = W(pol, "Alice likes tea.", entry_class="preference")
    lines = pol.store.log_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["supersedes"] = [a.entry_id]
    lines[1] = json.dumps(rec)
    pol.store.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ids = [e.entry_id for e in recall(pol.store, "u-alice").entries]
    assert a.entry_id in ids and b.entry_id not in ids


def test_principal_filter(tmp_path):
    s = FileStore.create(tmp_path / "shared", "u-alice")
    raw_write(s, content="Alice's PIN hint: cat name", entry_class="fact",
              source_class="user_explicit", principal="u-alice")
    raw_write(s, content="Bob's diagnosis: diabetes", entry_class="fact",
              source_class="user_explicit", principal="u-bob")
    res = recall(s, "u-alice")
    assert [e.principal for e in res.entries] == ["u-alice"]
    assert res.filtered_foreign_principal == 1
    assert [e.content for e in recall(s, "u-bob").entries] == ["Bob's diagnosis: diabetes"]
    # Unguarded baseline leaks across principals.
    assert len(recall(s, "u-alice", guarded=False).entries) == 2


def test_superseded_versions_not_returned(pol):
    W(pol, "Lyon", slot="home_city", sealed=True)
    W(pol, "Paris", slot="home_city", sealed=True)
    assert [e.content for e in recall(pol.store, "u-alice").entries] == ["Paris"]


def test_term_matching_is_case_and_width_insensitive(pol):
    W(pol, "ユーザーは ＴＯＫＹＯ 在住")
    assert recall(pol.store, "u-alice", ["tokyo"]).entries
    assert not recall(pol.store, "u-alice", ["osaka"]).entries


def test_slot_name_is_searchable(pol):
    W(pol, "Lyon", slot="home_city", sealed=True)
    assert [e.content for e in recall(pol.store, "u-alice", ["home_city"]).entries] == ["Lyon"]
    assert [e.content for e in recall(pol.store, "u-alice", ["home_city"], guarded=False).entries] == ["Lyon"]
