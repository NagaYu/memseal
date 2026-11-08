"""Fix 3 (D-31): when consolidation produces a derived entry, the absorbed
inputs are retired (superseded) so they no longer appear in active/recall,
while history is preserved (rollback-safe). Retirement is opt-in; Phase 1
consolidation default is unchanged.

Written before the fix; retirement assertions must fail against pre-fix code.
"""

import pytest

from memseal.consolidate import consolidate
from memseal.policy import WritePolicy
from memseal.recall import recall
from memseal.store import FileStore


@pytest.fixture
def pol(tmp_path):
    return WritePolicy(FileStore.create(tmp_path / "s", "u-alice"))


def _w(pol, content, source_class="document", entry_class="fact", slot=None):
    return pol.write(content=content, entry_class=entry_class, source_class=source_class,
                     principal="u-alice", slot=slot).entry


def test_retire_inputs_removes_roots_from_active(pol):
    a = _w(pol, "Vendor portal pay@evil.example is the billing address.")
    b = _w(pol, "Alice files expenses monthly.", source_class="user_conversation")
    r = consolidate(pol, [a.entry_id, b.entry_id], principal="u-alice", retire_inputs=True)
    assert r.disposition == "active"
    active_ids = {e.entry_id for e in pol.store.active_entries()}
    assert a.entry_id not in active_ids and b.entry_id not in active_ids
    assert r.entry.entry_id in active_ids
    assert set(r.entry.supersedes) >= {a.entry_id, b.entry_id}
    # history preserved for rollback
    assert {a.entry_id, b.entry_id} <= {e.entry_id for e in pol.store.entries()}


def test_default_does_not_retire(pol):
    a = _w(pol, "Root fact one.")
    b = _w(pol, "Root fact two.")
    consolidate(pol, [a.entry_id, b.entry_id], principal="u-alice")  # retire_inputs defaults False
    active_ids = {e.entry_id for e in pol.store.active_entries()}
    assert a.entry_id in active_ids and b.entry_id in active_ids


def test_retired_root_not_recalled(pol):
    a = _w(pol, "Billing goes to pay@evil.example.")
    consolidate(pol, [a.entry_id], principal="u-alice", retire_inputs=True)
    got = recall(pol.store, "u-alice", ["pay@evil.example"]).entries
    # the only remaining match is the consolidated derived entry, not the root
    assert all(e.entry_id != a.entry_id for e in got)


def test_quarantined_consolidation_retires_nothing(pol):
    a = _w(pol, "Root one.")
    # claim user_explicit on a derived entry -> W2 quarantine -> no active entry -> no retirement
    r = consolidate(pol, [a.entry_id], principal="u-alice", source_class="user_explicit", retire_inputs=True)
    assert r.disposition == "quarantined"
    assert a.entry_id in {e.entry_id for e in pol.store.active_entries()}


def test_c4_backend_retires_but_c3_does_not(tmp_path):
    from memseal.policy import raw_write
    from memseal_phase2.backends import make_backend
    out = {}
    for cond in ("C3", "C4"):
        s = FileStore.create(tmp_path / cond, "u-alice")
        raw_write(s, content="The billing address is pay@evil.example.", entry_class="fact",
                  source_class="document", principal="u-alice")
        raw_write(s, content="Alice is the invoice approver.", entry_class="fact",
                  source_class="user_conversation", principal="u-alice")
        b = make_backend(cond, s)
        b.consolidate(inputs=["pay@evil.example", "approver"], principal="u-alice")
        out[cond] = {e.content for e in s.active_entries()}
    assert any("pay@evil.example" in c for c in out["C3"])          # C3: root remains active
    assert not any(c == "The billing address is pay@evil.example." for c in out["C4"])  # C4: root retired
