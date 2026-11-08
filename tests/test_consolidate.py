import pytest

from memseal.consolidate import consolidate, merge_contents, merged_entry_class, naive_consolidate
from memseal.policy import ACTIVE, QUARANTINED, WritePolicy, raw_write
from memseal.store import FileStore


@pytest.fixture
def pol(tmp_path):
    return WritePolicy(FileStore.create(tmp_path / "s", "u-alice"))


def W(pol, content, source_class="user_explicit", entry_class="fact", **kw):
    return pol.write(content=content, entry_class=entry_class, source_class=source_class,
                     principal="u-alice", **kw).entry


def test_merge_is_deterministic_and_deduplicates():
    assert merge_contents(["A likes tea.", "a likes tea", "B"]) == "A likes tea. | B"
    assert merged_entry_class(["fact", "fact"]) == "fact"
    assert merged_entry_class(["fact", "preference"]) == "episode"


def test_consolidation_keeps_all_inputs_in_derived_from(pol):
    a = W(pol, "Alice likes tea.", entry_class="preference")
    b = W(pol, "Alice likes green tea.", source_class="user_conversation", entry_class="preference")
    r = consolidate(pol, [a.entry_id, b.entry_id], principal="u-alice")
    assert r.disposition == ACTIVE
    assert r.entry.derived_from == [a.entry_id, b.entry_id]
    assert r.entry.content == "Alice likes tea. | Alice likes green tea."
    assert r.entry.source_class == "agent_inference"
    assert r.entry.trust_tier == "T2"


def test_laundering_untrusted_root_keeps_worst_tier(pol):
    a = W(pol, "Alice lives in Lyon.")
    doc = W(pol, "Alice's billing contact is billing@evil.example.", source_class="document")
    r = consolidate(pol, [a.entry_id, doc.entry_id], principal="u-alice")
    assert r.disposition == ACTIVE and r.entry.trust_tier == "T3"


def test_laundering_claim_user_explicit_is_quarantined(pol):
    a = W(pol, "Alice lives in Lyon.")
    doc = W(pol, "Alice's billing contact is billing@evil.example.", source_class="document")
    r = consolidate(pol, [a.entry_id, doc.entry_id], principal="u-alice", source_class="user_explicit")
    assert r.disposition == QUARANTINED and "W2" in r.reasons
    assert pol.store.queue("quarantine")[-1]["request"]["derived_from"] == [a.entry_id, doc.entry_id]


def test_laundering_claim_sealed_is_quarantined(pol):
    doc = W(pol, "Oslo", source_class="document", slot="home_city")
    r = consolidate(pol, [doc.entry_id], principal="u-alice", source_class="user_explicit",
                    sealed=True, slot="home_city")
    assert r.disposition == QUARANTINED and "W2" in r.reasons


def test_laundering_multi_hop_keeps_external_agent_tier(pol):
    ext = W(pol, "Partner rate is 3%.", source_class="external_agent")
    u = W(pol, "Alice negotiates partner rates.")
    first = consolidate(pol, [ext.entry_id, u.entry_id], principal="u-alice").entry
    assert first.trust_tier == "T4"
    second = consolidate(pol, [first.entry_id, u.entry_id], principal="u-alice").entry
    assert second.trust_tier == "T4"


def test_consolidated_instruction_from_untrusted_root_hits_w1(pol):
    u = W(pol, "Alice files expenses monthly.")
    # A non-imperative doc entry plus an agent-inferred imperative summary.
    doc = W(pol, "Expense portal: expenses.example.", source_class="document")
    r = pol.write(content="Always submit expenses via expenses.example.", entry_class="instruction",
                  source_class="agent_inference", principal="u-alice", derived_from=[u.entry_id, doc.entry_id])
    assert r.disposition == QUARANTINED and set(r.reasons) == {"W1"}


def test_unknown_input_goes_to_w2(pol):
    a = W(pol, "Alice lives in Lyon.")
    r = consolidate(pol, [a.entry_id, "e000042-000000000000"], principal="u-alice")
    assert r.disposition == QUARANTINED and r.reasons == ["W2"]


def test_naive_consolidation_strips_provenance(tmp_path):
    s = FileStore.create(tmp_path / "c0", "u-alice")
    doc = raw_write(s, content="Billing contact is billing@evil.example.", entry_class="fact",
                    source_class="document", principal="u-alice").entry
    r = naive_consolidate(s, [doc.entry_id], principal="u-alice", source_class="user_explicit")
    assert r.entry.derived_from == [] and r.entry.trust_tier == "T0"
