import dataclasses

import pytest

from memseal.envelope import (
    GENESIS_HASH,
    Envelope,
    build_envelope,
    canonical_json,
    make_entry_id,
    tier_for_source,
    verify_chain,
    worst_tier,
)


def _chain(n=4):
    envs = []
    prev = GENESIS_HASH
    for i in range(n):
        e = build_envelope(seq=i, content=f"fact number {i}", entry_class="fact",
                           source_class="user_explicit", principal="u-alice",
                           prev_hash=prev, trust_tier=0)
        envs.append(e)
        prev = e.hash
    return envs


def test_trust_tier_mapping_is_fixed():
    assert tier_for_source("user_explicit") == 0
    assert tier_for_source("user_conversation") == 1
    assert tier_for_source("agent_inference") == 2
    assert tier_for_source("document") == 3
    assert tier_for_source("tool_output") == 3
    assert tier_for_source("external_agent") == 4
    with pytest.raises(ValueError):
        tier_for_source("admin")


def test_worst_tier_is_least_trusted():
    assert worst_tier([0, 3, 1]) == 3


def test_entry_id_is_seq_plus_content_hash_and_deterministic():
    a = make_entry_id(7, "hello")
    assert a.startswith("e000007-") and len(a) == len("e000007-") + 12
    assert a == make_entry_id(7, "hello")
    assert a != make_entry_id(7, "hello!")
    assert a != make_entry_id(8, "hello")


def test_canonical_json_is_key_order_independent():
    assert canonical_json({"b": 1, "a": "x"}) == canonical_json({"a": "x", "b": 1})


def test_sealed_only_for_user_explicit_fact():
    with pytest.raises(ValueError):
        build_envelope(seq=0, content="x", entry_class="fact", source_class="document",
                       principal="u", prev_hash=GENESIS_HASH, trust_tier=3, sealed=True)
    with pytest.raises(ValueError):
        build_envelope(seq=0, content="x", entry_class="preference", source_class="user_explicit",
                       principal="u", prev_hash=GENESIS_HASH, trust_tier=0, sealed=True)
    e = build_envelope(seq=0, content="x", entry_class="fact", source_class="user_explicit",
                       principal="u", prev_hash=GENESIS_HASH, trust_tier=0, sealed=True)
    assert e.sealed


def test_roundtrip_dict():
    e = _chain(1)[0]
    assert Envelope.from_dict(e.to_dict()) == e


def test_valid_chain_has_no_issues():
    issues, bad = verify_chain(_chain())
    assert issues == [] and bad == set()


def test_detects_in_place_content_edit():
    envs = _chain()
    envs[2] = dataclasses.replace(envs[2], content="tampered")
    issues, bad = verify_chain(envs)
    kinds = {i.kind for i in issues}
    assert "hash_mismatch" in kinds and "entry_id_mismatch" in kinds
    assert envs[2].entry_id in bad
    assert envs[0].entry_id not in bad and envs[3].entry_id not in bad


def test_detects_edit_with_recomputed_hash():
    envs = _chain()
    t = dataclasses.replace(envs[1], content="tampered", entry_id=make_entry_id(1, "tampered"))
    t.hash = t.compute_hash()
    envs[1] = t
    issues, bad = verify_chain(envs)
    assert any(i.kind == "link_break" and i.seq == 2 for i in issues)
    assert t.entry_id in bad and envs[2].entry_id in bad
    assert envs[0].entry_id not in bad and envs[3].entry_id not in bad


def test_detects_deletion():
    envs = _chain()
    del envs[1]
    issues, bad = verify_chain(envs)
    kinds = {i.kind for i in issues}
    assert "link_break" in kinds and "seq_gap" in kinds


def test_detects_provenance_field_tamper():
    envs = _chain()
    envs[3] = dataclasses.replace(envs[3], source_class="document")
    issues, bad = verify_chain(envs)
    assert envs[3].entry_id in bad
