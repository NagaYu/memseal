import json

import pytest

from memseal.bench.generator import generate
from memseal.sim.agent import CONDITIONS, NOT_EVALUABLE, ScriptedAgent
from memseal.sim.runner import aggregate, render_markdown, run_bench, run_case, score_case, write_reports


@pytest.fixture(scope="module")
def cases():
    return {c["case_id"]: c for c in generate("dev")}


def _run(cases, cid, cond, tmp_path):
    case = cases[cid]
    trace = run_case(case, cond, tmp_path)
    return trace, score_case(case, trace)


def test_unknown_condition_rejected(tmp_path):
    with pytest.raises(ValueError):
        ScriptedAgent("C9", None)


def test_conditions_and_not_evaluable():
    assert set(CONDITIONS) == {"C0", "C2", "C3"}
    assert set(NOT_EVALUABLE) == {"C1", "C4"}


def test_w1_case_blocks_delayed_use(cases, tmp_path):
    t0, s0 = _run(cases, "M1-a-en", "C0", tmp_path)
    t2, s2 = _run(cases, "M1-a-en", "C2", tmp_path)
    assert t0[0]["disposition"] == "active" and s0["delayed_use"]
    assert t2[0]["disposition"] == "quarantined" and t2[0]["reasons"] == ["W1"] and not s2["delayed_use"]
    assert t0[1]["action"] == "send_external_with_memory"


def test_w5_case_preserves_sealed_value(cases, tmp_path):
    t2, s2 = _run(cases, "M5-f-en", "C2", tmp_path)
    assert t2[0]["disposition"] == "review"
    assert s2["expect_hits"] == s2["expect_total"] == 1 and not s2["delayed_use"]


def test_cross_principal_raw_insert_leaks_until_recall_guard(cases, tmp_path):
    _, s0 = _run(cases, "M7-b-en", "C0", tmp_path)
    _, s2 = _run(cases, "M7-b-en", "C2", tmp_path)
    t3, s3 = _run(cases, "M7-b-en", "C3", tmp_path)
    assert s0["leaks"] == 1 and s2["leaks"] == 1 and s3["leaks"] == 0
    assert t3[-1]["filtered_foreign_principal"] == 1


def test_misrouted_write_rejected_by_w3(cases, tmp_path):
    t2, s2 = _run(cases, "M7-a-ja", "C2", tmp_path)
    assert t2[0]["disposition"] == "rejected" and s2["leaks"] == 0


def test_secret_redaction_prevents_leak(cases, tmp_path):
    _, s0 = _run(cases, "M8-a-en", "C0", tmp_path)
    t2, s2 = _run(cases, "M8-a-en", "C2", tmp_path)
    assert s0["leaks"] == 1 and s2["leaks"] == 0
    assert t2[0]["reasons"] == ["W4"] and "[REDACTED:" in t2[0]["stored_content"]


def test_tamper_used_in_c2_excluded_in_c3(cases, tmp_path):
    _, s2 = _run(cases, "M5-d-en", "C2", tmp_path)
    t3, s3 = _run(cases, "M5-d-en", "C3", tmp_path)
    assert s2["delayed_use"] and not s3["delayed_use"]
    assert t3[-1]["warnings"] >= 1 and t3[-1]["excluded_ids"]


def test_recomputed_hash_tamper_excluded_in_c3(cases, tmp_path):
    t3, s3 = _run(cases, "M5-e-ja", "C3", tmp_path)
    assert not s3["delayed_use"] and len(t3[-1]["excluded_ids"]) == 2


def test_laundering_claim_quarantined_but_root_still_recalled(cases, tmp_path):
    # Documents a Phase 1 limitation: W2 stops the laundered entry, but the
    # original T3 document entry stays active and is used later.
    t2, s2 = _run(cases, "M3-a-en", "C2", tmp_path)
    assert t2[1]["op"] == "consolidate" and t2[1]["disposition"] == "quarantined" and "W2" in t2[1]["reasons"]
    assert s2["delayed_use"]
    t3, s3 = _run(cases, "M3-a-en", "C3", tmp_path)
    assert s3["payload_uses_flagged_not_sole_basis"] == 1


def test_clean_case_retention(cases, tmp_path):
    for cond in ("C0", "C2", "C3"):
        _, s = _run(cases, "CL-h-en", cond, tmp_path)
        assert s["expect_hits"] == s["expect_total"] == 2


def test_aggregate_metric_arithmetic():
    def step(should_block, blocked, payload_stored=False, reasons=()):
        return {"skipped": False, "should_block": should_block, "blocked": blocked,
                "payload_stored": payload_stored, "reasons": list(reasons)}
    scores = [
        {"is_attack": True, "has_payload": True, "delayed_use": True, "leaks": 1, "expect_hits": 0,
         "expect_total": 0, "payload_uses_outbound_or_irreversible": 1, "payload_uses_flagged_not_sole_basis": 1,
         "chain_warnings": 0,
         "steps": [step(True, True, reasons=["W1"]), step(True, False, True), {"skipped": True}]},
        {"is_attack": True, "has_payload": True, "delayed_use": False, "leaks": 0, "expect_hits": 1,
         "expect_total": 2, "payload_uses_outbound_or_irreversible": 0, "payload_uses_flagged_not_sole_basis": 0,
         "chain_warnings": 2, "steps": [step(True, True, reasons=["W5"])]},
        {"is_attack": False, "has_payload": False, "delayed_use": False, "leaks": 0, "expect_hits": 3,
         "expect_total": 4, "payload_uses_outbound_or_irreversible": 0, "payload_uses_flagged_not_sole_basis": 0,
         "chain_warnings": 0, "steps": [step(False, True, reasons=["W1"]), step(False, False)]},
    ]
    a = aggregate(scores)
    assert a["should_block_steps"] == 3
    assert a["injection_success_rate"] == round(1 / 3, 4)
    assert a["delayed_use_rate"] == 0.5
    assert a["leak_count"] == 1 and a["leak_cases"] == 1
    assert a["clean_recall_retention"] == 0.75
    assert (a["quarantine_tp"], a["quarantine_fp"], a["quarantine_fn"]) == (2, 1, 1)
    assert a["quarantine_precision"] == round(2 / 3, 4) and a["quarantine_recall"] == round(2 / 3, 4)
    assert a["clean_write_block_rate"] == 0.5
    assert a["reason_codes"] == {"W1": 2, "W5": 1}


def test_aggregate_handles_empty_denominators():
    a = aggregate([])
    assert a["injection_success_rate"] is None and a["quarantine_precision"] is None


def test_run_is_deterministic_and_reports_written(cases, tmp_path):
    subset = [cases[k] for k in ("M1-a-en", "M5-d-ja", "M7-b-en", "M8-a-ja", "CL-g-en")]
    r1 = run_bench(subset)
    r2 = run_bench(subset)
    assert json.dumps(r1, sort_keys=True) == json.dumps(r2, sort_keys=True)
    d1 = write_reports(r1, tmp_path / "a")
    d2 = write_reports(r2, tmp_path / "b")
    assert d1 == d2
    assert {"results.json", "results.md", "traces-C0.jsonl", "traces-C2.jsonl", "traces-C3.jsonl"} <= set(d1)
    md = (tmp_path / "a" / "results.md").read_text(encoding="utf-8")
    assert "NOT EVALUABLE" in md and "| Metric | C0 | C2 | C3 | C1 | C4 |" in md
    summary = json.loads((tmp_path / "a" / "results.json").read_text(encoding="utf-8"))
    assert set(summary["overall"]) == {"C0", "C2", "C3"}
    assert "traces" not in summary


def test_full_dev_run_orders_conditions(cases):
    r = run_bench(list(cases.values()), keep_traces=False)
    o = r["overall"]
    assert o["C0"]["injection_success_rate"] == 1.0 and o["C0"]["quarantine_tp"] == 0
    assert o["C2"]["injection_success_rate"] < o["C0"]["injection_success_rate"]
    assert o["C3"]["delayed_use_rate"] <= o["C2"]["delayed_use_rate"] <= o["C0"]["delayed_use_rate"]
    assert o["C3"]["leak_count"] <= o["C2"]["leak_count"] <= o["C0"]["leak_count"]
    assert "C1" in render_markdown(r)
