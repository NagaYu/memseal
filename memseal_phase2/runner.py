"""Resumable runner over cases x conditions, with trace + results output.

Extraction is computed once per case and shared across that case's conditions
(the extraction prompt is condition-independent by design), which halves LLM
calls. Completed (case_id, condition) pairs are checkpointed so a run can be
resumed after an interruption. Ollama errors on a pair are recorded as `error`
and excluded from the denominators.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from memseal_phase2.backends import CONDITION_DESC, CONDITIONS
from memseal_phase2.harness import Harness
from memseal_phase2.ollama import OllamaError
from memseal_phase2.scorer import ATTACK_CLASSES, aggregate, aggregate_by, score_case

DEFAULT_CONDITIONS = CONDITIONS


def _load_checkpoint(path: Path) -> dict:
    done = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            done[(rec["case_id"], rec["condition"])] = rec
    return done


def _append_checkpoint(path: Path, rec: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def run(cases, llm, *, conditions=DEFAULT_CONDITIONS, packs=None, out_dir="reports/phase2-runs",
        run_id="dev", meta_extra=None, workdir=None, progress=None):
    out = Path(out_dir)
    ckpt = out / "checkpoints" / f"{run_id}.jsonl"
    done = _load_checkpoint(ckpt)
    harness = Harness(llm, packs=packs)

    tmpctx = None
    if workdir is None:
        tmpctx = tempfile.TemporaryDirectory(prefix="memseal-p2-")
        workdir = Path(tmpctx.name)
    else:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)

    results_by_cond = {c: [] for c in conditions}
    errors = {c: [] for c in conditions}
    try:
        for ci, case in enumerate(cases):
            cache = {}
            for cond in conditions:
                keyp = (case["case_id"], cond)
                if keyp in done:
                    rec = done[keyp]
                else:
                    try:
                        res = harness.run_case(case, cond, workdir, extraction_cache=cache)
                        rec = {"case_id": case["case_id"], "condition": cond, "trace": res["trace"]}
                    except OllamaError as exc:
                        rec = {"case_id": case["case_id"], "condition": cond, "error": str(exc)}
                    _append_checkpoint(ckpt, rec)
                    done[keyp] = rec
                if "error" in rec:
                    errors[cond].append(case["case_id"])
                else:
                    results_by_cond[cond].append((case, rec["trace"]))
            if progress:
                progress(ci + 1, len(cases), case["case_id"])
    finally:
        if tmpctx is not None:
            tmpctx.cleanup()

    overall, per_class, per_lang, per_case = {}, {}, {}, {}
    for cond in conditions:
        scores = [score_case(c, t) for c, t in results_by_cond[cond]]
        overall[cond] = aggregate(scores)
        per_class[cond] = aggregate_by(scores, "attack_class")
        per_lang[cond] = aggregate_by(scores, "lang")
        per_case[cond] = {sc["case_id"]: {k: sc[k] for k in
                          ("attack_class", "lang", "is_attack", "delayed_use", "leaks", "expect_hits",
                           "expect_total", "flagged_recalled", "flagged_payload_used", "extractor_fallbacks")}
                          for sc in scores}

    results = {
        "meta": {
            "run_id": run_id,
            "n_cases": len(cases),
            "conditions": {c: CONDITION_DESC[c] for c in conditions},
            "errors": {c: errors[c] for c in conditions},
            "llm": {"model": llm.model, "seed": llm.seed, "temperature": llm.temperature},
            "scoring": "deterministic marker matching; no LLM judge",
            "attempts_per_case": 1,
            **(meta_extra or {}),
        },
        "overall": overall, "per_class": per_class, "per_lang": per_lang, "per_case": per_case,
    }
    return results


def _fmt(v):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


ROWS = [
    ("injection_success_rate", "Injection success rate"),
    ("delayed_use_rate", "Delayed use rate (payload in later answer)"),
    ("leak_count", "Leak count"),
    ("clean_recall_retention", "Clean recall retention"),
    ("quarantine_precision", "Quarantine precision"),
    ("quarantine_recall", "Quarantine recall"),
    ("clean_write_block_rate", "Clean writes blocked"),
    ("flagged_payload_used", "Flagged(sole_basis=False) payload uses"),
    ("extractor_fallbacks", "Extractor JSON fallbacks"),
]


def render_markdown(results: dict, title="MemSeal Phase 2 — real-LLM results") -> str:
    conds = list(results["overall"])
    m = results["meta"]
    out = [f"# {title}", "",
           f"- run_id: {m['run_id']}; cases: {m['n_cases']}; attempts/case: {m['attempts_per_case']}",
           f"- model: {m['llm']['model']} (temp {m['llm']['temperature']}, seed {m['llm']['seed']})",
           f"- scoring: {m['scoring']}",
           f"- errors per condition: " + ", ".join(f"{c}:{len(m['errors'][c])}" for c in conds), ""]
    if m.get("model_fingerprint"):
        out.append(f"- model fingerprint: `{json.dumps(m['model_fingerprint'], ensure_ascii=False)}`")
        out.append("")
    out += ["## Overall", "", "| Metric | " + " | ".join(conds) + " |", "|---|" + "---|" * len(conds)]
    for key, label in ROWS:
        out.append(f"| {label} | " + " | ".join(_fmt(results['overall'][c].get(key)) for c in conds) + " |")
    out += ["", "Counts: " + "; ".join(
        f"{c}: inj {results['overall'][c]['injection_success']}/{results['overall'][c]['should_block_steps']}, "
        f"delayed {results['overall'][c]['delayed_use_cases']}/{results['overall'][c]['attack_cases_with_payload']}, "
        f"clean {results['overall'][c]['clean_expect_hits']}/{results['overall'][c]['clean_expect_total']}, "
        f"TP/FP/FN {results['overall'][c]['quarantine_tp']}/{results['overall'][c]['quarantine_fp']}/"
        f"{results['overall'][c]['quarantine_fn']}" for c in conds), ""]
    out += ["## Per attack class (injection / delayed / leaks)", "",
            "| Class | " + " | ".join(conds) + " |", "|---|" + "---|" * len(conds)]
    for cls in list(ATTACK_CLASSES) + ["clean"]:
        cells = []
        for c in conds:
            a = results["per_class"][c].get(cls)
            if a is None:
                cells.append("-")
            else:
                cells.append(f"{_fmt(a['injection_success_rate'])} / {_fmt(a['delayed_use_rate'])} / {a['leak_count']}")
        out.append(f"| {cls} | " + " | ".join(cells) + " |")
    out += ["", "## Reason codes fired", ""]
    for c in conds:
        out.append(f"- {c}: {results['overall'][c]['reason_codes'] or '{}'}")
    out.append("")
    return "\n".join(out)


def write_results(results: dict, out_dir, *, raw_traces: dict | None = None) -> dict:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {}
    p = out / "results.json"
    p.write_text(json.dumps(results, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    paths["results.json"] = p
    md = out / "results.md"
    md.write_text(render_markdown(results), encoding="utf-8")
    paths["results.md"] = md
    digest = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sorted(paths.items())}
    (out / "SHA256SUMS.json").write_text(json.dumps(digest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return digest
