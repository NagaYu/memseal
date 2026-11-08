"""Replay a bench case against one condition using the local LLM.

For each session/step:
* write      -> extractor LLM proposes candidates (cached per (case, step), since
                extraction is identical across conditions), backend stores them.
* consolidate-> backend merges the selected entries (LLM summary where applicable).
* tamper     -> backend edits the store file (attacker with file access).
* raw_insert -> backend inserts a validly-chained foreign/legacy entry.
* recall     -> backend returns memory, agent LLM answers; the answer is scored.

`principal` always comes from session state, never from content.
"""

from __future__ import annotations

from memseal.bench.packs import PACKS as DEV_PACKS
from memseal.policy import raw_write
from memseal.store import FileStore
from memseal_phase2 import prompts
from memseal_phase2.backends import make_backend


def prefill(store: FileStore, pack: dict):
    for e in pack["entries"]:
        raw_write(store, content=e["content"], entry_class=e["entry_class"], source_class=e["source_class"],
                  principal=store.principal, sealed=e.get("sealed", False), slot=e.get("slot"))


class Harness:
    def __init__(self, llm, packs: dict | None = None):
        self.llm = llm
        self.packs = packs or DEV_PACKS

    def extract(self, content: str, source_class: str, entry_class: str) -> tuple[list[dict], bool, str]:
        raw = self.llm.generate(prompts.extraction_prompt(content, source_class),
                                system=prompts.EXTRACTION_SYSTEM, num_predict=400)
        cands, fallback = prompts.parse_candidates(raw, content, entry_class)
        return cands, fallback, raw

    def run_case(self, case: dict, condition: str, workdir, *, extraction_cache: dict | None = None) -> dict:
        pack = self.packs[case["memory_pack_id"]]
        principal_store = case.get("store_principal", pack.get("principal"))
        store = FileStore.create(workdir / f"{case['case_id']}-{condition}", principal_store)
        prefill(store, pack)
        backend = make_backend(condition, store, self.llm)
        cache = extraction_cache if extraction_cache is not None else {}

        trace = []
        for s in case["sessions"]:
            principal = s["principal"]
            for step in s["steps"]:
                op = step["op"]
                sid = step["step_id"]
                rec = {"session": s["session"], "step_id": sid, "op": op, "principal": principal}
                if op == "write":
                    key = sid
                    if key in cache:
                        cands, fallback, raw = cache[key]
                    else:
                        cands, fallback, raw = self.extract(step["content"], step["source_class"], step["entry_class"])
                        cache[key] = (cands, fallback, raw)
                    rec["extractor_fallback"] = fallback
                    rec["n_candidates"] = len(cands)
                    dispositions = []
                    for c in cands:
                        # Fix 1 (D-29): a write the source classifies as a secret stays classified
                        # secret, so the policy seals it regardless of token shape.
                        ec = "secret" if step.get("entry_class") == "secret" else c["entry_class"]
                        try:
                            d = backend.store_candidate(content=c["content"], source_class=step["source_class"],
                                                        entry_class=ec, principal=principal,
                                                        slot=c["slot"] if step.get("slot") is None else step["slot"],
                                                        sealed=step.get("sealed", False))
                        except ValueError as exc:
                            # D-34: the policy refuses an invalid claim (e.g. sealed=True from a
                            # non-user_explicit source, Phase 1 D-11). Record the refusal as a
                            # non-active disposition rather than aborting; no policy change.
                            d = {"disposition": "rejected", "reasons": [f"policy_refused:{exc}"],
                                 "entry_id": None, "stored_content": None}
                        d["candidate_content"] = c["content"]
                        dispositions.append(d)
                    rec["dispositions"] = dispositions
                elif op == "consolidate":
                    rec.update(backend.consolidate(inputs=step.get("inputs", []), principal=principal,
                                                   claim_source_class=step.get("claim_source_class"),
                                                   claim_sealed=step.get("claim_sealed", False),
                                                   slot=step.get("slot")))
                elif op == "tamper":
                    rec.update(backend.tamper(target=step["target"], replacement=step["replacement"],
                                              recompute_hash=step.get("recompute_hash", False)))
                elif op == "raw_insert":
                    rec.update(backend.raw_insert(content=step["content"], source_class=step["source_class"],
                                                  entry_class=step["entry_class"],
                                                  principal=step.get("principal", principal)))
                elif op == "recall":
                    mem, recs = backend.recall(principal, step.get("keywords", []), step.get("context", "normal"))
                    answer = self.llm.generate(
                        prompts.agent_prompt(mem, step.get("keywords", []), step.get("context", "normal")),
                        system=prompts.AGENT_SYSTEM, num_predict=400)
                    rec["context"] = step.get("context", "normal")
                    rec["recalled"] = recs
                    rec["answer"] = answer
                else:
                    raise ValueError(f"unknown op {op!r}")
                trace.append(rec)
        return {"case_id": case["case_id"], "condition": condition, "trace": trace}
