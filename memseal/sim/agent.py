"""Deterministic scripted agent (no LLM).

The agent executes a bench case's script against one memory condition:

* ``C0`` plain store: no write policy, unguarded recall.
* ``C2`` MemSeal write path (W1–W5) on, unguarded recall.
* ``C3`` C2 + guarded recall path (chain verification, principal filter,
  provenance and ``sole_basis_for_irreversible`` flags).

Decision rule (identical in every condition): after a recall the agent *uses
every entry returned* to form its action. It does not itself enforce the
``sole_basis_for_irreversible`` flag — enforcing it is out of Phase 1 scope;
the flag is reported as data.
"""

from __future__ import annotations

import json

from ..consolidate import consolidate, merge_contents, naive_consolidate
from ..envelope import Envelope, make_entry_id
from ..policy import ACTIVE, WritePolicy, raw_write
from ..recall import recall
from ..store import FileStore

CONDITIONS = {
    "C0": {"write_policy": False, "recall_guard": False,
           "description": "plain store, no policy"},
    "C2": {"write_policy": True, "recall_guard": False,
           "description": "MemSeal write path (W1-W5) enabled"},
    "C3": {"write_policy": True, "recall_guard": True,
           "description": "C2 + MemSeal recall path"},
}

NOT_EVALUABLE = {
    "C1": "NOT EVALUABLE in Phase 1: a detector-only filter condition is not implemented as a separate runner condition.",
    "C4": "NOT EVALUABLE in Phase 1: consolidation guard is implemented (Step 5) but its dedicated measurement is Phase 2.",
}

ACTIONS = {"normal": "answer", "outbound": "send_external", "irreversible": "irreversible_action"}


def prefill(store: FileStore, pack: dict) -> None:
    for e in pack["entries"]:
        raw_write(store, content=e["content"], entry_class=e["entry_class"], source_class=e["source_class"],
                  principal=pack["principal"], sealed=e["sealed"], slot=e["slot"])


class ScriptedAgent:
    def __init__(self, condition: str, store: FileStore):
        if condition not in CONDITIONS:
            raise ValueError(f"unknown condition {condition!r}")
        self.condition = condition
        self.cfg = CONDITIONS[condition]
        self.store = store
        self.policy = WritePolicy(store) if self.cfg["write_policy"] else None

    # ------------------------------------------------------------ ops
    def _write(self, step, principal):
        kw = dict(content=step["content"], entry_class=step["entry_class"], source_class=step["source_class"],
                  principal=principal, slot=step["slot"], sealed=step["sealed"])
        res = self.policy.write(**kw) if self.policy else raw_write(self.store, **kw)
        return {"disposition": res.disposition, "reasons": res.reasons,
                "entry_id": res.entry.entry_id if res.entry else None,
                "stored_content": res.entry.content if res.entry else None,
                "trust_tier": res.trust_tier, "pre_content": step["content"]}

    def _consolidate(self, step, principal):
        envs = self.store.active_entries()
        ids = [e.entry_id for e in envs if any(m in e.content for m in step["inputs"])]
        if not ids:
            return {"disposition": "skipped", "reasons": [], "inputs": [], "entry_id": None,
                    "stored_content": None, "pre_content": ""}
        by_id = {e.entry_id: e for e in envs}
        pre = merge_contents([by_id[i].content for i in ids])
        src = step["claim_source_class"] or "agent_inference"
        if self.policy:
            res = consolidate(self.policy, ids, principal=principal, source_class=src,
                              sealed=step["claim_sealed"], slot=step["slot"])
        else:
            res = naive_consolidate(self.store, ids, principal=principal, source_class=src,
                                    sealed=step["claim_sealed"], slot=step["slot"])
        return {"disposition": res.disposition, "reasons": res.reasons, "inputs": ids,
                "entry_id": res.entry.entry_id if res.entry else None,
                "stored_content": res.entry.content if res.entry else None,
                "trust_tier": res.trust_tier, "pre_content": pre}

    def _recall(self, step, principal):
        res = recall(self.store, principal, step["keywords"], guarded=self.cfg["recall_guard"])
        used = [{"entry_id": e.entry_id, "content": e.content, "principal": e.principal,
                 "trust_tier": e.provenance["trust_tier"] if e.provenance else None,
                 "sole_basis_for_irreversible": e.sole_basis_for_irreversible} for e in res.entries]
        verb = ACTIONS[step["context"]]
        return {"context": step["context"], "used": used,
                "action": f"{verb}_with_memory" if used else f"{verb}_without_memory",
                "warnings": len(res.warnings), "excluded_ids": res.excluded_ids,
                "filtered_foreign_principal": res.filtered_foreign_principal}

    def _tamper(self, step):
        """Attacker with file access edits the first entry containing ``target``."""
        lines = self.store.log_path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            env = Envelope.from_dict(json.loads(line))
            if step["target"] in env.content:
                env.content = env.content.replace(step["target"], step["replacement"])
                if step["recompute_hash"]:
                    env.entry_id = make_entry_id(env.seq, env.content)
                    env.hash = env.compute_hash()
                lines[n] = json.dumps(env.to_dict(), sort_keys=True, ensure_ascii=False)
                self.store.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return {"tampered_seq": env.seq, "recomputed": step["recompute_hash"]}
        return {"tampered_seq": None}

    def _raw_insert(self, step):
        res = raw_write(self.store, content=step["content"], entry_class=step["entry_class"],
                        source_class=step["source_class"], principal=step["principal"])
        return {"entry_id": res.entry.entry_id}

    # ------------------------------------------------------------ run
    def run(self, case: dict) -> list[dict]:
        trace = []
        for s in case["sessions"]:
            for step in s["steps"]:
                op = step["op"]
                if op == "write":
                    out = self._write(step, s["principal"])
                elif op == "consolidate":
                    out = self._consolidate(step, s["principal"])
                elif op == "recall":
                    out = self._recall(step, s["principal"])
                elif op == "tamper":
                    out = self._tamper(step)
                elif op == "raw_insert":
                    out = self._raw_insert(step)
                else:
                    raise ValueError(f"unknown op {op!r}")
                trace.append({"session": s["session"], "step_id": step["step_id"], "op": op, **out})
        return trace


def is_active(rec: dict) -> bool:
    return rec.get("disposition") == ACTIVE
