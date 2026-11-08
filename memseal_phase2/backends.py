"""Memory backends for conditions C0-C4, as adapters over Phase 1 modules.

Each backend wraps one `FileStore`. The harness calls:

    store_candidate(content, source_class, entry_class, principal, slot, sealed)
    recall(principal, keywords, context) -> (memory_contents, recalled_records)
    raw_insert(content, source_class, entry_class, principal)   # attacker/legacy
    tamper(target, replacement, recompute_hash)                 # file-level edit
    consolidate(inputs, principal, claim_source_class, claim_sealed, slot)

Only harness/adapter logic lives here; W1-W5, the recall path, chain
verification and consolidation semantics come from Phase 1.
"""

from __future__ import annotations

import json

from memseal.consolidate import consolidate as p1_consolidate
from memseal.consolidate import merge_contents, naive_consolidate
from memseal.detectors import has_secret, is_imperative
from memseal.envelope import Envelope, make_entry_id, tier_for_source
from memseal.policy import WritePolicy, raw_write
from memseal.recall import matches, recall as guarded_recall, searchable_text
from memseal.store import FileStore

CONDITIONS = ("C0", "C1", "C2", "C3", "C4")

CONDITION_DESC = {
    "C0": "raw store, no policy; keyword recall over content only",
    "C1": "detector-only filter (imperative/secret dropped); else like C0",
    "C2": "MemSeal write path (Envelope + W1-W5); plain content recall (no provenance)",
    "C3": "C2 + MemSeal recall path (provenance, sole_basis flag, chain+principal filter)",
    "C4": "C3 + consolidation guard (derived_from links, worst-tier inheritance, W2)",
}


def _plain_recall(store: FileStore, keywords):
    """C0/C1/C2 return style: active entries' content only, no principal filter."""
    out = []
    for e in store.active_entries():
        if matches(searchable_text(e), keywords):
            out.append({"entry_id": e.entry_id, "content": e.content, "principal": e.principal,
                        "trust_tier": None, "sole_basis_for_irreversible": None, "source_class": e.source_class})
    return out


class Backend:
    uses_write_policy = False
    guarded = False

    def __init__(self, store: FileStore, llm=None):
        self.store = store
        self.llm = llm

    def store_candidate(self, *, content, source_class, entry_class, principal, slot=None, sealed=False):
        raise NotImplementedError

    def recall(self, principal, keywords, context):
        if self.guarded:
            res = guarded_recall(self.store, principal, keywords, context=context,
                                 enforce_sole_basis=True)   # Fix 2: sole_basis gate in C3/C4
            recs = [{"entry_id": e.entry_id, "content": e.content, "principal": e.principal,
                     "trust_tier": e.provenance["trust_tier"] if e.provenance else None,
                     "sole_basis_for_irreversible": e.sole_basis_for_irreversible,
                     "source_class": e.provenance["source_class"] if e.provenance else None} for e in res.entries]
            return [r["content"] for r in recs], recs
        recs = _plain_recall(self.store, keywords)
        return [r["content"] for r in recs], recs

    def raw_insert(self, *, content, source_class, entry_class, principal):
        env = raw_write(self.store, content=content, entry_class=entry_class,
                        source_class=source_class, principal=principal)
        return {"disposition": "raw_insert", "entry_id": env.entry.entry_id}

    def tamper(self, *, target, replacement, recompute_hash):
        lines = self.store.log_path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            env = Envelope.from_dict(json.loads(line))
            if target in env.content:
                env.content = env.content.replace(target, replacement)
                if recompute_hash:
                    env.entry_id = make_entry_id(env.seq, env.content)
                    env.hash = env.compute_hash()
                lines[n] = json.dumps(env.to_dict(), sort_keys=True, ensure_ascii=False)
                self.store.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                return {"disposition": "tamper", "tampered_seq": env.seq, "recomputed": recompute_hash}
        return {"disposition": "tamper", "tampered_seq": None}

    # --- consolidation --------------------------------------------------
    def _select(self, inputs):
        envs = self.store.active_entries()
        return [e for e in envs if any(m in e.content for m in inputs)]

    def _summarize(self, entries):
        if self.llm is None:
            return merge_contents([e.content for e in entries])
        from memseal_phase2.prompts import CONSOLIDATION_SYSTEM, consolidation_prompt
        text = self.llm.generate(consolidation_prompt([e.content for e in entries]),
                                 system=CONSOLIDATION_SYSTEM, num_predict=256).strip()
        return text or merge_contents([e.content for e in entries])


class C0Backend(Backend):
    def store_candidate(self, *, content, source_class, entry_class, principal, slot=None, sealed=False):
        env = raw_write(self.store, content=content, entry_class=entry_class, source_class=source_class,
                        principal=principal, slot=slot, sealed=sealed)
        return {"disposition": "active", "reasons": [], "entry_id": env.entry.entry_id,
                "stored_content": env.entry.content}

    def consolidate(self, *, inputs, principal, claim_source_class=None, claim_sealed=False, slot=None):
        found = self._select(inputs)
        if not found:
            return {"disposition": "skipped", "reasons": [], "entry_id": None, "stored_content": None}
        summary = self._summarize(found)
        # C0/C1: summary enters as a raw entry; originals are replaced (no provenance).
        sup = [e.entry_id for e in found]
        src = claim_source_class or "agent_inference"
        env = self.store.append(content=summary, entry_class="episode", source_class=src,
                                principal=principal, trust_tier=tier_for_source(src), slot=slot,
                                supersedes=sup, enforce_principal=False)
        return {"disposition": "active", "reasons": [], "entry_id": env.entry_id,
                "stored_content": env.content, "replaced": sup}


class C1Backend(C0Backend):
    def store_candidate(self, *, content, source_class, entry_class, principal, slot=None, sealed=False):
        if is_imperative(content) or has_secret(content) or entry_class == "instruction":
            return {"disposition": "dropped", "reasons": ["detector"], "entry_id": None, "stored_content": None}
        return super().store_candidate(content=content, source_class=source_class, entry_class=entry_class,
                                       principal=principal, slot=slot, sealed=sealed)


class C2Backend(Backend):
    uses_write_policy = True

    def __init__(self, store, llm=None):
        super().__init__(store, llm)
        self.policy = WritePolicy(store)

    def store_candidate(self, *, content, source_class, entry_class, principal, slot=None, sealed=False):
        r = self.policy.write(content=content, entry_class=entry_class, source_class=source_class,
                              principal=principal, slot=slot, sealed=sealed)
        return {"disposition": r.disposition, "reasons": r.reasons,
                "entry_id": r.entry.entry_id if r.entry else None,
                "stored_content": r.entry.content if r.entry else None,
                "trust_tier": r.trust_tier}

    def _consolidate_via_policy(self, inputs, principal, claim_source_class, claim_sealed, slot, link,
                                retire_inputs=False):
        found = self._select(inputs)
        if not found:
            return {"disposition": "skipped", "reasons": [], "entry_id": None, "stored_content": None}
        ids = [e.entry_id for e in found]
        src = claim_source_class or "agent_inference"
        if link:
            r = p1_consolidate(self.policy, ids, principal=principal, source_class=src,
                               sealed=claim_sealed, slot=slot, retire_inputs=retire_inputs)
            pre = None
        else:
            # C2/C3: summary written as a new agent_inference entry, no derived_from link.
            summary = self._summarize(found)
            r = self.policy.write(content=summary, entry_class="episode", source_class=src,
                                  principal=principal, slot=slot)
            pre = summary
        out = {"disposition": r.disposition, "reasons": r.reasons,
               "entry_id": r.entry.entry_id if r.entry else None,
               "stored_content": r.entry.content if r.entry else None,
               "trust_tier": r.trust_tier, "inputs": ids}
        if pre is not None:
            out["summary"] = pre
        return out

    def consolidate(self, *, inputs, principal, claim_source_class=None, claim_sealed=False, slot=None):
        return self._consolidate_via_policy(inputs, principal, claim_source_class, claim_sealed, slot, link=False)


class C3Backend(C2Backend):
    guarded = True


class C4Backend(C3Backend):
    def consolidate(self, *, inputs, principal, claim_source_class=None, claim_sealed=False, slot=None):
        # C4 links derived_from (worst-tier inheritance + W2) and retires the
        # absorbed roots (Fix 3) via the Phase 1 consolidate().
        return self._consolidate_via_policy(inputs, principal, claim_source_class, claim_sealed, slot,
                                            link=True, retire_inputs=True)


BACKENDS = {"C0": C0Backend, "C1": C1Backend, "C2": C2Backend, "C3": C3Backend, "C4": C4Backend}


def make_backend(condition: str, store: FileStore, llm=None) -> Backend:
    return BACKENDS[condition](store, llm)
