"""Provenance-preserving consolidation (deterministic, no LLM).

Consolidation merges several entries into one by template concatenation with
duplicate removal. The output's ``derived_from`` lists *every* input, and the
result is written through :class:`~memseal.policy.WritePolicy`, so W2 decides
its trust tier and rejects attempts to pass it off as user-sourced.

``naive_consolidate`` is the provenance-stripping baseline used for C0: it
writes the merged content as a fresh, underived entry.
"""

from __future__ import annotations

from .policy import WritePolicy, WriteResult, normalize_value, raw_write
from .store import FileStore

SEPARATOR = " | "


def merge_contents(contents: list[str]) -> str:
    seen, out = set(), []
    for c in contents:
        k = normalize_value(c)
        if k and k not in seen:
            seen.add(k)
            out.append(c.strip())
    return SEPARATOR.join(out)


def merged_entry_class(classes: list[str]) -> str:
    classes = [c for c in classes if c]
    if classes and all(c == classes[0] for c in classes):
        return classes[0]
    return "episode"


def _dedupe(ids: list[str]) -> list[str]:
    out = []
    for i in ids:
        if i not in out:
            out.append(i)
    return out


def consolidate(policy: WritePolicy, entry_ids: list[str], *, principal: str,
                source_class: str = "agent_inference", sealed: bool = False,
                slot: str | None = None, entry_class: str | None = None,
                retire_inputs: bool = False) -> WriteResult:
    """Merge ``entry_ids`` into one entry and write it through the policy.

    ``source_class`` / ``sealed`` are what the consolidating caller *claims*;
    W2 quarantines any claim of user provenance or sealing. With
    ``retire_inputs`` (Fix 3, D-31), a successfully stored derived entry retires
    (supersedes) the inputs it absorbed, so they drop out of active/recall;
    history is kept in the log for rollback.
    """
    ids = _dedupe(list(entry_ids))
    if not ids:
        raise ValueError("consolidate needs at least one input entry")
    by_id = {e.entry_id: e for e in policy.store.entries()}
    found = [by_id[i] for i in ids if i in by_id]
    content = merge_contents([e.content for e in found]) or "(empty consolidation)"
    ec = entry_class or merged_entry_class([e.entry_class for e in found])
    extra = [e.entry_id for e in found] if retire_inputs else None
    return policy.write(content=content, entry_class=ec, source_class=source_class, principal=principal,
                        derived_from=ids, sealed=sealed, slot=slot, extra_supersedes=extra)


def naive_consolidate(store: FileStore, entry_ids: list[str], *, principal: str,
                      source_class: str = "agent_inference", sealed: bool = False,
                      slot: str | None = None) -> WriteResult:
    """Baseline consolidation that drops provenance (derived_from = [])."""
    by_id = {e.entry_id: e for e in store.entries()}
    found = [by_id[i] for i in _dedupe(list(entry_ids)) if i in by_id]
    content = merge_contents([e.content for e in found]) or "(empty consolidation)"
    ec = merged_entry_class([e.entry_class for e in found])
    return raw_write(store, content=content, entry_class=ec, source_class=source_class,
                     principal=principal, derived_from=[], sealed=sealed, slot=slot)
