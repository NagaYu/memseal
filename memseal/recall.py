"""Trust-tiered recall path.

The guarded recall (:func:`recall` with ``guarded=True``):

* verifies the hash chain and excludes failing entries (listed in ``warnings``);
* computes supersession only from verified entries (a tampered entry cannot
  hide a legitimate one);
* returns only entries whose principal equals the querying principal (pair of W3);
* attaches provenance (source_class / trust_tier / derived_from) to every entry;
* sets ``sole_basis_for_irreversible = False`` for trust tier T3 or worse.
  This is data only; enforcing it is the caller's job (out of Phase 1 scope).

The unguarded recall (``guarded=False``) is the plain-store baseline used by
conditions C0 and C2: keyword match over active entries, no verification, no
principal filter, no provenance.
"""

from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass, field

from .envelope import Envelope, tier_value, verify_chain
from .store import FileStore

SOLE_BASIS_MIN_UNTRUSTED_TIER = 3  # T3 and T4


def _norm(s: str) -> str:
    return unicodedata.normalize("NFKC", s).casefold()


def matches(content: str, terms: list[str] | None) -> bool:
    if not terms:
        return True
    c = _norm(content)
    return any(_norm(t) in c for t in terms if t)


def searchable_text(e: Envelope) -> str:
    """Content plus slot name, so a slot fact can be found by its key."""
    return f"{e.content} {e.slot}" if e.slot else e.content


@dataclass
class RecalledEntry:
    entry_id: str
    content: str
    entry_class: str
    slot: str | None
    sealed: bool
    principal: str
    provenance: dict | None = None
    sole_basis_for_irreversible: bool | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RecallResult:
    entries: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    excluded_ids: list = field(default_factory=list)
    filtered_foreign_principal: int = 0
    guarded: bool = True
    gated: list = field(default_factory=list)          # Fix 2: entries withheld by the sole_basis gate
    sole_basis_gated_count: int = 0

    def to_dict(self) -> dict:
        return {"entries": [e.to_dict() for e in self.entries], "warnings": self.warnings,
                "excluded_ids": self.excluded_ids,
                "filtered_foreign_principal": self.filtered_foreign_principal, "guarded": self.guarded,
                "gated": self.gated, "sole_basis_gated_count": self.sole_basis_gated_count}


def _annotate(e: Envelope) -> RecalledEntry:
    return RecalledEntry(
        entry_id=e.entry_id, content=e.content, entry_class=e.entry_class, slot=e.slot, sealed=e.sealed,
        principal=e.principal,
        provenance={"source_class": e.source_class, "trust_tier": e.trust_tier,
                    "derived_from": list(e.derived_from)},
        sole_basis_for_irreversible=tier_value(e.trust_tier) < SOLE_BASIS_MIN_UNTRUSTED_TIER,
    )


GATED_CONTEXTS = ("outbound", "irreversible")
GATED_CLASSES = ("fact", "preference")


def _sig(slot, content):
    from .policy import normalize_value
    return (slot or "", normalize_value(content))


def recall(store: FileStore, principal: str, terms: list[str] | None = None, *,
           guarded: bool = True, context: str = "normal", enforce_sole_basis: bool = False) -> RecallResult:
    envs, parse_issues = store.load()
    if not guarded:
        out = [RecalledEntry(e.entry_id, e.content, e.entry_class, e.slot, e.sealed, e.principal)
               for e in store.active_entries(envs) if matches(searchable_text(e), terms)]
        return RecallResult(entries=out, guarded=False)

    issues, bad = verify_chain(envs)
    warnings = [i.to_dict() for i in parse_issues + issues]
    verified = [e for e in envs if e.entry_id not in bad]
    sup: set[str] = set()
    for e in verified:
        sup.update(e.supersedes)
    mine = [e for e in verified if e.entry_id not in sup and e.principal == principal]
    foreign = sum(1 for e in verified if e.entry_id not in sup and e.principal != principal)

    # Fix 2 (D-30): user-rooted (T0/T1) signatures that can corroborate a low-trust claim.
    gate_on = enforce_sole_basis and context in GATED_CONTEXTS
    user_sigs = {_sig(e.slot, e.content) for e in mine if tier_value(e.trust_tier) <= 1} if gate_on else set()

    out, gated = [], []
    for e in mine:
        if not matches(searchable_text(e), terms):
            continue
        if gate_on and e.entry_class in GATED_CLASSES and tier_value(e.trust_tier) >= SOLE_BASIS_MIN_UNTRUSTED_TIER:
            if _sig(e.slot, e.content) not in user_sigs:   # no user corroboration -> withhold
                gated.append(_annotate(e).to_dict())
                continue
        out.append(_annotate(e))
    return RecallResult(entries=out, warnings=warnings, excluded_ids=sorted(bad),
                        filtered_foreign_principal=foreign, guarded=True,
                        gated=gated, sole_basis_gated_count=len(gated))
