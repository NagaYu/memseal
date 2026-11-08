"""Write policy W1–W5 and the quarantine / review queues.

Nothing is silently dropped: every non-active outcome is recorded in a queue
with reason codes, and every decision is written to the audit log.

Order of evaluation (see DECISIONS.md D-05):

1. shape validation (unknown enums -> ValueError, caller bug)
2. W3 principal check          -> ``rejected`` (content withheld from the record)
3. W4 secret shapes             -> content redacted before anything is stored
4. W2 derived-entry provenance  -> ``quarantined``
5. W1 instruction form          -> ``quarantined``
6. W5 sealed-slot contradiction -> ``review``
7. otherwise                    -> ``active`` (appended to the chain)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from .detectors import detect_imperative, redact
from .envelope import (
    ENTRY_CLASSES,
    SOURCE_CLASSES,
    USER_SOURCE_CLASSES,
    Envelope,
    content_hash,
    tier_for_source,
    tier_name,
    tier_value,
    worst_tier,
)
from .store import FileStore

ACTIVE, QUARANTINED, REVIEW, REJECTED = "active", "quarantined", "review", "rejected"


def seal_secret_content(original: str, redacted: str, findings) -> tuple[str, bool]:
    """Fix 1 (D-29): sealing for entry_class=secret entries.

    If the shape table already redacted the secret span, keep the redacted text
    (context preserved, value removed). Otherwise the content is a secret we
    cannot locate by shape, so the whole content is withheld -- never stored in
    plaintext -- behind a non-sensitive placeholder plus a content hash.
    """
    if findings:
        return redacted, True
    return f"[REDACTED:SECRET:{content_hash(original)[:8]}]", True


def normalize_value(text: str) -> str:
    """Normalisation used for W5 slot comparison."""
    t = unicodedata.normalize("NFKC", text).casefold().strip()
    t = re.sub(r"\s+", " ", t)
    return t.rstrip(" .。!！?？")


@dataclass
class WriteResult:
    disposition: str
    reasons: list = field(default_factory=list)
    entry: Envelope | None = None
    record: dict | None = None
    trust_tier: str | None = None
    redactions: list = field(default_factory=list)

    @property
    def active(self) -> bool:
        return self.disposition == ACTIVE


class WritePolicy:
    """Applies W1–W5 in front of a :class:`FileStore`."""

    def __init__(self, store: FileStore):
        self.store = store

    # ------------------------------------------------------------ helpers
    def ancestor_tiers(self, derived_from: list, envs: list[Envelope]) -> tuple[list[int], list[str]]:
        by_id = {e.entry_id: e for e in envs}
        tiers, missing, seen = [], [], set()
        stack = list(derived_from)
        while stack:
            eid = stack.pop()
            if eid in seen:
                continue
            seen.add(eid)
            e = by_id.get(eid)
            if e is None:
                missing.append(eid)
                continue
            tiers.append(tier_value(e.trust_tier))
            stack.extend(e.derived_from)
        return tiers, sorted(missing)

    def _record(self, queue: str, disposition: str, reasons: list, req: dict, **extra) -> dict:
        rec = {"disposition": disposition, "reasons": reasons, "request": req, **extra}
        return self.store.enqueue(queue, rec)

    def _audit(self, disposition, reasons, req, entry_id=None, **extra):
        self.store.enqueue("audit", {
            "event": "write", "disposition": disposition, "reasons": reasons,
            "source_class": req["source_class"], "principal": req["principal"],
            "content_sha256": content_hash(req["content"]), "entry_id": entry_id, **extra})

    # ------------------------------------------------------------ main
    def write(self, *, content: str, entry_class: str, source_class: str, principal: str,
              derived_from: list | None = None, sealed: bool = False, slot: str | None = None,
              extra_supersedes: list | None = None) -> WriteResult:
        if entry_class not in ENTRY_CLASSES:
            raise ValueError(f"unknown entry_class {entry_class!r}")
        if source_class not in SOURCE_CLASSES:
            raise ValueError(f"unknown source_class {source_class!r}")
        derived_from = list(derived_from or [])
        req = {"content": content, "entry_class": entry_class, "source_class": source_class,
               "principal": principal, "derived_from": derived_from, "sealed": bool(sealed), "slot": slot}

        # W3 -- principal must match the store's principal. The foreign content is
        # not copied into this store's queue (that would itself be a leak).
        if principal != self.store.principal:
            withheld = {**req, "content": None, "content_sha256": content_hash(content)}
            rec = self._record("quarantine", REJECTED, ["W3"], withheld,
                               store_principal=self.store.principal)
            self._audit(REJECTED, ["W3"], req)
            return WriteResult(REJECTED, ["W3"], record=rec)

        envs = self.store.entries()

        # W3 (derived) -- consolidating another principal's entries into this
        # principal's memory is a cross-principal write (DECISIONS.md D-07).
        by_id = {e.entry_id: e for e in envs}
        foreign_inputs = sorted(i for i in derived_from if i in by_id and by_id[i].principal != principal)
        if foreign_inputs:
            withheld = {**req, "content": None, "content_sha256": content_hash(content)}
            rec = self._record("quarantine", REJECTED, ["W3"], withheld,
                               store_principal=self.store.principal, foreign_inputs=foreign_inputs)
            self._audit(REJECTED, ["W3"], req)
            return WriteResult(REJECTED, ["W3"], record=rec)

        reasons: list[str] = []

        # W4 -- secrets never enter the store in plaintext. Two nets (D-29):
        #  (1) classification: entry_class == "secret" is always sealed, whatever
        #      the content shape (opaque tokens included);
        #  (2) shape table: secret shapes that slip into a non-secret entry.
        red_content, findings = redact(content)
        redactions = [{"kind": f.kind, "fingerprint": f.fingerprint} for f in findings]
        sealed_secret = False
        if entry_class == "secret":
            red_content, sealed_secret = seal_secret_content(content, red_content, findings)
            if sealed_secret and not findings:
                redactions.append({"kind": "SECRET_CLASS", "fingerprint": content_hash(content)[:8]})
        if findings or entry_class == "secret":
            reasons.append("W4")
        stored_req = {**req, "content": red_content}

        tier = tier_for_source(source_class)

        # W2 -- derived entries inherit the worst ancestor tier and cannot claim
        # user provenance or the sealed flag.
        w2 = []
        if derived_from:
            anc, missing = self.ancestor_tiers(derived_from, envs)
            if missing:
                w2.append(f"unknown_ancestor:{','.join(missing)}")
            if anc:
                tier = worst_tier([tier] + anc)
            if source_class in USER_SOURCE_CLASSES:
                w2.append(f"derived_entry_claims_{source_class}")
            if sealed:
                w2.append("derived_entry_claims_sealed")
        if w2:
            reasons.append("W2")

        # W1 -- instruction-form content from anything but user_explicit.
        imperative = [m.pattern_id for m in detect_imperative(content)]
        w1 = source_class != "user_explicit" and (bool(imperative) or entry_class == "instruction")
        if w1:
            reasons.append("W1")

        # W5 -- contradiction with a sealed fact in the same slot.
        supersedes: list[str] = list(extra_supersedes or [])   # Fix 3: consolidation root retirement
        conflicts: list[str] = []
        if slot and entry_class == "fact":
            sup = self.store.superseded_ids(envs)
            sealed_in_slot = [e for e in envs if e.sealed and e.slot == slot
                              and e.principal == principal and e.entry_id not in sup]
            conflicts = [e.entry_id for e in sealed_in_slot
                         if normalize_value(e.content) != normalize_value(red_content)]
            if conflicts:
                if source_class == "user_explicit" and not derived_from:
                    supersedes = supersedes + conflicts  # only an explicit user write may overwrite
                else:
                    reasons.append("W5")

        if sealed and not (source_class == "user_explicit" and entry_class == "fact") and "W2" not in reasons:
            raise ValueError("sealed=True is only allowed for user_explicit facts")

        detail = {"imperative_patterns": imperative, "w2_detail": w2, "w5_conflicts": conflicts,
                  "trust_tier": tier_name(tier), "redactions": redactions}

        if "W1" in reasons or "W2" in reasons:
            rec = self._record("quarantine", QUARANTINED, reasons, stored_req, **detail)
            self._audit(QUARANTINED, reasons, req)
            return WriteResult(QUARANTINED, reasons, record=rec, trust_tier=tier_name(tier), redactions=redactions)
        if "W5" in reasons:
            rec = self._record("review", REVIEW, reasons, stored_req, **detail)
            self._audit(REVIEW, reasons, req)
            return WriteResult(REVIEW, reasons, record=rec, trust_tier=tier_name(tier), redactions=redactions)

        env = self.store.append(content=red_content, entry_class=entry_class, source_class=source_class,
                                principal=principal, trust_tier=tier, derived_from=derived_from,
                                sealed=sealed, slot=slot, supersedes=supersedes)
        self._audit(ACTIVE, reasons, req, entry_id=env.entry_id, redactions=redactions,
                    supersedes=supersedes)
        return WriteResult(ACTIVE, reasons, entry=env, trust_tier=env.trust_tier, redactions=redactions)


def raw_write(store: FileStore, *, content: str, entry_class: str, source_class: str, principal: str,
              derived_from: list | None = None, sealed: bool = False, slot: str | None = None) -> WriteResult:
    """Policy-free write used for the C0 baseline (and for pre-filling memory packs).

    No W-checks: foreign principals are accepted, nothing is redacted, and an
    invalid ``sealed`` claim is dropped instead of raising.
    """
    ok_seal = sealed and source_class == "user_explicit" and entry_class == "fact" and not derived_from
    env = store.append(content=content, entry_class=entry_class, source_class=source_class,
                       principal=principal, trust_tier=tier_for_source(source_class),
                       derived_from=derived_from, sealed=ok_seal, slot=slot, enforce_principal=False)
    return WriteResult(ACTIVE, [], entry=env, trust_tier=env.trust_tier)
