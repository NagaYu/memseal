"""Provenance Envelope and SHA-256 hash chain.

Every memory entry is wrapped in an :class:`Envelope`. Envelopes are chained:
``hash = sha256(canonical_json(envelope without 'hash'))`` and each envelope's
``prev_hash`` equals the previous envelope's ``hash`` (``GENESIS_HASH`` for the
first entry).
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Iterable

ENTRY_CLASSES = ("fact", "preference", "instruction", "secret", "episode")
SOURCE_CLASSES = (
    "user_explicit",
    "user_conversation",
    "document",
    "tool_output",
    "agent_inference",
    "external_agent",
)
USER_SOURCE_CLASSES = frozenset({"user_explicit", "user_conversation"})

# Fixed mapping source_class -> trust tier (T0 most trusted .. T4 least).
SOURCE_TIER = {
    "user_explicit": 0,
    "user_conversation": 1,
    "agent_inference": 2,
    "document": 3,
    "tool_output": 3,
    "external_agent": 4,
}
TIER_NAMES = ("T0", "T1", "T2", "T3", "T4")

GENESIS_HASH = "0" * 64
HASH_FIELD = "hash"


def tier_name(tier: int) -> str:
    return TIER_NAMES[tier]


def tier_value(name: str) -> int:
    return TIER_NAMES.index(name)


def tier_for_source(source_class: str) -> int:
    if source_class not in SOURCE_TIER:
        raise ValueError(f"unknown source_class: {source_class!r}")
    return SOURCE_TIER[source_class]


def worst_tier(tiers: Iterable[int]) -> int:
    """Lowest trust == highest tier number."""
    tiers = list(tiers)
    if not tiers:
        raise ValueError("worst_tier of empty set")
    return max(tiers)


def canonical_json(obj) -> str:
    """Normalised JSON: sorted keys, no whitespace, UTF-8 kept, NFC strings."""
    return json.dumps(_nfc(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _nfc(obj):
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, list):
        return [_nfc(x) for x in obj]
    if isinstance(obj, tuple):
        return [_nfc(x) for x in obj]
    if isinstance(obj, dict):
        return {_nfc(k): _nfc(v) for k, v in obj.items()}
    return obj


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def content_hash(content: str) -> str:
    return sha256_hex(unicodedata.normalize("NFC", content))


def make_entry_id(seq: int, content: str) -> str:
    """Deterministic id: sequence number + content hash prefix."""
    return f"e{seq:06d}-{content_hash(content)[:12]}"


@dataclass
class Envelope:
    seq: int
    entry_id: str
    content: str
    entry_class: str
    source_class: str
    principal: str
    derived_from: list = field(default_factory=list)
    trust_tier: str = "T4"
    sealed: bool = False
    slot: str | None = None
    supersedes: list = field(default_factory=list)
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    # ---- validation -------------------------------------------------
    def validate_shape(self) -> None:
        if self.entry_class not in ENTRY_CLASSES:
            raise ValueError(f"unknown entry_class: {self.entry_class!r}")
        if self.source_class not in SOURCE_CLASSES:
            raise ValueError(f"unknown source_class: {self.source_class!r}")
        if not isinstance(self.principal, str) or not self.principal:
            raise ValueError("principal must be a non-empty string")
        if self.trust_tier not in TIER_NAMES:
            raise ValueError(f"unknown trust_tier: {self.trust_tier!r}")
        if self.sealed and not (self.source_class == "user_explicit" and self.entry_class == "fact"):
            raise ValueError("sealed=True is only allowed for user_explicit facts")
        if self.sealed and self.derived_from:
            raise ValueError("derived entries cannot be sealed")

    # ---- hashing ----------------------------------------------------
    def body(self) -> dict:
        d = asdict(self)
        d.pop(HASH_FIELD)
        return d

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.body()))

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Envelope":
        known = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**known)

    def self_check(self) -> list[str]:
        """Return a list of integrity problems with this envelope alone."""
        problems = []
        if self.hash != self.compute_hash():
            problems.append("hash_mismatch")
        if self.entry_id != make_entry_id(self.seq, self.content):
            problems.append("entry_id_mismatch")
        return problems


def build_envelope(
    *,
    seq: int,
    content: str,
    entry_class: str,
    source_class: str,
    principal: str,
    prev_hash: str,
    trust_tier: int,
    derived_from: list | None = None,
    sealed: bool = False,
    slot: str | None = None,
    supersedes: list | None = None,
) -> Envelope:
    env = Envelope(
        seq=seq,
        entry_id=make_entry_id(seq, content),
        content=content,
        entry_class=entry_class,
        source_class=source_class,
        principal=principal,
        derived_from=list(derived_from or []),
        trust_tier=tier_name(trust_tier),
        sealed=bool(sealed),
        slot=slot,
        supersedes=list(supersedes or []),
        prev_hash=prev_hash,
    )
    env.validate_shape()
    env.hash = env.compute_hash()
    return env


@dataclass
class ChainIssue:
    seq: int
    entry_id: str
    kind: str  # hash_mismatch | entry_id_mismatch | link_break | seq_gap | malformed
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def verify_chain(envelopes: list[Envelope]) -> tuple[list[ChainIssue], set[str]]:
    """Verify a chain. Returns (issues, ids_of_untrusted_entries).

    Exclusion rule (see DECISIONS.md D-03): an entry is untrusted if its own
    hash/id check fails, or if it sits on either side of a broken link
    (``prev_hash`` of entry *i* != stored ``hash`` of entry *i-1*). This
    catches in-place edits, edits with a recomputed hash, insertions and
    deletions, without discarding the whole tail of the chain.
    """
    issues: list[ChainIssue] = []
    bad: set[str] = set()
    prev_hash = GENESIS_HASH
    prev: Envelope | None = None
    for i, env in enumerate(envelopes):
        for p in env.self_check():
            issues.append(ChainIssue(env.seq, env.entry_id, p))
            bad.add(env.entry_id)
        if env.prev_hash != prev_hash:
            issues.append(ChainIssue(env.seq, env.entry_id, "link_break",
                                     f"prev_hash does not match entry at position {i - 1}"))
            bad.add(env.entry_id)
            if prev is not None:
                bad.add(prev.entry_id)
        expected_seq = 0 if prev is None else prev.seq + 1
        if env.seq != expected_seq:
            issues.append(ChainIssue(env.seq, env.entry_id, "seq_gap", f"expected seq {expected_seq}"))
            bad.add(env.entry_id)
        prev_hash = env.hash
        prev = env
    return issues, bad
