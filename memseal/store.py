"""File-backed memory store: append-only hash-chained log, versions,
snapshots, rollback, and side queues (quarantine / review / audit).

Layout of a store directory::

    meta.json          {"format": "memseal-store/1", "principal": "..."}
    log.jsonl          one Envelope per line (the hash chain)
    quarantine.jsonl   quarantined write attempts (reason codes W1/W2/W3)
    review.jsonl       writes held for review (reason code W5)
    audit.jsonl        every policy decision, incl. W4 redaction notices
    snapshots/<name>.json   full copy of the log at snapshot time
    archive/rollback-<k>.jsonl   log tail removed by a rollback (never discarded)

The store itself does not apply write policy. It offers principal scoping
(``append`` refuses a foreign principal unless explicitly told not to, which
is only used for the policy-free C0 baseline) and integrity primitives.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .envelope import GENESIS_HASH, ChainIssue, Envelope, build_envelope, verify_chain

FORMAT = "memseal-store/1"
QUEUES = ("quarantine", "review", "audit")
_SNAPSHOT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class StoreError(Exception):
    pass


class PrincipalScopeError(StoreError):
    pass


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


def _dump(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


class FileStore:
    def __init__(self, root: str | os.PathLike):
        self.root = Path(root)
        meta_path = self.root / "meta.json"
        if not meta_path.exists():
            raise StoreError(f"not a MemSeal store: {self.root}")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("format") != FORMAT:
            raise StoreError(f"unsupported store format: {meta.get('format')!r}")
        self.principal: str = meta["principal"]

    # ---- lifecycle ------------------------------------------------------
    @classmethod
    def create(cls, root: str | os.PathLike, principal: str) -> "FileStore":
        root = Path(root)
        if (root / "meta.json").exists():
            raise StoreError(f"store already exists: {root}")
        if not principal:
            raise StoreError("store principal must be non-empty")
        root.mkdir(parents=True, exist_ok=True)
        (root / "snapshots").mkdir(exist_ok=True)
        (root / "archive").mkdir(exist_ok=True)
        _write_atomic(root / "meta.json", _dump({"format": FORMAT, "principal": principal}) + "\n")
        (root / "log.jsonl").touch()
        for q in QUEUES:
            (root / f"{q}.jsonl").touch()
        return cls(root)

    @property
    def log_path(self) -> Path:
        return self.root / "log.jsonl"

    # ---- reading --------------------------------------------------------
    def _read_lines(self) -> list[str]:
        text = self.log_path.read_text(encoding="utf-8")
        return [ln for ln in text.splitlines() if ln.strip()]

    def load(self) -> tuple[list[Envelope], list[ChainIssue]]:
        """Parse the log. Malformed lines are reported, not raised."""
        envs, issues = [], []
        for n, line in enumerate(self._read_lines()):
            try:
                envs.append(Envelope.from_dict(json.loads(line)))
            except (ValueError, TypeError, KeyError) as exc:
                issues.append(ChainIssue(-1, f"line-{n}", "malformed", str(exc)))
        return envs, issues

    def entries(self) -> list[Envelope]:
        return self.load()[0]

    def get(self, entry_id: str) -> Envelope | None:
        for e in self.entries():
            if e.entry_id == entry_id:
                return e
        return None

    def version(self) -> int:
        return len(self._read_lines())

    def head_hash(self) -> str:
        envs = self.entries()
        return envs[-1].hash if envs else GENESIS_HASH

    def superseded_ids(self, envs: list[Envelope] | None = None) -> set[str]:
        envs = self.entries() if envs is None else envs
        out: set[str] = set()
        for e in envs:
            out.update(e.supersedes)
        return out

    def active_entries(self, envs: list[Envelope] | None = None) -> list[Envelope]:
        """Entries not superseded by a later entry (no integrity filtering)."""
        envs = self.entries() if envs is None else envs
        sup = self.superseded_ids(envs)
        return [e for e in envs if e.entry_id not in sup]

    def entries_for(self, principal: str) -> list[Envelope]:
        return [e for e in self.active_entries() if e.principal == principal]

    def verify(self) -> tuple[list[ChainIssue], set[str]]:
        envs, parse_issues = self.load()
        issues, bad = verify_chain(envs)
        return parse_issues + issues, bad

    # ---- writing --------------------------------------------------------
    def append(
        self,
        *,
        content: str,
        entry_class: str,
        source_class: str,
        principal: str,
        trust_tier: int,
        derived_from: list | None = None,
        sealed: bool = False,
        slot: str | None = None,
        supersedes: list | None = None,
        enforce_principal: bool = True,
    ) -> Envelope:
        if enforce_principal and principal != self.principal:
            raise PrincipalScopeError(
                f"principal {principal!r} cannot write to store of {self.principal!r}")
        envs = self.entries()
        seq = envs[-1].seq + 1 if envs else 0
        prev = envs[-1].hash if envs else GENESIS_HASH
        env = build_envelope(
            seq=seq, content=content, entry_class=entry_class, source_class=source_class,
            principal=principal, prev_hash=prev, trust_tier=trust_tier,
            derived_from=derived_from, sealed=sealed, slot=slot, supersedes=supersedes)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(_dump(env.to_dict()) + "\n")
        return env

    # ---- queues ---------------------------------------------------------
    def enqueue(self, queue: str, record: dict) -> dict:
        if queue not in QUEUES:
            raise StoreError(f"unknown queue {queue!r}")
        path = self.root / f"{queue}.jsonl"
        n = len([ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()])
        rec = {"queue_seq": n, **record}
        with open(path, "a", encoding="utf-8") as f:
            f.write(_dump(rec) + "\n")
        return rec

    def queue(self, queue: str) -> list[dict]:
        if queue not in QUEUES:
            raise StoreError(f"unknown queue {queue!r}")
        path = self.root / f"{queue}.jsonl"
        return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    # ---- snapshots / rollback -------------------------------------------
    def snapshot(self, name: str) -> dict:
        if not _SNAPSHOT_NAME.match(name):
            raise StoreError(f"invalid snapshot name {name!r}")
        path = self.root / "snapshots" / f"{name}.json"
        if path.exists():
            raise StoreError(f"snapshot exists: {name}")
        lines = self._read_lines()
        snap = {"name": name, "version": len(lines), "head_hash": self.head_hash(), "lines": lines}
        _write_atomic(path, _dump(snap) + "\n")
        return {k: snap[k] for k in ("name", "version", "head_hash")}

    def snapshots(self) -> list[str]:
        return sorted(p.stem for p in (self.root / "snapshots").glob("*.json"))

    def _archive_and_replace(self, new_lines: list[str]) -> Path:
        current = self._read_lines()
        archive_dir = self.root / "archive"
        k = len(list(archive_dir.glob("rollback-*.jsonl")))
        archive = archive_dir / f"rollback-{k:04d}.jsonl"
        _write_atomic(archive, "".join(ln + "\n" for ln in current))
        _write_atomic(self.log_path, "".join(ln + "\n" for ln in new_lines))
        return archive

    def rollback(self, name: str) -> dict:
        """Restore the log to a named snapshot. The replaced log is archived."""
        path = self.root / "snapshots" / f"{name}.json"
        if not path.exists():
            raise StoreError(f"no such snapshot: {name}")
        snap = json.loads(path.read_text(encoding="utf-8"))
        archive = self._archive_and_replace(snap["lines"])
        self.enqueue("audit", {"event": "rollback", "snapshot": name,
                               "version": snap["version"], "archive": archive.name})
        return {"version": snap["version"], "head_hash": self.head_hash(), "archive": archive.name}

    def rollback_to_version(self, version: int) -> dict:
        """Truncate the log to its first ``version`` entries (archiving the rest)."""
        lines = self._read_lines()
        if not 0 <= version <= len(lines):
            raise StoreError(f"version out of range: {version}")
        archive = self._archive_and_replace(lines[:version])
        self.enqueue("audit", {"event": "rollback", "version": version, "archive": archive.name})
        return {"version": version, "head_hash": self.head_hash(), "archive": archive.name}
