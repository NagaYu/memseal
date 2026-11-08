"""MemSeal command-line interface (Phase 1, offline).

    memseal verify <store_dir>          verify the hash chain; exit 1 on any issue
    memseal quarantine <store_dir>      list quarantine + review queues
    memseal bench generate [--split dev] [--seed N] [--out DIR]
    memseal run [--bench FILE] [--out DIR] [--conditions C0,C2,C3]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .store import FileStore, StoreError


def _print(obj, as_json):
    if as_json:
        print(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))


def cmd_verify(args) -> int:
    try:
        store = FileStore(args.store)
    except StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    issues, bad = store.verify()
    report = {"store": str(store.root), "principal": store.principal, "version": store.version(),
              "head_hash": store.head_hash(), "ok": not issues,
              "issues": [i.to_dict() for i in issues], "untrusted_entries": sorted(bad)}
    if args.json:
        _print(report, True)
    else:
        print(f"store      {report['store']}")
        print(f"principal  {report['principal']}")
        print(f"version    {report['version']}")
        print(f"head_hash  {report['head_hash']}")
        if not issues:
            print("chain OK")
        else:
            print(f"chain FAILED: {len(issues)} issue(s), {len(bad)} untrusted entr(y/ies)")
            for i in issues:
                print(f"  seq={i.seq} {i.entry_id} {i.kind} {i.detail}".rstrip())
    return 0 if not issues else 1


def cmd_quarantine(args) -> int:
    try:
        store = FileStore(args.store)
    except StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    rows = [("quarantine", r) for r in store.queue("quarantine")] + [("review", r) for r in store.queue("review")]
    if args.json:
        _print([{"queue": q, **r} for q, r in rows], True)
        return 0
    if not rows:
        print("no quarantined or review items")
        return 0
    for q, r in rows:
        req = r.get("request", {})
        content = req.get("content")
        shown = "<withheld: foreign principal>" if content is None else content
        if len(shown) > 100:
            shown = shown[:97] + "..."
        print(f"[{q}#{r['queue_seq']}] {r['disposition']:<11} reasons={','.join(r['reasons'])} "
              f"source={req.get('source_class')} principal={req.get('principal')}")
        print(f"    {shown}")
    return 0


def cmd_bench_generate(args) -> int:
    from .bench.generator import HoldoutRefused, write_bench
    try:
        manifest = write_bench(args.out, split=args.split, seed=args.seed)
    except HoldoutRefused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def cmd_run(args) -> int:
    from .bench.generator import load_cases
    from .sim.runner import run_bench, write_reports
    conds = tuple(c.strip() for c in args.conditions.split(",") if c.strip())
    results = run_bench(load_cases(args.bench), conds)
    digest = write_reports(results, args.out)
    print(json.dumps({"out": args.out, "files": digest}, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="memseal", description="MemSeal Phase 1 (offline, deterministic)")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="verify a store's hash chain")
    v.add_argument("store")
    v.add_argument("--json", action="store_true")
    v.set_defaults(func=cmd_verify)

    q = sub.add_parser("quarantine", help="list quarantine and review queues")
    q.add_argument("store")
    q.add_argument("--json", action="store_true")
    q.set_defaults(func=cmd_quarantine)

    b = sub.add_parser("bench", help="MemSeal Bench")
    bsub = b.add_subparsers(dest="bench_cmd", required=True)
    g = bsub.add_parser("generate", help="generate bench cases")
    g.add_argument("--split", default="dev", choices=["dev", "holdout"])
    g.add_argument("--seed", type=int, default=None)
    g.add_argument("--out", default="bench/dev")
    g.set_defaults(func=cmd_bench_generate)

    r = sub.add_parser("run", help="run the scripted-agent simulation")
    r.add_argument("--bench", default="bench/dev/memseal_bench_dev.jsonl")
    r.add_argument("--out", default="reports/phase1-runs")
    r.add_argument("--conditions", default="C0,C2,C3")
    r.set_defaults(func=cmd_run)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
