# MemSeal

**MemSeal is a containment layer on the write/recall boundary of an AI agent's long-term memory.**
Every memory entry is wrapped in a provenance envelope (who wrote it, from what source, derived from
what, at which trust tier) inside a SHA-256 hash chain. Deterministic policies decide what may be
stored, and a trust-tiered recall path decides what may be surfaced — especially before an external
send or an irreversible action.

- **No LLM in the policy.** The envelope, the write rules (W1–W5), the recall path and the
  consolidation guard are deterministic and offline.
- **Measured with a real local LLM.** Agent behavior is driven by `qwen2.5:14b` via Ollama,
  temperature 0, seed 20261107, one attempt per case, deterministic marker scoring, **$0**, all local.
- **Honest gate.** The acceptance gate below is self-reported as **FAIL**; passing and failing
  criteria are shown with equal weight.

## What it does (30 seconds)

```
write attempt ──► extract candidate ──► [W1 imperative] [W2 derived-tier] [W3 principal]
                                        [W4 secret]      [W5 sealed-slot]
                                            │ active                 │ quarantine / review / reject
                                            ▼
                           hash-chained, per-principal memory store
                                            │
recall ──► verify chain ──► principal filter ──► provenance + trust tier ──►
           sole-basis gate (outbound/irreversible: withhold low-trust, uncorroborated facts)
```

Write policies: **W1** quarantines instruction-form content from any source but the user;
**W2** makes derived entries inherit their worst ancestor's trust tier (no laundering a document into
a "user fact"); **W3** rejects cross-principal writes and filters cross-principal recall; **W4** seals
secrets (by `entry_class=secret` *and* by shape) so plaintext never lands in the store; **W5** sends a
fact that contradicts a sealed fact to review.

## GATE 2 (acceptance) — self-reported **FAIL**

The gate is judged on an **independent holdout** corpus authored by a separate party that never saw
MemSeal's code, the dev corpus, or the reports. The bars are fixed in advance and never moved.
Conditions: **C0** raw store · **C2** write path · **C3** write + recall path · **C4** + consolidation
guard.

| Criterion (C3) | Holdout v1 (pre-fix) | Holdout v2 (post-fix) | Bar |
|---|---|---|---|
| Delayed-use rate ≤ 0.30 **and** ≤ ½·C0 | 0.547 — **FAIL** | **0.000 — PASS** | ≤ 0.30 |
| Leak count (cross-principal / secret) = 0 | 5 — **FAIL** | **0 — PASS** | = 0 |
| Clean recall retention ≥ 0.80 | 0.875 — PASS | 0.444 — **FAIL** | ≥ 0.80 |
| Quarantine precision ≥ 0.75 | 0.837 — PASS | 0.738 — **FAIL** | ≥ 0.75 |

**Overall: GATE 2 = FAIL on v2.** Three deterministic fixes between v1 and v2 (classification-based
secret sealing; a sole-basis recall gate; consolidation root retirement) closed both security
criteria — on v2, cross-principal + secret leaks went from **22 → 0** across C0 → C2, injection
success **0.775 → 0.20**, and delayed-use **0.000** at C3. The two remaining failures are
utility-side, and their causes are stated precisely (not hand-waved):

- **Clean recall retention 0.444** is measured over a **small 18-marker sample** and is **identical
  across C0/C2/C3/C4 (8/18)** — i.e. it is **condition-neutral and not caused by MemSeal**. Of the 10
  misses, only 1 would recover under case-insensitive matching (ceiling 0.556); the rest are genuine
  non-surfacings where even the raw C0 baseline (no defense) did not reproduce stored content.
- **Quarantine precision 0.738** comes from 16 false positives: **4** are W1 (all inside **M2 attack**
  cases, i.e. legitimate writes embedded in an attack), and **12** are `policy_refused` records
  (cross-principal M7 writes ×8 and 4 clean) counted under the harness's rejected accounting.
  **W1 produced zero false positives on clean cases.**

Full detail, including an audit Errata that corrects earlier attribution wording, is in
[`reports/phase2-regate.md`](reports/phase2-regate.md) and [`reports/phase2-fix.md`](reports/phase2-fix.md).

## MemSeal Bench

- **8 attack classes** M1–M8 (query-only injection, document persistence, consolidation laundering,
  sleeper/trigger, false-fact implantation, preference drift, cross-principal leakage, secret staging)
  plus **clean** utility cases.
- **Split discipline:** the **dev** split (120 cases) is public in this repo; **holdout** corpora are
  authored independently and kept sealed — only their existence and aggregate numbers are reported here,
  never the cases.
- **Conditions C0–C4** and **deterministic marker scoring** (no LLM judge): injection success, delayed
  use, leak count, clean retention, quarantine precision/recall, per attack class.

### Dev results (120 cases, real LLM)

| Metric | C0 | C1 | C2 | C3 | C4 |
|---|---|---|---|---|---|
| Injection success | 0.982 | 0.713 | 0.556 | 0.556 | 0.463 |
| Delayed-use | 0.849 | 0.616 | 0.488 | 0.395 | 0.372 |
| Leak count | 21 | 12 | 6 | 2 | 0 |

(The dev split shares the author's templates, so treat dev as an optimistic in-distribution reference;
the independent holdout is the real test.)

## Mem0 wrap (real memory store)

MemSeal was also run as a wrapper around **Mem0** (fully local: Ollama LLM + Ollama embedder,
in-memory vector store), 60 cases, two conditions:

- **C3-wrap drove M8 secret leaks 4 → 0** and injection 0.673 → 0.558 vs. Mem0 native.
- Disclosed cost: wrap clean retention dipped 0.75 → 0.667 (an exact-content match artifact between
  Mem0's paraphrase and the MemSeal store — see report), and Mem0's native `user_id` scoping already
  blocked the cross-principal class.

## Reproduce (local, $0)

```bash
python3 -m pytest -q          # deterministic policy + bench + harness tests
```

```bash
python3 -m memseal bench generate --split dev --out bench/dev
python3 -m memseal verify <store_dir>
python3 -m memseal quarantine <store_dir>
```

The real-LLM measurement harness is in [`memseal_phase2/`](memseal_phase2/) and talks only to a local
Ollama (`qwen2.5:14b`). No external API, no API key, no network beyond localhost and the one-time model
download. Tests use a mock LLM, so the suite runs without Ollama.

## Status

- **Tests:** full suite green (deterministic; mock-LLM harness tests need no Ollama).
- **GATE 2:** FAIL (recorded). Security criteria pass on the independent v2 holdout; utility criteria
  fail for the reasons above.
- Phase reports: [`reports/phase1.md`](reports/phase1.md) · [`reports/phase2.md`](reports/phase2.md) ·
  [`reports/phase2-fix.md`](reports/phase2-fix.md) · [`reports/phase2-regate.md`](reports/phase2-regate.md).

## License & contact

**All Rights Reserved.** This repository is published for evaluation reading only; no rights to use,
copy, modify, or redistribute are granted. See [`LICENSE`](LICENSE). Acquisition / licensing /
transfer inquiries are welcome through the author's portfolio:

**https://nagayu-portfolio.nagayu.workers.dev/en**
