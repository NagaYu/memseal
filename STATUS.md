# STATUS — Phase 1

| Step | Module | Tests | State |
|---|---|---|---|
| 0 | scaffold (`pyproject.toml`, `memseal/`, docs) | `test_scaffold.py` (1) | done |
| 1 | `envelope.py` — Envelope, tiers, SHA-256 chain, verification | `test_envelope.py` (11) | done |
| 2 | `store.py` — file store, principal scope, versions, snapshot/rollback, queues | `test_store.py` (13) | done |
| 3 | `detectors.py` — imperative EN/JA, secret shapes, redaction | `test_detectors.py` (53) | done |
| 4 | `policy.py` — W1–W5, quarantine/review/audit | `test_policy.py` (32) | done |
| 5 | `consolidate.py` — provenance-preserving consolidation | `test_consolidate.py` (9) | done |
| 6 | `recall.py` — guarded recall | `test_recall.py` (9) | done |
| 7 | `bench/` — packs, templates, generator, holdout guard | `test_bench_generator.py` (18) | done |
| 8 | `sim/` — scripted agent, runner, metrics, reports | `test_sim.py` (15), `test_no_network.py` (3) | done |
| 9 | `cli.py`, README, `reports/phase1.md` | `test_cli.py` (6) | done |

Total: 170 tests, all passing (Python 3.13.15, pytest 9.0.3).

## Not implemented / out of scope in Phase 1

* C1 (detector-only filter) and C4 (consolidation guard measurement): `NOT EVALUABLE`.
* Holdout split: guard implemented and tested for refusal; **no holdout generated**.
* Enforcement of `sole_basis_for_irreversible` by the caller (data only).
* Review-queue resolution workflow (no API to approve/reject W5 / quarantine items).
* External anchoring of the chain head (full-chain rewrite is undetectable, D-03).
* Real LLM measurements, Mem0 adapter (Phase 2).

## Phase 2 (real-LLM measurement) — status

Measurement phase on qwen2.5:14b (Ollama, temp 0, seed 20261107, 1 attempt/case,
deterministic marker scoring). Phase 2 code lives in `memseal_phase2/` and adds
no runtime deps to the `memseal/` library. **182 tests green** (170 Phase 1
unchanged + 12 Phase 2 with a MockLLM).

| Step | Artifact | State |
|---|---|---|
| 0 freeze + anchor | `bench/dev-frozen/`, `reports/phase2-start.json` | done (Phase 1 reproduced) |
| 1–3 harness/adapters/scorer | `memseal_phase2/`, `tests/test_phase2.py` | done |
| 4 pilot + predictions | `reports/phase2-pilot/`, `reports/phase2-predictions.md` | done |
| 5 dev run C0–C4 × 120 | `reports/phase2-runs/` | done, 0 errors |
| 6 Mem0 partial (60 × 2) | `reports/phase2-mem0/` | done, 0 errors (fully local, $0) |
| 7 holdout graded once | `reports/phase2_holdout_scores.json`, `reports/phase2-holdout/` | done, 0 errors |
| 8 report | `reports/phase2.md` | done |

**GATE 4 = FAIL (recorded).** Holdout C3: delayed-use 0.547 (needs ≤0.30) and
leak 5 (needs 0) fail; clean retention 0.875 (≥0.80) and quarantine precision
0.837 (≥0.75) pass. Causes: W4 misses the holdout's unseen secret shapes (M8);
declarative M2/M3/M5/M6 pass the form detectors. Detectors/policy/prompts were
NOT changed after seeing the holdout. See `reports/phase2.md`.

## Phase 2 fix round (Fix 1–3) — status

Deterministic fixes for the GATE-4 failure, implemented TDD (182 original tests
unchanged + 19 new in `tests/test_fix_*.py` = **201 green**). No tuning to v1
strings/shapes. Script-sim still reproduces Phase 1 exactly.

| Fix | Mechanism | Files |
|---|---|---|
| 1 (D-29) | `entry_class=secret` always sealed; shape table = 2nd net | `memseal/policy.py`, harness |
| 2 (D-30) | sole_basis gate in guarded recall (outbound/irreversible, T3/T4 declarative) | `memseal/recall.py`, backends |
| 3 (D-31) | consolidation retires absorbed inputs (C4) | `memseal/consolidate.py`, backends |

Post-fix real-LLM regression (0 errors):
- dev C3 delayed-use 0.395→0.291, C4 0.372→0.174; clean retention held (C3 0.867, C4 0.90); leaks unchanged (Fix 1 no-op on dev).
- holdout **v1 re-score (regression, NOT a gate)**: leak C3 5→0, delayed-use C3 0.547→0.422, clean 0.875, precision 0.837. 3 of 4 v1 criteria pass post-fix; delayed-use improved but still >0.30 (residual = T2 agent-inference / declarative M3/M5/M6).

**GATE 2 remains FAIL.** Re-gating is judged later against independent holdout v2
(not built or seen here). v2 predictions pre-registered in
`reports/phase2-fix-predictions.md`. See `reports/phase2-fix.md`.

## Phase 2 re-gate (holdout v2) — GATE 2 = FAIL (security criteria pass; utility criteria fail)

Scored once, C0/C2/C3/C4 × 80 on the independent v2 corpus (cases_sha256 238b734d…,
0 LLM errors), with pre-registered scoring-side adapters D-32/D-33/D-36/D-37 and
crash-fix D-34 (corpus/policy/detectors/fix unchanged). GATE 2 criterion-4 bars
unchanged:

| criterion | C3 | bar | verdict |
|---|---|---|---|
| delayed-use ≤ 0.30 and ≤ ½·C0 | 0.000 | ≤0.30 | PASS |
| leak = 0 | 0 | =0 | PASS |
| clean retention ≥ 0.80 | 0.444 | ≥0.80 | FAIL |
| quarantine precision ≥ 0.75 | 0.738 | ≥0.75 | FAIL |

**GATE 2 = FAIL** (recorded). The two failures are utility-side: clean retention
0.444 is **identical across C0–C4** (MemSeal does not degrade it) and is confounded
by case-sensitive matching of v2's prose `should_surface` markers plus some retrieval
misses — not a MemSeal effect (no case-insensitive match applied post-hoc); precision
0.738 is a real near-miss from W1 over-blocking imperative-looking legitimate clean
writes (fp=16). Security is strong and real: injection 0.775→0.20, leak C0 22 → C2+ 0
(M8 sealed by Fix 1, M7 by W3), identifier-subset delayed-use C0 0.219 → C3 0.0.
See `reports/phase2-regate.md`, `reports/phase2_regate_scores.json`. **Audit Errata** in phase2-regate.md corrects the precision-FP attribution (clean W1 FP = 0; 12/16 FP are D-34 rejected), the clean-retention framing (small 18-marker sample, condition-neutral, not a matching artifact), and a recall typo (0.46 → 0.5625).
