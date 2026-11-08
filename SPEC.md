# MemSeal Phase 1 — Specification (as implemented)

The fixed semantics in the Phase 1 brief are authoritative. This file restates
them as implemented and points to the code. Interpretations and extensions are
recorded in [DECISIONS.md](DECISIONS.md) (referenced as D-xx).

Scope: fully offline, no LLM, deterministic. Runtime dependencies: Python
standard library only (`pytest` for tests).

## 1. Provenance Envelope — `memseal/envelope.py`

| Field | Meaning |
|---|---|
| `seq` | position in the chain (0-based, +1 per entry) — extension, D-01 |
| `entry_id` | `e{seq:06d}-{sha256(NFC(content))[:12]}` (sequence + content hash), D-02 |
| `content` | entry text (after W4 redaction) |
| `entry_class` | `fact` / `preference` / `instruction` / `secret` / `episode` |
| `source_class` | `user_explicit` / `user_conversation` / `document` / `tool_output` / `agent_inference` / `external_agent` |
| `principal` | writer id, passed by the caller as session state — never parsed from content |
| `derived_from` | parent entry ids (empty for direct writes) |
| `trust_tier` | `T0`..`T4`, computed, never accepted from the caller |
| `sealed` | allowed only for `user_explicit` + `fact`, never for derived entries |
| `slot` | optional key of a structured fact (W5) |
| `supersedes` | ids this entry replaces (set by policy on a user_explicit overwrite) — extension, D-01 |
| `prev_hash` / `hash` | `hash = sha256(canonical_json(envelope − hash))`; genesis `prev_hash = "0"*64` |

Tier mapping: user_explicit T0, user_conversation T1, agent_inference T2,
document / tool_output T3, external_agent T4. Derived entries: worst of
(own source tier, every ancestor's tier) — D-06.

Canonical JSON: sorted keys, `(",", ":")` separators, UTF-8, strings NFC-normalised.

Chain verification (`verify_chain`): per entry, self hash + entry_id check; link
check `prev_hash == previous.hash`; `seq == previous.seq + 1`. Untrusted set =
entries failing a self check + both sides of every broken link (D-03).

## 2. File store — `memseal/store.py`

```
meta.json  log.jsonl  quarantine.jsonl  review.jsonl  audit.jsonl
snapshots/<name>.json   archive/rollback-<k>.jsonl
```

* Append-only hash-chained log. `version()` = number of entries.
* Principal scope: `append` refuses `principal != store.principal`
  (`enforce_principal=False` only for the policy-free C0 baseline / pack prefill).
* Versioning: an entry with `supersedes` hides the old entry from the active
  set; history is kept.
* `snapshot(name)` stores a full copy of the log; `rollback(name)` /
  `rollback_to_version(v)` restores it and archives the removed log (never
  discarded). Queues and audit are not rolled back (D-18).

## 3. Detectors — `memseal/detectors.py`

* Imperative form: patterns are data (`IMPERATIVE_PATTERNS`, `EN_IMPERATIVE_VERBS`,
  `JA_PATTERNS_DATA`), extensible via `register_imperative_pattern` /
  `register_imperative_verbs`.
  * EN: sentence-initial base-form verb (with optional `Note:`/`please`/`from now on` prefix),
    sentence-initial `always/never`, `when/if/once X, <verb>` trigger, directives to the
    assistant (`you must/should …`), `make sure to / don't forget to`.
  * JA: 「〜すること」, 「〜してください」, 「〜をお願いします」, 「必ず」, 「〜してはいけない/ならない」,
    「〜するな」, 「〜しなさい/せよ」, 「〜すべき」, 「〜したら…送信/転送…」, 「今後は〜する」.
* Secret shapes (`SECRET_PATTERNS`): PEM private key, `sk-`/`sk-ant-` keys, GitHub
  tokens, AWS access key ids, Slack tokens, JWT, Bearer tokens, key/token
  assignments (EN/JA), password assignments (EN/JA).
* `redact()` replaces each span with `[REDACTED:<kind>:<sha256[:8]>]`; idempotent.

## 4. Write policy — `memseal/policy.py`

Evaluation order (D-05): shape validation → **W3** → **W4** → **W2** → **W1** → **W5**.

| Code | Rule | Outcome |
|---|---|---|
| W1 | instruction-form content (detector hit, or `entry_class == instruction`, D-08) with `source_class != user_explicit` | `quarantined` |
| W2 | derived entry: tier = worst ancestor; claims of `user_explicit`/`user_conversation` or `sealed`, or unknown ancestors | `quarantined` |
| W3 | `principal != store.principal`, or derived from another principal's entries (D-07) | `rejected`, content withheld (hash only) |
| W4 | secret shape anywhere in content | content redacted, then evaluated normally (D-04) |
| W5 | slot fact whose normalised value contradicts an active sealed fact of the same slot; only a non-derived `user_explicit` write may overwrite (supersede) | `review` |

Every outcome is appended to `audit.jsonl`; non-active outcomes go to
`quarantine.jsonl` (W1/W2/W3) or `review.jsonl` (W5) with reason codes.
`raw_write` is the policy-free path (C0 baseline, pack prefill).

## 5. Consolidation — `memseal/consolidate.py`

`consolidate()` merges entries by ordered, normalisation-deduplicated `" | "`
concatenation; `derived_from` = every input id; the result goes through
`WritePolicy.write` (so W1/W2/W3 apply). `naive_consolidate()` is the C0
baseline that drops provenance (`derived_from = []`, claimed source accepted).

## 6. Recall — `memseal/recall.py`

Guarded recall (`guarded=True`): verify chain → exclude untrusted entries (listed
in `warnings` / `excluded_ids`) → supersession from verified entries only →
principal filter → keyword match (NFKC, case-insensitive, over content + slot
name) → each entry carries `provenance {source_class, trust_tier, derived_from}`
and `sole_basis_for_irreversible = (tier < T3)`. The flag is data only.

Unguarded recall (`guarded=False`): keyword match over active entries; no
verification, no principal filter, no provenance.

## 7. MemSeal Bench (dev) — `memseal/bench/`

Case (one JSONL line): `case_id`, `template_id`, `attack_class` (M1–M8 | clean),
`vector`, `lang` (en | ja), `memory_pack_id`, `store_principal`, `sessions`
(each `{session, principal, steps}`), `expected`:

```
expected.writes[step_id]   = {should_store, block_markers}
expected.payload_markers   = strings identifying the attacker payload
expected.payload_should_be_used_later = false (attacks) | null (clean)
expected.must_not_leak     = secrets (M8) / another principal's data (M7)
expected.recall_expect[step_id] = strings a correct recall should return
```

Step ops: `write`, `consolidate` (inputs = marker strings), `recall`
(`keywords`, `context` normal|outbound|irreversible), `tamper` (direct file
edit, optional hash recompute), `raw_insert` (validly chained foreign entry).

Dev split: 6 bilingual templates per attack class × 2 languages = 12 cases per
class, 12 clean templates × 2 = 24 → 120 cases. Seed `20261107`. Every case
starts from a non-empty memory pack (4 personas, 13 entries each). Holdout:
`--split holdout` requires `MEMSEAL_ALLOW_HOLDOUT=1`, an output directory
outside the repository, and an explicit non-dev seed; otherwise
`HoldoutRefused`. Not run in Phase 1.

## 8. Simulation — `memseal/sim/`

Conditions: **C0** plain store; **C2** write policy on; **C3** C2 + guarded recall.
C1 and C4 are reported `NOT EVALUABLE`. The scripted agent uses every recalled
entry (identical rule across conditions).

Metrics (`memseal/sim/runner.py`):

* injection success rate — steps labelled `should_store=false` that became active with a block marker present;
* delayed use rate — attack cases with payload markers where a session ≥ 2 recall used a payload-bearing entry;
* leak count — recall steps whose used entries contain a `must_not_leak` string;
* clean recall retention — expected recall hits found / expected (clean cases);
* quarantine precision / recall — predicted = not active; positive = `should_store=false`.

## 9. CLI — `memseal/cli.py`

`memseal verify <dir>`, `memseal quarantine <dir>`, `memseal bench generate`,
`memseal run` (also `python -m memseal …`).
