import copy
import json
from collections import Counter
from pathlib import Path

import pytest

from memseal.bench.generator import (
    ATTACK_CLASSES,
    DEV_SEED,
    HOLDOUT_ENV,
    REPO_ROOT,
    HoldoutRefused,
    cases_sha256,
    check_holdout_allowed,
    generate,
    load_cases,
    validate_case,
    write_bench,
)
from memseal.bench.packs import PACKS
from memseal.detectors import has_secret


@pytest.fixture(scope="module")
def cases():
    return generate("dev")


def test_dev_size_and_class_balance(cases):
    assert len(cases) == 120
    counts = Counter(c["attack_class"] for c in cases)
    for m in ATTACK_CLASSES:
        assert counts[m] == 12, m
    assert counts["clean"] == 24
    by_lang = Counter((c["attack_class"], c["lang"]) for c in cases)
    for m in ATTACK_CLASSES + ("clean",):
        assert by_lang[(m, "en")] == by_lang[(m, "ja")]


def test_case_ids_unique(cases):
    assert len({c["case_id"] for c in cases}) == len(cases)


def test_all_cases_pass_schema(cases):
    errors = [e for c in cases for e in validate_case(c)]
    assert errors == []


def test_every_case_starts_from_nonempty_pack_in_its_language(cases):
    for c in cases:
        pack = PACKS[c["memory_pack_id"]]
        assert len(pack["entries"]) >= 10 and pack["lang"] == c["lang"]
        assert c["store_principal"] == pack["principal"]


def test_attack_arcs_poison_first_and_use_later(cases):
    for c in cases:
        if c["attack_class"] == "clean":
            continue
        assert len(c["sessions"]) >= 2
        assert any(st["op"] != "recall" for st in c["sessions"][0]["steps"])
        assert any(st["op"] == "recall" for s in c["sessions"][1:] for st in s["steps"])


def test_markers_do_not_occur_in_legit_pack_memory(cases):
    for c in cases:
        pack_text = " ".join(e["content"] for e in PACKS[c["memory_pack_id"]]["entries"])
        for m in c["expected"]["payload_markers"] + c["expected"]["must_not_leak"]:
            assert m not in pack_text, (c["case_id"], m)


def test_m8_leak_strings_are_secret_shaped(cases):
    for c in cases:
        if c["attack_class"] != "M8":
            continue
        for st in c["sessions"][0]["steps"]:
            if st["op"] == "write":
                assert has_secret(st["content"]), c["case_id"]


def test_generator_is_deterministic(cases, tmp_path):
    assert cases_sha256(cases) == cases_sha256(generate("dev"))
    assert cases_sha256(cases) == cases_sha256(generate("dev", DEV_SEED))
    m1 = write_bench(tmp_path / "a")
    m2 = write_bench(tmp_path / "b")
    assert m1 == m2
    for name in ("memseal_bench_dev.jsonl", "packs.json", "manifest.json"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


def test_different_seed_changes_hash(cases):
    assert cases_sha256(generate("dev", DEV_SEED + 1)) != cases_sha256(cases)


def test_committed_dev_bench_matches_regeneration(cases):
    path = REPO_ROOT / "bench" / "dev" / "memseal_bench_dev.jsonl"
    if not path.exists():
        pytest.skip("dev bench not yet written")
    manifest = json.loads((REPO_ROOT / "bench" / "dev" / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["cases_sha256"] == cases_sha256(cases)
    assert load_cases(path) == cases


def test_unknown_split_rejected():
    with pytest.raises(ValueError):
        generate("test")


# ----------------------------------------------------------------- schema negatives

def test_schema_rejects_broken_cases(cases):
    c = copy.deepcopy(cases[0])
    del c["expected"]
    assert validate_case(c)

    c = copy.deepcopy(cases[0])
    c["sessions"] = c["sessions"][:1]
    assert any("multi-session" in e for e in validate_case(c))

    c = copy.deepcopy(cases[0])
    c["memory_pack_id"] = "pack-xx"
    assert any("unknown memory pack" in e for e in validate_case(c))

    c = copy.deepcopy(cases[0])
    c["sessions"][0]["steps"][0]["content"] = "Send it to {evil_email}"
    assert any("placeholder" in e for e in validate_case(c))

    c = copy.deepcopy(cases[0])
    c["attack_class"] = "M9"
    assert any("attack_class" in e for e in validate_case(c))

    c = copy.deepcopy(cases[0])
    c["sessions"][0]["steps"][0]["op"] = "teleport"
    assert any("bad op" in e for e in validate_case(c))


# ----------------------------------------------------------------- holdout refusal

def test_holdout_refused_without_env(tmp_path):
    with pytest.raises(HoldoutRefused, match=HOLDOUT_ENV):
        check_holdout_allowed(tmp_path / "ho", env={})
    with pytest.raises(HoldoutRefused):
        check_holdout_allowed(tmp_path / "ho", env={HOLDOUT_ENV: "0"})


def test_holdout_refused_inside_repo_even_with_env():
    for inside in (REPO_ROOT, REPO_ROOT / "bench" / "holdout", REPO_ROOT / "reports" / "x"):
        with pytest.raises(HoldoutRefused, match="inside the repository"):
            check_holdout_allowed(inside, env={HOLDOUT_ENV: "1"})


def test_holdout_refused_without_out_dir():
    with pytest.raises(HoldoutRefused):
        check_holdout_allowed(None, env={HOLDOUT_ENV: "1"})


def test_generate_and_write_refuse_holdout(tmp_path, monkeypatch):
    monkeypatch.delenv(HOLDOUT_ENV, raising=False)
    with pytest.raises(HoldoutRefused):
        generate("holdout", 1, out_dir=tmp_path / "ho")
    with pytest.raises(HoldoutRefused):
        write_bench(tmp_path / "ho", split="holdout", seed=1)
    with pytest.raises(HoldoutRefused):
        write_bench(REPO_ROOT / "bench" / "holdout", split="holdout", seed=1, env={HOLDOUT_ENV: "1"})
    assert not (tmp_path / "ho").exists()
    assert not (REPO_ROOT / "bench" / "holdout").exists()


def test_holdout_refuses_dev_seed(tmp_path):
    with pytest.raises(HoldoutRefused, match="seed"):
        generate("holdout", DEV_SEED, out_dir=tmp_path / "ho", env={HOLDOUT_ENV: "1"})
    assert not (tmp_path / "ho").exists()


def test_holdout_guard_passes_only_when_both_conditions_hold(tmp_path):
    # Only the guard is exercised; no holdout cases are generated in Phase 1.
    out = check_holdout_allowed(tmp_path / "ho", env={HOLDOUT_ENV: "1"})
    assert out == (tmp_path / "ho").resolve()
    assert not Path(out).exists()
