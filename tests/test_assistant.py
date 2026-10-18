"""Unit tests run on a tiny made-up ATT&CK bundle and KEV file; the last tests use the real corpus if it's built."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.answer import Answer, Assistant, check  # noqa: E402
from src.ingest import build_corpus, chunk, clean, load_corpus  # noqa: E402
from src.retrieve import Retriever, tokenize  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
ALIASES = {"log4shell": "CVE-2021-44228", "mfa fatigue": "T1621"}


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("c") / "corpus.jsonl"
    stats = build_corpus(FIX / "attack_small.json", FIX / "kev_small.json", out)
    return load_corpus(out), stats


@pytest.fixture(scope="module")
def r(corpus):
    return Retriever(corpus[0], ALIASES)


def test_clean_removes_citations_and_links():
    assert clean("Text (Citation: Foo) and [a link](http://x)") == "Text and a link"


def test_chunk_keeps_chunks_short():
    parts = chunk("\n".join(["word " * 100] * 5), max_words=220)
    assert len(parts) >= 2 and all(len(p.split()) <= 220 for p in parts)


def test_ingest_builds_each_document_kind(corpus):
    docs, stats = corpus
    kinds = {(d["ref_id"], d["kind"]) for d in docs}
    assert {("T1110.003", "technique"), ("T1110.003", "detection"), ("T1110.003", "mitigation"),
            ("T1110.003", "groups"), ("CVE-2021-44228", "kev")} <= kinds
    assert not any(d["ref_id"] == "T9998" for d in docs)          # revoked techniques are skipped
    spray = next(d for d in docs if d["ref_id"] == "T1110.003" and d["kind"] == "technique")
    assert "sub-technique of T1110 Brute Force" in spray["text"] and "Citation" not in spray["text"]


def test_tokenizer_keeps_ids_and_stems():
    t = tokenize("Detecting T1110.003 password spraying and CVE-2021-44228")
    assert "t1110.003" in t and "cve-2021-44228" in t and "spray" in t


def test_intent_routes_to_the_right_kind(r):
    assert r.search("How do I detect password spraying?", k=1)[0]["kind"] == "detection"
    assert r.search("How do I prevent password spraying?", k=1)[0]["kind"] == "mitigation"
    assert r.search("Which threat groups use password spraying?", k=1)[0]["kind"] == "groups"


def test_exact_id_and_alias(r):
    assert r.search("What is the required action for CVE-2020-1938?", k=1)[0]["ref_id"] == "CVE-2020-1938"
    top = r.search("Is Log4Shell exploited?", k=1)[0]
    assert top["ref_id"] == "CVE-2021-44228" and top["aliases_used"] == ["CVE-2021-44228"]


def test_citation_checks_catch_bad_answers(r):
    src = r.search("How do I stop MFA fatigue?", k=2)
    good = check(Answer("q", "Use number matching [1].", src, "t"))
    assert good.grounded and not good.invalid_citations
    bad = check(Answer("q", "Use number matching [5] and look at T9999.", src, "t"))
    assert not bad.grounded and bad.invalid_citations == [5] and bad.ids_not_in_sources == ["T9999"]
    uncited = check(Answer("q", "Use number matching.", src, "t"))
    assert not uncited.grounded


def test_off_topic_questions_are_refused(r):
    a = Assistant(r, backend="extractive", min_score=1.0)
    assert not a.ask("How do I bake sourdough bread?").in_scope
    on = a.ask("How do I stop MFA fatigue attacks?")
    assert on.in_scope and on.grounded and on.citations


def test_unreachable_model_falls_back(r):
    a = Assistant(r, backend="ollama", host="http://127.0.0.1:9", min_score=1.0)
    ans = a.ask("How do I prevent password spraying?")
    assert ans.backend == "extractive" and "failed" in ans.error and ans.grounded


REAL = ROOT / "data" / "corpus.jsonl"


@pytest.mark.skipif(not REAL.exists(), reason="run build_index.py first")
def test_real_corpus_retrieval_quality():
    r = Retriever.from_files(REAL, ROOT / "config" / "aliases.json")
    qs = [json.loads(line) for line in open(ROOT / "eval" / "questions_holdout.jsonl")]
    hits = 0
    for q in qs:
        res = r.search(q["question"], k=5)
        hits += any(d["ref_id"] in q["expected"] and (not q["kind"] or d["kind"] == q["kind"]) for d in res)
    assert hits / len(qs) >= 0.9
