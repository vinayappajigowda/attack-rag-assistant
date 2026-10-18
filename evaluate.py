"""Measure the assistant.

1. Retrieval: does the right document come back? hit@1, hit@5 and MRR for TF-IDF, BM25 and hybrid,
   on the development questions (used while building) and a held-out set (written before testing, run once).
2. Scope gate: are off-topic questions refused, and on-topic ones answered?
3. Answers (optional, needs a backend): are citations valid, are invented IDs avoided, is the expected ID named?

Usage:
    python evaluate.py                       # retrieval + scope gate (no LLM needed)
    python evaluate.py --answers ollama      # also grade answers from a local model
    python evaluate.py --answers anthropic   # or from Claude (needs ANTHROPIC_API_KEY)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from src.answer import NOT_COVERED, Assistant
from src.retrieve import Retriever

METHODS = [("TF-IDF", "tfidf", False), ("BM25", "bm25", False), ("Hybrid (no aliases)", "hybrid", False),
           ("Hybrid + aliases", "hybrid", True)]


def load(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def retrieval(r: Retriever, questions: list[dict], k: int = 5) -> pd.DataFrame:
    rows = []
    for q in [q for q in questions if q["expected"]]:
        for label, method, al in METHODS:
            res = r.search(q["question"], k=k, method=method, use_aliases=al)
            hit = [i for i, d in enumerate(res) if d["ref_id"] in q["expected"] and (not q["kind"] or d["kind"] == q["kind"])]
            rows.append(dict(id=q["id"], category=q["category"], method=label, question=q["question"],
                             expected=" / ".join(q["expected"]) + (f" ({q['kind']})" if q["kind"] else ""),
                             rank=hit[0] + 1 if hit else None,
                             top_result=f"{res[0]['ref_id']} ({res[0]['kind']})" if res else ""))
    return pd.DataFrame(rows)


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby("method", sort=False)
    return pd.DataFrame({"questions": g.size(), "hit@1": g["rank"].apply(lambda s: (s == 1).mean()),
                         "hit@5": g["rank"].apply(lambda s: s.notna().mean()),
                         "MRR": g["rank"].apply(lambda s: (1 / s).fillna(0).mean())}).round(3)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--answers", choices=["extractive", "ollama", "anthropic"], default=None)
    ap.add_argument("--model", default=None, help="e.g. qwen2.5:7b or llama3.2:3b (default: OLLAMA_MODEL or llama3.2)")
    args = ap.parse_args()
    out = Path("reports")
    out.mkdir(exist_ok=True)
    r = Retriever.from_files("data/corpus.jsonl")
    dev, hold = load("eval/questions.jsonl"), load("eval/questions_holdout.jsonl")

    prev = json.loads((out / "eval_summary.json").read_text()) if (out / "eval_summary.json").exists() else {}
    results = {"answers": prev.get("answers", {})} if isinstance(prev.get("answers"), dict) and \
        all(isinstance(v, dict) for v in prev.get("answers", {}).values()) else {}
    for name, qs in [("development", dev), ("holdout", hold)]:
        df = retrieval(r, qs)
        df.to_csv(out / f"retrieval_{name}.csv", index=False)
        s = summarise(df)
        results[name] = s.reset_index().to_dict("records")
        print(f"\n=== Retrieval: {name} set ({len([q for q in qs if q['expected']])} questions) ===")
        print(s.to_string())
        if name == "development":
            by_cat = df[df["method"] == "Hybrid + aliases"].groupby("category")["rank"].apply(
                lambda x: f"{x.notna().sum()}/{len(x)}")
            print("\nHybrid + aliases, found in top 5, by question type:")
            print(by_cat.to_string())
            misses = df[(df["method"] == "Hybrid + aliases") & df["rank"].isna()]
            if len(misses):
                print("\nMissed:")
                for m in misses.itertuples():
                    print(f"  {m.id} {m.question[:60]:<60} expected {m.expected}, got {m.top_result}")

    # Scope gate: off-topic questions should be refused, on-topic answered
    a = Assistant(r, backend="extractive")
    gate = []
    for q in dev + hold:
        ans = a.ask(q["question"])
        gate.append(dict(id=q["id"], on_topic=bool(q["expected"]), answered=ans.in_scope))
    g = pd.DataFrame(gate)
    off, on = g[~g["on_topic"]], g[g["on_topic"]]
    results["scope_gate"] = dict(off_topic_refused=f"{(~off['answered']).sum()}/{len(off)}",
                                 on_topic_answered=f"{on['answered'].sum()}/{len(on)}",
                                 on_topic_refused=list(on.loc[~on["answered"], "id"]))
    print(f"\n=== Scope gate ===\nOff-topic refused: {results['scope_gate']['off_topic_refused']}  |  "
          f"On-topic answered: {results['scope_gate']['on_topic_answered']}  "
          f"(refused: {', '.join(results['scope_gate']['on_topic_refused']) or 'none'})")

    if args.answers:
        a = Assistant(r, backend=args.answers, model=args.model)
        rows = []
        for q in dev + hold:
            ans = a.ask(q["question"])
            named = any(e.lower() in ans.text.lower() for e in q["expected"]) if q["expected"] else None
            exp = {e.lower() for e in q["expected"]}
            cited_ok = any(1 <= n <= len(ans.sources) and ans.sources[n - 1]["ref_id"].lower() in exp
                           for n in ans.citations) if q["expected"] else None
            rows.append(dict(id=q["id"], question=q["question"], expected=" / ".join(q["expected"]),
                             backend=ans.backend, in_scope=ans.in_scope, grounded=ans.grounded,
                             citations=len(ans.citations), invalid_citations=len(ans.invalid_citations),
                             invented_ids=", ".join(ans.ids_not_in_sources), names_expected_id=named, cites_expected_source=cited_ok,
                             said_not_covered=NOT_COVERED.lower().rstrip(".") in ans.text.lower(),
                             error=ans.error, answer=ans.text))
            print(f"  {q['id']} grounded={ans.grounded} invented={ans.ids_not_in_sources or '-'}")
        d = pd.DataFrame(rows)
        tag = args.answers if args.answers == "extractive" else f"{args.answers}_{a.model.replace(':', '-')}"
        d.to_csv(out / f"answers_{tag}.csv", index=False)
        on = d[d["expected"] != ""]
        results.setdefault("answers", {})
        results["answers"][tag] = dict(
            backend=args.answers, model=a.model, questions=len(d),
            grounded=f"{int(d['grounded'].sum())}/{len(d)}",
            answers_with_invalid_citations=int((d["invalid_citations"] > 0).sum()),
            answers_with_invented_ids=int((d["invented_ids"] != "").sum()),
            names_expected_id=f"{int(on['names_expected_id'].sum())}/{len(on)}",
            cites_expected_source=f"{int(on['cites_expected_source'].sum())}/{len(on)}",
            errors=int((d["error"] != "").sum()))
        print(f"\n=== Answers ({tag}) ===")
        for k, v in results["answers"][tag].items():
            print(f"  {k}: {v}")

    (out / "eval_summary.json").write_text(json.dumps(results, indent=2, default=str))
    print(f"\nSaved {out}/retrieval_development.csv, retrieval_holdout.csv, eval_summary.json")


if __name__ == "__main__":
    main()
