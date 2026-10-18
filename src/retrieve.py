"""Search the corpus. Three methods, so they can be compared:

  tfidf    TF-IDF vectors + cosine similarity (scikit-learn)
  bm25     Okapi BM25, the classic search-engine ranking
  hybrid   BM25 + exact ID matches (T1110.003, CVE-2020-1938) + query-intent routing
           (detect / prevent / who uses / vulnerability) + optional alias expansion
           ("Log4Shell" -> CVE-2021-44228)
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|CVE-\d{4}-\d{4,7})\b", re.I)
STOP = set("""a an and are as at be by can do does for from has have how i if in into is it its may of on or
should that the their them then there these they this to was what when where which who why will with you your
my we our me us about any been being but could did would""".split())
INTENT = {  # words in the question -> the kind of document that answers it
    "technique": ["explain", "describe", "what is", "tell me about", "which technique", "what technique",
                  "technique is"],
    "detection": ["detect", "detection", "monitor", "log", "logs", "alert", "hunt", "hunting", "spot", "identify",
                  "sigma", "siem", "event id", "telemetry", "find evidence"],
    "mitigation": ["prevent", "mitigate", "mitigation", "mitigations", "stop", "block", "defend", "protect",
                   "harden", "reduce the risk", "defence", "defense", "security controls"],
    "groups": ["who uses", "which groups", "threat actor", "threat actors", "apt", "group uses", "groups use",
               "attributed"],
    "kev": ["cve", "vulnerability", "vulnerabilities", "patch", "exploited", "kev", "known exploited", "zero-day",
            "zero day", "due date", "ransomware campaign"],
}


def stem(w: str) -> str:
    """A deliberately tiny stemmer: spraying -> spray, credentials -> credential."""
    if ID_RE.fullmatch(w) or len(w) <= 4:
        return w
    for suf in ("ings", "ing", "ies", "ed", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 4:
            return w[: -len(suf)] + ("y" if suf == "ies" else "")
    return w


def tokenize(text: str) -> list[str]:
    text = text.lower()
    ids = [m.lower() for m in ID_RE.findall(text)]
    words = re.findall(r"[a-z0-9]+(?:[-'][a-z0-9]+)*", ID_RE.sub(" ", text))
    return ids + [stem(w) for w in words if w not in STOP and len(w) > 1]


class BM25:
    def __init__(self, docs_tokens: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.tf = [Counter(d) for d in docs_tokens]
        self.len = np.array([len(d) for d in docs_tokens], dtype=float)
        self.avg = float(self.len.mean())
        df = Counter(t for d in docs_tokens for t in set(d))
        n = len(docs_tokens)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.postings: dict[str, list[int]] = {}
        for i, d in enumerate(self.tf):
            for t in d:
                self.postings.setdefault(t, []).append(i)

    def scores(self, q: list[str]) -> np.ndarray:
        s = np.zeros(len(self.tf))
        for t in set(q):
            if t not in self.idf:
                continue
            idf = self.idf[t]
            for i in self.postings[t]:
                f = self.tf[i][t]
                s[i] += idf * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg))
        return s


class Retriever:
    def __init__(self, docs: list[dict], aliases: dict | None = None):
        self.docs = docs
        self.aliases = {k.lower(): v for k, v in (aliases or {}).items()}
        texts = [f"{d['title']}\n{d['text']}" for d in docs]
        self.bm25 = BM25([tokenize(t) for t in texts])
        self.tfidf = TfidfVectorizer(tokenizer=tokenize, lowercase=False, token_pattern=None, sublinear_tf=True)
        self.matrix = self.tfidf.fit_transform(texts)
        self._kind = np.array([d["kind"] for d in docs])
        self.by_ref: dict[str, list[int]] = {}
        for i, d in enumerate(docs):
            self.by_ref.setdefault(d["ref_id"].lower(), []).append(i)

    @classmethod
    def from_files(cls, corpus: str | Path, aliases: str | Path | None = "config/aliases.json"):
        from .ingest import load_corpus
        al = json.loads(Path(aliases).read_text()) if aliases and Path(aliases).exists() else {}
        al = {k: v for k, v in al.items() if not k.startswith("_")}
        return cls(load_corpus(corpus), al)

    def intent(self, query: str) -> str | None:
        q = query.lower()
        hits = {k: sum(bool(re.search(rf"\b{re.escape(w)}\b", q)) for w in words) for k, words in INTENT.items()}
        best = max(hits, key=hits.get)
        return best if hits[best] else None

    def expand(self, query: str) -> tuple[str, list[str]]:
        """Add the IDs behind well-known nicknames (from config/aliases.json)."""
        added = [ref for name, ref in self.aliases.items() if re.search(rf"\b{re.escape(name)}\b", query.lower())]
        return (query + " " + " ".join(added)) if added else query, added

    def search(self, query: str, k: int = 5, method: str = "hybrid", use_aliases: bool = True) -> list[dict]:
        expanded, added = self.expand(query) if (method == "hybrid" and use_aliases) else (query, [])
        if method == "tfidf":
            s = (self.matrix @ self.tfidf.transform([query]).T).toarray().ravel()
        else:
            s = self.bm25.scores(tokenize(expanded))
        raw = s.copy()
        if method == "hybrid":
            top = s.max() or 1.0
            s = s / top
            for ref in {m.lower() for m in ID_RE.findall(expanded)}:
                for i in self.by_ref.get(ref, []):
                    s[i] += 1.0  # an exact ID in the question is the strongest signal there is
            want = self.intent(query)
            if want:
                s = np.where(self._kind == want, s * 1.35, s)
        order = np.argsort(-s)[: k]
        return [dict(self.docs[i], score=float(s[i]), raw_score=float(raw[i]), rank=r + 1, aliases_used=added)
                for r, i in enumerate(order) if s[i] > 0]
