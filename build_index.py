"""Download MITRE ATT&CK and CISA KEV (or use local copies) and build data/corpus.jsonl.

Usage:
    python build_index.py              # download if data/raw/ is empty, then build
    python build_index.py --offline    # only use files already in data/raw/
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import requests

from src.ingest import ATTACK_URL, KEV_URLS, build_corpus

RAW = Path("data/raw")


def fetch(urls: list[str], dest: Path) -> None:
    for url in urls:
        try:
            print(f"Downloading {url} ...")
            r = requests.get(url, timeout=120)
            r.raise_for_status()
            dest.write_bytes(r.content)
            return
        except requests.RequestException as e:
            print(f"  failed: {e}")
    raise SystemExit(f"Could not download {dest.name}. Put a copy in {RAW}/ and run with --offline.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--refresh", action="store_true", help="download again even if files exist")
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    attack, kev = RAW / "enterprise-attack.json", RAW / "kev.json"
    if not args.offline:
        if args.refresh or not attack.exists():
            fetch([ATTACK_URL], attack)
        if args.refresh or not kev.exists():
            fetch(KEV_URLS, kev)
    stats = build_corpus(attack, kev, Path("data/corpus.jsonl"))
    Path("data/corpus_stats.json").write_text(json.dumps(stats, indent=2))
    print(f"Built data/corpus.jsonl: {stats['documents']:,} documents "
          f"(ATT&CK {stats['attack_version']}, KEV {stats['kev_catalog']}, {stats['kev_entries']:,} CVEs)")
    for k, n in stats["by_kind"].items():
        print(f"  {k:<11} {n:>6,}")


if __name__ == "__main__":
    main()
