"""Turn MITRE ATT&CK (STIX) and the CISA KEV catalogue into small, citable documents.

Each document has one job, so a search result can be cited precisely:
  technique   what the technique is (ID, name, tactics, platforms, description)
  detection   how to detect it (ATT&CK detection strategies and analytics, with log sources)
  mitigation  how to prevent it (ATT&CK mitigations and how each applies)
  groups      which threat groups are known to use it
  kev         a CISA Known Exploited Vulnerabilities entry
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"]
MAX_WORDS = 220  # long texts are split so each chunk stays focused


def clean(text: str) -> str:
    """Remove ATT&CK citation markers, markdown links and HTML tags."""
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    text = re.sub(r"</?code>|<br>|</?b>|</?i>", "", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\s*\n\s*", "\n", text).strip()


def chunk(text: str, max_words: int = MAX_WORDS) -> list[str]:
    """Split on paragraphs, packing them into chunks of at most max_words."""
    out, cur, n = [], [], 0
    for para in [p for p in text.split("\n") if p.strip()]:
        w = len(para.split())
        if cur and n + w > max_words:
            out.append("\n".join(cur))
            cur, n = [], 0
        if w > max_words:  # a single very long paragraph: split by sentences
            sents = re.split(r"(?<=[.!?])\s+", para)
            buf = []
            for s in sents:
                if buf and len(" ".join(buf + [s]).split()) > max_words:
                    out.append(" ".join(buf))
                    buf = []
                buf.append(s)
            para, w = " ".join(buf), len(" ".join(buf).split())
        cur.append(para)
        n += w
    if cur:
        out.append("\n".join(cur))
    return out or [""]


def _ext_id(obj) -> tuple[str, str]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return "", ""


def _live(obj) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse_attack(bundle: dict) -> list[dict]:
    objs = {o["id"]: o for o in bundle["objects"]}
    tactics = {o.get("x_mitre_shortname"): o["name"] for o in bundle["objects"] if o["type"] == "x-mitre-tactic"}
    techniques = {i: o for i, o in objs.items() if o["type"] == "attack-pattern" and _live(o)}
    parent = {}
    mitigations, detections, groups = defaultdict(list), defaultdict(list), defaultdict(set)
    for r in bundle["objects"]:
        if r["type"] != "relationship" or not _live(r):
            continue
        src, tgt, kind = objs.get(r["source_ref"]), r["target_ref"], r["relationship_type"]
        if src is None or tgt not in techniques and kind != "subtechnique-of":
            continue
        if kind == "subtechnique-of":
            parent[r["source_ref"]] = tgt
        elif kind == "mitigates" and src["type"] == "course-of-action" and _live(src):
            mitigations[tgt].append((src, clean(r.get("description", ""))))
        elif kind == "detects" and src["type"] == "x-mitre-detection-strategy" and _live(src):
            detections[tgt].append(src)
        elif kind == "uses" and src["type"] == "intrusion-set" and _live(src):
            groups[tgt].add(src["name"])

    docs = []
    for tid, t in techniques.items():
        ext, url = _ext_id(t)
        if not ext:
            continue
        name = t["name"]
        if tid in parent and parent[tid] in techniques:
            pext, _ = _ext_id(techniques[parent[tid]])
            full = f"{ext} {techniques[parent[tid]]['name']}: {name}"
            sub = f" It is a sub-technique of {pext} {techniques[parent[tid]]['name']}."
        else:
            full, sub = f"{ext} {name}", ""
        tac = ", ".join(tactics.get(k["phase_name"], k["phase_name"]) for k in t.get("kill_chain_phases", []))
        plat = ", ".join(t.get("x_mitre_platforms", []))
        head = f"{full}. Tactic: {tac}. Platforms: {plat}.{sub}"
        base = dict(source="MITRE ATT&CK", ref_id=ext, name=name, url=url)

        for i, part in enumerate(chunk(clean(t.get("description", "")))):
            docs.append(dict(base, kind="technique", title=f"{full}: what it is", text=f"{head}\n{part}", part=i))

        det_lines = []
        for s in detections.get(tid, []):
            det_lines.append(f"Detection strategy: {s['name']}.")
            for ref in s.get("x_mitre_analytic_refs", []):
                a = objs.get(ref)
                if not a or not _live(a):
                    continue
                logs = ", ".join(dict.fromkeys(x.get("name", "") for x in a.get("x_mitre_log_source_references", [])))
                plats = ", ".join(a.get("x_mitre_platforms", []))
                det_lines.append(f"{plats}: {clean(a.get('description', ''))}" + (f" Log sources: {logs}." if logs else ""))
        for i, part in enumerate(chunk("\n".join(det_lines))) if det_lines else []:
            docs.append(dict(base, kind="detection", title=f"{full}: how to detect it",
                             text=f"How to detect {full}.\n{part}", part=i))

        mit_lines = []
        for m, how in mitigations.get(tid, []):
            mext, _ = _ext_id(m)
            mit_lines.append(f"{mext} {m['name']}: {how or clean(m.get('description', ''))}")
        for i, part in enumerate(chunk("\n".join(mit_lines))) if mit_lines else []:
            docs.append(dict(base, kind="mitigation", title=f"{full}: how to prevent it",
                             text=f"Mitigations for {full}.\n{part}", part=i))

        if groups.get(tid):
            g = sorted(groups[tid])
            docs.append(dict(base, kind="groups", title=f"{full}: threat groups that use it", part=0,
                             text=f"Threat groups known to use {full} ({len(g)}): {', '.join(g)}."))
    return docs


def parse_kev(catalog: dict) -> list[dict]:
    docs = []
    for v in catalog["vulnerabilities"]:
        cve = v["cveID"]
        text = (f"{cve}: {v.get('vulnerabilityName', '')}. Vendor: {v.get('vendorProject', '')}. "
                f"Product: {v.get('product', '')}. This vulnerability is in the CISA Known Exploited "
                f"Vulnerabilities (KEV) catalogue: it has been exploited in the wild. Added to KEV: "
                f"{v.get('dateAdded', '')}. Known use in ransomware campaigns: "
                f"{v.get('knownRansomwareCampaignUse', 'Unknown')}.\n{v.get('shortDescription', '')}\n"
                f"Required action: {v.get('requiredAction', '')} Due date for US federal agencies: "
                f"{v.get('dueDate', '')}.")
        docs.append(dict(source="CISA KEV", kind="kev", ref_id=cve, name=v.get("vulnerabilityName", ""),
                         title=f"{cve}: {v.get('vulnerabilityName', '')}", text=text, part=0,
                         url=f"https://nvd.nist.gov/vuln/detail/{cve}"))
    return docs


def build_corpus(attack_path: Path, kev_path: Path, out: Path) -> dict:
    attack = json.loads(Path(attack_path).read_text(encoding="utf-8"))
    kev = json.loads(Path(kev_path).read_text(encoding="utf-8"))
    docs = parse_attack(attack) + parse_kev(kev)
    for i, d in enumerate(docs):
        d["doc_id"] = f"D{i:05d}"
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for d in docs:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    version = next((o.get("x_mitre_version") for o in attack["objects"] if o["type"] == "x-mitre-collection"), None)
    if version is None:  # newer bundles have no collection object: report the latest modification date
        version = "updated " + max(o.get("modified", "") for o in attack["objects"] if o["type"] == "attack-pattern")[:10]
    counts = defaultdict(int)
    for d in docs:
        counts[d["kind"]] += 1
    return dict(documents=len(docs), by_kind=dict(counts), attack_version=version,
                kev_catalog=kev.get("catalogVersion"), kev_entries=len(kev["vulnerabilities"]))


def load_corpus(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
