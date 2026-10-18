"""Security analyst assistant.  Run:  streamlit run app.py"""
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.answer import Assistant
from src.retrieve import Retriever

st.set_page_config(page_title="ATT&CK and KEV Assistant", layout="wide")
KIND_LABEL = {"technique": "What it is", "detection": "How to detect", "mitigation": "How to prevent",
              "groups": "Who uses it", "kev": "CISA KEV entry"}
EXAMPLES = ["How can I detect password spraying?", "How do I stop MFA fatigue attacks?",
            "Is Log4Shell being exploited and what should we do?", "What is the required action for CVE-2020-1938?",
            "Attacker creates a scheduled task to run at every logon", "Which threat groups use Kerberoasting?"]


@st.cache_resource
def retriever():
    return Retriever.from_files("data/corpus.jsonl")


if not Path("data/corpus.jsonl").exists():
    st.error("No corpus yet. Run `python build_index.py` first.")
    st.stop()

stats = json.loads(Path("data/corpus_stats.json").read_text()) if Path("data/corpus_stats.json").exists() else {}
with st.sidebar:
    st.header("Settings")
    backend = st.radio("Answer engine", ["extractive", "ollama", "anthropic"],
                       captions=["No AI model: quotes the sources (offline)", "Local model via Ollama (free)",
                                 "Claude API (needs ANTHROPIC_API_KEY)"])
    model = st.text_input("Model", "qwen2.5:7b" if backend == "ollama" else "claude-haiku-4-5",
                          disabled=backend == "extractive")
    k = st.slider("Sources to retrieve", 3, 10, 5)
    st.divider()
    st.caption(f"Knowledge base: {stats.get('documents', 0):,} documents from MITRE ATT&CK "
               f"({stats.get('attack_version', '')}) and CISA KEV ({stats.get('kev_catalog', '')}, "
               f"{stats.get('kev_entries', 0):,} CVEs).")
    st.caption("Answers come only from these sources. It's an aid for analysts, not a replacement for judgement.")

st.title("ATT&CK and KEV Assistant")
st.caption("Ask about attacker techniques, how to detect or prevent them, who uses them, or whether a CVE "
           "is known to be exploited. Every answer cites its sources.")

cols = st.columns(3)
for i, ex in enumerate(EXAMPLES):
    if cols[i % 3].button(ex, key=f"ex{i}"):
        st.session_state["q"] = ex
q = st.text_input("Your question", key="q", placeholder="e.g. How do I detect Kerberoasting?")

if q:
    a = Assistant(retriever(), backend=backend, k=k, model=model if backend != "extractive" else None)
    with st.spinner("Searching and answering..."):
        ans = a.ask(q)
    if ans.error:
        st.warning(ans.error)
    if not ans.in_scope:
        st.info(ans.text)
        st.stop()
    st.subheader("Answer")
    st.markdown(ans.text)

    checks = st.columns(3)
    checks[0].metric("Citations", len(ans.citations))
    checks[1].metric("Invalid citations", len(ans.invalid_citations))
    checks[2].metric("IDs not in sources", len(ans.ids_not_in_sources))
    if not ans.grounded:
        st.error("This answer isn't properly grounded in the sources (missing or invalid citations). Treat it with care.")
    if ans.ids_not_in_sources:
        st.error(f"The answer mentions IDs that aren't in the sources: {', '.join(ans.ids_not_in_sources)}. "
                 "These may be made up.")
    if ans.sources and ans.sources[0].get("aliases_used"):
        st.caption(f"Nickname recognised: added {', '.join(ans.sources[0]['aliases_used'])} to the search.")

    st.subheader("Sources")
    for i, s in enumerate(ans.sources, 1):
        with st.expander(f"[{i}] {s['title']}  ·  {KIND_LABEL.get(s['kind'], s['kind'])}  ·  {s['source']}",
                         expanded=i == 1):
            st.markdown(f"[Open on {'attack.mitre.org' if s['source'] == 'MITRE ATT&CK' else 'NVD'}]({s['url']})")
            st.text(s["text"])

with st.expander("How well does it work?"):
    p = Path("reports/eval_summary.json")
    if p.exists():
        res = json.loads(p.read_text())
        for name in ("development", "holdout"):
            if name in res:
                st.markdown(f"**Retrieval, {name} questions**")
                st.dataframe(pd.DataFrame(res[name]), hide_index=True, width="stretch")
        if "scope_gate" in res:
            g = res["scope_gate"]
            st.markdown(f"**Off-topic questions refused:** {g['off_topic_refused']} · "
                        f"**On-topic answered:** {g['on_topic_answered']}")
        if res.get("answers"):
            st.markdown("**Answer checks by engine**")
            st.dataframe(pd.DataFrame(res["answers"]).T, width="stretch")
    else:
        st.write("Run `python evaluate.py` to see results here.")
