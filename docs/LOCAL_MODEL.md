# Running with a local model (Ollama)

A local model keeps every question on your own machine and costs nothing.

1. Install Ollama from https://ollama.com (Windows, macOS or Linux).
2. Download a small model (about 2 GB):
   ```
   ollama pull llama3.2   # or qwen2.5:7b (better, about 4.7 GB)
   ```
3. Check it runs:
   ```
   ollama run llama3.2 "Say hello"
   ```
4. In the app's sidebar choose **ollama** (model `llama3.2`), or grade it on all 88 questions:
   ```
   python evaluate.py --answers ollama --model qwen2.5:7b
   ```
   On a laptop CPU this can take 10 to 30 minutes. Results are saved to `reports/answers_ollama_qwen2.5-7b.csv`, with a summary in `reports/eval_summary.json`.

## Reading the answer results

| Column | Good value | Meaning |
|---|---|---|
| `grounded` | True | Every citation points to a real source, or the answer says the sources don't cover it |
| `invalid_citations` | 0 | Citations like [7] when only 5 sources were given |
| `invented_ids` | empty | Technique or CVE IDs in the answer that aren't in the sources |
| `names_expected_id` | True | The answer text contains the ID the question was about |
| `cites_expected_source` | True | At least one citation points to the source with that ID (fairer for models that use names) |
| `said_not_covered` | True only for off-topic questions | The model refused |

Read a sample of answers yourself as well: the checks catch made-up IDs and bad citations, not every subtle mistake.

## Settings

| Variable | Default | Use |
|---|---|---|
| `OLLAMA_MODEL` | `llama3.2` | Any model you've pulled, e.g. `qwen2.5:7b` |
| `OLLAMA_HOST` | `http://localhost:11434` | If Ollama runs elsewhere |
| `ANTHROPIC_API_KEY` | none | Needed for the anthropic engine |
| `ANTHROPIC_MODEL` | `claude-haiku-4-5` | Any Claude model your key can use |

If the model can't be reached, the app falls back to the extractive answer and says why.
