# APISentry

Multi-agent API abuse detection system. Detects DoS, credential stuffing, bot activity, and other API-level attacks by analysing gateway logs — no inline proxy, no code changes required by API owners.

Built as a research prototype for IEEE paper validation, with a production SaaS path planned post-publication.

---

## What It Does

APISentry runs autonomous detection agents that each follow an OODA reasoning loop (Observe → Orient → Hypothesize → Investigate → Evaluate → Conclude). Agents share an evidence board, call statistical tools dynamically, and optionally consult a local LLM to produce a final verdict. A MetaAgent orchestrator fuses all agent findings into a single `FusionVerdict`.

**Agents implemented (Phase 1):**
- **VolumeAgent** — DoS / DDoS / scraping via rate and dominance analysis
- **TemporalAgent** — Bot periodicity detection via FFT/KS-test on inter-arrival times
- **AuthAgent** — Credential stuffing and brute force via auth failure pattern analysis

**Optional LLM integration:** any OpenAI-compatible endpoint (Ollama, vLLM, etc.). Falls back to rule-based detection if unavailable.

---

## Directory Structure

```
abuse-engine/
├── datasets/
│   ├── CICIDS2017/              # Raw CICIDS 2017 CSVs (not in git)
│   ├── CICIDS2017-ML/           # ML-ready variant CSVs (not in git)
│   └── processed/               # API-normalised output from prepare script
│       └── cicids2017_api_logs.csv
├── engine/
│   ├── agents/                  # VolumeAgent, TemporalAgent, AuthAgent, BaseAgent
│   ├── coordinator/             # MetaAgentOrchestrator
│   ├── ingestion/               # CICIDSIngestion — batch iterator over processed CSV
│   ├── llm/                     # LLMClient + prompt templates (Ollama / OpenAI-compat)
│   ├── memory/                  # SharedMemory: STM, LTM, EvidenceBoard
│   ├── normalization/           # (stub — future universal log parser)
│   ├── pipeline/                # (stub — future streaming pipeline)
│   ├── tests/                   # run_tests.py — 32 tests, no pytest dependency
│   └── tools/                   # ToolRegistry (statistical tests, periodicity, evidence board)
├── evaluation/
│   └── evaluator.py             # Batch-level majority-label metrics
├── results/                     # JSON output from evaluation runs
├── schemas/
│   └── models.py                # Pydantic schemas (LogRecord, AgentFinding, FusionVerdict)
├── scripts/
│   └── prepare_cicids_dataset.py  # Converts raw CICIDS CSVs to API-normalised format
├── main.py                      # CLI entry point
├── requirements.txt
├── CONTEXT.md                   # Full implementation + architecture reference (keep updated)
└── NOTES.md                     # Code review findings and decisions log
```

---

## Dataset

Uses **CICIDS 2017** — 2.83M network flow records converted to API-like log format.

**Prepare the dataset** (run once after downloading raw CSVs into `datasets/CICIDS2017/`):
```bash
python scripts/prepare_cicids_dataset.py
```
This produces `datasets/processed/cicids2017_api_logs.csv` with fields: `timestamp`, `ip`, `method`, `endpoint`, `status`, `response_size`, `latency`, `user_agent`, `attack_category`, `is_attack`.

**Class distribution (full 2.83M records):**

| Category | Count |
|---|---|
| Benign | 2,273,097 |
| DoS | 380,688 |
| Port Scan | 158,930 |
| Brute Force | 15,342 |
| Botnet | 1,966 |
| Web Attack | 673 |
| Infiltration | 36 |
| Heartbleed | 11 |

---

## Setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Running

**Rule-based detection (no dependencies beyond pip install):**
```bash
python main.py \
  --data datasets/processed/ \
  --window 500 \
  --max-records 50000 \
  --output results/phase1.json \
  --warmup-batches 10
```

**With local LLM via Ollama:**
```bash
# Install Ollama and pull model (once)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:7b

python main.py \
  --data datasets/processed/ \
  --window 500 \
  --max-records 50000 \
  --output results/phase1_llm.json \
  --warmup-batches 10 \
  --llm-url http://localhost:11434/v1 \
  --llm-model qwen2.5:7b
```

**CLI flags:**

| Flag | Default | Description |
|---|---|---|
| `--data` | `datasets/processed/` | Path to processed CSV directory |
| `--window` | `500` | Records per batch |
| `--max-records` | `0` (all) | Limit total records processed |
| `--output` | `results/phase1.json` | Path for metrics JSON output |
| `--warmup-batches` | `10` | First N batches used for baseline learning only (not scored) |
| `--llm-url` | *(none)* | OpenAI-compatible LLM endpoint — omit for rule-based only |
| `--llm-model` | `qwen2.5:7b` | Model name for LLM endpoint |
| `--verbose` / `-v` | off | Debug logging + print all verdicts |

**Run the test suite:**
```bash
python -m engine.tests.run_tests
```

---

## Current Results (Phase 1 — rule-based, 50k records)

| Metric | Value |
|---|---|
| Accuracy | 92.22% |
| Precision | 1.0000 |
| Recall | 0.9231 |
| F1 | 0.9600 |
| False Positive Rate | 0% |
| Test suite | 32/32 passing |