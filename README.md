# Abuse Engine

Research prototype for **"Adaptive Multi-Agent Framework for Autonomous API Abuse Detection Using OODA-Loop Reasoning"** (IEEE submission).

Detects DoS, DDoS, credential stuffing, port scanning, web attacks, botnet C2 traffic, and geographic anomalies from API gateway logs, no inline proxy, no source code changes required. Validated across four public network intrusion datasets totalling ≈4.6M records.

---

## Key Results

All runs: `window=500`, `attack_threshold=0.05` (≥5% attack-presence per batch), `warmup_batches=10`, rule-based only (no LLM).

| Dataset | Records | Batches | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|---|---|
| CICIDS 2017 | 2,830,743 | 5,652 | **0.785** | **0.937** | **0.854** | 0.914 |
| CSIC 2010 | 56,538 | 113 | **1.000** | **0.941** | **0.970** | 0.974 |
| CTU-13 Scenario 10 | ~1,305,000 | 2,610 | **0.974** | **0.613** | **0.753** | 0.952 |
| AWS Honeypot (marx-geo) | ~449,500 | 899 | **1.000** | **0.859** | **0.924** | 0.859 |

32/32 tests passing. Zero false positives on CSIC 2010 and AWS Honeypot.

---

## Architecture

```
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │  Cross-Dataset Evaluation  (4 datasets · 500 records / batch)                     │
 │                                                                                    │
 │  CICIDS 2017        2,830,743 records  │  CSIC 2010 HTTP        56,538 records    │
 │  CTU-13 Scenario 10  ~1,305,000 records│  AWS Honeypot          ~449,500 records  │
 └───────────────────────────────────────┬───────────────────────────────────────────┘
                                         │
                                         ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │  CICIDSIngestion  ·  sliding window · 500 records / batch                         │
 └──────────────────────────┬────────────────────────────────────────────────────────┘
                            │ each batch
              ┌─────────────┴──────────────────────────────────────────┐
              │                                                        │
              ▼                                                        ▼
 ┌──────────────────────────────────────┐    ┌──────────────────────────────────────────────────────────┐
 │   Shared Memory  (in-process dicts)  │    │   Detection Agents  ·  ThreadPoolExecutor (parallel)      │
 │                                      │    │                                                          │
 │  STM  sliding window counters        │◄──►│  ┌───────────────────────────────────────────────────┐  │
 │  LTM  per-IP/endpoint baselines      │    │  │ VolumeAgent       OODA loop · max 3 iterations    │  │
 │  EB   Evidence Board (blackboard)    │◄──►│  │ Isolation Forest · dom_ratio · Path-2 cap-ratio   │  │
 └──────────────────────────────────────┘    │  │ Detects: DoS · DDoS · Scraping                    │  │
                                             │  ├───────────────────────────────────────────────────┤  │
 ┌──────────────────────────────────────┐    │  │ TemporalAgent     OODA loop · max 3 iterations    │  │
 │   Tool Registry  (12 tools)          │    │  │ FFT · KS-test · CUSUM · IAT resolution guard      │  │
 │                                      │◄···│  │ Detects: Bot periodicity · Off-hours access       │  │
 │  run_statistical_test                │    │  ├───────────────────────────────────────────────────┤  │
 │  detect_periodicity                  │    │  │ AuthAgent         OODA loop · max 3 iterations    │  │
 │  compute_entropy                     │    │  │ Failure streaks · success-rate ratio              │  │
 │  calculate_similarity                │    │  │ Detects: Brute force · Credential stuffing        │  │
 │  query_historical_baseline           │    │  ├───────────────────────────────────────────────────┤  │
 │  get_session_history                 │    │  │ PayloadAgent      OODA loop · max 3 iterations    │  │
 │  query_ip_reputation                 │    │  │ Shannon entropy · hard-bypass (6.0 bits) · z-score│  │
 │  post/read_evidence_board            │    │  │ Detects: Port Scan · Endpoint Enumeration         │  │
 │  query_agent                         │    │  ├───────────────────────────────────────────────────┤  │
 │  query/update_knowledge_base         │    │  │ SequenceAgent     OODA loop · max 3 iterations    │  │
 └──────────────────────────────────────┘    │  │ Markov endpoint transitions · N-gram frequency   │  │
                                             │  │ Detects: Sequence Abuse · Enumeration · BOLA      │  │
 ┌──────────────────────────────────────┐    │  ├───────────────────────────────────────────────────┤  │
 │   KnowledgeAgent  (passive)          │    │  │ GeoIPAgent        OODA loop · max 3 iterations    │  │
 │                                      │◄···│  │ RFC1918 heuristics · TOR/VPN evidence from EB     │  │
 │  IP reputation priors                │    │  │ Detects: Geo Anomaly · Impossible Travel          │  │
 │  cross-batch attack signatures       │    │  └───────────────────────────────────────────────────┘  │
 │  time-decay scoring                  │    │                                                          │
 │  conf-gated write (> 0.85)           │    │  KnowledgeAgent queried via tool - no verdict emitted   │
 └──────────────────────────────────────┘    └────────────────────────────────┬─────────────────────────┘
                                                                              │ AgentFinding × 6
 ┌──────────────────────────────────────┐                                    │
 │   LLM  (optional)                    │◄·····per-agent verdict override····┤
 │   Ollama · qwen2.5:7b                │◄·····meta-fusion override··········┘
 │   Falls back to rules on error       │
 └──────────────────────────────────────┘
                                             ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │   MetaAgentOrchestrator                                                           │
 │                                                                                   │
 │   _triage()          → DispatchPlan (skip agents with no relevant signal)         │
 │   _resolve_conflicts()→ escalate silent agents when related threat fires HIGH     │
 │   Compound detection → 5 rules map co-occurring threats to higher classes         │
 │   Weighted fusion   → LTM-derived per-agent weights (self-updating)               │
 │   XGBoost stacking  → activates after ≥ 50 labelled verdicts (0.4 WA + 0.6 XGB)  │
 │   LLM override      → optional authoritative verdict (falls back to rules)        │
 └───────────────────────────────────────────────────────────────────────────────────┘
                                             │ FusionVerdict
                                             ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │  Evaluator  (batch-level ≥5% attack-presence threshold)                          │
 │                                                                                  │
 │  CICIDS 2017   F1=0.854  P=0.785  R=0.937   │  CSIC 2010   F1=0.970  P=1.000    │
 │  CTU-13 Sc.10  F1=0.753  P=0.974  R=0.613   │  Honeypot    F1=0.924  P=1.000    │
 └──────────────────────────────────────────────────────────────────────────────────┘

 Legend:  ──►  data flow     ◄──►  read + write     ···►  optional / async
```

---

## Detection Agents

Each agent implements a six-step **OODA reasoning loop**: Observe → Orient → Hypothesize → Investigate → Evaluate → Conclude. Agents run in parallel via `ThreadPoolExecutor` and share state through SharedMemory and the Evidence Board.

| Agent | Detects | Key Signals |
|---|---|---|
| **VolumeAgent** | DoS, DDoS, Scraping | Dominance ratio, per-IP request rate, Path-2 cap-ratio on port 80/8080, Isolation Forest anomaly score |
| **TemporalAgent** | Bot periodicity, Off-hours access | FFT, KS-test, CUSUM on inter-arrival times; skips if median IAT < 500 ms (resolution guard) |
| **AuthAgent** | Brute force, Credential stuffing | Consecutive 401/403 streaks ≥ 10; success rate 1–8% with ≥ 20 attempts |
| **PayloadAgent** | Port scan, Endpoint enumeration | Shannon entropy of endpoint distribution; hard-bypass at ≥ 100 distinct endpoints + entropy ≥ 6.0 bits |
| **SequenceAgent** | Sequence abuse, Enumeration, BOLA | Markov chain N-gram transitions on per-IP endpoint sequences; anomalous transition probabilities vs LTM baseline |
| **GeoIPAgent** | Geo anomaly, Impossible travel | RFC1918 heuristics; TOR/VPN evidence from Evidence Board; spatial diversity detection for botnet spread |
| **KnowledgeAgent** | *(passive, no verdict)* | IP reputation priors; cross-batch attack signatures; confidence-gated write (> 0.85); time-decay scoring |

---

## Memory

```
TIER 1: Short-Term Memory  (in-process dict)
  Active session states, sliding window counters,
  current investigation state per agent, Evidence Board
  Updated: every batch

TIER 2: Long-Term Memory  (in-process dict)
  Per-IP/endpoint baselines, learned IAT distributions (up to 2 000 samples),
  entropy baselines per agent, past investigation outcomes,
  agent rolling precision (used for self-weighting)
  Updated: every batch

TIER 3: KnowledgeAgent store  (in-process dict)
  Confirmed attack signatures keyed by IP, confidence-gated write (> 0.85),
  time-decay scoring, cross-batch pattern synthesis
  Updated: after each high-confidence verdict
```

---

## Tool Registry

Agents call `ToolRegistry.call(tool_name, **kwargs)` dynamically during `investigate()`. All 12 tools:

| Tool | Category | Description |
|---|---|---|
| `run_statistical_test` | Logic | z-score, KS-test, Mann-Whitney U |
| `detect_periodicity` | Logic | FFT + coefficient-of-variation on IATs |
| `compute_entropy` | Logic | Shannon entropy of discrete distribution |
| `calculate_similarity` | Logic | Jaccard similarity between endpoint sequences |
| `query_historical_baseline` | Data | Mean request rate for endpoint from LTM |
| `get_session_history` | Data | All records for an IP within rolling window |
| `query_ip_reputation` | Data | Geo/VPN/TOR flags from Evidence Board or default |
| `post_to_evidence_board` | Social | Write tagged evidence entry to shared blackboard |
| `read_evidence_board` | Social | Read entries filtered by key or min confidence |
| `query_agent` | Social | Read all evidence posted by a specific agent |
| `query_knowledge_base` | Knowledge | IP reputation prior from KnowledgeAgent |
| `update_knowledge_base` | Knowledge | Record confirmed verdict outcome for an IP |

---

## Datasets

### CICIDS 2017

Network flow records from a 5-day testbed capture (Canadian Institute for Cybersecurity).  
**Records:** 2,830,743 → `datasets/processed/cicids2017_api_logs.csv`  
**Batches evaluated:** 5,652 × 500 records

| Class | Count | % |
|---|---|---|
| Benign | 2,273,097 | 80.3% |
| DoS (Slowloris, Hulk, GoldenEye, Slowhttptest) | 380,688 | 13.5% |
| Port Scan | 158,930 | 5.6% |
| Brute Force (FTP-Patator, SSH-Patator, Web) | 15,342 | 0.5% |
| Botnet (ISCX) | 1,966 | 0.07% |
| Web Attack (SQLi, XSS, Brute Force) | 673 | 0.02% |

**Known limitations:** Timestamps have 1-second resolution (TemporalAgent IAT guard activates). All IPs are RFC-1918 private (GeoIPAgent dormant and validated separately on CTU-13 and Honeypot).

---

### CSIC 2010 HTTP

Web application attack dataset from Universidad Carlos III de Madrid.  
**Records:** 56,538 → `datasets/processed/csic_api_logs.csv`  
**Batches evaluated:** 113 × 500 records

| Class | Count | % |
|---|---|---|
| Normal | 30,994 | 54.8% |
| Anomalous (Web Attack) | 25,544 | 45.2% |

**Attack taxonomy:** SQL injection, XSS, CSRF, path traversal, buffer overflow, format string. Full HTTP transactions with URL and POST body payloads. Validates PayloadAgent and SequenceAgent.

---

### CTU-13 Scenario 10

Real botnet capture from Czech Technical University (Neris botnet family).  
**Records:** ~1,305,000 → `datasets/processed/ctu13_scenario10_logs.csv`  
**Batches evaluated:** 2,610 × 500 records

| Class | Count |
|---|---|
| Background (Benign) | ~1,150,000 |
| Botnet (C2 traffic) | ~155,000 |

**Attack taxonomy:** Neris botnet performing spam + click-fraud via HTTP; C2 connections to external IPs; IRC-based heartbeats; high-volume SMTP floods. Uses routable public IPs to validate GeoIPAgent.

---

### AWS Honeypot (marx-geo)

Internet-facing AWS honeypot with real-world attacker traffic (Kaggle public dataset).  
**Records:** ~449,500 → `datasets/processed/honeypot_geo_logs.csv`  
**Batches evaluated:** 899 × 500 records (100% attack traffic)

Captures automated probes, port scans, brute-force SSH, and reconnaissance from global source IPs with country-level ground truth. Validates GeoIPAgent on real adversarial traffic.

---

## Detailed Results

### CICIDS 2017: Full 2.8M (`results/cicids/full_2.8M.json`)

| Metric | Value |
|---|---|
| Precision | 0.7854 |
| Recall | 0.9367 |
| F1 Score | **0.8544** |
| Accuracy | 0.9144 |
| TP / FP / FN / TN | 1,420 / 388 / 96 / 3,748 |

**Per-threat (≥5% threshold):**

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Benign | 0.975 | 0.906 | 0.939 | 4,136 |
| Brute Force | 0.732 | 0.986 | **0.840** | 221 |
| DoS | 0.651 | 0.903 | **0.757** | 627 |
| Port Scan | 0.691 | 0.836 | **0.757** | 348 |
| DDoS | 0.168 | 0.128 | 0.145 | 290 |
| Botnet | 0.000 | 0.000 | 0.000 | 19 |

**Per-agent contribution:**

| Agent | TP | FP |
|---|---|---|
| VolumeAgent | 1,157 | 212 |
| PayloadAgent | 343 | 187 |
| AuthAgent | 218 | 83 |
| TemporalAgent | 59 | 26 |
| SequenceAgent | 1 | 0 |
| GeoIPAgent | - | - (dormant: RFC1918 IPs) |

---

### Ablation Study: CICIDS 2017, 1.4M record slice (`results/ablation_study.json`)

| Mode | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| A - Static rules only (cold-start) | 1.000 | 0.692 | 0.818 | 0 | 167 |
| B - Rules + adaptive thresholds | 0.979 | 0.759 | **0.855** | 9 | 131 |
| C - Full system (adaptive + XGBoost) | 0.938 | 0.786 | 0.856 | 28 | 116 |

Mode B (adaptive thresholds, no XGBoost) provides the largest single gain (+3.7 pp F1 over static rules). XGBoost stacking in Mode C is too aggressive on the heavily benign CICIDS distribution (2.1M benign vs 0.5M attack).

---

### CSIC 2010 (`results/csic/phase1.json`)

| Metric | Value |
|---|---|
| Precision | 1.0000 |
| Recall | 0.9412 |
| F1 Score | **0.9697** |
| Accuracy | 0.9735 |
| TP / FP / FN / TN | 48 / 0 / 3 / 62 |

PayloadAgent primary detector (TP=48, FP=0). Zero false positives. The 3 FNs are sparse attack batches with minimal payloads below the entropy threshold.

---

### CTU-13 Scenario 10 (`results/ctu-13/ctu13_scenario10_eval_fixed.json`)

| Metric | Value |
|---|---|
| Precision | 0.9744 |
| Recall | 0.6129 |
| F1 Score | **0.7525** |
| Accuracy | 0.9521 |
| TP / FP / FN / TN | 190 / 5 / 120 / 2,295 |

VolumeAgent detects high-volume SMTP spam floods (TP=188). GeoIPAgent validates on routable IPs (TP=139, FP=5). Low recall due to distributed C2 beaconing staying below per-IP dominance thresholds.

---

### AWS Honeypot (`results/honeypot/honeypot_geo_v3.json`)

| Metric | Value |
|---|---|
| Precision | 1.0000 |
| Recall | 0.8587 |
| F1 Score | **0.9240** |
| Accuracy | 0.8587 |
| TP / FP / FN / TN | 772 / 0 / 127 / 0 |

GeoIPAgent is the dominant detector (TP=770 / 899 batches). Zero false positives. The 127 FNs are batches where probe traffic is below volume/geo thresholds.

---

## Why Agentic (not a pipeline)

| Capability | Pipeline | Abuse Engine |
|---|---|---|
| Planning | Fixed feature→score | Agent observes anomaly, plans multi-step investigation, adapts |
| Tool Use | Hardcoded extraction | Agent dynamically calls statistical tests, GeoIP, baselines on demand |
| Stateful Autonomy | Stateless per-request | Agent remembers past sessions, builds evolving threat profiles |
| Reasoning Loops | Single forward pass | Observe → Hypothesize → Investigate → Revise → Conclude (iterative, max 3) |
| Inter-Agent Comms | Scores passed to ensemble | Agents post and read each other's findings via Evidence Board |
| Self-Reflection | No error awareness | Agent evaluates its own confidence, requests more data when uncertain |

The `MetaAgentOrchestrator` uses `ThreadPoolExecutor` for parallel dispatch and a hand-written state machine for conflict resolution and fusion, architecturally equivalent to a directed agentic graph (LangGraph supervisor pattern). The `OrchestratorState` TypedDict is LangGraph-compatible should a future implementation migrate.

---

## Setup

**Requirements:** Python 3.11, packages in `requirements.txt`.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Prepare datasets** (run once after downloading raw source files):

```bash
python scripts/prepare_cicids_dataset.py     # CICIDS 2017
python scripts/prepare_csic_dataset.py       # CSIC 2010
python scripts/prepare_ctu13_dataset.py      # CTU-13 Scenario 10
python scripts/prepare_honeypot_dataset.py   # AWS Honeypot
```

---

## Running

**Rule-based (no LLM):**
```bash
python main.py \
  --data datasets/processed/ \
  --window 500 \
  --max-records 0 \
  --output results/run.json \
  --warmup-batches 10
```

**With local LLM via Ollama:**
```bash
ollama pull qwen2.5:7b

python main.py \
  --data datasets/processed/ \
  --window 500 \
  --output results/run_llm.json \
  --llm-url http://localhost:11434/v1 \
  --llm-model qwen2.5:7b
```

**CLI flags:**

| Flag | Default | Description |
|---|---|---|
| `--data` | `datasets/processed/` | Path to processed CSV directory |
| `--window` | `500` | Records per batch |
| `--max-records` | `0` (all) | Limit total records |
| `--output` | `results/phase1.json` | Metrics JSON output path |
| `--warmup-batches` | `10` | Batches used for baseline learning only |
| `--attack-threshold` | `0.05` | Min attack-record ratio for a batch to count as attack |
| `--home-country` | `""` | Tenant home country code (e.g. `CZ`) for GeoIPAgent |
| `--llm-url` | *(none)* | OpenAI-compatible LLM endpoint |
| `--llm-model` | `qwen2.5:7b` | LLM model name |
| `--verbose` / `-v` | off | Debug logging |

**Test suite:**
```bash
python -m engine.tests.run_tests
```

---

## Project Structure

```
abuse-engine/
├── datasets/
│   ├── CICIDS2017/          # Raw CICIDS 2017 CSVs (not in repo)
│   ├── CICIDS2017-ML/       # ML-ready variant (not in repo)
│   └── processed/           # API-normalised CSVs produced by prepare scripts
├── engine/
│   ├── agents/              # VolumeAgent, TemporalAgent, AuthAgent, PayloadAgent,
│   │                        # SequenceAgent, GeoIPAgent, KnowledgeAgent, BaseAgent
│   ├── coordinator/         # MetaAgentOrchestrator
│   ├── ingestion/           # CICIDSIngestion, UNSWNB15Ingestion
│   ├── llm/                 # LLMClient, prompts (Ollama / OpenAI-compatible)
│   ├── memory/              # SharedMemory (STM + LTM + EvidenceBoard)
│   ├── tests/               # run_tests.py, 32 tests, no pytest required
│   └── tools/               # ToolRegistry (12 tools)
├── evaluation/
│   └── evaluator.py         # Batch-level ≥5% threshold metrics
├── results/
│   ├── cicids/              # full_2.8M.json
│   ├── csic/                # phase1.json
│   ├── ctu-13/              # ctu13_scenario10_eval_fixed.json
│   ├── honeypot/            # honeypot_geo_v3.json
│   └── ablation_study.json
├── schemas/
│   └── models.py            # Pydantic schemas: LogRecord, AgentFinding, FusionVerdict
├── scripts/
│   ├── prepare_cicids_dataset.py
│   ├── prepare_csic_dataset.py
│   ├── prepare_ctu13_dataset.py
│   ├── prepare_honeypot_dataset.py
│   └── rescore.py           # Re-score existing results JSON without re-running pipeline
├── main.py                  # CLI entry point
├── requirements.txt
└── CONTEXT.md               # Full implementation + architecture reference
```
