# AutoForensiq

Autonomous digital forensics pipeline with explainable AI. Takes a plain-text incident report and produces a structured forensic report — no human intervention between input and output.

```
incident.txt → Classifier → Tool Selector → Orchestrator → Aggregator → ML/XAI → final_report.md
```

Conference target: **SecTor 2026** (May 26 deadline).

---

## Pipeline stages

| Stage | Module | Owner | Status |
|-------|--------|-------|--------|
| 1 — Intent Classifier | `src/classifier/intent_classifier.py` | P1 | ✅ Live |
| 2 — Tool Selector | `src/agents/tool_selector.py` | P2 | ✅ Live |
| 3 — Execution Orchestrator | `src/orchestrator.py` | P3 | ✅ Live |
| 4 — Evidence Aggregator | `src/aggregator/evidence_aggregator.py` | P4 | ✅ Live |
| 5 — Anomaly Detector | `src/ml/anomaly_detector.py` | P5 | ✅ Live |
| 6 — XAI Explainer | `src/ml/xai_explainer.py` | P5 | ✅ Live |
| 7 — Report Generator | `src/report_generator/report_generator.py` | P1 | ✅ Live |

---

## Forensic tools integrated

| Tool | Wrapper | Evidence type |
|------|---------|---------------|
| Volatility3 | `volatility_wrapper.py` | Memory dump |
| Tshark | `tshark_wrapper.py` | PCAP |
| Sleuthkit (tsk_fls) | `tsk_wrapper.py` | Disk image |
| RegRipper | `regripper_wrapper.py` | Registry hive |
| Plaso | `plaso_wrapper.py` | Timeline source |
| Email parser | `email_wrapper.py` | Email archive (phishing) |
| Browser parser | `browser_wrapper.py` | Browser history (phishing) |

---

## Setup

```bash
pip install -r requirements.txt
```

> **Note:** NumPy must be below 2.0 for scikit-learn/scipy compatibility. The
> `requirements.txt` pins this automatically. If you hit a NumPy version error,
> run: `pip install "numpy<2" --force-reinstall`

To use a live LLM, export your API key and set `mock_mode: false` in `config.yaml`:

```bash
export ANTHROPIC_API_KEY=your_key   # or OPENAI_API_KEY
```

---

## Running

```bash
# Classifier only (no API key needed)
python autoforensiq.py --report tests/incidents/01_ransomware.txt --mock --skip-tools

# Full pipeline
python autoforensiq.py --report tests/incidents/01_ransomware.txt --mock

# With real evidence files
python autoforensiq.py --report tests/incidents/01_ransomware.txt \
  --evidence data/test_cases/memory.dmp data/test_cases/capture.pcap

# Orchestrator standalone
python -m src.orchestrator

# Classifier standalone
python -m src.classifier.intent_classifier tests/incidents/01_ransomware.txt
```

---

## Output files

All written to `output/` (gitignored):

| File | Written by |
|------|-----------|
| `case_context.json` | Classifier (P1) |
| `execution_plan.json` | Tool Selector (P2) |
| `raw/<tool>_output.json` | Orchestrator (P3) |
| `unified_evidence.json` | Aggregator (P4) |
| `shap_explanations.json` | XAI (P5) |
| `audit_log.json` | Orchestrator (P3) |
| `final_report.md` | Report Generator (P1) |

---

## Supported incident types

`ransomware` · `apt_intrusion` · `data_exfiltration` · `insider_threat` · `malware_infection` · `phishing`

Sample incident reports are in `tests/incidents/`.
