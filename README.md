# AutoForensiq

> Autonomous digital forensics pipeline with explainable AI — from incident report to structured forensic report with zero human intervention.

```
  Incident Report          Evidence Artifacts (any format, any combination)
  ───────────────          ──────────────────────────────────────────────────
  incident.txt             memory.dmp  capture.pcap  disk.img  NTUSER.DAT
                           system.hiv  events.evtx   mail.eml  browser.db  …
        │                        │
        └────────────────────────┘
                      │
                      ▼
        ┌─────────────────────────┐
        │   AutoForensiq GUI      │  python autoforensiq.py
        │   (or CLI flags)        │
        └─────────────┬───────────┘
                      │
          ┌───────────▼───────────┐
          │  Intent Classifier    │  reads report → attack type + hypotheses
          │  (LLM)                │
          └───────────┬───────────┘
                      │ case_context.json
          ┌───────────▼───────────┐
          │  Dynamic Tool         │  maps artifact types → tool list
          │  Selector (DTSA)      │
          └───────────┬───────────┘
                      │ execution_plan.json
          ┌───────────▼───────────┐
          │  Execution            │  runs forensic tools as subprocesses
          │  Orchestrator         │
          └───────────┬───────────┘
                      │ raw/<tool>_output.json
          ┌───────────▼───────────┐
          │  Evidence Aggregator  │  deduplicates + normalises + MITRE maps
          │  + Anomaly Detector   │  Isolation Forest anomaly scoring
          │  + XAI (SHAP / LIME)  │  per-finding plain-English explanations
          └───────────┬───────────┘
                      │ unified_evidence.json · shap_explanations.json
          ┌───────────▼───────────┐
          │  Report Generator     │  LLM-written forensic report
          │  (LLM + Kill Chain)   │  + interactive HTML timeline
          └───────────┬───────────┘
                      │
               final_report.md
               timeline.html
               audit_log.json
```

---

## Key capabilities

| Capability | Detail |
|---|---|
| **Zero-touch pipeline** | Incident text in → forensic report out, no analyst in the loop |
| **Attack classification** | LLM-powered intent classifier with JSON schema validation |
| **Dynamic tool selection** | DTSA algorithm selects forensic tools based on artifact types |
| **7 forensic tool wrappers** | Volatility3, Tshark, Sleuthkit, RegRipper, Plaso, email & browser parsers |
| **Anomaly detection** | Isolation Forest on normalised evidence features |
| **Explainability** | SHAP global attributions + LIME local per-finding explanations |
| **MITRE ATT&CK mapping** | Each evidence item mapped to tactic/technique IDs |
| **Cyber Kill Chain tracker** | Shows attacker progression stage with gaps highlighted |
| **Interactive timeline** | Self-contained HTML timeline of evidence coloured by severity |
| **Chain-of-custody audit log** | SHA-256 hash log written for every tool invocation |
| **Mock mode** | Full pipeline runs without any API key for CI and demos |

---

## Requirements

- Python 3.10+
- One of: `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` (optional — mock mode works without either)
- Python packages from `requirements.txt`:
  - `anthropic`, `openai`, `pyyaml`, `python-dotenv`, `jsonschema`
  - `scikit-learn`, `shap`, `lime`, `numpy`, `pandas`, `volatility3`
  - `customtkinter`, `tqdm`, `pytest`
- Forensic tools installed on PATH for live evidence runs: `vol` / `vol3`, `tshark`, `fls` (SleuthKit), `perl`, `log2timeline.py` or `log2timeline`, plus RegRipper (`REGRIPPER_PATH` or a common `rip.pl` location such as `~/regripper/rip.pl`)

---

## Installation

### Option 1: automatic bootstrap

Use the OS-specific helper to create a virtual environment and install the Python dependencies:

```bash
# Linux / macOS
bash scripts/bootstrap.sh

# Windows PowerShell
pwsh -File scripts/bootstrap.ps1
```

The helpers install everything from `requirements.txt` and then report any missing forensic binaries that still need to be installed separately.

### Option 2: manual setup

```bash
git clone https://github.com/your-org/autoforensiq.git
cd autoforensiq
pip install -r requirements.txt
```

### External tools for live runs

Install these separately if you want the full evidence-processing workflow instead of mock mode:

| Tool | Why it is needed | Typical install note |
|---|---|---|
| Volatility 3 | Memory-dump analysis | Installed via `pip` from `requirements.txt` |
| Tshark | PCAP parsing | Install your Wireshark package (`tshark`) |
| SleuthKit `fls` | Disk-image triage | Install the SleuthKit package (`fls`) |
| RegRipper `rip.pl` | Registry hive parsing | Set `REGRIPPER_PATH` or place `rip.pl` in a common location such as `~/regripper/rip.pl` |
| Plaso `log2timeline.py` | Timeline generation | Install Plaso so `log2timeline.py` or `log2timeline` is on PATH |

> **NumPy compatibility note:** `requirements.txt` pins `numpy<2.0` for scikit-learn/scipy compatibility.
> If you hit a NumPy version conflict after upgrading other packages, run:
> ```bash
> pip install "numpy<2" --force-reinstall
> ```

---

## Running the tool

### GUI (recommended)

Run with no arguments to open the graphical launcher:

```bash
python autoforensiq.py
```

The GUI lets you select an incident report, attach any number of evidence files (type is auto-detected from the extension), optionally reorder artifacts by priority, configure the LLM provider, and launch the full pipeline — all without touching the command line again.

---

### CLI

Pass `--report` to skip the GUI and run the pipeline directly:

```bash
# Classifier only — no API key, no evidence files needed
python autoforensiq.py --report tests/incidents/01_ransomware.txt --mock --skip-tools

# Full pipeline in mock mode
python autoforensiq.py --report tests/incidents/01_ransomware.txt --mock

# Full pipeline with evidence files and a live LLM
export ANTHROPIC_API_KEY=sk-ant-...
python autoforensiq.py \
  --report   tests/incidents/01_ransomware.txt \
  --evidence data/test_cases/memory.dmp \
             data/test_cases/capture.pcap \
             data/test_cases/disk.img \
             data/test_cases/NTUSER.DAT
```

On success the final report is written to `output/final_report.md`.

---

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| _(none)_ | — | — | Opens the GUI launcher |
| `--report <path>` | string | — | Path to the plain-text incident report. Required for CLI mode. |
| `--evidence <paths…>` | list | _(none)_ | One or more artifact files. Type is auto-detected from extension/name. **Order = priority** — the first file listed is processed first. |
| `--tools <names…>` | list | all | Restrict which forensic tools run. Names: `volatility3` `tshark` `tsk_fls` `regripper` `plaso` `email` `browser`. Default runs all tools selected by the DTSA. |
| `--mock` | flag | off | Run without a real API key. The classifier and report generator return deterministic mock output. |
| `--skip-tools` | flag | off | Stop after Stage 1 (classifier only). No tools are run, no evidence is processed. |
| `--gui` | flag | off | Force the GUI to open even when other flags are present. |

---

## Configuration

All runtime settings live in `config.yaml`. Do **not** paste API keys there — use environment variables or a `.env` file.

```yaml
llm:
  provider: "anthropic"          # "anthropic" | "openai"
  anthropic_model: "claude-sonnet-4-6"
  openai_model: "gpt-4o"
  mock_mode: true                # set false to use a live LLM
  temperature: 0.0               # keep at 0 — outputs are structured JSON
  max_tokens: 1024

paths:
  case_context_output:   "output/case_context.json"
  execution_plan_output: "output/execution_plan.json"
  raw_outputs_dir:       "output/raw"
  final_report_output:   "output/final_report.md"
  audit_log_output:      "output/audit_log.json"
```

**Switching providers:**

```bash
# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
# then set provider: "anthropic" in config.yaml

# OpenAI
export OPENAI_API_KEY=sk-...
# then set provider: "openai" in config.yaml
```

---

## Pipeline stages

All seven stages are live. Each stage writes a JSON handoff file consumed by the next.

| # | Stage | Entry point | Output |
|---|---|---|---|
| 1 | **Intent Classifier** | `src/classifier/intent_classifier.py` | `output/case_context.json` |
| 2 | **Dynamic Tool Selector** | `src/agents/tool_selector.py` | `output/execution_plan.json` |
| 3 | **Execution Orchestrator** | `src/orchestrator.py` | `output/raw/<tool>_output.json` |
| 4 | **Evidence Aggregator** | `src/aggregator/evidence_aggregator.py` | `output/unified_evidence.json` |
| 5 | **Anomaly Detector** | `src/ml/anomaly_detector.py` | `output/anomaly_scores.json` |
| 6 | **XAI Explainer** | `src/ml/xai_explainer.py` | `output/shap_explanations.json` |
| 7 | **Report Generator** | `src/report_generator/report_generator.py` | `output/final_report.md` |

Individual stages can be invoked standalone:

```bash
# Run the classifier alone
python -m src.classifier.intent_classifier tests/incidents/02_apt_intrusion.txt

# Run the orchestrator alone (reads execution_plan.json from output/)
python -m src.orchestrator
```

Tool `name` values must exactly match the orchestrator's `WRAPPER_MAP` keys.
</details>

<details>
<summary><code>evidence_item</code> — Orchestrator → Aggregator (per item)</summary>

```json
{
  "artifact_id": "string",
  "source_tool": "volatility3 | tshark | tsk_fls | regripper | plaso",
  "evidence_type": "string",
  "timestamp": "ISO 8601 or empty string",
  "value": "string",
  "severity": "low | medium | high | critical",
  "confidence": 0.9,
  "linked_artifacts": ["artifact_id strings"]
}
```

Always produced via `BaseWrapper.make_evidence_item()` — never construct manually.
</details>

---

## Forensic tools

| Tool | Evidence type | Wrapper |
|---|---|---|
| [Volatility3](https://github.com/volatilityfoundation/volatility3) | Memory dump (`.dmp`, `.raw`, `.mem`) | `src/wrappers/volatility_wrapper.py` |
| [Tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | Network capture (`.pcap`, `.pcapng`) | `src/wrappers/tshark_wrapper.py` |
| [SleuthKit `fls`](https://www.sleuthkit.org/) | Disk image (`.img`, `.dd`, `.E01`) | `src/wrappers/tsk_wrapper.py` |
| [RegRipper](https://github.com/keydet89/RegRipper3.0) | Windows registry hive | `src/wrappers/regripper_wrapper.py` |
| [Plaso / log2timeline](https://github.com/log2timeline/plaso) | Multi-source timeline | `src/wrappers/plaso_wrapper.py` |
| Email parser | Email archive (phishing analysis) | `src/wrappers/email_wrapper.py` |
| Browser history parser | Browser history (phishing analysis) | `src/wrappers/browser_wrapper.py` |

All wrappers inherit from `src/wrappers/base_wrapper.py` and produce a uniform `evidence_item` schema — the load-bearing contract between the orchestrator (Stage 3) and aggregator (Stage 4).

---

## Project structure

```
autoforensiq/
├── autoforensiq.py                    # CLI entry point
├── config.yaml                        # LLM provider, paths, mock mode
├── requirements.txt
│
├── src/
│   ├── classifier/
│   │   └── intent_classifier.py       # Stage 1 — LLM → case_context.json
│   ├── agents/
│   │   └── tool_selector.py           # Stage 2 — DTSA → execution_plan.json
│   ├── orchestrator.py                # Stage 3 — subprocess wrappers
│   ├── wrappers/                      # Stage 3 — one wrapper per tool
│   │   ├── base_wrapper.py            # make_evidence_item() contract
│   │   ├── volatility_wrapper.py
│   │   ├── tshark_wrapper.py
│   │   ├── tsk_wrapper.py
│   │   ├── regripper_wrapper.py
│   │   ├── plaso_wrapper.py
│   │   ├── email_wrapper.py
│   │   └── browser_wrapper.py
│   ├── aggregator/
│   │   └── evidence_aggregator.py     # Stage 4 — normalise + deduplicate
│   ├── ml/
│   │   ├── anomaly_detector.py        # Stage 5 — Isolation Forest
│   │   └── xai_explainer.py          # Stage 6 — SHAP + LIME
│   ├── report_generator/
│   │   └── report_generator.py        # Stage 7 — LLM report + HTML timeline
│   ├── utils/
│   │   └── audit_log.py               # SHA-256 chain-of-custody log
│   └── schemas/
│       ├── case_context_schema.json
│       ├── execution_plan.json
│       ├── evidence_item.json
│       └── unified_evidence.json
│
├── tests/
│   ├── incidents/                     # 5 sample plain-text incident reports
│   └── test_wrappers.py
│
├── data/
│   └── test_cases/                    # Sample evidence files (memory.dmp, capture.pcap, …)
│
└── output/                            # Runtime output — gitignored
```

---

## Security notes

- **Never commit API keys.** Use environment variables or a `.env` file. `config.yaml` stores only the environment variable *name*, not the key value.
- **Evidence files may contain sensitive data.** The `output/` directory is gitignored — keep it that way.
- **Audit log integrity.** `output/audit_log.json` contains SHA-256 hashes of all evidence files at time of processing. Do not modify evidence files after a run if chain-of-custody matters.

---

| Type | Sample report |
|---|---|
| `ransomware` | `tests/incidents/01_ransomware.txt` |
| `apt_intrusion` | `tests/incidents/02_apt_intrusion.txt` |
| `data_exfiltration` | `tests/incidents/03_data_exfiltration.txt` |
| `insider_threat` | `tests/incidents/04_insider_threat.txt` |
| `malware_infection` | `tests/incidents/05_malware_infection.txt` |
| `phishing` | _(use the email + browser wrappers)_ |
| `unknown` | Classifier fallback — full pipeline still runs |

---

## Output files

Everything is written to `output/` (gitignored). A complete run produces:

| File | Stage | Contents |
|---|---|---|
| `case_context.json` | 1 — Classifier | Attack type, hypotheses, affected systems, artifact types |
| `execution_plan.json` | 2 — Tool Selector | Ordered list of tools with args |
| `raw/<tool>_output.json` | 3 — Orchestrator | Raw evidence items per tool |
| `unified_evidence.json` | 4 — Aggregator | Deduplicated, normalised evidence with MITRE ATT&CK mappings |
| `anomaly_scores.json` | 5 — ML | Isolation Forest anomaly scores per evidence item |
| `shap_explanations.json` | 6 — XAI | SHAP global weights + LIME plain-English reason per finding |
| `audit_log.json` | 3 — Orchestrator | SHA-256 chain-of-custody log for every tool invocation |
| `final_report.md` | 7 — Report Generator | Full forensic report with Kill Chain summary and ATT&CK table |
| `timeline.html` | 7 — Report Generator | Self-contained interactive evidence timeline |

---

## JSON schema contracts

Handoff files between stages have fixed field names. Renaming any field breaks the downstream consumer.

<details>
<summary><code>case_context.json</code> — Classifier → Tool Selector</summary>

```json
{
  "case_id": "uuid4",
  "case_type": "ransomware | apt_intrusion | data_exfiltration | insider_threat | malware_infection | phishing | unknown",
  "artifact_types": ["memory_dump | disk_image | pcap | registry_hive | log_files | email_archive | browser_history"],
  "hypotheses": ["ranked investigable hypothesis strings"],
  "affected_systems": ["hostnames or IPs"],
  "classifier_confidence": 0.95,
  "generated_at": "2026-05-08T12:00:00Z",
  "raw_incident_summary": "one sentence summary"
}
```

Validated against `src/schemas/case_context_schema.json` on every run.
</details>

<details>
<summary><code>execution_plan.json</code> — Tool Selector → Orchestrator</summary>

```json
{
  "tools": [
    { "name": "volatility3", "order": 1, "args": { "image": true } },
    { "name": "tshark",      "order": 2, "args": { "pcap": true  } },
    { "name": "tsk_fls",     "order": 3, "args": { "image": true } },
    { "name": "regripper",   "order": 4, "args": { "hive": true  } },
    { "name": "plaso",       "order": 5, "args": { "source": true} }
  ]
}
```

Tool `name` values must exactly match the orchestrator's `WRAPPER_MAP` keys.
</details>

<details>
<summary><code>evidence_item</code> — Orchestrator → Aggregator (per item)</summary>

```json
{
  "artifact_id": "string",
  "source_tool": "volatility3 | tshark | tsk_fls | regripper | plaso",
  "evidence_type": "string",
  "timestamp": "ISO 8601 or empty string",
  "value": "string",
  "severity": "low | medium | high | critical",
  "confidence": 0.9,
  "linked_artifacts": ["artifact_id strings"]
}
```

Always produced via `BaseWrapper.make_evidence_item()` — never construct manually.
</details>

---

## Running tests

```bash
# Wrapper unit tests (P3)
python -m pytest tests/test_wrappers.py -v

# Classifier round-trip (all 5 incident types)
for i in 01 02 03 04 05; do
  python -m src.classifier.intent_classifier tests/incidents/${i}_*.txt
done
```

---

## Project structure

```
autoforensiq/
├── autoforensiq.py                    # Entry point — GUI (no args) or CLI (--report …)
├── config.yaml                        # LLM provider, paths, mock mode
├── requirements.txt
│
├── src/
│   ├── gui/                           # Graphical launcher
│   │   ├── launcher.py                # Main window, all sections, pipeline wiring
│   │   ├── widgets.py                 # ArtifactRow and other reusable widgets
│   │   └── theme.py                   # Colour palette and font constants
│   ├── classifier/
│   │   └── intent_classifier.py       # Stage 1 — LLM → case_context.json
│   ├── agents/
│   │   └── tool_selector.py           # Stage 2 — DTSA → execution_plan.json
│   ├── orchestrator.py                # Stage 3 — subprocess wrappers
│   ├── wrappers/                      # Stage 3 — one wrapper per tool
│   │   ├── base_wrapper.py            # make_evidence_item() contract
│   │   ├── volatility_wrapper.py
│   │   ├── tshark_wrapper.py
│   │   ├── tsk_wrapper.py
│   │   ├── regripper_wrapper.py
│   │   ├── plaso_wrapper.py
│   │   ├── email_wrapper.py
│   │   └── browser_wrapper.py
│   ├── aggregator/
│   │   └── evidence_aggregator.py     # Stage 4 — normalise + deduplicate
│   ├── ml/
│   │   ├── anomaly_detector.py        # Stage 5 — Isolation Forest
│   │   └── xai_explainer.py          # Stage 6 — SHAP + LIME
│   ├── report_generator/
│   │   └── report_generator.py        # Stage 7 — LLM report + HTML timeline
│   ├── utils/
│   │   └── audit_log.py               # SHA-256 chain-of-custody log
│   └── schemas/
│       ├── case_context_schema.json
│       ├── execution_plan.json
│       ├── evidence_item.json
│       └── unified_evidence.json
│
├── tests/
│   ├── incidents/                     # 5 sample plain-text incident reports
│   └── test_wrappers.py
│
├── data/
│   └── test_cases/                    # Sample evidence files (memory.dmp, capture.pcap, …)
│
└── output/                            # Runtime output — gitignored
```

---

## License

MIT — see `LICENSE`.
