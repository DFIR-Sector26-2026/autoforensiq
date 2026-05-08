# Graph Report - .  (2026-05-08)

## Corpus Check
- Corpus is ~14,581 words - fits in a single context window. You may not need a graph.

## Summary
- 244 nodes · 366 edges · 14 communities detected
- Extraction: 81% EXTRACTED · 19% INFERRED · 0% AMBIGUOUS · INFERRED: 70 edges (avg confidence: 0.78)
- Token cost: 8,200 input · 3,100 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Forensic Tool Wrappers|Forensic Tool Wrappers]]
- [[_COMMUNITY_Tool Selector & Execution Plan|Tool Selector & Execution Plan]]
- [[_COMMUNITY_Evidence Aggregation & Deduplication|Evidence Aggregation & Deduplication]]
- [[_COMMUNITY_Audit Log & Chain of Custody|Audit Log & Chain of Custody]]
- [[_COMMUNITY_Pipeline Architecture & Team Ownership|Pipeline Architecture & Team Ownership]]
- [[_COMMUNITY_Schema Contracts & Configuration|Schema Contracts & Configuration]]
- [[_COMMUNITY_CLI Entry Point & Pipeline Orchestration|CLI Entry Point & Pipeline Orchestration]]
- [[_COMMUNITY_Intent Classifier (LLM)|Intent Classifier (LLM)]]
- [[_COMMUNITY_Orchestrator & Evidence Schema|Orchestrator & Evidence Schema]]
- [[_COMMUNITY_ML Anomaly Detection & Feature Engineering|ML Anomaly Detection & Feature Engineering]]
- [[_COMMUNITY_Report Generator (LLM)|Report Generator (LLM)]]
- [[_COMMUNITY_Evidence Aggregator Module|Evidence Aggregator Module]]
- [[_COMMUNITY_PyYAML Dependency|PyYAML Dependency]]
- [[_COMMUNITY_Pandas Dependency|Pandas Dependency]]

## God Nodes (most connected - your core abstractions)
1. `VolatilityWrapper` - 12 edges
2. `BaseWrapper` - 11 edges
3. `main()` - 10 edges
4. `aggregate_evidence()` - 10 edges
5. `TsharkWrapper` - 10 edges
6. `BaseWrapper â€” make_evidence_item() Shared Method` - 9 edges
7. `classify()` - 8 edges
8. `generate_report()` - 8 edges
9. `Intent Classifier (Stage 1)` - 8 edges
10. `_stage()` - 7 edges

## Surprising Connections (you probably didn't know these)
- `run_classifier()` --calls--> `classify_file()`  [INFERRED]
  autoforensiq.py → src\classifier\intent_classifier.py
- `run_tool_selector()` --calls--> `generate_execution_plan()`  [INFERRED]
  autoforensiq.py → src\agents\tool_selector.py
- `run_aggregator()` --calls--> `aggregate_evidence()`  [INFERRED]
  autoforensiq.py → src\aggregator\evidence_aggregator.py
- `run_report_generator()` --calls--> `generate_report()`  [INFERRED]
  autoforensiq.py → src\report_generator\report_generator.py
- `run_ml_pipeline()` --calls--> `train_model()`  [INFERRED]
  src\ml\pipeline.py → src\ml\anomaly_detector.py

## Hyperedges (group relationships)
- **AutoForensiq Pipeline Stages (1-7)** — claudemd_intent_classifier, claudemd_tool_selector, claudemd_orchestrator, claudemd_aggregator, claudemd_anomaly_detector, claudemd_xai_explainer, claudemd_report_generator [EXTRACTED 1.00]
- **JSON Schema Handoff Contracts Between Modules** — claudemd_case_context_json, claudemd_execution_plan_json, claudemd_evidence_item, claudemd_unified_evidence_json, claudemd_shap_explanations_json [EXTRACTED 1.00]
- **Forensic Tool Wrappers (P3)** — claudemd_volatility_wrapper, claudemd_tshark_wrapper, claudemd_tsk_wrapper, claudemd_regripper_wrapper, claudemd_plaso_wrapper, readme_email_wrapper, readme_browser_wrapper [EXTRACTED 1.00]
- **XAI and ML Libraries** — requirements_sklearn, requirements_shap, requirements_lime, requirements_numpy, requirements_pandas [EXTRACTED 1.00]
- **SecTor 2026 Novelty Features** — novelty_mitre_attack, novelty_html_timeline, novelty_kill_chain [EXTRACTED 1.00]
- **5-Person Team** — claudemd_p1_merull, claudemd_p2, claudemd_p3, claudemd_p4, claudemd_p5 [EXTRACTED 1.00]

## Communities

### Community 0 - "Forensic Tool Wrappers"
Cohesion: 0.1
Nodes (7): BaseWrapper, Runs a shell command.         Returns (stdout, stderr, returncode).         Logs, Returns a dict matching the agreed evidence_item schema exactly.         Every w, PlasoWrapper, TsharkWrapper, TSKWrapper, VolatilityWrapper

### Community 1 - "Tool Selector & Execution Plan"
Cohesion: 0.1
Nodes (26): build_execution_plan(), generate_execution_plan(), load_case_context(), load_json(), main(), Dynamic Tool Selector Agent.  Reads a structured case context and the forensic t, Validate ontology structure and wrapper compatibility., Return True if the tool can process at least one available artifact. (+18 more)

### Community 2 - "Evidence Aggregation & Deduplication"
Cohesion: 0.1
Nodes (25): aggregate_evidence(), build_indices(), deduplicate_items(), load_json(), load_raw_outputs(), Evidence Aggregator (P4) — Normalize and consolidate forensic evidence  Responsi, Sort evidence items by:       1. Severity (critical → high → medium → low), Build lookup indices for evidence items.     Returns {       'by_type': {evidenc (+17 more)

### Community 3 - "Audit Log & Chain of Custody"
Cohesion: 0.1
Nodes (12): log_action(), sha256_file(), BaseWrapper, BrowserWrapper, EmailWrapper, RegRipperWrapper, test_audit_log_creates_entry(), test_base_wrapper_makes_evidence_item() (+4 more)

### Community 4 - "Pipeline Architecture & Team Ownership"
Cohesion: 0.1
Nodes (25): Evidence Aggregator (Stage 4), Anomaly Detector (Stage 5), AutoForensiq Autonomous Forensics Pipeline, P4 â€” Evidence Parsers, Correlation, Deduplication, P5 â€” Isolation Forest, SHAP, LIME, Evaluation, SecTor 2026 Conference Target (May 26 deadline), unified_evidence.json â€” Aggregator Output / ML Input, XAI Explainer (Stage 6) (+17 more)

### Community 5 - "Schema Contracts & Configuration"
Cohesion: 0.12
Nodes (20): case_context.json â€” Classifier Output / Tool Selector Input, execution_plan.json â€” Tool Selector Output / Orchestrator Input, Intent Classifier (Stage 1), Mock Mode â€” Deterministic pipeline without API key, P1 Merull â€” Intent Classifier, Report Generator, Integration Lead, P2 â€” Tool Ontology, DTSA Algorithm, Tool Selector, Report Generator (Stage 7), shap_explanations.json â€” XAI Output / Report Generator Input (+12 more)

### Community 6 - "CLI Entry Point & Pipeline Orchestration"
Cohesion: 0.25
Nodes (16): _ensure_output_dir(), _load_json(), main(), _map_evidence_files(), parse_args(), AutoForensiq — Main CLI Entry Point (P1) =======================================, Map raw file paths to evidence type keys based on extension., run_aggregator() (+8 more)

### Community 7 - "Intent Classifier (LLM)"
Cohesion: 0.21
Nodes (15): _call_anthropic(), _call_openai(), classify(), classify_file(), _load_config(), _load_schema(), _mock_classify(), _parse_llm_json() (+7 more)

### Community 8 - "Orchestrator & Evidence Schema"
Cohesion: 0.14
Nodes (15): Audit Log (SHA256 chain-of-custody), BaseWrapper â€” make_evidence_item() Shared Method, evidence_item â€” Orchestrator Output / Aggregator Input Schema, Execution Orchestrator (Stage 3), P3 â€” Subprocess Wrappers, Audit Log, Orchestrator, Plaso Wrapper, RegRipper Wrapper, Tshark Wrapper (+7 more)

### Community 9 - "ML Anomaly Detection & Feature Engineering"
Cohesion: 0.26
Nodes (7): predict(), train_model(), create_features(), load_data(), run_ml_pipeline(), explain_instance(), generate_shap()

### Community 10 - "Report Generator (LLM)"
Cohesion: 0.27
Nodes (10): _build_user_prompt(), _call_anthropic(), _call_openai(), generate_report(), _load_config(), _mock_report(), AutoForensiq — Report Generator (P1 Burst 2) ===================================, Build a structured Markdown report from data alone — no LLM required. (+2 more)

### Community 11 - "Evidence Aggregator Module"
Cohesion: 1.0
Nodes (1): Evidence Aggregator Agent (P4)  Reads raw outputs from forensic tools (P3), norm

### Community 17 - "PyYAML Dependency"
Cohesion: 1.0
Nodes (1): PyYAML (pyyaml>=6.0) â€” config.yaml parsing

### Community 18 - "Pandas Dependency"
Cohesion: 1.0
Nodes (1): pandas>=2.2.0

## Knowledge Gaps
- **71 isolated node(s):** `AutoForensiq — Main CLI Entry Point (P1) =======================================`, `Map raw file paths to evidence type keys based on extension.`, `Dynamic Tool Selector Agent.  Reads a structured case context and the forensic t`, `Load a JSON object from disk.`, `Write a JSON object to disk, creating the parent directory if needed.` (+66 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Evidence Aggregator Module`** (2 nodes): `Evidence Aggregator Agent (P4)  Reads raw outputs from forensic tools (P3), norm`, `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `PyYAML Dependency`** (1 nodes): `PyYAML (pyyaml>=6.0) â€” config.yaml parsing`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Pandas Dependency`** (1 nodes): `pandas>=2.2.0`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `run_tools()` connect `CLI Entry Point & Pipeline Orchestration` to `Forensic Tool Wrappers`?**
  _High betweenness centrality (0.215) - this node is a cross-community bridge._
- **Why does `run_tool_selector()` connect `CLI Entry Point & Pipeline Orchestration` to `Tool Selector & Execution Plan`?**
  _High betweenness centrality (0.128) - this node is a cross-community bridge._
- **Are the 7 inferred relationships involving `BaseWrapper` (e.g. with `BrowserWrapper` and `EmailWrapper`) actually correct?**
  _`BaseWrapper` has 7 INFERRED edges - model-reasoned connections that need verification._
- **Are the 4 inferred relationships involving `BaseWrapper` (e.g. with `test_base_wrapper_makes_evidence_item()` and `test_base_wrapper_run_command_success()`) actually correct?**
  _`BaseWrapper` has 4 INFERRED edges - model-reasoned connections that need verification._
- **Are the 3 inferred relationships involving `aggregate_evidence()` (e.g. with `run_aggregator()` and `test_aggregate_evidence_with_empty_tools()`) actually correct?**
  _`aggregate_evidence()` has 3 INFERRED edges - model-reasoned connections that need verification._
- **What connects `AutoForensiq — Main CLI Entry Point (P1) =======================================`, `Map raw file paths to evidence type keys based on extension.`, `Dynamic Tool Selector Agent.  Reads a structured case context and the forensic t` to the rest of the system?**
  _71 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Forensic Tool Wrappers` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._