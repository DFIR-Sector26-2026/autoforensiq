"""AutoForensiq — Intent Classifier (P1): plain-text incident report → structured
case_context.json for the Dynamic Tool Selector (P2). Providers: anthropic / openai / deepseek,
or mock_mode (no API key). Standalone: python -m src.classifier.intent_classifier <report.txt>"""

import os
import re
import sys
import json
import uuid
import yaml
import jsonschema
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────

ROOT_DIR   = Path(__file__).resolve().parents[2]
CONFIG_PATH  = ROOT_DIR / "config.yaml"
SCHEMA_PATH  = ROOT_DIR / "src" / "schemas" / "case_context_schema.json"

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a digital forensics triage expert embedded in an automated pipeline.

Your task: read the incident report provided by the user and return ONLY a valid JSON object.
Do NOT include any markdown fences, explanations, or text outside the JSON.

The JSON must conform exactly to this schema:

{
  "case_id":              "<generate a UUID4>",
  "case_type":            "<one of: ransomware | apt_intrusion | data_exfiltration | insider_threat | malware_infection | phishing | unknown>",
  "artifact_types":       ["<array of one or more: memory_dump | disk_image | pcap | registry_hive | log_files | email_archive | browser_history>"],
  "hypotheses":           ["<array of 2–4 specific forensic hypotheses to investigate, ranked by likelihood>"],
  "affected_systems":     ["<array of hostnames, IPs, or system identifiers mentioned in the report; empty array if none>"],
  "classifier_confidence": <float 0.0–1.0, your confidence in the case_type classification>,
  "generated_at":         "<ISO 8601 UTC timestamp>",
  "raw_incident_summary": "<one sentence summary of what happened, in plain English>"
}

Rules:
- artifact_types must only contain items from the allowed enum. Include every type that is relevant.
- hypotheses must be specific and investigable (e.g. "Lateral movement via compromised admin credentials" not "malware present").
- If evidence files are mentioned (e.g. memory dump, pcap), include the matching artifact_type.
- classifier_confidence reflects how clearly the incident report maps to the case_type (0.9+ = very clear, 0.5 = ambiguous).
- Return ONLY the JSON object. No markdown. No explanation."""


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"config.yaml not found at {CONFIG_PATH}")
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ── Schema validator ──────────────────────────────────────────────────────────

def _load_schema() -> dict:
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def validate_case_context(data: dict) -> None:
    """Raises jsonschema.ValidationError if data does not match the schema."""
    schema = _load_schema()
    jsonschema.validate(instance=data, schema=schema)


# ── Mock classifier ───────────────────────────────────────────────────────────

_MOCK_KEYWORDS = {
    "ransomware":        ["ransom", "encrypt", "decrypt", "bitcoin", "locked", ".crypt", "payment"],
    "apt_intrusion":     ["apt", "advanced persistent", "nation-state", "lateral movement", "spear phish", "c2", "command and control"],
    "data_exfiltration": ["exfil", "data theft", "stolen", "upload", "ftp", "transfer", "leak", "exfiltrat"],
    "insider_threat":    ["insider", "employee", "disgruntled", "privileged user", "unauthorised access", "unauthorized access"],
    "malware_infection": ["malware", "trojan", "worm", "virus", "injected", "backdoor", "rootkit", "payload"],
    "phishing":          ["phishing", "spear phish", "email", "credential harvest", "fake login", "link clicked"],
}

_ARTIFACT_KEYWORDS = {
    "memory_dump":    ["memory", ".dmp", "memory dump", "ram"],
    "disk_image":     ["disk", ".img", ".dd", "drive", "disk image"],
    "pcap":           ["pcap", "network capture", ".pcap", "wireshark", "traffic"],
    "registry_hive":  ["registry", "ntuser", "ntuser.dat", "hive", "regedit"],
    "log_files":      ["log", "event log", "syslog", "windows event", ".log", "evtx"],
    "email_archive":  ["email", "pst", ".pst", "mailbox", "outlook"],
    "browser_history":["browser", "chrome", "firefox", "history", "cookies"],
}

def _mock_classify(report_text: str) -> dict:
    """Deterministic keyword-based classifier — no LLM/API key needed."""
    text_lower = report_text.lower()

    # Determine case_type by scoring each category
    scores = {ct: 0 for ct in _MOCK_KEYWORDS}
    for case_type, keywords in _MOCK_KEYWORDS.items():
        for kw in keywords:
            if kw in text_lower:
                scores[case_type] += 1

    best_type  = max(scores, key=scores.get)
    best_score = scores[best_type]
    case_type  = best_type if best_score > 0 else "unknown"
    confidence = min(0.5 + (best_score * 0.1), 0.95) if best_score > 0 else 0.35

    # Determine artifact_types
    artifact_types = []
    for artifact, keywords in _ARTIFACT_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            artifact_types.append(artifact)
    if not artifact_types:
        artifact_types = ["memory_dump"]  # safe default

    # Build hypotheses from case type
    hypotheses_map = {
        "ransomware":        [
            "Ransomware binary executed via phishing attachment or RDP brute force",
            "File encryption process spawned from a suspicious parent process",
            "C2 beacon established prior to encryption to exfiltrate data",
            "Persistence mechanism installed in registry run keys before detonation",
        ],
        "apt_intrusion":     [
            "Initial access via spear-phishing or supply chain compromise",
            "Lateral movement using stolen credentials or pass-the-hash",
            "Long-dwell persistence established via scheduled tasks or WMI subscriptions",
            "Data staging and exfiltration to attacker-controlled C2 infrastructure",
        ],
        "data_exfiltration": [
            "Sensitive data accessed and staged in a temporary directory",
            "Exfiltration via encrypted channel to external IP or cloud storage",
            "Credential theft used to escalate privileges before data access",
            "Unusual outbound network volume at off-hours indicating transfer",
        ],
        "insider_threat":    [
            "Privileged user accessed data outside normal business hours",
            "Bulk download or copy of sensitive files to removable media",
            "Attempts to cover tracks via log clearing or file deletion",
            "Unusual authentication patterns prior to resignation or termination",
        ],
        "malware_infection": [
            "Malware injected into a legitimate process to evade detection",
            "Suspicious DLL loaded by a trusted process (DLL hijacking or sideloading)",
            "Persistence mechanism established in registry or scheduled tasks",
            "C2 communication established from infected host to attacker infrastructure",
        ],
        "phishing":          [
            "Malicious email link or attachment opened by target user",
            "Credential harvesting page used to steal user login credentials",
            "Payload downloaded and executed following link click",
            "Lateral movement initiated from compromised user account",
        ],
        "unknown":           [
            "Investigate all available artifacts for signs of compromise",
            "Baseline system state against known-good to identify anomalies",
            "Review authentication logs for unusual access patterns",
        ],
    }

    # Extract affected systems (simple heuristic: look for hostnames/IPs)
    ip_pattern   = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_text)
    host_pattern = re.findall(r'\b[A-Z][A-Z0-9\-]{3,}\b', report_text)
    # Require a hostname *shape*, not an English word (B5): real machine names carry a digit/hyphen
    # and fit the 15-char NetBIOS limit; all-caps report headings don't — so the acronym stop-list
    # needn't be exhaustive.
    host_pattern = [
        h for h in host_pattern
        if len(h) <= 15
        and (any(c.isdigit() for c in h) or "-" in h)
        and h not in ("HTTP", "HTTPS", "WIN32", "WIN64")
    ]
    affected_systems = list(dict.fromkeys(ip_pattern + host_pattern[:3]))[:5]

    # Summary sentence
    summaries = {
        "ransomware":        "Ransomware incident where files were encrypted and a ransom demand was made.",
        "apt_intrusion":     "Advanced persistent threat intrusion with signs of long-dwell lateral movement.",
        "data_exfiltration": "Suspected data exfiltration incident with unauthorised access to sensitive files.",
        "insider_threat":    "Insider threat incident involving unauthorised data access by a privileged user.",
        "malware_infection": "Malware infection detected with signs of process injection and C2 communication.",
        "phishing":          "Phishing-initiated compromise resulting in credential theft or payload execution.",
        "unknown":           "Incident of unknown type requiring broad forensic investigation across all artifacts.",
    }

    return {
        "case_id":              str(uuid.uuid4()),
        "case_type":            case_type,
        "artifact_types":       artifact_types,
        "hypotheses":           hypotheses_map.get(case_type, hypotheses_map["unknown"]),
        "affected_systems":     affected_systems,
        "classifier_confidence": round(confidence, 2),
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "raw_incident_summary": summaries.get(case_type, summaries["unknown"]),
    }


# ── Real LLM classifiers ──────────────────────────────────────────────────────

def _call_anthropic(report_text: str, cfg: dict) -> dict:
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package not installed. Run: pip install anthropic")

    api_key = os.environ.get(cfg["llm"]["anthropic_api_key_env"])
    if not api_key:
        raise EnvironmentError(
            f"API key not found. Set the {cfg['llm']['anthropic_api_key_env']} "
            "environment variable, or enable mock_mode in config.yaml."
        )

    client = anthropic.Anthropic(api_key=api_key)
    model  = cfg["llm"]["anthropic_model"]

    message = client.messages.create(
        model=model,
        max_tokens=cfg["llm"]["max_tokens"],
        temperature=cfg["llm"]["temperature"],
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": report_text}],
    )

    raw = message.content[0].text.strip()
    return _parse_llm_json(raw)


def _call_openai(report_text: str, cfg: dict) -> dict:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    api_key = os.environ.get(cfg["llm"]["openai_api_key_env"])
    if not api_key:
        raise EnvironmentError(
            f"API key not found. Set the {cfg['llm']['openai_api_key_env']} "
            "environment variable, or enable mock_mode in config.yaml."
        )

    client = OpenAI(api_key=api_key)
    model  = cfg["llm"]["openai_model"]

    response = client.chat.completions.create(
        model=model,
        max_tokens=cfg["llm"]["max_tokens"],
        temperature=cfg["llm"]["temperature"],
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": report_text},
        ],
    )

    raw = response.choices[0].message.content.strip()
    return _parse_llm_json(raw)


def _call_deepseek(report_text: str, cfg: dict) -> dict:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    api_key = os.environ.get(cfg["llm"]["deepseek_api_key_env"])
    if not api_key:
        raise EnvironmentError(
            f"API key not found. Set the {cfg['llm']['deepseek_api_key_env']} "
            "environment variable, or enable mock_mode in config.yaml."
        )

    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    model  = cfg["llm"]["deepseek_model"]

    response = client.chat.completions.create(
        model=model,
        max_tokens=cfg["llm"]["max_tokens"],
        temperature=cfg["llm"]["temperature"],
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": report_text},
        ],
    )

    raw = response.choices[0].message.content.strip()
    return _parse_llm_json(raw)


def _parse_llm_json(raw: str) -> dict:
    """Strip markdown fences if present, parse JSON; ValueError on invalid."""
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\s*```$",          "", raw, flags=re.MULTILINE)
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"LLM returned invalid JSON: {e}\n\nRaw output:\n{raw}")


# ── Public API ────────────────────────────────────────────────────────────────

# Canonical artifact_type ordering (matches the case_context schema enum). Used to render a
# deterministic, narrowed artifact_types list (issue 1.2).
_ARTIFACT_TYPE_ORDER = [
    "memory_dump", "disk_image", "pcap", "registry_hive",
    "log_files", "email_archive", "browser_history",
]


def _narrow_artifact_types(result: dict, provided_artifact_types) -> None:
    """Replace the narrative artifact_types with the evidence types actually provided (1.2),
    keeping the claim under artifact_types_claimed. No-op when nothing was provided (standalone
    classify / GUI without files)."""
    if not provided_artifact_types:
        return

    present = {t for t in provided_artifact_types if t in _ARTIFACT_TYPE_ORDER}
    if not present:
        return

    result["artifact_types_claimed"] = list(result.get("artifact_types", []))
    result["artifact_types"] = [t for t in _ARTIFACT_TYPE_ORDER if t in present]


def classify(report_text: str, config_override: dict = None,
             provided_artifact_types=None) -> dict:
    """Classify an incident report → validated case_context dict. When provided_artifact_types is
    given, artifact_types is narrowed to it (1.2). Raises on schema violation, unparseable LLM
    JSON, or missing API key."""
    cfg = _load_config()
    if config_override:
        # Deep merge — only top-level keys for simplicity
        for k, v in config_override.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k].update(v)
            else:
                cfg[k] = v

    mock_mode = cfg["llm"].get("mock_mode", True)
    provider  = cfg["llm"].get("provider", "anthropic")

    if mock_mode:
        print("[CLASSIFIER] Running in MOCK mode (no API call)")
        result = _mock_classify(report_text)
    elif provider == "anthropic":
        print(f"[CLASSIFIER] Calling Anthropic ({cfg['llm']['anthropic_model']})")
        result = _call_anthropic(report_text, cfg)
    elif provider == "openai":
        print(f"[CLASSIFIER] Calling OpenAI ({cfg['llm']['openai_model']})")
        result = _call_openai(report_text, cfg)
    elif provider == "deepseek":
        print(f"[CLASSIFIER] Calling DeepSeek ({cfg['llm']['deepseek_model']})")
        result = _call_deepseek(report_text, cfg)
    else:
        raise ValueError(f"Unknown LLM provider: '{provider}'. Use 'anthropic', 'openai', or 'deepseek'.")

    # Ensure required fields that the LLM might miss in live mode
    if "case_id" not in result or not result["case_id"]:
        result["case_id"] = str(uuid.uuid4())
    if "generated_at" not in result or not result["generated_at"]:
        result["generated_at"] = datetime.now(timezone.utc).isoformat()

    # Issue 1.2 — constrain the narrative artifact_types to what was actually supplied, so P2
    # doesn't select tools for evidence that was never provided.
    _narrow_artifact_types(result, provided_artifact_types)

    # Validate against schema — raises jsonschema.ValidationError on failure
    validate_case_context(result)
    print(f"[CLASSIFIER] Schema validation passed ✔")
    print(f"[CLASSIFIER] case_type={result['case_type']} "
          f"confidence={result['classifier_confidence']} "
          f"artifacts={result['artifact_types']}")

    return result


def classify_file(report_path: str, output_path: str = None,
                  config_override: dict = None,
                  provided_artifact_types=None) -> dict:
    """Classify a report file; optionally write case_context.json to output_path (defaults to
    config.yaml's paths.case_context_output)."""
    report_path = Path(report_path)
    if not report_path.exists():
        raise FileNotFoundError(f"Incident report not found: {report_path}")

    print(f"[CLASSIFIER] Reading incident report: {report_path}")
    report_text = report_path.read_text(encoding="utf-8")

    result = classify(report_text, config_override,
                      provided_artifact_types=provided_artifact_types)

    # Determine output path
    if output_path is None:
        cfg = _load_config()
        output_path = ROOT_DIR / cfg["paths"]["case_context_output"]

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[CLASSIFIER] Output written → {output_path}")

    return result


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.classifier.intent_classifier <path/to/incident_report.txt>")
        print("       python -m src.classifier.intent_classifier <path/to/incident_report.txt> <output/case_context.json>")
        sys.exit(1)

    report  = sys.argv[1]
    out     = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        context = classify_file(report, out)
        print("\n── case_context.json ─────────────────────────────────")
        print(json.dumps(context, indent=2))
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
