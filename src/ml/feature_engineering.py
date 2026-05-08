import pandas as pd
import json
import math

SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1}
FEATURE_NAMES = [
    "high_entropy",
    "rare_process",
    "unusual_parent",
    "parent_mismatch",
    "port_suspicious",
    "network_flag",
    "name_length"
]

def load_data(path):
    with open(path, 'r') as f:
        data = json.load(f)

    # -------- HANDLE MULTIPLE SCHEMAS --------
    if isinstance(data, dict) and "evidence_items" in data:
        data = data["evidence_items"]
    elif isinstance(data, dict) and "items" in data:
        data = data["items"]

    # -------- SAFETY CHECK --------
    if not isinstance(data, list):
        raise ValueError("Expected a list of evidence items")

    return pd.DataFrame(data)


def entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])


def create_features(df):
    df = df.copy()

    # Severity as numeric score
    df['severity_score'] = df['severity'].apply(
        lambda x: SEVERITY_MAP.get(str(x).lower(), 1)
    )

    # Confidence directly
    df['confidence'] = df['confidence'].astype(float)

    # Entropy of the value string (random-looking values are suspicious)
    df['value_entropy'] = df['value'].apply(entropy)

    # Whether this item is linked to other artifacts
    df['has_links'] = df['linked_artifacts'].apply(
        lambda x: 1 if x else 0
    )

    # Network-related evidence
    NETWORK_TYPES = ['network_connection', 'suspicious_url', 'connection']
    NETWORK_TOOLS = ['tshark', 'browser']
    df['is_network'] = df.apply(
        lambda r: 1 if any(t in str(r['evidence_type']).lower() for t in NETWORK_TYPES)
                     or str(r.get('source_tool', '')).lower() in NETWORK_TOOLS else 0,
        axis=1
    )

    # Known suspicious evidence types
    SUSPICIOUS_TYPES = ['phishing_email', 'suspicious_url', 'malfind', 'suspicious_connection']
    df['is_suspicious_type'] = df['evidence_type'].apply(
        lambda x: 1 if any(s in str(x).lower() for s in SUSPICIOUS_TYPES) else 0
    )

    # Length of value string
    df['value_length'] = df['value'].apply(len)

    return df[[
        'severity_score',
        'confidence',
        'value_entropy',
        'has_links',
        'is_network',
        'is_suspicious_type',
        'value_length'
    ]]
