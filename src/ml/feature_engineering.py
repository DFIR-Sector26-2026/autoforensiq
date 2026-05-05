import pandas as pd
import json
import math


def load_data(path):
    with open(path, 'r') as f:
        data = json.load(f)
    return pd.DataFrame(data)


def entropy(s):
    if not s:
        return 0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])


def create_features(df):
    # ---------- ENTROPY ----------
    df['name_entropy'] = df['process_name'].apply(entropy)
    df['high_entropy'] = df['name_entropy'].apply(lambda x: 1 if x > 3.5 else 0)

    # ---------- SUSPICIOUS PARENTS ----------
    SUSPICIOUS_PARENTS = ["cmd.exe", "powershell.exe", "winword.exe"]

    df['unusual_parent'] = df['parent_process'].apply(
        lambda x: 1 if str(x).lower() in SUSPICIOUS_PARENTS else 0
    )

    # ---------- RARE PROCESS ----------
    COMMON_PROCESSES = ["chrome.exe", "explorer.exe", "notepad.exe", "spotify.exe", "zoom.exe"]

    df['rare_process'] = df['process_name'].apply(
        lambda x: 0 if str(x).lower() in COMMON_PROCESSES else 1
    )

    # ---------- SUSPICIOUS PORTS ----------
    SUSPICIOUS_PORTS = [4444, 1337, 5555]

    df['port_suspicious'] = df['port'].apply(
        lambda x: 1 if x in SUSPICIOUS_PORTS else 0
    )

    # ---------- NETWORK FLAG ----------
    df['network_flag'] = df['has_network'].astype(int)

    # ---------- PROCESS NAME LENGTH ----------
    df['name_length'] = df['process_name'].apply(len)

    # ---------- PARENT-CHILD MISMATCH ----------
    def parent_child_mismatch(row):
        parent = str(row['parent_process']).lower()

        if parent == "explorer.exe":
            return 0

        if parent in ["cmd.exe", "powershell.exe", "winword.exe"]:
            return 1

        return 0

    df['parent_mismatch'] = df.apply(parent_child_mismatch, axis=1)

    # ---------- FINAL FEATURE SET ----------
    return df[
        [
            'high_entropy',
            'rare_process',
            'unusual_parent',
            'parent_mismatch',
            'port_suspicious',
            'network_flag',
            'name_length'
        ]
    ]