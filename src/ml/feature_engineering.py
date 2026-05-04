import pandas as pd
import json
import math

def load_data(path):
    with open(path, 'r') as f:
        data = json.load(f)
    return pd.DataFrame(data)

def entropy(s):
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log2(p) for p in prob])

def create_features(df):
    df['name_entropy'] = df['process_name'].apply(entropy)
    df['unusual_parent'] = df['parent_process'].apply(lambda x: 1 if x == "cmd.exe" else 0)
    df['port_suspicious'] = df['port'].apply(lambda x: 1 if x not in [80, 443] else 0)
    df['has_network'] = df['has_network'].astype(int)

    return df[['name_entropy', 'unusual_parent', 'port_suspicious', 'has_network']]

