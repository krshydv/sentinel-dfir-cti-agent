import numpy as np
import pandas as pd

from dfir_cti.config import first_present


def standardize_columns(df, cfg):
    d = cfg["dataset"]
    mapping = {}
    for canonical, key in [
        ("ts", "timestamp_candidates"),
        ("src_ip", "src_ip_candidates"),
        ("dst_ip", "dst_ip_candidates"),
        ("src_port", "src_port_candidates"),
        ("dst_port", "dst_port_candidates"),
        ("label_binary", "label_binary_candidates"),
        ("label_tactic", "label_tactic_candidates"),
        ("label_technique", "label_technique_candidates"),
    ]:
        found = first_present(df.columns, d[key])
        if found and found != canonical:
            mapping[found] = canonical
    return df.rename(columns=mapping)


def parse_timestamps(df):
    if "ts" not in df.columns:
        return df
    ts = df["ts"]
    if pd.api.types.is_numeric_dtype(ts):
        median = ts.dropna().median() if ts.notna().any() else 0
        unit = "ms" if median > 1e11 else "s"
        df["ts"] = pd.to_datetime(ts, unit=unit, errors="coerce", utc=True)
    else:
        df["ts"] = pd.to_datetime(ts, errors="coerce", utc=True)
    return df


def normalize_labels(df):
    if "label_binary" in df.columns:
        col = df["label_binary"]
        if col.dtype == object:
            lowered = col.astype(str).str.strip().str.lower()
            df["label_binary"] = (~lowered.isin(["false", "0", "benign", "normal", "none", "nan", ""])).astype(int)
        else:
            df["label_binary"] = col.fillna(0).astype(int).clip(0, 1)
    return df


def clean(df, cfg):
    df = standardize_columns(df, cfg)
    df = df.drop_duplicates().reset_index(drop=True)
    df = parse_timestamps(df)
    if "ts" in df.columns:
        df = df.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
    df = normalize_labels(df)
    for col in cfg["features"]["numeric_candidates"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan)
    return df
