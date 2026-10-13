import numpy as np
import pandas as pd


def flow_features(df, cfg):
    f = cfg["features"]
    numeric = [c for c in f["numeric_candidates"] if c in df.columns]
    X = df[numeric].copy()
    X = X.fillna(0)
    for col in numeric:
        X[f"log_{col}"] = np.log1p(X[col].clip(lower=0))
    for col in f["categorical_candidates"]:
        if col in df.columns:
            dummies = pd.get_dummies(df[col].fillna("unknown").astype(str), prefix=col)
            X = pd.concat([X, dummies.astype(float)], axis=1)
    if "dst_port" in df.columns:
        port = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
        X["dst_port"] = port
        X["is_well_known_port"] = (port < 1024).astype(float)
    if "orig_bytes" in X.columns and "resp_bytes" in X.columns:
        X["byte_ratio"] = (X["orig_bytes"] + 1) / (X["resp_bytes"] + 1)
    return X


def window_features(df, cfg):
    if not {"ts", "src_ip"}.issubset(df.columns):
        return pd.DataFrame()
    secs = cfg["features"]["window_seconds"]
    work = df.copy()
    work["window"] = work["ts"].dt.floor(f"{secs}s")
    grp = work.groupby(["src_ip", "window"])
    agg = grp.agg(
        flow_count=("ts", "size"),
        unique_dst_ips=("dst_ip", "nunique") if "dst_ip" in work.columns else ("ts", "size"),
        unique_dst_ports=("dst_port", "nunique") if "dst_port" in work.columns else ("ts", "size"),
        total_orig_bytes=("orig_bytes", "sum") if "orig_bytes" in work.columns else ("ts", "size"),
        total_resp_bytes=("resp_bytes", "sum") if "resp_bytes" in work.columns else ("ts", "size"),
        mean_duration=("duration", "mean") if "duration" in work.columns else ("ts", "size"),
    ).reset_index()
    if "label_binary" in work.columns:
        lab = grp["label_binary"].max().reset_index(name="label_binary")
        agg = agg.merge(lab, on=["src_ip", "window"])
    return agg


def split_xy(df, X):
    y = df["label_binary"].values if "label_binary" in df.columns else None
    return X.values.astype(np.float32), y
