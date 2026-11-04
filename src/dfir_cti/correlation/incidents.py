import numpy as np
import pandas as pd

from dfir_cti.detection.rules import run_rules

FAILED_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"}


def _top(series, n=3):
    counts = series.value_counts().head(n)
    return {str(key): int(value) for key, value in counts.items()}


def _majority(series):
    values = series.dropna()
    if values.empty:
        return None
    return str(values.value_counts().idxmax())


def _rules_for(alerts, src_ip, start, end, window_seconds):
    if alerts.empty:
        return []
    first_window = start.floor(f"{window_seconds}s")
    hits = alerts[
        (alerts["src_ip"] == src_ip) & (alerts["window"] >= first_window) & (alerts["window"] <= end)
    ]
    return sorted(hits["rule"].unique())


def _summarise(group, alerts, window_seconds):
    src_ip = group["src_ip"].iloc[0]
    start = group["ts"].min()
    end = group["ts"].max()

    record = {
        "src_ip": src_ip,
        "start": start,
        "end": end,
        "duration_s": float((end - start).total_seconds()),
        "flows": int(len(group)),
        "unique_dsts": int(group["dst_ip"].nunique()) if "dst_ip" in group.columns else 0,
        "unique_ports": int(group["dst_port"].nunique()) if "dst_port" in group.columns else 0,
        "top_dsts": _top(group["dst_ip"]) if "dst_ip" in group.columns else {},
        "top_ports": _top(group["dst_port"]) if "dst_port" in group.columns else {},
        "bytes_out": float(group["orig_bytes"].fillna(0).sum()) if "orig_bytes" in group.columns else 0.0,
        "failed_ratio": float(group["conn_state"].isin(FAILED_STATES).mean()) if "conn_state" in group.columns else 0.0,
        "mean_score": float(group["score"].mean()),
        "max_score": float(group["score"].max()),
        "rules": _rules_for(alerts, src_ip, start, end, window_seconds),
        "true_tactic": _majority(group["label_tactic"]) if "label_tactic" in group.columns else None,
        "true_technique": _majority(group["label_technique"]) if "label_technique" in group.columns else None,
    }
    return record


def build_incidents(frame, flagged, cfg, scores=None):
    settings = cfg["correlation"]
    gap = pd.Timedelta(seconds=settings["gap_seconds"])
    window_seconds = cfg["rules"]["window_seconds"]

    mask = np.asarray(flagged).astype(bool)
    work = frame.loc[mask].copy()
    work["score"] = np.asarray(scores, dtype=float)[mask] if scores is not None else 1.0
    work = work.sort_values(["src_ip", "ts"])

    new_incident = (work["src_ip"] != work["src_ip"].shift()) | (work["ts"].diff() > gap)
    work["incident_no"] = new_incident.cumsum()

    alerts = run_rules(frame, cfg)

    found = []
    for _, group in work.groupby("incident_no"):
        if len(group) < settings["min_flows"]:
            continue
        found.append((_summarise(group, alerts, window_seconds), group.index))

    found.sort(key=lambda item: item[0]["start"])

    assignment = pd.Series([None] * len(frame), index=frame.index, dtype=object)
    records = []
    for number, (record, index) in enumerate(found, start=1):
        incident_id = f"INC-{number:04d}"
        record["incident_id"] = incident_id
        assignment.loc[index] = incident_id
        records.append(record)

    incidents = pd.DataFrame(records)
    if not incidents.empty:
        columns = ["incident_id"] + [c for c in incidents.columns if c != "incident_id"]
        incidents = incidents[columns]

    return incidents, assignment
