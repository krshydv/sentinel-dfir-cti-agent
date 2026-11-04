import pandas as pd

from dfir_cti.correlation.incidents import FAILED_STATES

TIMELINE_COLUMNS = [
    "ts",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "service",
    "conn_state",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
]


def build_timeline(frame, assignment, incident_id):
    rows = frame[assignment == incident_id].sort_values("ts")
    columns = [c for c in TIMELINE_COLUMNS if c in rows.columns]
    return rows[columns].reset_index(drop=True)


def timeline_stats(timeline):
    per_minute = timeline.set_index("ts").resample("1min").size()
    stats = {
        "first_seen": timeline["ts"].min(),
        "last_seen": timeline["ts"].max(),
        "peak_flows_per_min": int(per_minute.max()),
        "active_minutes": int((per_minute > 0).sum()),
        "failed_ratio": 0.0,
        "bytes_out": 0.0,
        "bytes_in": 0.0,
    }
    if "conn_state" in timeline.columns:
        stats["failed_ratio"] = float(timeline["conn_state"].isin(FAILED_STATES).mean())
    if "orig_bytes" in timeline.columns:
        stats["bytes_out"] = float(timeline["orig_bytes"].fillna(0).sum())
    if "resp_bytes" in timeline.columns:
        stats["bytes_in"] = float(timeline["resp_bytes"].fillna(0).sum())
    return stats


def activity_bursts(timeline, gap_seconds=300):
    burst_no = (timeline["ts"].diff() > pd.Timedelta(seconds=gap_seconds)).cumsum()
    bursts = []
    for _, group in timeline.groupby(burst_no):
        bursts.append({"start": group["ts"].min(), "end": group["ts"].max(), "flows": int(len(group))})
    return bursts
