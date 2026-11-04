import json
from pathlib import Path

import numpy as np
import pandas as pd

from dfir_cti.config import resolve_path
from dfir_cti.correlation.incidents import build_incidents
from dfir_cti.forensics.timeline import activity_bursts, build_timeline, timeline_stats
from dfir_cti.threat_intel.attack_mapping import map_incidents
from dfir_cti.threat_intel.iocs import extract_iocs, load_blocklist


def investigate(frame, flagged, scores, cfg):
    incidents, assignment = build_incidents(frame, flagged, cfg, scores)
    incidents = map_incidents(incidents, cfg)

    blocklist = load_blocklist(resolve_path(cfg, "intel") / cfg["threat_intel"]["blocklist_file"])

    reports = []
    for record in incidents.to_dict("records"):
        timeline = build_timeline(frame, assignment, record["incident_id"])
        record["timeline"] = timeline_stats(timeline)
        record["bursts"] = activity_bursts(timeline)
        record["iocs"] = extract_iocs(timeline, blocklist)
        reports.append(record)

    return incidents, assignment, reports


def _encode(value):
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (set, tuple)):
        return list(value)
    return str(value)


def save_reports(reports, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2, default=_encode)
    return path
