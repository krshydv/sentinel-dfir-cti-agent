import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from make_synthetic import generate

from dfir_cti.config import load_config
from dfir_cti.correlation.incidents import build_incidents
from dfir_cti.forensics.timeline import activity_bursts, build_timeline, timeline_stats
from dfir_cti.investigation import investigate
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.threat_intel.attack_mapping import map_incidents, mapping_accuracy
from dfir_cti.threat_intel.iocs import classify_ip, extract_iocs


def _setup():
    cfg = load_config()
    frame = clean(generate(6000, 0.1, 3), cfg)
    flagged = frame["label_binary"].values
    return cfg, frame, flagged


def test_incidents_group_by_source():
    cfg, frame, flagged = _setup()
    incidents, assignment = build_incidents(frame, flagged, cfg)
    assert len(incidents) > 0
    assert incidents["incident_id"].is_unique
    assert (incidents["flows"] >= cfg["correlation"]["min_flows"]).all()
    assert assignment.notna().sum() == incidents["flows"].sum()


def test_timeline_and_iocs():
    cfg, frame, flagged = _setup()
    incidents, assignment = build_incidents(frame, flagged, cfg)
    incident_id = incidents.iloc[0]["incident_id"]
    timeline = build_timeline(frame, assignment, incident_id)
    stats = timeline_stats(timeline)
    assert stats["peak_flows_per_min"] >= 1
    assert len(activity_bursts(timeline)) >= 1
    iocs = extract_iocs(timeline)
    assert any(i["role"] == "source" for i in iocs)
    assert any(i["type"] == "port" for i in iocs)


def test_attack_mapping_matches_labels():
    cfg, frame, flagged = _setup()
    incidents, _, reports = investigate(frame, flagged, np.ones(len(frame)), cfg)
    accuracy = mapping_accuracy(incidents)
    assert accuracy["tactic_accuracy"] >= 0.6
    assert all("iocs" in r and "timeline" in r for r in reports)


def test_classify_ip():
    assert classify_ip("10.0.0.5") == "internal"
    assert classify_ip("8.8.8.8") == "external"
