import gzip
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dfir_cti.config import load_config
from dfir_cti.ingestion.zeek import read_conn_dir, read_conn_log
from dfir_cti.investigation import investigate
from dfir_cti.pipeline import rule_flags
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.simulation import SCENARIOS, simulate_lab, write_conn_log
from dfir_cti.threat_intel.attack_mapping import mapping_accuracy


def test_conn_log_round_trip(tmp_path):
    frame = simulate_lab(seed=1, benign_flows=800)
    path = write_conn_log(frame, tmp_path / "conn.log")
    parsed = read_conn_log(path)
    assert len(parsed) == len(frame)
    assert {"src_ip", "dst_ip", "src_port", "dst_port", "uid"}.issubset(parsed.columns)
    assert set(parsed["uid"]) == set(frame["uid"])
    assert np.isclose(parsed["orig_bytes"].sum(), frame["orig_bytes"].sum())
    assert parsed["dst_port"].dtype.kind in "if"


def test_unset_fields_and_gzip(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_bytes\n"
        "1762000000.5\tCa\t10.0.0.1\t4444\t10.0.0.2\t22\ttcp\t-\t120\n"
        "1762000001.5\tCb\t10.0.0.1\t4445\t10.0.0.2\t22\ttcp\tssh\t-\n#close\t2026\n"
    )
    parsed = read_conn_log(path)
    assert len(parsed) == 2
    assert pd.isna(parsed.loc[0, "service"])
    assert pd.isna(parsed.loc[1, "orig_bytes"])

    packed = tmp_path / "sub" / "conn.01.log.gz"
    packed.parent.mkdir()
    packed.write_bytes(gzip.compress(path.read_bytes()))
    assert len(read_conn_dir(packed.parent)) == 2


def test_json_conn_log(tmp_path):
    path = tmp_path / "conn.json"
    path.write_text(
        '{"ts":1762000000.5,"uid":"Ca","id.orig_h":"10.0.0.1","id.orig_p":4444,"id.resp_h":"10.0.0.2","id.resp_p":22,"proto":"tcp"}\n'
        '{"ts":1762000001.5,"uid":"Cb","id.orig_h":"10.0.0.1","id.orig_p":4445,"id.resp_h":"10.0.0.2","id.resp_p":22,"proto":"tcp"}\n'
    )
    parsed = read_conn_log(path)
    assert list(parsed["dst_port"]) == [22, 22]
    assert parsed["src_ip"].iloc[0] == "10.0.0.1"


def test_lab_scenarios_are_detected_and_mapped(tmp_path):
    cfg = load_config()
    frame = simulate_lab(seed=7, benign_flows=3000)
    path = write_conn_log(frame, tmp_path / "conn.log")
    raw = read_conn_log(path).merge(frame[["uid", "label_binary", "label_tactic", "label_technique"]], on="uid")
    cleaned = clean(raw, cfg)
    flagged = rule_flags(cleaned, cfg)

    attack = cleaned["label_binary"] == 1
    assert flagged[attack.values].mean() > 0.9
    assert flagged[~attack.values].mean() < 0.02

    incidents, _, _ = investigate(cleaned, flagged, np.where(flagged == 1, 1.0, 0.0), cfg)
    summary = mapping_accuracy(incidents)
    assert summary["tactic_accuracy"] == 1.0
    assert set(incidents["technique_id"]) >= {t for _, t in SCENARIOS.values()}
