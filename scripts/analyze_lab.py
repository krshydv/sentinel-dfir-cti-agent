import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.config import load_config, resolve_path
from dfir_cti.detection.rules import run_rules
from dfir_cti.ingestion.zeek import read_conn_dir, read_conn_log
from dfir_cti.investigation import investigate, save_reports
from dfir_cti.pipeline import rule_flags
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.storage import open_store
from dfir_cti.threat_intel.attack_mapping import mapping_accuracy

import numpy as np
import pandas as pd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/lab")
    parser.add_argument("--truth", default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    source = Path(args.input)
    raw = read_conn_log(source) if source.is_file() else read_conn_dir(source)

    truth_path = Path(args.truth) if args.truth else (source if source.is_dir() else source.parent) / "ground_truth.csv"
    if truth_path.exists() and "uid" in raw.columns:
        raw = raw.merge(pd.read_csv(truth_path), on="uid", how="left")

    frame = clean(raw, cfg)
    flagged = rule_flags(frame, cfg)
    print("Flows:", len(frame), " Flagged by rules:", int(flagged.sum()))
    print(run_rules(frame, cfg)["rule"].value_counts().to_string())

    incidents, _, reports = investigate(frame, flagged, np.where(flagged == 1, 1.0, 0.0), cfg)
    accuracy = mapping_accuracy(incidents)
    print("Incidents:", accuracy["incidents"], " Tactic accuracy:", accuracy.get("tactic_accuracy"))

    agent = InvestigationAgent(cfg)
    results = [agent.investigate(r) for r in reports]
    out = resolve_path(cfg, "reports") / "lab"
    out.mkdir(parents=True, exist_ok=True)
    save_reports(reports, out / "incidents.json")
    for r in results:
        (out / f"{r['incident_id']}.md").write_text(r["report"], encoding="utf-8")
        print(r["incident_id"], r["severity"]["level"], r["technique_id"])

    with open_store(cfg, out / "lab.db") as store:
        store.save_incidents(reports)
        store.save_agent_results(results)
        print("Database:", store.path)


if __name__ == "__main__":
    main()
