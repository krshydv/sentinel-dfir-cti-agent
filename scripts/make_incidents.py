import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.config import load_config, resolve_path
from dfir_cti.investigation import investigate, save_reports
from dfir_cti.pipeline import run_detailed
from dfir_cti.threat_intel.attack_mapping import mapping_accuracy
from dfir_cti.visualization import plot_attack_mapping, plot_incident_overview


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--gaps", type=int, nargs="*", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    results, artifacts = run_detailed(cfg, args.max_rows)

    frame = artifacts["test_frame"]
    flagged = artifacts["predictions"]["rules_plus_fused"]

    if args.gaps:
        for gap in args.gaps:
            cfg["correlation"]["gap_seconds"] = gap
            found, _, _ = investigate(frame, flagged, artifacts["scores"]["fused"], cfg)
            summary = mapping_accuracy(found)
            print(gap, "incidents:", summary["incidents"], "accuracy:", summary["tactic_accuracy"])
            print(summary["confusion"])
        return

    incidents, assignment, reports = investigate(frame, flagged, artifacts["scores"]["fused"], cfg)

    reports_dir = resolve_path(cfg, "reports")
    save_reports(reports, reports_dir / "incidents.json")
    incidents.drop(columns=["evidence"]).to_csv(reports_dir / "incidents.csv", index=False)

    accuracy = mapping_accuracy(incidents)
    print("Incidents:", accuracy["incidents"])
    print("Attack incidents:", accuracy.get("attack_incidents"))
    print("False-alarm incidents:", accuracy.get("false_alarm_incidents"))
    print("Tactic accuracy:", accuracy.get("tactic_accuracy"))
    print(accuracy.get("confusion"))

    figures = reports_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    plot_incident_overview(incidents, path=figures / "incident_overview.png")
    if not accuracy["confusion"].empty:
        plot_attack_mapping(accuracy["confusion"], path=figures / "attack_mapping.png")

    print(incidents[["incident_id", "src_ip", "flows", "unique_dsts", "tactic_pred", "technique_id", "true_tactic"]].head(15))


if __name__ == "__main__":
    main()
