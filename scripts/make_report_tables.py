import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.config import load_config, resolve_path

NAMES = {
    "isolation_forest": "Isolation Forest",
    "xgboost": "XGBoost",
    "autoencoder": "Autoencoder",
    "fused": "Fused score",
    "rules_only": "Rules only",
    "rules_plus_fused": "Rules + fused",
}


def table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--out", default="docs/RESULTS.md")
    args = parser.parse_args()

    cfg = load_config(args.config)
    reports = resolve_path(cfg, "reports")
    metrics_path = reports / "baseline_metrics.json"
    if not metrics_path.exists():
        sys.exit(f"{metrics_path} not found. Run python -m dfir_cti.pipeline first.")
    metrics = json.loads(metrics_path.read_text())

    out = ["# Results", "", f"Flows: {metrics['n_rows']:,} total, {metrics['n_test']:,} in the test split, attack rate {metrics['attack_rate']:.3f}.", ""]

    out += ["## Detection", ""]
    rows = []
    for key, name in NAMES.items():
        m = metrics[key]
        rows.append([name, f"{m['precision']:.4f}", f"{m['recall']:.4f}", f"{m['f1']:.4f}", f"{m['fpr']:.4f}", m["tp"], m["fp"], m["tn"], m["fn"]])
    out.append(table(["Method", "Precision", "Recall", "F1", "FPR", "TP", "FP", "TN", "FN"], rows))

    out += ["", "## Top features", ""]
    out.append(table(["Feature", "Importance"], [[k, f"{v:.3f}"] for k, v in metrics["top_features"].items()]))

    incidents_path = reports / "incidents.csv"
    if incidents_path.exists():
        inc = pd.read_csv(incidents_path)
        out += ["", "## Incidents and ATT&CK mapping", "", f"Incidents: {len(inc)}", ""]
        counts = inc.groupby(["technique_id", "technique"], dropna=False).size().reset_index(name="incidents")
        out.append(table(["Technique", "Name", "Incidents"], counts.values.tolist()))
        known = inc[inc["true_tactic"].astype(str).str.lower().ne("none")]
        if len(known):
            match = (known["tactic_pred"].astype(str) == known["true_tactic"].astype(str)).mean()
            out += ["", f"Tactic accuracy on attack incidents: {match:.3f} ({len(known)} incidents). Mapping rules were tuned on this dataset, so this is not an independent test."]

    summary_path = reports / "agent" / "agent_summary.json"
    if summary_path.exists():
        summary = json.loads(summary_path.read_text())
        levels = pd.Series([s["severity"]["level"] for s in summary]).value_counts()
        order = [lvl for lvl in ["critical", "high", "medium", "low"] if lvl in levels.index]
        out += ["", "## Agent investigation", "", table(["Severity", "Incidents"], [[lvl, int(levels[lvl])] for lvl in order])]

    figures = reports / "figures"
    if figures.exists():
        out += ["", "## Figures", ""]
        out += [f"- `reports/figures/{p.name}`" for p in sorted(figures.glob("*.png"))]

    out += [
        "",
        "## Limits",
        "",
        "- Attack and benign flows in the dataset subset come from different time periods, which makes them easier to separate than live traffic",
        "- Exfiltration has very few flows, so its metrics are not reliable",
        "- Mapping rules and rule thresholds were tuned on this dataset",
        "- Threat intelligence uses a local blocklist only; mitigation actions are simulated inside the lab",
        "",
    ]

    path = Path(args.out)
    if not path.is_absolute():
        path = Path(cfg["_root"]) / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(out), encoding="utf-8")
    print("Wrote", path)


if __name__ == "__main__":
    main()
