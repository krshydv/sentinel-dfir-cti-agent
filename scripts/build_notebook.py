from pathlib import Path

import nbformat as nbf

REPO_URL = "https://github.com/krshydv/sentinel-dfir-cti-agent.git"
REPO_DIR = "sentinel-dfir-cti-agent"

cells = []


def md(text):
    cells.append(nbf.v4.new_markdown_cell(text.strip()))


def code(text):
    cells.append(nbf.v4.new_code_cell(text.strip()))


md(
    """
# Agentic AI-Driven Hybrid Digital Forensics & Cyber Threat Intelligence Framework

Detection results notebook: hybrid detection (Isolation Forest, XGBoost, deep autoencoder) with score fusion and a rule engine, evaluated with confusion matrices, ROC and precision-recall curves, and a model comparison.

Run the cells from top to bottom. In Google Colab, run the setup cell first.
"""
)

md("## 1. Setup")

code(
    f"""
import os
import sys

IN_COLAB = "google.colab" in sys.modules

if IN_COLAB:
    if not os.path.isdir("{REPO_DIR}"):
        !git clone {REPO_URL}
    %cd {REPO_DIR}
    !pip install -q -e .
elif os.path.basename(os.getcwd()) == "notebooks":
    os.chdir("..")

sys.path.insert(0, os.path.abspath("src"))

os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
os.environ["OMP_NUM_THREADS"] = "1"
print(os.getcwd())
"""
)

md(
    """
## 2. Dataset

Put the UWF-ZeekData24 files in `data/raw/` (in Colab, use the file panel on the left to upload them there). If the folder is empty, the cell below generates a small sample Zeek-style dataset so the notebook still runs. Sample data is easy to separate, so its scores will look unrealistically high.
"""
)

code(
    """
from pathlib import Path

raw_dir = Path("data/raw")
raw_dir.mkdir(parents=True, exist_ok=True)
data_files = [p for p in raw_dir.rglob("*") if p.suffix in {".csv", ".parquet", ".json"}]

if data_files:
    print("Using dataset files:", [p.name for p in data_files])
    USING_SAMPLE_DATA = all(p.name.startswith("synthetic") for p in data_files)
else:
    !python scripts/make_synthetic.py --rows 30000
    USING_SAMPLE_DATA = True

print("Sample data in use:", USING_SAMPLE_DATA)
"""
)

code(
    """
from dfir_cti.config import load_config
from dfir_cti.ingestion.loader import load_raw
from dfir_cti.preprocessing.cleaning import clean

cfg = load_config()
df = clean(load_raw(cfg), cfg)

print("Rows:", len(df), " Columns:", df.shape[1])
df.head()
"""
)

code(
    """
import matplotlib.pyplot as plt

fig, axes = plt.subplots(1, 2, figsize=(11, 4))

counts = df["label_binary"].map({0: "Normal", 1: "Attack"}).value_counts()
axes[0].bar(counts.index, counts.values, color=["#4c72b0", "#c44e52"])
axes[0].set_title("Traffic class balance")
axes[0].set_ylabel("Flows")

if "label_tactic" in df.columns:
    tactics = df.loc[df["label_binary"] == 1, "label_tactic"].value_counts()
    axes[1].barh(tactics.index[::-1], tactics.values[::-1], color="#dd8452")
    axes[1].set_title("Attack flows by MITRE ATT&CK tactic")
    axes[1].set_xlabel("Flows")

plt.tight_layout()
plt.show()
"""
)

md(
    """
## 3. Train and evaluate

Features are built from the flows, the data is split into train and test sets, and the three models are trained: Isolation Forest (unsupervised baseline), XGBoost (known attacks) and an autoencoder trained on normal traffic only (unknown behaviour). Their scores are fused and combined with the rule engine.
"""
)

code(
    """
from dfir_cti.pipeline import run_detailed

results, artifacts = run_detailed(cfg)
y_test = artifacts["y_test"]
print("Test flows:", results["n_test"], " Attack rate:", round(results["attack_rate"], 3))
"""
)

md("## 4. Metrics")

code(
    """
import pandas as pd

names = {
    "isolation_forest": "Isolation Forest",
    "xgboost": "XGBoost",
    "autoencoder": "Autoencoder",
    "fused": "Fused score",
    "rules_only": "Rules only",
    "rules_plus_fused": "Rules + fused",
}

table = pd.DataFrame(
    {
        names[k]: {m: results[k][m] for m in ["precision", "recall", "f1", "fpr"]}
        for k in names
    }
).T
table.columns = ["Precision", "Recall", "F1", "False positive rate"]
table.round(4)
"""
)

code(
    """
from dfir_cti.visualization import plot_metric_comparison

plot_metric_comparison(results)
plt.show()
"""
)

md("## 5. Confusion matrices")

code(
    """
from dfir_cti.visualization import plot_confusion_matrices

plot_confusion_matrices(y_test, artifacts["predictions"])
plt.show()
"""
)

md("## 6. ROC and precision-recall curves")

code(
    """
from dfir_cti.visualization import plot_pr_curves, plot_roc_curves

plot_roc_curves(y_test, artifacts["scores"])
plt.show()

plot_pr_curves(y_test, artifacts["scores"])
plt.show()
"""
)

md("## 7. Score distributions")

code(
    """
from dfir_cti.visualization import plot_score_distributions

plot_score_distributions(y_test, artifacts["scores"])
plt.show()
"""
)

md("## 8. Feature importance")

code(
    """
from dfir_cti.visualization import plot_feature_importance

plot_feature_importance(artifacts["importance"])
plt.show()
"""
)

md(
    """
## 9. Incident correlation and ATT&CK mapping

Flows flagged by the rules and the fused score are grouped into incidents per source host. Each incident gets a forensic timeline, extracted indicators of compromise (IOCs) and a MITRE ATT&CK technique, and the mapping is checked against the dataset's own tactic labels.
"""
)

code(
    """
from dfir_cti.investigation import investigate
from dfir_cti.threat_intel.attack_mapping import mapping_accuracy

frame = artifacts["test_frame"]
flagged = artifacts["predictions"]["rules_plus_fused"]

incidents, assignment, reports = investigate(frame, flagged, artifacts["scores"]["fused"], cfg)

accuracy = mapping_accuracy(incidents)
print("Incidents:", accuracy["incidents"])
print("Attack incidents:", accuracy["attack_incidents"], " False-alarm incidents:", accuracy["false_alarm_incidents"])
print("Tactic accuracy:", accuracy["tactic_accuracy"])

incidents[["incident_id", "src_ip", "flows", "unique_dsts", "unique_ports", "technique_id", "tactic_pred", "true_tactic"]].head(15)
"""
)

code(
    """
from dfir_cti.visualization import plot_attack_mapping, plot_incident_overview

plot_incident_overview(incidents)
plt.show()

if not accuracy["confusion"].empty:
    plot_attack_mapping(accuracy["confusion"])
    plt.show()
"""
)

code(
    """
import json

example = reports[0]
print(example["incident_id"], example["src_ip"], example["technique_id"], example["technique"])
print("Evidence:", example["evidence"])
print("Timeline:", {k: str(v) for k, v in example["timeline"].items()})

pd.DataFrame(example["iocs"])[["type", "value", "role", "scope", "flows", "context"]]
"""
)

md(
    """
## 10. Agentic investigation

A single agent works through each incident: it chooses its next tool from what it has already found (summary, timeline, IOCs, blocklist check, ATT&CK context, severity), then writes the report and proposes mitigation. Actions are limited to a pre-approved list, only inside the isolated lab, and only with human confirmation.
"""
)

code(
    """
from IPython.display import Markdown, display

from dfir_cti.agent.agent import InvestigationAgent

agent = InvestigationAgent(cfg)
results = [agent.investigate(r) for r in reports]

rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
results.sort(key=lambda r: (rank[r["severity"]["level"]], r["severity"]["points"]), reverse=True)

pd.DataFrame(
    [
        {"incident": r["incident_id"], "severity": r["severity"]["level"], "technique": r["technique_id"]}
        for r in results
    ]
).head(10)
"""
)

code(
    """
display(Markdown(results[0]["report"]))
"""
)

code(
    """
action = next(p for p in results[0]["proposals"] if p["kind"] == "action")
print("Proposed:", action["action"], "on", action["target"], "-", action["status"])

try:
    record = agent.execute(action, human_confirmed=True)
    print("Executed (simulated):", record["action"], "on", record["target"])
except Exception as exc:
    print("Guardrail:", exc)
"""
)

md("## 11. Save figures")

code(
    """
from dfir_cti.visualization import save_all

saved = save_all(results, artifacts, "reports/figures")
print("Saved to reports/figures:", saved)

if USING_SAMPLE_DATA:
    print("These results come from sample data. Re-run on UWF-ZeekData24 for reportable numbers.")
"""
)

nb = nbf.v4.new_notebook()
nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python"},
    "colab": {"provenance": []},
}

out = Path(__file__).resolve().parents[1] / "notebooks" / "dfir_cti_results.ipynb"
out.parent.mkdir(parents=True, exist_ok=True)
nbf.write(nb, out)
print(out)
