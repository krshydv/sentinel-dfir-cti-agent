from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter
from sklearn.metrics import (
    auc,
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    roc_curve,
)

LABELS = {
    "isolation_forest": "Isolation Forest",
    "xgboost": "XGBoost",
    "autoencoder": "Autoencoder",
    "fused": "Fused score",
    "rules_only": "Rules only",
    "rules_plus_fused": "Rules + fused",
}

COLORS = {
    "isolation_forest": "#1f77b4",
    "xgboost": "#2ca02c",
    "autoencoder": "#ff7f0e",
    "fused": "#d62728",
}

SCORE_MODELS = ["isolation_forest", "xgboost", "autoencoder", "fused"]
METRIC_NAMES = ["precision", "recall", "f1", "fpr"]


def _finish(fig, path):
    fig.tight_layout()
    if path is not None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fig.savefig(path, dpi=150, bbox_inches="tight")
    return fig


def plot_confusion_matrices(y_true, predictions, path=None):
    names = [n for n in LABELS if n in predictions]
    cols = 3
    rows = int(np.ceil(len(names) / cols))
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4.4 * rows))
    axes = np.atleast_1d(axes).ravel()

    for ax, name in zip(axes, names):
        cm = confusion_matrix(y_true, predictions[name], labels=[0, 1])
        row_share = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
        ax.imshow(row_share, cmap="Blues", vmin=0, vmax=1)
        ax.set_title(LABELS[name])
        ax.set_xticks([0, 1], ["Normal", "Attack"])
        ax.set_yticks([0, 1], ["Normal", "Attack"])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        for i in range(2):
            for j in range(2):
                colour = "white" if row_share[i, j] > 0.5 else "black"
                ax.text(
                    j,
                    i,
                    f"{cm[i, j]:,}\n({row_share[i, j]:.1%})",
                    ha="center",
                    va="center",
                    color=colour,
                    fontsize=12,
                )

    for ax in axes[len(names):]:
        ax.axis("off")

    fig.suptitle("Confusion matrices on the test set", fontsize=15)
    return _finish(fig, path)


def plot_roc_curves(y_true, scores, path=None):
    fig, ax = plt.subplots(figsize=(6.5, 5.5))

    for name in SCORE_MODELS:
        fpr, tpr, _ = roc_curve(y_true, scores[name])
        ax.plot(fpr, tpr, color=COLORS[name], lw=2, label=f"{LABELS[name]} (AUC {auc(fpr, tpr):.3f})")

    ax.plot([0, 1], [0, 1], "k--", lw=1)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curves")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.3)
    return _finish(fig, path)


def plot_pr_curves(y_true, scores, path=None):
    fig, ax = plt.subplots(figsize=(6.5, 5.5))

    for name in SCORE_MODELS:
        precision, recall, _ = precision_recall_curve(y_true, scores[name])
        ap = average_precision_score(y_true, scores[name])
        ax.plot(recall, precision, color=COLORS[name], lw=2, label=f"{LABELS[name]} (AP {ap:.3f})")

    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-recall curves")
    ax.legend(loc="lower left")
    ax.grid(alpha=0.3)
    return _finish(fig, path)


def plot_metric_comparison(results, path=None):
    names = [n for n in LABELS if n in results]
    x = np.arange(len(names))
    width = 0.2
    fig, ax = plt.subplots(figsize=(11, 5))

    for k, metric in enumerate(METRIC_NAMES):
        values = [results[n][metric] for n in names]
        bars = ax.bar(x + (k - 1.5) * width, values, width, label=metric.upper() if metric == "fpr" else metric.capitalize())
        for bar, v in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, v + 0.01, f"{v:.2f}", ha="center", fontsize=8)

    ax.set_xticks(x, [LABELS[n] for n in names], rotation=15)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score")
    ax.set_title("Model comparison")
    ax.legend(ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.18), frameon=False)
    ax.grid(axis="y", alpha=0.3)
    return _finish(fig, path)


def plot_score_distributions(y_true, scores, path=None):
    y_true = np.asarray(y_true)
    fig, axes = plt.subplots(2, 2, figsize=(11, 7))

    for ax, name in zip(axes.ravel(), SCORE_MODELS):
        s = np.asarray(scores[name])
        bins = np.linspace(0, 1, 41)
        ax.hist(s[y_true == 0], bins=bins, alpha=0.65, color="#4c72b0", label="Normal")
        ax.hist(s[y_true == 1], bins=bins, alpha=0.65, color="#c44e52", label="Attack")
        ax.set_yscale("log")
        ax.set_title(LABELS[name])
        ax.set_xlabel("Anomaly / attack score")
        ax.set_ylabel("Flows (log scale)")
        ax.legend()

    fig.suptitle("Score distributions: normal vs attack traffic", fontsize=14)
    return _finish(fig, path)


def plot_feature_importance(importance, top_n=10, path=None):
    items = list(importance.items())[:top_n][::-1]
    names = [k for k, _ in items]
    values = [v for _, v in items]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(names, values, color="#2ca02c")
    ax.set_xlabel("XGBoost importance")
    ax.set_title(f"Top {len(items)} features")
    ax.grid(axis="x", alpha=0.3)
    return _finish(fig, path)


TACTIC_COLORS = {
    "Reconnaissance": "#1f77b4",
    "Credential Access": "#d62728",
    "Exfiltration": "#ff7f0e",
    "Unmapped": "#7f7f7f",
}


def plot_incident_overview(incidents, top_n=15, path=None):
    ranked = incidents.sort_values("flows", ascending=False).head(top_n).iloc[::-1]
    labels = [f"{row.incident_id}  {row.src_ip}" for row in ranked.itertuples()]
    colors = [TACTIC_COLORS.get(t, "#7f7f7f") for t in ranked["tactic_pred"]]

    fig, ax = plt.subplots(figsize=(9, 0.45 * len(ranked) + 2))
    ax.barh(labels, ranked["flows"], color=colors)
    ax.set_xscale("log")
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax.xaxis.set_minor_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}" if v in (2, 5, 20, 50, 200, 500, 2000, 5000) else ""))
    ax.set_xlabel("Flagged flows (log scale)")
    ax.set_title("Correlated incidents by predicted ATT&CK tactic")

    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in TACTIC_COLORS.values()]
    ax.legend(handles, TACTIC_COLORS.keys(), loc="lower right", frameon=False)
    ax.grid(axis="x", alpha=0.3)
    return _finish(fig, path)


def plot_attack_mapping(confusion, path=None):
    rows = list(confusion.index)
    cols = sorted(set(confusion.columns) | set(rows))
    table = confusion.reindex(index=rows, columns=cols, fill_value=0)
    share = table.values / np.maximum(table.values.sum(axis=1, keepdims=True), 1)

    fig, ax = plt.subplots(figsize=(1.6 * len(cols) + 3, 1.2 * len(rows) + 2.5))
    ax.imshow(share, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(cols)), cols, rotation=20)
    ax.set_yticks(range(len(rows)), rows)
    ax.set_xlabel("Predicted tactic")
    ax.set_ylabel("Actual tactic (dataset label)")
    ax.set_title("ATT&CK tactic mapping of incidents")
    for i in range(len(rows)):
        for j in range(len(cols)):
            colour = "white" if share[i, j] > 0.5 else "black"
            ax.text(j, i, f"{table.values[i, j]:,}", ha="center", va="center", color=colour, fontsize=13)
    return _finish(fig, path)


def save_all(results, artifacts, out_dir):
    out_dir = Path(out_dir)
    y = artifacts["y_test"]

    figures = {
        "confusion_matrices.png": plot_confusion_matrices(y, artifacts["predictions"]),
        "roc_curves.png": plot_roc_curves(y, artifacts["scores"]),
        "pr_curves.png": plot_pr_curves(y, artifacts["scores"]),
        "model_comparison.png": plot_metric_comparison(results),
        "score_distributions.png": plot_score_distributions(y, artifacts["scores"]),
        "feature_importance.png": plot_feature_importance(artifacts["importance"]),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    for filename, fig in figures.items():
        fig.savefig(out_dir / filename, dpi=150, bbox_inches="tight")
        plt.close(fig)

    return sorted(figures)
