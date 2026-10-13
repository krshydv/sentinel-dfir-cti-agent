import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


def binary_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fpr),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def best_threshold_metrics(y_true, scores):
    best = None
    for t in np.linspace(0.05, 0.95, 91):
        m = binary_metrics(y_true, (scores >= t).astype(int))
        if best is None or m["f1"] > best["f1"]:
            best = {**m, "threshold": float(t)}
    return best
