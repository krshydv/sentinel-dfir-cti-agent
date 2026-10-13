import argparse
import json

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

from dfir_cti.config import load_config, resolve_path
from dfir_cti.detection.autoencoder import AutoencoderDetector
from dfir_cti.detection.fusion import ScoreFusion
from dfir_cti.detection.isolation_forest import IsolationForestDetector
from dfir_cti.detection.rules import run_rules
from dfir_cti.detection.xgb_classifier import XGBAttackClassifier
from dfir_cti.evaluation import best_threshold_metrics, binary_metrics
from dfir_cti.ingestion.loader import load_raw
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.preprocessing.features import flow_features


def rule_flags(df, cfg):
    alerts = run_rules(df, cfg)
    flags = np.zeros(len(df), dtype=int)
    if alerts.empty:
        return flags
    secs = cfg["rules"]["window_seconds"]
    keys = set(zip(alerts["src_ip"], alerts["window"]))
    windows = df["ts"].dt.floor(f"{secs}s")
    flags[[(s, w) in keys for s, w in zip(df["src_ip"], windows)]] = 1
    return flags


def run(cfg, max_rows=None, strategy=None):
    m = cfg["models"]
    df = clean(load_raw(cfg, max_rows=max_rows), cfg)
    if "label_binary" not in df.columns:
        raise ValueError("No binary label column found; update dataset.label_binary_candidates in config.")
    X = flow_features(df, cfg)
    names = list(X.columns)
    Xv = X.values.astype(np.float32)
    y = df["label_binary"].values
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=m["test_size"], random_state=m["random_state"], stratify=y)
    Xtr, ytr, Xte, yte = Xv[tr], y[tr], Xv[te], y[te]

    iforest = IsolationForestDetector(**m["isolation_forest"], random_state=m["random_state"]).fit(Xtr)
    xgb = XGBAttackClassifier(**m["xgboost"], random_state=m["random_state"]).fit(Xtr, ytr)
    ae = AutoencoderDetector(
        hidden_dims=m["autoencoder"]["hidden_dims"],
        epochs=m["autoencoder"]["epochs"],
        batch_size=m["autoencoder"]["batch_size"],
        learning_rate=m["autoencoder"]["learning_rate"],
        random_state=m["random_state"],
    ).fit(Xtr[ytr == 0])

    train_scores = {
        "isolation_forest": iforest.score(Xtr),
        "xgboost": xgb.score(Xtr),
        "autoencoder": ae.score(Xtr),
    }
    test_scores = {
        "isolation_forest": iforest.score(Xte),
        "xgboost": xgb.score(Xte),
        "autoencoder": ae.score(Xte),
    }

    fcfg = cfg["fusion"]
    fusion = ScoreFusion(strategy=strategy or fcfg["strategy"], weights=fcfg["weights"], threshold=fcfg["threshold"])
    fusion.fit(train_scores, ytr)
    fusion.tune_threshold(train_scores, ytr)

    results = {"n_rows": int(len(df)), "n_test": int(len(te)), "attack_rate": float(y.mean())}
    for name, s in test_scores.items():
        results[name] = best_threshold_metrics(yte, s)
    fused_test = fusion.fuse(test_scores)
    results["fused"] = {**binary_metrics(yte, (fused_test >= fusion.threshold).astype(int)), "threshold": fusion.threshold}

    flags = rule_flags(df.iloc[te].reset_index(drop=True), cfg)
    results["rules_only"] = binary_metrics(yte, flags)
    results["rules_plus_fused"] = binary_metrics(
        yte, np.maximum(flags, (fused_test >= fusion.threshold).astype(int))
    )
    results["top_features"] = dict(list(xgb.feature_importance(names).items())[:10])
    results["top_features"] = {k: float(v) for k, v in results["top_features"].items()}

    models_dir = resolve_path(cfg, "models")
    reports_dir = resolve_path(cfg, "reports")
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"iforest": iforest, "xgb": xgb, "fusion": fusion, "features": names}, models_dir / "classical.joblib")
    ae_state = {"scaler": ae.scaler, "state": ae.net.state_dict(), "lo": ae._lo, "hi": ae._hi, "dims": ae.hidden_dims, "in": len(names)}
    joblib.dump(ae_state, models_dir / "autoencoder.joblib")
    with open(reports_dir / "baseline_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return results


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=None)
    p.add_argument("--max-rows", type=int, default=None)
    p.add_argument("--strategy", choices=["weighted", "meta"], default=None)
    a = p.parse_args()
    cfg = load_config(a.config)
    print(json.dumps(run(cfg, a.max_rows, a.strategy), indent=2))


if __name__ == "__main__":
    main()
