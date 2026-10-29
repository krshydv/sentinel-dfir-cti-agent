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

    window_secs = cfg["rules"]["window_seconds"]
    alert_keys = set(zip(alerts["src_ip"], alerts["window"]))
    windows = df["ts"].dt.floor(f"{window_secs}s")

    matched = [(ip, w) in alert_keys for ip, w in zip(df["src_ip"], windows)]
    flags[matched] = 1

    return flags


def prepare_data(cfg, max_rows):
    df = clean(load_raw(cfg, max_rows=max_rows), cfg)

    if "label_binary" not in df.columns:
        raise ValueError(
            "No binary label column found; update dataset.label_binary_candidates in config."
        )

    features = flow_features(df, cfg)
    return df, features


def split_data(df, features, model_cfg):
    X = features.values.astype(np.float32)
    y = df["label_binary"].values
    indices = np.arange(len(df))

    train_idx, test_idx = train_test_split(
        indices,
        test_size=model_cfg["test_size"],
        random_state=model_cfg["random_state"],
        stratify=y,
    )

    return X[train_idx], y[train_idx], X[test_idx], y[test_idx], test_idx


def train_models(X_train, y_train, model_cfg):
    seed = model_cfg["random_state"]
    ae_cfg = model_cfg["autoencoder"]

    iforest = IsolationForestDetector(**model_cfg["isolation_forest"], random_state=seed)
    iforest.fit(X_train)

    xgb = XGBAttackClassifier(**model_cfg["xgboost"], random_state=seed)
    xgb.fit(X_train, y_train)

    autoencoder = AutoencoderDetector(
        hidden_dims=ae_cfg["hidden_dims"],
        epochs=ae_cfg["epochs"],
        batch_size=ae_cfg["batch_size"],
        learning_rate=ae_cfg["learning_rate"],
        random_state=seed,
    )
    autoencoder.fit(X_train[y_train == 0])

    return iforest, xgb, autoencoder


def score_all(iforest, xgb, autoencoder, X):
    return {
        "isolation_forest": iforest.score(X),
        "xgboost": xgb.score(X),
        "autoencoder": autoencoder.score(X),
    }


def build_fusion(cfg, strategy, train_scores, y_train):
    fusion_cfg = cfg["fusion"]

    fusion = ScoreFusion(
        strategy=strategy or fusion_cfg["strategy"],
        weights=fusion_cfg["weights"],
        threshold=fusion_cfg["threshold"],
    )
    fusion.fit(train_scores, y_train)
    fusion.tune_threshold(train_scores, y_train)

    return fusion


def evaluate(df, y, y_test, test_idx, test_scores, fusion, xgb, feature_names, cfg):
    results = {
        "n_rows": int(len(df)),
        "n_test": int(len(test_idx)),
        "attack_rate": float(y.mean()),
    }
    predictions = {}

    for model_name, scores in test_scores.items():
        results[model_name] = best_threshold_metrics(y_test, scores)
        predictions[model_name] = (scores >= results[model_name]["threshold"]).astype(int)

    fused_scores = fusion.fuse(test_scores)
    fused_pred = (fused_scores >= fusion.threshold).astype(int)

    results["fused"] = {
        **binary_metrics(y_test, fused_pred),
        "threshold": fusion.threshold,
    }
    predictions["fused"] = fused_pred

    flags = rule_flags(df.iloc[test_idx].reset_index(drop=True), cfg)
    combined = np.maximum(flags, fused_pred)
    results["rules_only"] = binary_metrics(y_test, flags)
    results["rules_plus_fused"] = binary_metrics(y_test, combined)
    predictions["rules_only"] = flags
    predictions["rules_plus_fused"] = combined

    importance = xgb.feature_importance(feature_names)
    top_ten = list(importance.items())[:10]
    results["top_features"] = {name: float(value) for name, value in top_ten}

    scores_out = dict(test_scores)
    scores_out["fused"] = fused_scores

    artifacts = {
        "y_test": y_test,
        "scores": scores_out,
        "predictions": predictions,
        "importance": {name: float(value) for name, value in importance.items()},
    }

    return results, artifacts


def save_outputs(cfg, iforest, xgb, autoencoder, fusion, feature_names, results):
    models_dir = resolve_path(cfg, "models")
    reports_dir = resolve_path(cfg, "reports")
    models_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    classical = {
        "iforest": iforest,
        "xgb": xgb,
        "fusion": fusion,
        "features": feature_names,
    }
    joblib.dump(classical, models_dir / "classical.joblib")

    ae_state = {
        "scaler": autoencoder.scaler,
        "state": autoencoder.net.state_dict(),
        "lo": autoencoder._lo,
        "hi": autoencoder._hi,
        "dims": autoencoder.hidden_dims,
        "in": len(feature_names),
    }
    joblib.dump(ae_state, models_dir / "autoencoder.joblib")

    with open(reports_dir / "baseline_metrics.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def run_detailed(cfg, max_rows=None, strategy=None):
    model_cfg = cfg["models"]

    df, features = prepare_data(cfg, max_rows)
    feature_names = list(features.columns)

    X_train, y_train, X_test, y_test, test_idx = split_data(df, features, model_cfg)

    iforest, xgb, autoencoder = train_models(X_train, y_train, model_cfg)

    train_scores = score_all(iforest, xgb, autoencoder, X_train)
    test_scores = score_all(iforest, xgb, autoencoder, X_test)

    fusion = build_fusion(cfg, strategy, train_scores, y_train)

    results, artifacts = evaluate(
        df, df["label_binary"].values, y_test, test_idx, test_scores, fusion, xgb, feature_names, cfg
    )
    save_outputs(cfg, iforest, xgb, autoencoder, fusion, feature_names, results)

    return results, artifacts


def run(cfg, max_rows=None, strategy=None):
    results, _ = run_detailed(cfg, max_rows, strategy)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--strategy", choices=["weighted", "meta"], default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    results = run(cfg, args.max_rows, args.strategy)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
