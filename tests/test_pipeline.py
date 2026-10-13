import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from make_synthetic import generate

from dfir_cti.config import load_config
from dfir_cti.detection.fusion import ScoreFusion
from dfir_cti.detection.rules import run_rules
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.preprocessing.features import flow_features


def _df():
    cfg = load_config()
    return cfg, clean(generate(4000, 0.1, 1), cfg)


def test_clean_labels_and_time():
    cfg, df = _df()
    assert set(df["label_binary"].unique()) <= {0, 1}
    assert str(df["ts"].dtype).startswith("datetime64")


def test_features_numeric_no_nan():
    cfg, df = _df()
    X = flow_features(df, cfg)
    assert len(X) == len(df)
    assert not np.isnan(X.values.astype(float)).any()


def test_rules_detect_recon():
    cfg, df = _df()
    alerts = run_rules(df, cfg)
    assert len(alerts) > 0


def test_fusion_weighted_range():
    s = {k: np.array([0.0, 0.5, 1.0]) for k in ["isolation_forest", "xgboost", "autoencoder"]}
    fused = ScoreFusion().fuse(s)
    assert fused.min() >= 0 and fused.max() <= 1
