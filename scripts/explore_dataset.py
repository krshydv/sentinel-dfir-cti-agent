import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.config import load_config
from dfir_cti.ingestion.loader import load_raw
from dfir_cti.preprocessing.cleaning import clean


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--max-rows", type=int, default=200000)
    p.add_argument("--config", default=None)
    a = p.parse_args()
    cfg = load_config(a.config)
    raw = load_raw(cfg, max_rows=a.max_rows)
    print("raw shape:", raw.shape)
    print("columns:", list(raw.columns))
    df = clean(raw, cfg)
    print("clean shape:", df.shape)
    print(df.dtypes.to_string())
    print("missing values:")
    print(df.isna().sum()[df.isna().sum() > 0].to_string())
    for col in ["label_binary", "label_tactic", "label_technique", "proto", "service", "conn_state"]:
        if col in df.columns:
            print(f"\n{col}:")
            print(df[col].value_counts(dropna=False).head(15).to_string())
    if "ts" in df.columns:
        print("\ntime range:", df["ts"].min(), "->", df["ts"].max())


if __name__ == "__main__":
    main()
