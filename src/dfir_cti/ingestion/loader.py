from pathlib import Path

import pandas as pd

from dfir_cti.config import resolve_path


def _read_one(path):
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        return pd.read_parquet(path)
    if suffix == ".json":
        return pd.read_json(path, lines=True)
    return pd.read_csv(path, low_memory=False)


def list_data_files(directory, patterns=("*.csv", "*.parquet", "*.json")):
    directory = Path(directory)
    files = []
    for pattern in patterns:
        files.extend(sorted(directory.rglob(pattern)))
    return files


def load_raw(cfg, directory=None, max_rows=None):
    directory = Path(directory) if directory else resolve_path(cfg, "raw")
    files = list_data_files(directory)
    if not files:
        raise FileNotFoundError(
            f"No csv/parquet/json files found in {directory}. "
            "Run scripts/download_dataset.py or scripts/make_synthetic.py first."
        )
    limit = max_rows if max_rows is not None else cfg["dataset"].get("max_rows")
    frames = []
    total = 0
    for f in files:
        df = _read_one(f)
        df["source_file"] = f.name
        frames.append(df)
        total += len(df)
        if limit and total >= limit:
            break
    out = pd.concat(frames, ignore_index=True)
    if limit:
        out = out.iloc[:limit]
    return out
