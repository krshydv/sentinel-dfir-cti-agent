import argparse
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.config import load_config, resolve_path
from dfir_cti.pipeline import run_detailed
from dfir_cti.visualization import save_all


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--strategy", choices=["weighted", "meta"], default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    results, artifacts = run_detailed(cfg, args.max_rows, args.strategy)

    out_dir = resolve_path(cfg, "reports") / "figures"
    for name in save_all(results, artifacts, out_dir):
        print(out_dir / name)


if __name__ == "__main__":
    main()
