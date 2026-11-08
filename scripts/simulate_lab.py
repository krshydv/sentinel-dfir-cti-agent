import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.simulation import SCENARIOS, simulate_lab, write_conn_log


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default="data/lab")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--benign", type=int, default=6000)
    parser.add_argument("--duration", type=int, default=7200)
    parser.add_argument("--scenarios", nargs="*", default=list(SCENARIOS), choices=list(SCENARIOS))
    args = parser.parse_args()

    frame = simulate_lab(args.seed, args.duration, args.benign, args.scenarios)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    log = write_conn_log(frame, out / "conn.log")
    frame[["uid", "label_binary", "label_tactic", "label_technique"]].to_csv(out / "ground_truth.csv", index=False)
    print("Flows:", len(frame), " Attack flows:", int(frame["label_binary"].sum()))
    print(frame.loc[frame["label_binary"] == 1].groupby("label_tactic").size().to_string())
    print("Wrote", log, "and", out / "ground_truth.csv")


if __name__ == "__main__":
    main()
