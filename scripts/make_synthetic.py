import argparse
from pathlib import Path

import numpy as np
import pandas as pd


def generate(n, attack_rate, seed):
    rng = np.random.default_rng(seed)
    n_att = int(n * attack_rate)
    n_norm = n - n_att
    base = 1_760_000_000

    norm = pd.DataFrame(
        {
            "ts": base + np.sort(rng.uniform(0, 86400, n_norm)),
            "src_ip": [f"10.0.0.{i}" for i in rng.integers(2, 60, n_norm)],
            "dst_ip": [f"10.0.1.{i}" for i in rng.integers(2, 30, n_norm)],
            "src_port": rng.integers(1024, 65535, n_norm),
            "dst_port": rng.choice([80, 443, 53, 22, 25, 8080], n_norm, p=[0.3, 0.4, 0.2, 0.04, 0.03, 0.03]),
            "proto": rng.choice(["tcp", "udp"], n_norm, p=[0.8, 0.2]),
            "service": rng.choice(["http", "ssl", "dns", "ssh", "smtp"], n_norm, p=[0.3, 0.4, 0.2, 0.05, 0.05]),
            "conn_state": rng.choice(["SF", "S0", "REJ"], n_norm, p=[0.92, 0.05, 0.03]),
            "duration": rng.exponential(1.5, n_norm),
            "orig_bytes": rng.lognormal(6, 1.2, n_norm).astype(int),
            "resp_bytes": rng.lognormal(7, 1.4, n_norm).astype(int),
            "missed_bytes": 0,
            "orig_pkts": rng.integers(1, 40, n_norm),
            "orig_ip_bytes": rng.lognormal(6.5, 1.2, n_norm).astype(int),
            "resp_pkts": rng.integers(1, 60, n_norm),
            "resp_ip_bytes": rng.lognormal(7.5, 1.4, n_norm).astype(int),
            "label_binary": False,
            "label_tactic": "none",
            "label_technique": "none",
        }
    )

    n_bursts = max(n_att // 60, 1)
    burst_starts = rng.uniform(0, 86000, n_bursts)
    burst_kind = rng.choice(["recon", "credential_access", "exfiltration"], n_bursts, p=[0.45, 0.35, 0.2])
    burst_src = np.array([f"192.168.5.{i}" for i in rng.integers(2, 6, n_bursts)])
    burst_dst = np.array([f"10.0.1.{i}" for i in rng.integers(2, 6, n_bursts)])
    burst_idx = rng.integers(0, n_bursts, n_att)
    raw_times = burst_starts[burst_idx] + rng.uniform(0, 40, n_att)
    order = np.argsort(raw_times)
    burst_idx = burst_idx[order]
    burst_times = raw_times[order]
    kinds = burst_kind[burst_idx]
    att_src = list(burst_src[burst_idx])
    att_dst = list(burst_dst[burst_idx])
    att = pd.DataFrame(
        {
            "ts": base + burst_times,
            "src_ip": att_src,
            "dst_ip": att_dst,
            "src_port": rng.integers(1024, 65535, n_att),
            "dst_port": np.where(
                kinds == "recon",
                rng.integers(1, 10000, n_att),
                np.where(kinds == "credential_access", 22, 443),
            ),
            "proto": "tcp",
            "service": np.where(kinds == "credential_access", "ssh", np.where(kinds == "exfiltration", "ssl", "-")),
            "conn_state": np.where(kinds == "recon", rng.choice(["S0", "REJ"], n_att), "SF"),
            "duration": np.where(kinds == "exfiltration", rng.exponential(30, n_att), rng.exponential(0.2, n_att)),
            "orig_bytes": np.where(kinds == "exfiltration", rng.lognormal(12, 1, n_att), rng.lognormal(4, 0.8, n_att)).astype(int),
            "resp_bytes": rng.lognormal(4, 1, n_att).astype(int),
            "missed_bytes": 0,
            "orig_pkts": rng.integers(1, 12, n_att),
            "orig_ip_bytes": rng.lognormal(5, 1, n_att).astype(int),
            "resp_pkts": rng.integers(0, 8, n_att),
            "resp_ip_bytes": rng.lognormal(4, 1, n_att).astype(int),
            "label_binary": True,
            "label_tactic": np.where(
                kinds == "recon", "Reconnaissance", np.where(kinds == "credential_access", "Credential Access", "Exfiltration")
            ),
            "label_technique": np.where(
                kinds == "recon", "T1595", np.where(kinds == "credential_access", "T1110", "T1041")
            ),
        }
    )
    out = pd.concat([norm, att], ignore_index=True).sort_values("ts").reset_index(drop=True)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rows", type=int, default=50000)
    p.add_argument("--attack-rate", type=float, default=0.08)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default="data/raw/synthetic_zeek_like.csv")
    a = p.parse_args()
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    generate(a.rows, a.attack_rate, a.seed).to_csv(a.out, index=False)
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
