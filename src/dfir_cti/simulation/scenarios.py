from pathlib import Path

import numpy as np
import pandas as pd

LAB_PREFIX = "192.168.56"
ATTACKER = f"{LAB_PREFIX}.101"
VICTIMS = [f"{LAB_PREFIX}.{i}" for i in range(10, 15)]
CLIENTS = [f"{LAB_PREFIX}.{i}" for i in range(20, 41)]
EXTERNAL_SINK = "203.0.113.50"
BASE_TS = 1_762_000_000

SCENARIOS = {
    "port_scan": ("Reconnaissance", "T1595"),
    "ssh_bruteforce": ("Credential Access", "T1110"),
    "exfiltration": ("Exfiltration", "T1048"),
}

COLUMNS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "orig_pkts", "orig_ip_bytes",
    "resp_pkts", "resp_ip_bytes", "label_binary", "label_tactic", "label_technique",
]


def _flows(rng, n, start, spread, src, dst, dst_port, proto, service, conn_state, duration, orig, resp, label):
    ts = start + np.sort(rng.uniform(0, spread, n))
    orig = np.asarray(orig).astype(np.int64)
    resp = np.asarray(resp).astype(np.int64)
    frame = pd.DataFrame(
        {
            "ts": ts,
            "src_ip": src,
            "src_port": rng.integers(1024, 65535, n),
            "dst_ip": dst,
            "dst_port": dst_port,
            "proto": proto,
            "service": service,
            "duration": duration,
            "orig_bytes": orig,
            "resp_bytes": resp,
            "conn_state": conn_state,
            "missed_bytes": 0,
            "orig_pkts": np.maximum(orig // 600, 1),
            "orig_ip_bytes": orig + 40,
            "resp_pkts": np.maximum(resp // 600, 1),
            "resp_ip_bytes": resp + 40,
        }
    )
    tactic, technique = SCENARIOS[label] if label else ("none", "none")
    frame["label_binary"] = int(bool(label))
    frame["label_tactic"] = tactic
    frame["label_technique"] = technique
    return frame


def _benign(rng, n, duration_s):
    clients = rng.choice(CLIENTS, n)
    home = {c: rng.choice(VICTIMS, 2, replace=False) for c in CLIENTS}
    servers = np.array([home[c][rng.integers(0, 2)] for c in clients])
    return _flows(
        rng,
        n,
        BASE_TS,
        duration_s,
        clients,
        servers,
        rng.choice([80, 443, 53], n, p=[0.3, 0.5, 0.2]),
        "tcp",
        "ssl",
        rng.choice(["SF", "S0", "REJ"], n, p=[0.93, 0.04, 0.03]),
        rng.exponential(1.5, n),
        rng.lognormal(6, 1.2, n),
        rng.lognormal(7, 1.4, n),
        None,
    )


def _port_scan(rng, start, attacker, victim, n=400):
    return _flows(
        rng, n, start, 45, attacker, victim, rng.permutation(np.arange(1, 10001))[:n], "tcp", "-",
        rng.choice(["S0", "REJ"], n, p=[0.7, 0.3]), rng.exponential(0.05, n),
        rng.integers(0, 60, n), rng.integers(0, 20, n), "port_scan",
    )


def _ssh_bruteforce(rng, start, attacker, victim, n=250):
    return _flows(
        rng, n, start, 240, attacker, victim, 22, "tcp", "ssh",
        rng.choice(["SF", "RSTO", "S1"], n, p=[0.3, 0.5, 0.2]), rng.exponential(0.8, n),
        rng.integers(200, 900, n), rng.integers(200, 700, n), "ssh_bruteforce",
    )


def _exfiltration(rng, start, attacker, victim, n=30):
    return _flows(
        rng, n, start, 50, attacker, EXTERNAL_SINK, 443, "tcp", "ssl", "SF", rng.exponential(25, n),
        rng.lognormal(15.4, 0.3, n), rng.integers(100, 900, n), "exfiltration",
    )


def simulate_lab(seed=7, duration_s=7200, benign_flows=6000, scenarios=None, attackers=None):
    rng = np.random.default_rng(seed)
    scenarios = list(scenarios or SCENARIOS)
    attackers = attackers or {
        "port_scan": f"{LAB_PREFIX}.101",
        "ssh_bruteforce": f"{LAB_PREFIX}.102",
        "exfiltration": f"{LAB_PREFIX}.103",
    }
    builders = {"port_scan": _port_scan, "ssh_bruteforce": _ssh_bruteforce, "exfiltration": _exfiltration}

    parts = [_benign(rng, benign_flows, duration_s)]
    for name in scenarios:
        start = BASE_TS + rng.uniform(0.1, 0.8) * duration_s
        victim = str(rng.choice(VICTIMS))
        parts.append(builders[name](rng, start, attackers[name], victim))

    frame = pd.concat(parts, ignore_index=True).sort_values("ts").reset_index(drop=True)
    frame["uid"] = [f"C{i:08d}" for i in range(len(frame))]
    return frame[COLUMNS]


def write_conn_log(frame, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "orig_pkts", "orig_ip_bytes",
        "resp_pkts", "resp_ip_bytes",
    ]
    columns = [
        "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "service", "duration",
        "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "orig_pkts", "orig_ip_bytes",
        "resp_pkts", "resp_ip_bytes",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
        f.write("#path\tconn\n")
        f.write("#fields\t" + "\t".join(fields) + "\n")
        f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tcount\tcount\tcount\tcount\tcount\n")
        out = frame[columns].copy()
        out["ts"] = out["ts"].map(lambda v: f"{v:.6f}")
        out["duration"] = out["duration"].map(lambda v: f"{v:.6f}")
        out.to_csv(f, sep="\t", header=False, index=False)
        f.write("#close\t2026-11-07-00-00-00\n")
    return path
