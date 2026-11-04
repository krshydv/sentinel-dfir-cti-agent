import pandas as pd


def run_rules(df, cfg):
    r = cfg["rules"]
    required = {"ts", "src_ip"}
    if not required.issubset(df.columns):
        return pd.DataFrame(columns=["rule", "src_ip", "window", "evidence", "severity"])
    work = df.copy()
    work["window"] = work["ts"].dt.floor(f"{r['window_seconds']}s")
    alerts = []

    if "dst_port" in work.columns:
        ports = work.groupby(["src_ip", "window"])["dst_port"].nunique().reset_index(name="unique_ports")
        for row in ports[ports["unique_ports"] >= r["port_scan_unique_ports"]].itertuples():
            alerts.append(
                {
                    "rule": "port_scan",
                    "src_ip": row.src_ip,
                    "window": row.window,
                    "evidence": f"{row.unique_ports} unique destination ports",
                    "severity": "medium",
                }
            )

    if {"dst_ip", "dst_port"}.issubset(work.columns):
        watched_ports = r.get("brute_force_ports", [21, 22, 23, 3389, 445])
        auth_ports = work[work["dst_port"].isin(watched_ports)]
        attempts = (
            auth_ports.groupby(["src_ip", "dst_ip", "dst_port", "window"]).size().reset_index(name="attempts")
        )
        for row in attempts[attempts["attempts"] >= r["brute_force_attempts"]].itertuples():
            alerts.append(
                {
                    "rule": "brute_force",
                    "src_ip": row.src_ip,
                    "window": row.window,
                    "evidence": f"{row.attempts} connections to {row.dst_ip}:{row.dst_port}",
                    "severity": "high",
                }
            )

    if "dst_ip" in work.columns:
        sweep = work.groupby(["src_ip", "window"])["dst_ip"].nunique().reset_index(name="unique_dsts")
        for row in sweep[sweep["unique_dsts"] >= r.get("host_sweep_unique_dsts", 20)].itertuples():
            alerts.append(
                {
                    "rule": "host_sweep",
                    "src_ip": row.src_ip,
                    "window": row.window,
                    "evidence": f"{row.unique_dsts} unique destination hosts",
                    "severity": "medium",
                }
            )

    if "orig_bytes" in work.columns:
        vol = work.groupby(["src_ip", "window"])["orig_bytes"].sum().reset_index(name="bytes_out")
        for row in vol[vol["bytes_out"] >= r["high_volume_bytes"]].itertuples():
            alerts.append(
                {
                    "rule": "high_volume_outbound",
                    "src_ip": row.src_ip,
                    "window": row.window,
                    "evidence": f"{int(row.bytes_out)} bytes sent",
                    "severity": "medium",
                }
            )

    return pd.DataFrame(alerts, columns=["rule", "src_ip", "window", "evidence", "severity"])
