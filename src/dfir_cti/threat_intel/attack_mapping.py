import pandas as pd

TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
}

UNMAPPED = ("", "Unmapped anomaly", "Unmapped")


def map_incident(row, cfg):
    settings = cfg["attack_mapping"]
    watched = set(cfg["rules"]["brute_force_ports"])
    rules = set(row["rules"])
    flows = max(int(row["flows"]), 1)

    top_ports = row["top_ports"]
    top_port, top_count = (int(next(iter(top_ports))), next(iter(top_ports.values()))) if top_ports else (None, 0)
    port_share = top_count / flows

    heavy_upload = row["bytes_out"] / flows >= settings["exfil_bytes_per_flow"]
    per_target = flows / max(int(row["unique_dsts"]), 1)
    port_focused = top_port in watched and port_share >= settings["brute_port_share"]
    repeated = per_target >= settings["brute_flows_per_target"] or "brute_force" in rules
    scanning = (
        row["unique_dsts"] >= settings["scan_unique_dsts"]
        or row["unique_ports"] >= settings["scan_unique_ports"]
        or bool(rules & {"host_sweep", "port_scan"})
    )

    if heavy_upload or "high_volume_outbound" in rules:
        technique = "T1048"
        evidence = [f"{row['bytes_out'] / flows:,.0f} bytes sent per flow"]
        confident = "high_volume_outbound" in rules
    elif port_focused and repeated:
        technique = "T1110"
        evidence = [f"{port_share:.0%} of flows target port {top_port}", f"{per_target:.1f} flows per target host"]
        confident = "brute_force" in rules
    elif scanning:
        technique = "T1595"
        evidence = [f"{row['unique_dsts']} target hosts", f"{row['unique_ports']} distinct ports"]
        confident = bool(rules & {"host_sweep", "port_scan"})
    elif "brute_force" in rules:
        technique = "T1110"
        evidence = ["brute_force rule fired"]
        confident = True
    else:
        return {
            "technique_id": UNMAPPED[0],
            "technique": UNMAPPED[1],
            "tactic_pred": UNMAPPED[2],
            "confidence": "low",
            "evidence": ["no rule or behaviour pattern matched"],
        }

    name, tactic = TECHNIQUES[technique]
    if rules:
        evidence.append("rules fired: " + ", ".join(sorted(rules)))

    return {
        "technique_id": technique,
        "technique": name,
        "tactic_pred": tactic,
        "confidence": "high" if confident else "medium",
        "evidence": evidence,
    }


def map_incidents(incidents, cfg):
    if incidents.empty:
        return incidents
    mapped = pd.DataFrame([map_incident(row, cfg) for row in incidents.to_dict("records")], index=incidents.index)
    return pd.concat([incidents, mapped], axis=1)


def mapping_accuracy(incidents):
    if incidents.empty or "true_tactic" not in incidents.columns:
        return {"incidents": 0}

    labelled = incidents[incidents["true_tactic"].notna()]
    attacks = labelled[labelled["true_tactic"] != "none"]
    false_alarms = labelled[labelled["true_tactic"] == "none"]

    result = {
        "incidents": int(len(incidents)),
        "attack_incidents": int(len(attacks)),
        "false_alarm_incidents": int(len(false_alarms)),
        "tactic_accuracy": None,
        "confusion": pd.DataFrame(),
    }
    if len(attacks):
        result["tactic_accuracy"] = float((attacks["true_tactic"] == attacks["tactic_pred"]).mean())
        result["confusion"] = pd.crosstab(attacks["true_tactic"], attacks["tactic_pred"])
    return result
