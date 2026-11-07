def _bullets(items):
    return "\n".join(f"- {item}" for item in items) if items else "- none"


def build_report(incident, observations, trace, severity, proposals, summary):
    info = observations["incident_summary"]
    timeline = observations["timeline_overview"]
    iocs = observations["list_iocs"]
    attack = observations.get("attack_context")

    lines = [
        f"# Incident report {incident['incident_id']}",
        "",
        f"**Severity:** {severity['level']} ({severity['points']} points)  ",
        f"**Source:** {info['source_ip']}  ",
        f"**Window:** {timeline['first_seen']} to {timeline['last_seen']}",
        "",
        "## Summary",
        "",
        summary,
        "",
        "## ATT&CK mapping",
        "",
    ]

    if attack and attack["technique_id"]:
        lines += [
            f"- Technique: {attack['technique_id']} {attack['technique']}",
            f"- Tactic: {attack['tactic']}",
            f"- Confidence: {attack['confidence']}",
            f"- Meaning: {attack['description']}",
            "- Evidence:",
        ]
        lines += [f"  - {e}" for e in attack["evidence"]]
    else:
        lines.append("- No technique matched; manual triage needed")

    lines += [
        "",
        "## Timeline",
        "",
        f"- Flagged flows: {info['flows']} over {info['duration_hours']} hours",
        f"- Activity bursts: {timeline['bursts']} (longest has {timeline['longest_burst_flows']} flows)",
        f"- Peak rate: {timeline['peak_flows_per_min']} flows per minute",
        f"- Failed or reset connections: {timeline['failed_ratio']:.0%}",
        "",
        "## Indicators of compromise",
        "",
        "Sources:",
        _bullets(iocs["sources"]),
        "",
        "Targets:",
        _bullets(iocs["targets"][:10]),
        "",
        "Services:",
        _bullets(iocs["services"][:5]),
        "",
        "## Severity factors",
        "",
        _bullets(severity["factors"]),
        "",
        "## Recommended actions",
        "",
    ]

    advisory = [p for p in proposals if p["kind"] == "advisory"]
    actions = [p for p in proposals if p["kind"] == "action"]

    lines += ["Advisory steps for the analyst:", _bullets([p["description"] for p in advisory]), ""]
    lines.append("Guardrailed actions (nothing runs without human confirmation inside the lab):")
    lines.append(
        _bullets([f"{p['action']} on {p['target']}: {p['status'].replace('_', ' ')} ({p['reason']})" for p in actions])
    )

    lines += ["", "## Investigation steps taken", ""]
    lines += [f"{n}. {step['tool']}: {step['purpose']}" for n, step in enumerate(trace, start=1)]

    lines += [
        "",
        "## Limits",
        "",
        "- Threat intelligence uses a local blocklist only; external feeds are not connected",
        "- Mapping rules were tuned on this dataset and are not an independent test",
    ]
    return "\n".join(lines) + "\n"
