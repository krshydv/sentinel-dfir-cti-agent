PURPOSES = {
    "incident_summary": "Establish scope: who, how much, how long",
    "timeline_overview": "Understand pacing, bursts and failed connections",
    "list_iocs": "Collect indicators of compromise",
    "check_blocklist": "Compare external indicators with local threat intelligence",
    "attack_context": "Interpret the behaviour against MITRE ATT&CK",
    "assess_severity": "Rate how urgent the incident is",
}


def next_tool(incident, observations):
    if "incident_summary" not in observations:
        return "incident_summary"
    if "timeline_overview" not in observations:
        return "timeline_overview"
    if "list_iocs" not in observations:
        return "list_iocs"
    if observations["list_iocs"]["external_present"] and "check_blocklist" not in observations:
        return "check_blocklist"
    if incident["technique_id"] and "attack_context" not in observations:
        return "attack_context"
    if "assess_severity" not in observations:
        return "assess_severity"
    return None
