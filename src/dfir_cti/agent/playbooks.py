PLAYBOOKS = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Repeated connection attempts against one service to guess or exhaust credentials. "
            "Typical signs are many short, often failed connections from one source to the same port."
        ),
        "advisory": [
            "Restrict the targeted management port to an administrative network segment",
            "Enforce account lockout and multi-factor authentication on the targeted service",
            "Review authentication logs on the targeted hosts for successful logins from the source",
        ],
        "actions": ["block_ioc_test_rule", "isolate_lab_host"],
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": (
            "Probing many hosts or ports to map reachable services before an attack. "
            "Typical signs are one source touching many destinations with few flows each."
        ),
        "advisory": [
            "Rate-limit or drop traffic from the scanning source at the perimeter",
            "Check which probed services are exposed externally and close those that are not needed",
            "Watch the source for follow-up activity such as login attempts on the services it found",
        ],
        "actions": ["block_ioc_test_rule"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "description": (
            "Moving data out of the network over a protocol not normally used for transfers. "
            "Typical signs are unusually large outbound volume from a host that is normally quiet."
        ),
        "advisory": [
            "Apply egress filtering so internal hosts can only reach approved destinations",
            "Inspect the affected host for the process or account that started the transfer",
            "Identify what data was reachable from the host and assess exposure",
        ],
        "actions": ["isolate_lab_host", "block_ioc_test_rule"],
    },
}

DEFAULT_PLAYBOOK = {
    "name": "Unmapped anomaly",
    "tactic": "Unmapped",
    "description": "The behaviour did not match a known pattern and needs manual triage.",
    "advisory": [
        "Review the flagged flows manually before taking any action",
        "Compare the source against its normal baseline behaviour",
    ],
    "actions": [],
}


def playbook_for(technique_id):
    return PLAYBOOKS.get(technique_id, DEFAULT_PLAYBOOK)
