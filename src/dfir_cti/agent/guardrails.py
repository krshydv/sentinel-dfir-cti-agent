APPROVED_ACTIONS = {
    "isolate_lab_host",
    "block_ioc_test_rule",
    "draft_phishing_takedown_notice",
}

SUPPORTED_THREATS = {"ransomware", "malware", "phishing"}


class ActionRejected(Exception):
    pass


def authorize(action, target_in_lab, human_confirmed):
    if action not in APPROVED_ACTIONS:
        raise ActionRejected(f"action not pre-approved: {action}")
    if not target_in_lab:
        raise ActionRejected("target is outside the isolated lab")
    if not human_confirmed:
        raise ActionRejected("human confirmation required")
    return True
