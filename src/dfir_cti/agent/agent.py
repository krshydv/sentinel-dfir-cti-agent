import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from dfir_cti.agent.guardrails import ActionRejected, authorize
from dfir_cti.agent.narrators import TemplateNarrator
from dfir_cti.agent.planner import PURPOSES, next_tool
from dfir_cti.agent.playbooks import playbook_for
from dfir_cti.agent.report import build_report
from dfir_cti.agent.tools import Toolbox
from dfir_cti.config import resolve_path
from dfir_cti.threat_intel.iocs import load_blocklist


class InvestigationAgent:
    def __init__(self, cfg, narrator=None):
        agent_cfg = cfg["agent"]
        self.max_steps = agent_cfg["max_steps"]
        self.networks = [ipaddress.ip_network(n) for n in agent_cfg["lab_networks"]]
        self.narrator = narrator or TemplateNarrator()
        self.blocklist = load_blocklist(resolve_path(cfg, "intel") / cfg["threat_intel"]["blocklist_file"])

    def in_lab(self, address):
        try:
            ip = ipaddress.ip_address(str(address))
        except ValueError:
            return False
        return any(ip in network for network in self.networks)

    def _target_for(self, action, incident):
        if action == "isolate_lab_host":
            for ioc in incident["iocs"]:
                if ioc["role"] == "target" and self.in_lab(ioc["value"]):
                    return ioc["value"]
        return incident["src_ip"]

    def propose_actions(self, incident):
        book = playbook_for(incident["technique_id"])
        proposals = [{"kind": "advisory", "description": text} for text in book["advisory"]]

        for action in book["actions"]:
            target = self._target_for(action, incident)
            in_lab = self.in_lab(target)
            try:
                authorize(action, in_lab, False)
                status, reason = "approved", "ready"
            except ActionRejected as exc:
                reason = str(exc)
                status = "blocked_outside_lab" if not in_lab else "awaiting_human_confirmation"
            proposals.append(
                {
                    "kind": "action",
                    "action": action,
                    "target": target,
                    "target_in_lab": in_lab,
                    "status": status,
                    "reason": reason,
                }
            )
        return proposals

    def investigate(self, incident):
        toolbox = Toolbox(incident, self.blocklist)
        observations = {}
        trace = []

        for _ in range(self.max_steps):
            tool = next_tool(incident, observations)
            if tool is None:
                break
            observations[tool] = toolbox.call(tool)
            trace.append({"tool": tool, "purpose": PURPOSES[tool]})

        severity = observations["assess_severity"]
        proposals = self.propose_actions(incident)

        context = {
            "summary": observations["incident_summary"],
            "timeline": observations["timeline_overview"],
            "attack": observations.get("attack_context"),
            "severity": severity,
        }
        try:
            summary = self.narrator.narrate(context)
        except Exception:
            summary = TemplateNarrator().narrate(context)

        report = build_report(incident, observations, trace, severity, proposals, summary)

        return {
            "incident_id": incident["incident_id"],
            "severity": severity,
            "technique_id": incident["technique_id"],
            "proposals": proposals,
            "trace": trace,
            "summary": summary,
            "report": report,
        }

    def execute(self, proposal, human_confirmed, audit_path=None):
        authorize(proposal["action"], proposal["target_in_lab"], human_confirmed)
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "action": proposal["action"],
            "target": proposal["target"],
            "mode": "simulated",
            "human_confirmed": True,
        }
        if audit_path is not None:
            audit_path = Path(audit_path)
            audit_path.parent.mkdir(parents=True, exist_ok=True)
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        return record
