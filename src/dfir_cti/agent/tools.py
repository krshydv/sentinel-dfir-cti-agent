from dfir_cti.agent.playbooks import playbook_for
from dfir_cti.threat_intel.iocs import SERVICE_NAMES

CONFIDENCE_POINTS = {"high": 2, "medium": 1, "low": 0}


def _clock(value):
    return str(value)[:19].replace("T", " ") + " UTC"


class Toolbox:
    def __init__(self, incident, blocklist=None):
        self.incident = incident
        self.blocklist = blocklist or set()

    def registry(self):
        return {
            "incident_summary": self.incident_summary,
            "timeline_overview": self.timeline_overview,
            "list_iocs": self.list_iocs,
            "check_blocklist": self.check_blocklist,
            "attack_context": self.attack_context,
            "assess_severity": self.assess_severity,
        }

    def call(self, name):
        return self.registry()[name]()

    def incident_summary(self):
        inc = self.incident
        ports = {}
        for port, count in inc["top_ports"].items():
            service = SERVICE_NAMES.get(int(port), "unrecognised service")
            ports[f"{port} ({service})"] = count
        return {
            "incident_id": inc["incident_id"],
            "source_ip": inc["src_ip"],
            "flows": inc["flows"],
            "duration_hours": round(inc["duration_s"] / 3600, 2),
            "target_hosts": inc["unique_dsts"],
            "top_ports": ports,
            "bytes_out": inc["bytes_out"],
        }

    def timeline_overview(self):
        inc = self.incident
        stats = inc["timeline"]
        bursts = inc["bursts"]
        longest = max(bursts, key=lambda b: b["flows"]) if bursts else None
        return {
            "first_seen": _clock(stats["first_seen"]),
            "last_seen": _clock(stats["last_seen"]),
            "peak_flows_per_min": stats["peak_flows_per_min"],
            "active_minutes": stats["active_minutes"],
            "failed_ratio": round(stats["failed_ratio"], 3),
            "bursts": len(bursts),
            "longest_burst_flows": longest["flows"] if longest else 0,
        }

    def list_iocs(self):
        iocs = self.incident["iocs"]
        return {
            "sources": [f"{i['value']} ({i['scope']})" for i in iocs if i["role"] == "source"],
            "targets": [f"{i['value']} ({i['scope']})" for i in iocs if i["role"] == "target"],
            "services": [f"{i['value']} - {i['context']}" for i in iocs if i["role"] == "target_service"],
            "external_present": any(i["type"] == "ip" and i["scope"] == "external" for i in iocs),
        }

    def check_blocklist(self):
        ips = [i["value"] for i in self.incident["iocs"] if i["type"] == "ip"]
        listed = [ip for ip in ips if ip in self.blocklist]
        return {
            "checked": len(ips),
            "listed": listed,
            "note": "local blocklist only; external threat-intel feeds are not connected",
        }

    def attack_context(self):
        inc = self.incident
        book = playbook_for(inc["technique_id"])
        return {
            "technique_id": inc["technique_id"],
            "technique": book["name"],
            "tactic": book["tactic"],
            "description": book["description"],
            "confidence": inc["confidence"],
            "evidence": inc["evidence"],
        }

    def assess_severity(self):
        inc = self.incident
        points = 0
        factors = []

        confidence = CONFIDENCE_POINTS.get(inc["confidence"], 0)
        if confidence:
            points += confidence
            factors.append(f"{inc['confidence']} mapping confidence")
        if inc["flows"] >= 100:
            points += 1
            factors.append(f"{inc['flows']} flagged flows")
        if inc["rules"]:
            points += 1
            factors.append("rules fired: " + ", ".join(inc["rules"]))
        if inc["timeline"]["failed_ratio"] >= 0.5:
            points += 1
            factors.append("most connections failed or were reset")
        if inc["max_score"] >= 0.9:
            points += 1
            factors.append("detector score of 0.9 or higher")
        if inc["technique_id"] == "T1048":
            points += 2
            factors.append("possible data loss")
        if any(i["type"] == "ip" and i["scope"] == "external" for i in inc["iocs"]):
            points += 1
            factors.append("external address involved")

        if points >= 6:
            level = "critical"
        elif points >= 4:
            level = "high"
        elif points >= 2:
            level = "medium"
        else:
            level = "low"

        return {"level": level, "points": points, "factors": factors}
