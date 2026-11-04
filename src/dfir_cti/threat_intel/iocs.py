import ipaddress
from pathlib import Path

SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    123: "NTP",
    137: "NetBIOS name service",
    138: "NetBIOS datagram service",
    139: "NetBIOS session service",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    4848: "GlassFish admin console",
    8080: "HTTP alternate",
}


def classify_ip(value):
    try:
        return "internal" if ipaddress.ip_address(str(value)).is_private else "external"
    except ValueError:
        return "unknown"


def load_blocklist(path):
    path = Path(path)
    if not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def _ip_ioc(value, role, group, blocklist):
    return {
        "type": "ip",
        "value": str(value),
        "role": role,
        "scope": classify_ip(value),
        "flows": int(len(group)),
        "first_seen": group["ts"].min(),
        "last_seen": group["ts"].max(),
        "context": "listed in local blocklist" if str(value) in blocklist else "not in local blocklist",
    }


def extract_iocs(timeline, blocklist=None, max_targets=20, max_ports=10):
    blocklist = blocklist or set()
    iocs = []

    if "src_ip" in timeline.columns:
        for value, group in timeline.groupby("src_ip"):
            iocs.append(_ip_ioc(value, "source", group, blocklist))

    if "dst_ip" in timeline.columns:
        ranked = timeline["dst_ip"].value_counts().head(max_targets).index
        for value in ranked:
            iocs.append(_ip_ioc(value, "target", timeline[timeline["dst_ip"] == value], blocklist))

    if "dst_port" in timeline.columns:
        ranked = timeline["dst_port"].value_counts().head(max_ports).index
        for port in ranked:
            group = timeline[timeline["dst_port"] == port]
            proto = group["proto"].mode().iloc[0] if "proto" in group.columns and not group["proto"].mode().empty else "tcp"
            iocs.append(
                {
                    "type": "port",
                    "value": f"{int(port)}/{proto}",
                    "role": "target_service",
                    "scope": "-",
                    "flows": int(len(group)),
                    "first_seen": group["ts"].min(),
                    "last_seen": group["ts"].max(),
                    "context": SERVICE_NAMES.get(int(port), "unrecognised service"),
                }
            )

    return iocs
