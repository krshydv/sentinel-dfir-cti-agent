import json
import sqlite3
from pathlib import Path

from dfir_cti.config import resolve_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    src_ip TEXT NOT NULL,
    start TEXT,
    end TEXT,
    duration_s REAL,
    flows INTEGER,
    unique_dsts INTEGER,
    unique_ports INTEGER,
    bytes_out REAL,
    failed_ratio REAL,
    mean_score REAL,
    max_score REAL,
    rules TEXT,
    technique_id TEXT,
    technique TEXT,
    tactic_pred TEXT,
    confidence TEXT,
    true_tactic TEXT,
    true_technique TEXT,
    evidence TEXT,
    timeline TEXT,
    bursts TEXT,
    top_dsts TEXT,
    top_ports TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    type TEXT,
    value TEXT,
    role TEXT,
    scope TEXT,
    flows INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    context TEXT
);
CREATE TABLE IF NOT EXISTS agent_results (
    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
    severity_level TEXT,
    severity_points INTEGER,
    severity_factors TEXT,
    technique_id TEXT,
    summary TEXT,
    report TEXT,
    proposals TEXT,
    trace TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT,
    incident_id TEXT,
    action TEXT,
    target TEXT,
    mode TEXT,
    human_confirmed INTEGER
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_incident ON iocs(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_src ON incidents(src_ip);
"""

JSON_FIELDS = ("rules", "evidence", "timeline", "bursts", "top_dsts", "top_ports")
INCIDENT_COLUMNS = (
    "incident_id", "src_ip", "start", "end", "duration_s", "flows", "unique_dsts", "unique_ports",
    "bytes_out", "failed_ratio", "mean_score", "max_score", "rules", "technique_id", "technique",
    "tactic_pred", "confidence", "true_tactic", "true_technique", "evidence", "timeline", "bursts",
    "top_dsts", "top_ports",
)
SEVERITY_ORDER = "CASE severity_level WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'medium' THEN 1 ELSE 0 END"


def _dump(value):
    return json.dumps(value, default=str)


class Store:
    def __init__(self, path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def save_incidents(self, reports):
        with self.conn:
            for report in reports:
                self.conn.execute("DELETE FROM incidents WHERE incident_id = ?", (report["incident_id"],))
                values = []
                for column in INCIDENT_COLUMNS:
                    value = report.get(column)
                    if column in JSON_FIELDS:
                        value = _dump(value)
                    elif column in ("start", "end") and value is not None:
                        value = str(value)
                    values.append(value)
                marks = ",".join("?" * len(INCIDENT_COLUMNS))
                self.conn.execute(
                    f"INSERT INTO incidents ({','.join(INCIDENT_COLUMNS)}) VALUES ({marks})", values
                )
                for ioc in report.get("iocs", []):
                    self.conn.execute(
                        "INSERT INTO iocs (incident_id, type, value, role, scope, flows, first_seen, last_seen, context)"
                        " VALUES (?,?,?,?,?,?,?,?,?)",
                        (
                            report["incident_id"],
                            ioc.get("type"),
                            ioc.get("value"),
                            ioc.get("role"),
                            ioc.get("scope"),
                            ioc.get("flows"),
                            str(ioc.get("first_seen")),
                            str(ioc.get("last_seen")),
                            ioc.get("context"),
                        ),
                    )
        return len(reports)

    def save_agent_results(self, results):
        with self.conn:
            for r in results:
                self.conn.execute(
                    "INSERT OR REPLACE INTO agent_results VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        r["incident_id"],
                        r["severity"]["level"],
                        r["severity"]["points"],
                        _dump(r["severity"]["factors"]),
                        r["technique_id"],
                        r["summary"],
                        r["report"],
                        _dump(r["proposals"]),
                        _dump(r["trace"]),
                    ),
                )
        return len(results)

    def log_action(self, record, incident_id=None):
        with self.conn:
            self.conn.execute(
                "INSERT INTO audit_log (time, incident_id, action, target, mode, human_confirmed) VALUES (?,?,?,?,?,?)",
                (
                    record["time"],
                    incident_id,
                    record["action"],
                    record["target"],
                    record["mode"],
                    int(record["human_confirmed"]),
                ),
            )

    def _incident(self, row):
        item = dict(row)
        for field in JSON_FIELDS:
            if item.get(field) is not None:
                item[field] = json.loads(item[field])
        return item

    def list_incidents(self, severity=None, technique_id=None, src_ip=None, limit=100):
        sql = (
            "SELECT i.*, a.severity_level, a.severity_points FROM incidents i "
            "LEFT JOIN agent_results a ON a.incident_id = i.incident_id WHERE 1=1"
        )
        params = []
        if severity:
            sql += " AND a.severity_level = ?"
            params.append(severity)
        if technique_id:
            sql += " AND i.technique_id = ?"
            params.append(technique_id)
        if src_ip:
            sql += " AND i.src_ip = ?"
            params.append(src_ip)
        sql += f" ORDER BY {SEVERITY_ORDER} DESC, a.severity_points DESC, i.flows DESC LIMIT ?"
        params.append(limit)
        return [self._incident(r) for r in self.conn.execute(sql, params)]

    def get_incident(self, incident_id):
        row = self.conn.execute(
            "SELECT i.*, a.severity_level, a.severity_points, a.severity_factors, a.summary, a.report, a.proposals, a.trace "
            "FROM incidents i LEFT JOIN agent_results a ON a.incident_id = i.incident_id WHERE i.incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        item = self._incident(row)
        for field in ("severity_factors", "proposals", "trace"):
            if item.get(field) is not None:
                item[field] = json.loads(item[field])
        item["iocs"] = self.list_iocs(incident_id=incident_id)
        return item

    def list_iocs(self, incident_id=None, value=None, scope=None, limit=500):
        sql = "SELECT * FROM iocs WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        if value:
            sql += " AND value = ?"
            params.append(value)
        if scope:
            sql += " AND scope = ?"
            params.append(scope)
        sql += " ORDER BY flows DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def audit_log(self, limit=100):
        rows = self.conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    def stats(self):
        scalar = lambda sql: self.conn.execute(sql).fetchone()[0]
        by_severity = {
            r["severity_level"]: r["n"]
            for r in self.conn.execute("SELECT severity_level, COUNT(*) AS n FROM agent_results GROUP BY severity_level")
        }
        by_technique = {
            (r["technique_id"] or "unmapped"): r["n"]
            for r in self.conn.execute("SELECT technique_id, COUNT(*) AS n FROM incidents GROUP BY technique_id")
        }
        return {
            "incidents": scalar("SELECT COUNT(*) FROM incidents"),
            "iocs": scalar("SELECT COUNT(*) FROM iocs"),
            "investigated": scalar("SELECT COUNT(*) FROM agent_results"),
            "actions_logged": scalar("SELECT COUNT(*) FROM audit_log"),
            "by_severity": by_severity,
            "by_technique": by_technique,
        }


def open_store(cfg, path=None):
    target = Path(path) if path else resolve_path(cfg, "database")
    return Store(target)
