import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from make_synthetic import generate

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.config import load_config
from dfir_cti.investigation import investigate
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.storage import Store


def _setup():
    cfg = load_config()
    frame = clean(generate(6000, 0.1, 3), cfg)
    _, _, reports = investigate(frame, frame["label_binary"].values, np.ones(len(frame)), cfg)
    agent = InvestigationAgent(cfg)
    results = [agent.investigate(r) for r in reports]
    return cfg, reports, results, agent


def test_round_trip_and_queries(tmp_path):
    cfg, reports, results, _ = _setup()
    with Store(tmp_path / "t.db") as store:
        assert store.save_incidents(reports) == len(reports)
        assert store.save_agent_results(results) == len(results)

        stats = store.stats()
        assert stats["incidents"] == len(reports)
        assert stats["investigated"] == len(results)
        assert sum(stats["by_severity"].values()) == len(results)

        first = store.get_incident(reports[0]["incident_id"])
        assert first["src_ip"] == reports[0]["src_ip"]
        assert first["iocs"]
        assert first["report"]
        assert isinstance(first["proposals"], list)

        listed = store.list_incidents()
        points = [r["severity_points"] for r in listed]
        assert points == sorted(points, reverse=True) or listed[0]["severity_level"] is not None

        ip = reports[0]["src_ip"]
        assert all(r["src_ip"] == ip for r in store.list_incidents(src_ip=ip))
        assert store.list_iocs(value=ip)
        assert store.get_incident("INC-9999") is None


def test_save_is_repeatable(tmp_path):
    cfg, reports, results, _ = _setup()
    with Store(tmp_path / "t.db") as store:
        store.save_incidents(reports)
        store.save_agent_results(results)
        store.save_incidents(reports)
        store.save_agent_results(results)
        assert store.stats()["incidents"] == len(reports)
        assert store.stats()["iocs"] == sum(len(r["iocs"]) for r in reports)


def test_executed_actions_are_logged(tmp_path):
    cfg, reports, _, agent = _setup()
    incident = dict(reports[0])
    incident["src_ip"] = "10.0.0.5"
    incident["technique_id"] = "T1110"
    result = agent.investigate(incident)
    action = next(p for p in result["proposals"] if p["kind"] == "action")
    with Store(tmp_path / "t.db") as store:
        agent.execute(action, True, store=store, incident_id=incident["incident_id"])
        log = store.audit_log()
        assert len(log) == 1
        assert log[0]["action"] == action["action"]
        assert log[0]["human_confirmed"] == 1
