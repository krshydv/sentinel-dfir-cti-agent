import sys
from pathlib import Path

import numpy as np
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fastapi.testclient import TestClient
from make_synthetic import generate

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.api.app import create_app
from dfir_cti.config import load_config
from dfir_cti.investigation import investigate
from dfir_cti.preprocessing.cleaning import clean
from dfir_cti.storage import Store


@pytest.fixture()
def client(tmp_path):
    cfg = load_config()
    frame = clean(generate(6000, 0.1, 3), cfg)
    _, _, reports = investigate(frame, frame["label_binary"].values, np.ones(len(frame)), cfg)
    reports[0]["src_ip"] = "10.0.0.5"
    reports[0]["technique_id"] = "T1110"
    reports[1]["src_ip"] = "8.8.8.8"
    reports[1]["iocs"] = []
    agent = InvestigationAgent(cfg)
    results = [agent.investigate(r) for r in reports]
    path = tmp_path / "api.db"
    with Store(path) as store:
        store.save_incidents(reports)
        store.save_agent_results(results)
    app = create_app(cfg, path)
    test_client = TestClient(app)
    test_client.incident_id = reports[0]["incident_id"]
    test_client.outside_id = reports[1]["incident_id"]
    test_client.total = len(reports)
    return test_client


def test_health_and_stats(client):
    assert client.get("/health").json()["status"] == "ok"
    stats = client.get("/stats").json()
    assert stats["incidents"] == client.total
    assert stats["investigated"] == client.total


def test_incident_listing_and_filters(client):
    rows = client.get("/incidents").json()
    assert len(rows) == client.total
    level = rows[0]["severity_level"]
    filtered = client.get("/incidents", params={"severity": level}).json()
    assert filtered and all(r["severity_level"] == level for r in filtered)
    assert client.get("/incidents", params={"severity": "bogus"}).status_code == 422


def test_incident_detail_and_report(client):
    detail = client.get(f"/incidents/{client.incident_id}").json()
    assert detail["iocs"] and detail["proposals"]
    report = client.get(f"/incidents/{client.incident_id}/report")
    assert report.status_code == 200
    assert client.incident_id in report.text
    assert client.get("/incidents/INC-9999").status_code == 404
    assert client.get("/incidents/INC-9999/report").status_code == 404


def test_iocs_filter(client):
    known = client.get(f"/incidents/{client.incident_id}").json()["iocs"][0]["value"]
    found = client.get("/iocs", params={"value": known}).json()
    assert found and all(r["value"] == known for r in found)
    assert client.get("/iocs", params={"value": "no-such-value"}).json() == []


def test_action_needs_confirmation_then_logs(client):
    url = f"/incidents/{client.incident_id}/actions"
    action = next(
        p["action"] for p in client.get(f"/incidents/{client.incident_id}").json()["proposals"] if p["kind"] == "action"
    )
    assert client.post(url, json={"action": action}).status_code == 403
    assert client.get("/audit").json() == []
    done = client.post(url, json={"action": action, "human_confirmed": True})
    assert done.status_code == 200
    assert done.json()["mode"] == "simulated"
    log = client.get("/audit").json()
    assert len(log) == 1 and log[0]["incident_id"] == client.incident_id
    assert client.post(url, json={"action": "wipe_disk", "human_confirmed": True}).status_code == 404


def test_action_outside_lab_is_forbidden(client):
    detail = client.get(f"/incidents/{client.outside_id}").json()
    action = next(p["action"] for p in detail["proposals"] if p["kind"] == "action")
    res = client.post(f"/incidents/{client.outside_id}/actions", json={"action": action, "human_confirmed": True})
    assert res.status_code == 403
    assert client.get("/audit").json() == []
