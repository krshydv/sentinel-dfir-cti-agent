import sys
from pathlib import Path

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from make_synthetic import generate

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.agent.guardrails import ActionRejected
from dfir_cti.config import load_config
from dfir_cti.investigation import investigate
from dfir_cti.preprocessing.cleaning import clean


class BrokenNarrator:
    def narrate(self, context):
        raise RuntimeError("model unavailable")


def _reports():
    cfg = load_config()
    frame = clean(generate(6000, 0.1, 3), cfg)
    _, _, reports = investigate(frame, frame["label_binary"].values, np.ones(len(frame)), cfg)
    return cfg, reports


def test_agent_investigates_every_incident():
    cfg, reports = _reports()
    agent = InvestigationAgent(cfg)
    for incident in reports[:10]:
        result = agent.investigate(incident)
        assert result["severity"]["level"] in {"low", "medium", "high", "critical"}
        assert result["trace"][0]["tool"] == "incident_summary"
        assert result["trace"][-1]["tool"] == "assess_severity"
        assert incident["incident_id"] in result["report"]


def test_falls_back_when_model_fails():
    cfg, reports = _reports()
    agent = InvestigationAgent(cfg, BrokenNarrator())
    result = agent.investigate(reports[0])
    assert "flagged flows" in result["summary"]


def test_actions_outside_lab_are_blocked():
    cfg, reports = _reports()
    agent = InvestigationAgent(cfg)
    incident = dict(reports[0])
    incident["src_ip"] = "8.8.8.8"
    incident["iocs"] = []
    result = agent.investigate(incident)
    actions = [p for p in result["proposals"] if p["kind"] == "action"]
    assert actions
    assert all(p["status"] == "blocked_outside_lab" for p in actions)
    with pytest.raises(ActionRejected):
        agent.execute(actions[0], human_confirmed=True)


def test_lab_action_needs_human_confirmation(tmp_path):
    cfg, reports = _reports()
    agent = InvestigationAgent(cfg)
    incident = dict(reports[0])
    incident["src_ip"] = "10.0.0.5"
    incident["technique_id"] = "T1110"
    result = agent.investigate(incident)
    action = next(p for p in result["proposals"] if p["kind"] == "action")
    assert action["status"] == "awaiting_human_confirmation"
    with pytest.raises(ActionRejected):
        agent.execute(action, human_confirmed=False)
    record = agent.execute(action, human_confirmed=True, audit_path=tmp_path / "audit.jsonl")
    assert record["mode"] == "simulated"
    assert (tmp_path / "audit.jsonl").read_text().strip()
