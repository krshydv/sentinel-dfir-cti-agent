from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.agent.guardrails import ActionRejected
from dfir_cti.config import load_config
from dfir_cti.storage import open_store

SEVERITIES = {"critical", "high", "medium", "low"}


class ActionRequest(BaseModel):
    action: str
    human_confirmed: bool = False


def create_app(cfg=None, db_path=None):
    cfg = cfg or load_config()
    agent = InvestigationAgent(cfg)
    app = FastAPI(title="DFIR-CTI Framework API", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:5173"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    def store():
        return open_store(cfg, db_path)

    @app.get("/health")
    def health():
        with store() as s:
            return {"status": "ok", "database": s.path, "incidents": s.stats()["incidents"]}

    @app.get("/stats")
    def stats():
        with store() as s:
            return s.stats()

    @app.get("/incidents")
    def incidents(
        severity: str | None = None,
        technique_id: str | None = None,
        src_ip: str | None = None,
        limit: int = Query(100, ge=1, le=1000),
    ):
        if severity and severity not in SEVERITIES:
            raise HTTPException(422, f"severity must be one of {sorted(SEVERITIES)}")
        with store() as s:
            return s.list_incidents(severity, technique_id, src_ip, limit)

    @app.get("/incidents/{incident_id}")
    def incident(incident_id: str):
        with store() as s:
            found = s.get_incident(incident_id)
        if found is None:
            raise HTTPException(404, "incident not found")
        return found

    @app.get("/incidents/{incident_id}/report", response_class=PlainTextResponse)
    def report(incident_id: str):
        with store() as s:
            found = s.get_incident(incident_id)
        if found is None:
            raise HTTPException(404, "incident not found")
        if not found.get("report"):
            raise HTTPException(404, "incident has not been investigated yet")
        return PlainTextResponse(found["report"], media_type="text/markdown")

    @app.get("/iocs")
    def iocs(
        incident_id: str | None = None,
        value: str | None = None,
        scope: str | None = None,
        limit: int = Query(500, ge=1, le=5000),
    ):
        with store() as s:
            return s.list_iocs(incident_id, value, scope, limit)

    @app.get("/audit")
    def audit(limit: int = Query(100, ge=1, le=1000)):
        with store() as s:
            return s.audit_log(limit)

    @app.post("/incidents/{incident_id}/actions")
    def run_action(incident_id: str, request: ActionRequest):
        with store() as s:
            found = s.get_incident(incident_id)
            if found is None:
                raise HTTPException(404, "incident not found")
            proposals = found.get("proposals") or []
            match = next(
                (p for p in proposals if p.get("kind") == "action" and p.get("action") == request.action),
                None,
            )
            if match is None:
                raise HTTPException(404, "no such proposed action for this incident")
            try:
                record = agent.execute(match, request.human_confirmed, store=s, incident_id=incident_id)
            except ActionRejected as exc:
                raise HTTPException(403, str(exc))
            return record

    return app
