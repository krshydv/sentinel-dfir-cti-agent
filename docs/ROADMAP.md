# 12-Week Roadmap (synopsis Table 4.6)

| Week | Milestone | State |
|---|---|---|
| 1-2 | Literature review, architecture, UWF-ZeekData24 acquisition and exploration, isolated lab setup | repo scaffold and download/explore scripts done; dataset download and lab VM setup pending |
| 3-4 | Preprocessing, incident simulation, log parsing, database design | cleaning and flow features done; simulation, parsers, DB pending |
| 5-6 | Feature engineering, Isolation Forest, XGBoost, autoencoder, score fusion, baseline evaluation | baseline implemented; tune on real data pending |
| 7 | Rule engine, event correlation, forensic artefact integration | rule engine baseline done |
| 8 | IOC extraction, threat-intel enrichment, MITRE ATT&CK mapping | pending |
| 9-10 | Agentic AI layer: orchestrator, tools, planning and report prompts, sandboxed mitigation | pending |
| 11 | Dashboard integration, end-to-end testing | pending |
| 12 | Evaluation, analysis, paper draft, documentation, submission | pending |

## Immediate next steps

1. Download UWF-ZeekData24 into `data/raw/`, run `scripts/explore_dataset.py`, fix column mappings in `config/config.yaml`.
2. Run `python -m dfir_cti.pipeline` on real data and record baseline metrics.
3. Set up isolated lab VMs (VirtualBox or VMware) per `lab/README.md`.
4. Decide the DB (SQLite for the prototype) and the LLM provider for the agent.

## Suggested task split

| Member | Focus |
|---|---|
| Krish | Detection engine, fusion, evaluation |
| Shivansh | Dataset, preprocessing, feature engineering |
| Sofia | Forensics, IOC extraction, MITRE ATT&CK mapping |
| Sahil | Dashboard, backend API, reporting |
| All | Agentic layer (weeks 9-10), lab scenarios, paper |

Adjust as the team agrees.

## Git workflow

- `main` stays runnable.
- One feature branch per task: `feat/<module>-<short-name>`.
- Open a pull request, get one teammate review, then merge.
