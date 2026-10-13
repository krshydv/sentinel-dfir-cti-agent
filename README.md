# Agentic AI-Driven Hybrid Digital Forensics & Cyber Threat Intelligence Framework

B.Tech CSE major project, Graphic Era Deemed to be University, Dehradun.
Supervisor: Mr. Darshan Singh. Full specification: `docs/Major_Project_Synopsis.pdf`.

## Architecture (per synopsis, Table 4.1)

| Layer | Package | Status |
|---|---|---|
| Data ingestion | `src/dfir_cti/ingestion` | done |
| Preprocessing and feature engineering | `src/dfir_cti/preprocessing` | done (baseline) |
| Hybrid detection: Isolation Forest, XGBoost, deep autoencoder, score fusion | `src/dfir_cti/detection` | done (baseline) |
| Rule engine | `src/dfir_cti/detection/rules.py` | done (baseline) |
| Correlation and case management | `src/dfir_cti/correlation` | week 7 |
| Digital forensics artefacts | `src/dfir_cti/forensics` | week 7 |
| Threat intelligence, IOC, MITRE ATT&CK | `src/dfir_cti/threat_intel` | week 8 |
| Single agentic AI layer | `src/dfir_cti/agent` | weeks 9-10 |
| Dashboard and reporting | `src/dfir_cti/api`, `dashboard/` | week 11 |

Primary dataset: UWF-ZeekData24 (MITRE ATT&CK labelled Zeek network flows).
Fallback: self-generated lab dataset (see `lab/README.md`).

## Setup

```
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Dataset

1. Open https://datasets.uwf.edu/ and locate UWF-ZeekData24.
2. Download the files into `data/raw/`, or run `python scripts/download_dataset.py <url> [<url> ...]`.
3. Inspect it: `python scripts/explore_dataset.py`.
4. If the real column names differ from `config/config.yaml` (`dataset.*_candidates`), adjust the candidate lists.

Data files are git-ignored; every teammate downloads their own copy.

## Run the baseline

```
python -m dfir_cti.pipeline
python -m dfir_cti.pipeline --max-rows 500000
python -m dfir_cti.pipeline --strategy meta
```

Outputs: `models/` (trained models) and `reports/baseline_metrics.json` (precision, recall, F1, FPR per model, fused, rules only, rules plus fused).

## Smoke test without the real dataset

```
python scripts/make_synthetic.py --rows 30000
python -m pytest -q tests
python -m dfir_cti.pipeline
```

Synthetic data is trivially separable and only verifies that the code runs. Report metrics only from UWF-ZeekData24 or the lab dataset.

## Safety boundaries

All simulation and agent actions stay inside an isolated lab or public datasets. The agent only recommends or triggers pre-approved, reversible, sandboxed actions with human confirmation. No real malware on personal or production systems. See synopsis section 4.10.

See `docs/ROADMAP.md` for the 12-week plan and task split.
