# Agentic AI-Driven Hybrid Digital Forensics & Cyber Threat Intelligence Framework

Agentic AI framework for digital forensics and cyber threat intelligence.
Ingests and cleans forensic/security data for analysis.
Uses hybrid detection models, rules, and correlation to identify threats.
Includes testing, configuration, dataset tools, documentation, and a future dashboard.


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
