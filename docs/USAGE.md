# Usage

## Setup

```
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[api]" pytest
export KMP_DUPLICATE_LIB_OK=TRUE OMP_NUM_THREADS=1
```

## Data

Place the UWF-ZeekData24 CSV files in `data/raw/`. Without data, `python scripts/make_synthetic.py --rows 30000` creates a sample set that is easy to separate, so its scores are not reportable.

## Pipeline

| Step | Command | Output |
|---|---|---|
| Explore data | `python scripts/explore_dataset.py` | Column and label summary |
| Train and evaluate | `python -m dfir_cti.pipeline` | `reports/baseline_metrics.json`, saved models |
| Figures | `python scripts/make_figures.py` | `reports/figures/*.png` |
| Incidents and ATT&CK mapping | `python scripts/make_incidents.py` | `reports/incidents.json`, `incidents.csv`, database |
| Agent investigation | `python scripts/run_agent.py` | `reports/agent/INC-xxxx.md`, `agent_summary.json` |
| Results tables | `python scripts/make_report_tables.py` | `docs/RESULTS.md` |
| API | `python scripts/run_api.py` | Interactive docs at `http://127.0.0.1:8000/docs` |
| Tests | `python -m pytest -q` | |

## Lab simulation

```
python scripts/simulate_lab.py
python scripts/analyze_lab.py
python scripts/run_api.py --db reports/lab/lab.db
```

`simulate_lab.py` writes a Zeek-format `data/lab/conn.log` and a `ground_truth.csv`. `analyze_lab.py` parses it, runs the rules, correlation, mapping and the agent, and stores everything in `reports/lab/lab.db`. Real Zeek logs can be analysed the same way with `--input path/to/conn.log`.

## Optional LLM narrative

```
export ANTHROPIC_API_KEY=...
python scripts/run_agent.py --llm
```

## Notebook

`notebooks/dfir_cti_results.ipynb` runs the full flow with graphs and confusion matrices. In Colab, upload the dataset files to `data/raw/` before running.
