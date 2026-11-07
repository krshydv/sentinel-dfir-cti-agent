import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.agent.agent import InvestigationAgent
from dfir_cti.agent.narrators import AnthropicNarrator, TemplateNarrator
from dfir_cti.config import load_config, resolve_path

LEVELS = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=None)
    parser.add_argument("--incidents", default=None)
    parser.add_argument("--top", type=int, default=None)
    parser.add_argument("--llm", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    reports_dir = resolve_path(cfg, "reports")
    path = Path(args.incidents) if args.incidents else reports_dir / "incidents.json"

    if not path.exists():
        sys.exit(f"{path} not found. Run scripts/make_incidents.py first.")

    with open(path, encoding="utf-8") as f:
        incidents = json.load(f)

    narrator = AnthropicNarrator(cfg["agent"]["model"]) if args.llm else TemplateNarrator()
    agent = InvestigationAgent(cfg, narrator)

    results = [agent.investigate(incident) for incident in incidents]
    results.sort(key=lambda r: (LEVELS[r["severity"]["level"]], r["severity"]["points"]), reverse=True)

    top = args.top or cfg["agent"]["top_incidents"]
    out_dir = reports_dir / "agent"
    out_dir.mkdir(parents=True, exist_ok=True)

    for result in results[:top]:
        (out_dir / f"{result['incident_id']}.md").write_text(result["report"], encoding="utf-8")

    overview = [
        {key: r[key] for key in ("incident_id", "severity", "technique_id", "summary", "proposals")}
        for r in results
    ]
    with open(out_dir / "agent_summary.json", "w", encoding="utf-8") as f:
        json.dump(overview, f, indent=2)

    counts = {}
    for r in results:
        counts[r["severity"]["level"]] = counts.get(r["severity"]["level"], 0) + 1
    print("Incidents investigated:", len(results))
    print("By severity:", counts)
    for r in results[:top]:
        print(r["incident_id"], r["severity"]["level"], r["technique_id"], "->", out_dir / f"{r['incident_id']}.md")


if __name__ == "__main__":
    main()
