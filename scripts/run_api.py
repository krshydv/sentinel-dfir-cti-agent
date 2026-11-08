import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import uvicorn

from dfir_cti.api.app import create_app
from dfir_cti.config import load_config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default=None)
    parser.add_argument("--config", default=None)
    args = parser.parse_args()
    uvicorn.run(create_app(load_config(args.config), args.db), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
