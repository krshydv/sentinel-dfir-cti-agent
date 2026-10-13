import argparse
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dfir_cti.config import load_config, resolve_path


def download(url, dest):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=60) as r:
        r.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=1 << 20):
                f.write(chunk)
    return dest


def main():
    p = argparse.ArgumentParser()
    p.add_argument("urls", nargs="*")
    p.add_argument("--config", default=None)
    a = p.parse_args()
    cfg = load_config(a.config)
    urls = a.urls or cfg["dataset"].get("download_urls") or []
    raw = resolve_path(cfg, "raw")
    if not urls:
        print(f"No URLs provided. Open {cfg['dataset']['source_page']}, copy the UWF-ZeekData24 file links,")
        print("then run: python scripts/download_dataset.py <url1> <url2> ...")
        print(f"or place the downloaded files manually in {raw}")
        sys.exit(1)
    for u in urls:
        name = u.split("?")[0].rstrip("/").split("/")[-1]
        print(f"downloading {u}")
        print(download(u, raw / name))


if __name__ == "__main__":
    main()
