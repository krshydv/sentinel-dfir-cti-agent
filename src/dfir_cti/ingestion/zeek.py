from pathlib import Path

import pandas as pd

COLUMN_MAP = {
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
}

NUMERIC = [
    "ts",
    "src_port",
    "dst_port",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "missed_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
]


def _decode(value):
    return bytes(value, "utf-8").decode("unicode_escape")


def _read_tsv(path):
    separator, unset, empty, fields = "\t", "-", "(empty)", None
    with pd.io.common.get_handle(path, "r", compression="infer") as handle:
        for line in handle.handle:
            if not line.startswith("#"):
                break
            if line.startswith("#separator"):
                separator = _decode(line.split(" ", 1)[1].strip())
            elif line.startswith("#set_separator"):
                continue
            elif line.startswith("#empty_field"):
                empty = line.split(separator, 1)[1].strip()
            elif line.startswith("#unset_field"):
                unset = line.split(separator, 1)[1].strip()
            elif line.startswith("#fields"):
                fields = line.rstrip("\n").split(separator)[1:]
    if fields is None:
        raise ValueError(f"{path} has no #fields header; not a Zeek TSV log")
    return pd.read_csv(
        path,
        sep=separator,
        names=fields,
        comment="#",
        na_values=[unset, empty],
        keep_default_na=False,
        low_memory=False,
        compression="infer",
    )


def _read_json(path):
    return pd.read_json(path, lines=True, compression="infer")


def _is_json(path):
    with pd.io.common.get_handle(path, "r", compression="infer") as handle:
        for line in handle.handle:
            if line.strip():
                return line.lstrip().startswith("{")
    return False


def read_conn_log(path):
    path = Path(path)
    frame = _read_json(path) if _is_json(path) else _read_tsv(path)
    frame = frame.rename(columns=COLUMN_MAP)
    for column in NUMERIC:
        if column in frame.columns:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")
    frame["source_file"] = path.name
    return frame


def find_conn_logs(directory):
    directory = Path(directory)
    found = []
    for pattern in ("conn*.log", "conn*.log.gz", "conn*.json", "conn*.json.gz"):
        found.extend(sorted(directory.rglob(pattern)))
    return found


def read_conn_dir(directory):
    files = find_conn_logs(directory)
    if not files:
        raise FileNotFoundError(f"No Zeek conn logs found in {directory}")
    return pd.concat([read_conn_log(f) for f in files], ignore_index=True)
