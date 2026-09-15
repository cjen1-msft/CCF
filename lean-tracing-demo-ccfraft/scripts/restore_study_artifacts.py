#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Restore archived generated benchmark directories without overwriting existing data."""

import hashlib
import json
from pathlib import Path
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1] / "Measurements/encoding-study"


def extract(path, expected):
    target = ROOT / expected
    if target.exists():
        print(f"Keeping existing {target}")
        return
    with tarfile.open(path, "r:gz") as archive:
        for member in archive.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != expected or ".." in parts or Path(member.name).is_absolute():
                raise ValueError(f"Unexpected archived path: {member.name}")
        archive.extractall(ROOT, filter="data")
    print(f"Restored {target}")


def main():
    extract(ROOT / "raw-results.tar.gz", "results")
    extract(ROOT / "ledger-microbench-current.tar.gz", "microbench")
    if (ROOT / "matched-suite").exists():
        print("Keeping existing matched-suite")
        return
    manifest = json.loads((ROOT / "matched-suite-archive.json").read_text())
    with tempfile.TemporaryFile() as merged:
        for part in manifest["parts"]:
            data = (ROOT / part["file"]).read_bytes()
            if len(data) != part["bytes"] or hashlib.sha256(data).hexdigest() != part["sha256"]:
                raise ValueError(f"Archive checksum mismatch: {part['file']}")
            merged.write(data)
        merged.seek(0)
        with tarfile.open(fileobj=merged, mode="r:gz") as archive:
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if not parts or parts[0] != "matched-suite" or ".." in parts or Path(member.name).is_absolute():
                    raise ValueError(f"Unexpected archived path: {member.name}")
            archive.extractall(ROOT, filter="data")


if __name__ == "__main__":
    main()
