#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Losslessly compress large generated query artifacts after byte verification."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil

from encoding_study import save

NAMES = {"encoding.json", "request.json", "query.smt2"}


def compress_file(path, minimum=1024 * 1024):
    if not path.is_file() or path.is_symlink() or path.name not in NAMES or path.stat().st_size < minimum:
        return None
    compressed = path.with_suffix(path.suffix + ".gz")
    if compressed.exists():
        raise ValueError(f"Both expanded and compressed artifacts exist: {path}")
    temporary = compressed.with_suffix(compressed.suffix + ".tmp")
    with path.open("rb") as stream:
        expected = hashlib.file_digest(stream, "sha256").hexdigest()
    original_size = path.stat().st_size
    with path.open("rb") as source, gzip.open(temporary, "wb", compresslevel=3) as target:
        shutil.copyfileobj(source, target)
    with gzip.open(temporary, "rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise ValueError(f"Compressed bytes do not match: {path}")
    temporary.replace(compressed)
    path.unlink()
    return {"sha256": expected, "original_bytes": original_size, "compressed_bytes": compressed.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    expected = (Path(__file__).resolve().parents[1] / "Measurements/encoding-study/matched-suite").resolve()
    if root != expected:
        parser.error("This bulk command is restricted to the generated matched-suite directory")
    manifest = root / "compression.json"
    records = json.loads(manifest.read_text()) if manifest.exists() else {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name.endswith(".compression.json"):
            original = path.with_name(path.name.removesuffix(".compression.json"))
            records[str(original.relative_to(root))] = json.loads(path.read_text())
            continue
        result = compress_file(path)
        if result is not None:
            records[str(path.relative_to(root))] = result
            save(manifest, records)
    save(manifest, records)
    print(f"Verified and compressed {len(records)} generated files")


if __name__ == "__main__":
    main()
