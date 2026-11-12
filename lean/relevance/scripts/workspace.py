#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Write an out-of-tree Lake workspace for Lean packages of this checkout.

Usage: workspace.py [PACKAGE ...]   (default: common consensus)

For each package directory under `lean/`, the workspace gets a directory with a copy of the
package's `lakefile.toml` whose `srcDir` points back at the checkout, whose path requirements
point at the other workspace packages, and without the requirements listed in DROP (git
packages only needed for formatting). Lake therefore writes its build and package directories
in the workspace, never in the checkout. Prints the workspace directory; build with

    lake -d WORKSPACE/consensus build Consensus
"""

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

LEAN = Path(__file__).resolve().parents[2]
WORKSPACE = (
    Path.home()
    / ".cache/ccf-consensus-coverage"
    / ("ws-" + hashlib.sha256(str(LEAN).encode()).hexdigest()[:12])
)
# leanfmt is required only by `lake exe fmt`; no Lean source of these packages imports it.
DROP = {"leanfmt"}


def requirements(source: Path, config: dict) -> list[tuple[dict, Path]]:
    out = []
    for require in config.get("require", []):
        if require["name"] in DROP:
            continue
        if "path" not in require:
            raise RuntimeError(f"{source}: requirement {require['name']} is not a path")
        out.append((require, (source / require["path"]).resolve().relative_to(LEAN)))
    return out


def write_package(package: str) -> None:
    source = LEAN / package
    text = (source / "lakefile.toml").read_text()
    config = tomllib.loads(text)
    if any(key in config for key in ("srcDir", "buildDir", "packagesDir")):
        raise RuntimeError(f"{package}: package-level directories are already set")
    blocks = re.split(r"(?m)^(?=\[\[)", text)
    text = "".join(
        block
        for block in blocks
        if not (
            block.startswith("[[require]]")
            and tomllib.loads(block.replace("[[require]]", "", 1))["name"] in DROP
        )
    )
    required = requirements(source, config)
    for require, relative in required:
        old = f'path = "{require["path"]}"'
        if old not in text:
            raise RuntimeError(f"{package}: cannot find {old}")
        text = text.replace(old, f'path = "{WORKSPACE / relative}"', 1)
    header, _, rest = text.partition("\n")
    text = f'{header}\nsrcDir = "{source}"\n{rest}'
    target = WORKSPACE / package
    target.mkdir(parents=True, exist_ok=True)
    (target / "lakefile.toml").write_text(text)
    (target / "lean-toolchain").write_text((source / "lean-toolchain").read_text())
    manifest = {
        "version": "1.3.0",
        "packagesDir": str(WORKSPACE / "packages"),
        "packages": [
            {
                "type": "path",
                "scope": "",
                "name": require["name"],
                "manifestFile": "lake-manifest.json",
                "inherited": False,
                "dir": str(WORKSPACE / relative),
                **({"copy": require["copy"]} if "copy" in require else {}),
                "configFile": "lakefile.toml",
            }
            for require, relative in required
        ],
        "name": config["name"],
        "lakeDir": ".lake",
        "fixedToolchain": False,
    }
    (target / "lake-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def main() -> None:
    for package in sys.argv[1:] or ["common", "consensus"]:
        write_package(package)
    print(WORKSPACE)


if __name__ == "__main__":
    main()
