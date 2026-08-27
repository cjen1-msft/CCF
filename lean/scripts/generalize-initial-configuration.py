# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRITE_TARGETS = [
    ROOT / "lean/CCFRaft/Properties.lean",
    ROOT / "lean/CCFRaft/Proofs.lean",
]
CHECK_TARGETS = [
    ROOT / "lean/CCFRaft/Model.lean",
    ROOT / "lean/CCFRaft/Properties.lean",
    ROOT / "lean/CCFRaft/Proofs.lean",
    ROOT / "lean/CCFRaft/Simulation.lean",
    ROOT / "lean/CCFRaft.lean",
]
REPLACEMENTS = [
    (re.compile(r"\(start : Node\)"), "(start : InitialConfiguration)"),
    (re.compile(r"\{start : Node\}"), "{start : InitialConfiguration}"),
    (re.compile(r"forall start : Node"), "forall start : InitialConfiguration"),
    (re.compile(r"^  start : Node$", re.MULTILINE), "  start : InitialConfiguration"),
]
FORBIDDEN = [
    re.compile(r"\(start : Node\)"),
    re.compile(r"\{start : Node\}"),
    re.compile(r"forall start : Node"),
    re.compile(r"^  start : Node$", re.MULTILINE),
    re.compile(r"Fin 15"),
    re.compile(r"Finset\.univ"),
    re.compile(r"\bfin_cases\b"),
]


def rewrite(text: str) -> str:
    for pattern, replacement in REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="update the proof files in place",
    )
    args = parser.parse_args()

    changed = []
    for path in WRITE_TARGETS:
        original = path.read_text()
        updated = rewrite(original)
        if original != updated:
            changed.append(path)
            if args.write:
                path.write_text(updated)

    if not args.write and changed:
        for path in changed:
            print(path.relative_to(ROOT))
        return 1

    failures = []
    for path in CHECK_TARGETS:
        text = path.read_text()
        for pattern in FORBIDDEN:
            if pattern.search(text):
                failures.append((path, pattern.pattern))

    for path, pattern in failures:
        print(f"{path.relative_to(ROOT)} still matches {pattern}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
