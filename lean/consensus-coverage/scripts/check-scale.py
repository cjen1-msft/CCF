#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check native bounded-explorer fixpoints. Pass an executable and output directory."""

import argparse
import csv
import hashlib
import re
import subprocess
from pathlib import Path


ORACLES = [
    (2, 3, 618, 858, 76, "fd73c19a04fe8fd20de8ca4f9084602adad7414186c2e9cb0020f6e7ce5f4531"),
    (2, 4, 1891, 2508, 93, "d3e8675bc463d75bd7d8dc83ed079cf8dd1994ae9f801baa4c6b9adcdac2328c"),
    (3, 3, 10259, 14177, 113, "b794a0876f5cb6b378f1c1094e9db01f4ccfad75d354b822f755ae9ca4df6f80"),
    (5, 3, 2000475, 2878034, 115, "a540d2735b5d642b5486a130855e66714e82f9de9118c828ae12d2e12bb81629"),
]


def run(exe, directory, mode, log, term, queue, census=False):
    prefix = directory / f"{mode[2:]}-L{log}T{term}Q{queue}"
    out = prefix.with_suffix(".tsv")
    cmd = ["nice", exe, mode, "--max-log", str(log), "--max-term", str(term),
           "--max-network", str(queue), "--out", out]
    if mode == "--exhaust":
        cmd.append("--check-ghost")
    if census:
        cmd.extend(["--case-out", prefix.with_suffix(".cases.tsv")])
    text = subprocess.check_output(cmd, text=True)
    prefix.with_suffix(".log").write_text(text)
    frame = re.search(r"^frames: (\d+); expanded: (\d+); frontier: 0; fixpoint: true$", text, re.M)
    edge = re.search(r"^steps: (\d+);.*?keys: (\d+)", text, re.M)
    assert frame and edge and frame[1] == frame[2], prefix
    with out.open() as f:
        keys = sorted(int(x["key"]) for x in csv.DictReader(f, delimiter="\t"))
    assert len(set(keys)) == len(keys) == int(edge[2]), prefix
    digest = hashlib.sha256("".join(f"{k}\n" for k in keys).encode()).hexdigest()
    print(prefix.name, frame[1], edge[1], len(keys), digest, flush=True)
    return int(frame[1]), int(edge[1]), len(keys), digest


def census(directory, mode, queue):
    with (directory / f"{mode}-L2T3Q{queue}.cases.tsv").open() as f:
        return list(csv.DictReader(f, delimiter="\t"))


def main():
    if not __debug__:
        raise SystemExit("run without python -O: the oracle comparisons require assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("directory", type=Path)
    p.add_argument("--small", action="store_true", help="skip the two-million-frame log-five cell")
    args = p.parse_args()
    exe = args.exe.resolve(strict=True)
    args.directory.mkdir(exist_ok=True, parents=True)
    for log, term, *expected in ORACLES:
        if not (args.small and log == 5):
            assert run(exe, args.directory, "--scale", log, term, 1, (log, term) == (2, 3)) == tuple(expected)
    assert run(exe, args.directory, "--exhaust", 2, 3, 1, True) == ORACLES[0][2:]
    history = census(args.directory, "exhaust", 1)
    assert history and history == census(args.directory, "scale", 1)
    # A real overlap: checking only queue one would not exercise the residual
    # queue, present/absent send conditions, or the symbolic cardinality filter.
    left = run(exe, args.directory, "--scale", 2, 3, 2, True)
    right = run(exe, args.directory, "--symbolic", 2, 3, 2, True)
    assert left == right and left[:3] == (34256, 72012, 101)
    cases = census(args.directory, "scale", 2)
    assert [r["question"] for r in cases] == [r["question"] for r in history]
    assert cases == census(args.directory, "symbolic", 2)
    print(f"Full history/product census and overlapping product/symbolic census: {len(history)} questions.")
    assert run(exe, args.directory, "--queue-ladder", 2, 3, 2) == left
    text = (args.directory / "queue-ladder-L2T3Q2.log").read_text()
    first = {int(k): int(q) for q, k in re.findall(r"^first cap: (\d+); key: (\d+)$", text, re.M)}
    for q in (1, 2):
        with (args.directory / f"scale-L2T3Q{q}.tsv").open() as f:
            assert {k for k, cap in first.items() if cap <= q} == {
                int(row["key"]) for row in csv.DictReader(f, delimiter="\t")
            }


if __name__ == "__main__":
    main()
