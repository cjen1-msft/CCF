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


def run(exe, directory, mode, log, term, queue, census=False, exhaust=("--check-ghost",), readers=False):
    prefix = directory / f"{mode[2:]}-L{log}T{term}Q{queue}"
    out = prefix.with_suffix(".tsv")
    cmd = ["nice", exe, mode, "--max-log", str(log), "--max-term", str(term),
           "--max-network", str(queue), "--out", out]
    if mode == "--exhaust":
        cmd.extend(exhaust)
    if census:
        cmd.extend(["--case-out", prefix.with_suffix(".cases.tsv")])
    if readers:
        cmd.append("--factored-reader-census" if readers == "factored" else "--reader-census")
        if mode == "--scale" and readers != "factored":
            cmd[3:3] = ["--audit-reader-every", "1"]
    text = subprocess.check_output(cmd, text=True)
    prefix.with_suffix(".log").write_text(text)
    frame = re.search(r"^frames: (\d+); expanded: (\d+); frontier: 0; fixpoint: true$", text, re.M)
    edge = re.search(r"^steps: (\d+);.*?keys: (\d+)", text, re.M)
    assert frame and edge and frame[1] == frame[2], prefix
    if readers is True and mode == "--scale":
        assert f"ordered-history row comparisons: {edge[1]}\n" in text, prefix
    with out.open() as f:
        keys = sorted(int(x["key"]) for x in csv.DictReader(f, delimiter="\t"))
    assert len(set(keys)) == len(keys) == int(edge[2]), prefix
    digest = hashlib.sha256("".join(f"{k}\n" for k in keys).encode()).hexdigest()
    print(prefix.name, frame[1], edge[1], len(keys), digest, flush=True)
    return int(frame[1]), int(edge[1]), len(keys), digest


def census(directory, mode, queue):
    with (directory / f"{mode}-L2T3Q{queue}.cases.tsv").open() as f:
        return list(csv.DictReader(f, delimiter="\t"))


def check_reader_audit(log, partial, full, steps):
    assert len(partial) == len(full) == 516
    known = extra = 0
    for small, large in zip(partial, full, strict=True):
        assert small["question"] == large["question"]
        for row in (small, large):
            assert sum(int(row[k]) for k in ("known_true", "known_false", "unknown")) == steps
        for k in ("known_true", "known_false"):
            assert int(small[k]) <= int(large[k])
            known += int(small[k])
            extra += int(large[k]) - int(small[k])
    assert f"ordered-history row comparisons: {steps}\n" in log
    assert f"known finite answers checked: {known}; additional ordered answers: {extra}\n" in log


def main():
    if not __debug__:
        raise SystemExit("run without python -O: the oracle comparisons require assertions")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exe", type=Path)
    p.add_argument("directory", type=Path)
    p.add_argument("--small", action="store_true",
                   help="skip the two-million-frame log-five cell and the Lean-only queue-three run")
    p.add_argument("--readers", action="store_true",
                   help="also check generated census and wider keys against ordered histories")
    p.add_argument("--reader-queue", type=int, choices=(0, 1, 2),
                   help="run the reader comparison at one queue cap (0 is the five-edge smoke test)")
    args = p.parse_args()
    if args.reader_queue is not None and not args.readers:
        p.error("--reader-queue requires --readers")
    exe = args.exe.resolve(strict=True)
    args.directory.mkdir(exist_ok=True, parents=True)
    key = args.directory / "decoder-key.txt"
    key.write_text("618475535481\n")
    # Golden legacy header and values: adding proof questions must not silently
    # change the stable coordinate names/order or break --key-answers.
    decoded = subprocess.check_output(["nice", exe, "--key-answers", key])
    assert hashlib.sha256(decoded).hexdigest() == "b1bcd9d24ffd9b76ec111a814eee8fc4b64d2f875e69aecad0ee73a088651ecd"
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
    # The Lean-only search steps whole states with their real queues. Only
    # with overlapping messages does that test the native queue factoring.
    merged = ("--incremental", "--frontier-only", "--compact", "--merge-workers", "4")
    assert run(exe, args.directory, "--exhaust", 2, 3, 2, exhaust=merged) == left
    if not args.small:
        assert run(exe, args.directory, "--exhaust", 2, 3, 3, exhaust=merged) == run(
            exe, args.directory, "--scale", 2, 3, 3
        )
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
    if args.readers:
        reader_dir = args.directory / "readers"
        reader_dir.mkdir(exist_ok=True)
        factored_dir = reader_dir / "factored"
        factored_dir.mkdir(exist_ok=True)
        rejected = subprocess.run(
            ["nice", exe, "--symbolic", "--max-network", "0", "--reader-census",
             "--case-out", reader_dir / "invalid.cases.tsv", "--out", reader_dir / "invalid.tsv"],
            capture_output=True, text=True,
        )
        assert rejected.returncode and "no ordered witness pools" in rejected.stderr
        queues = (0, 1) if args.small else (0, 1, 2)
        for q in (queues if args.reader_queue is None else (args.reader_queue,)):
            scores = {}
            for mode in ("--scale", "--exhaust"):
                scores[mode] = run(exe, reader_dir, mode, 2, 3, q, True,
                                   exhaust=("--incremental", "--merge-workers", "3", "--merge-every", "0"),
                                   readers=True)
            for mode in ("--scale", "--symbolic"):
                scores["factored" + mode] = run(exe, factored_dir, mode, 2, 3, q, True, readers="factored")
            assert len(set(scores.values())) == 1
            reference = census(reader_dir, "exhaust", q)
            # A different BFS action tie-break is allowed; witness depth must be minimal.
            cols = ("question", "known_true", "known_false", "unknown", "depth")
            def observations(rows):
                return [tuple(r[k] for k in cols) for r in rows]
            assert observations(census(reader_dir, "scale", q)) == observations(reference)
            partial = census(factored_dir, "scale", q)
            assert observations(census(factored_dir, "symbolic", q)) == observations(partial)
            # Omitting one-sided witness pools may only discard answers. The every-edge
            # audit also checks the direction of each known answer, before aggregation.
            check_reader_audit((reader_dir / f"scale-L2T3Q{q}.log").read_text(), partial,
                               census(reader_dir, "scale", q), scores["--scale"][1])
            wider = []
            for directory, mode in ((reader_dir, "scale"), (reader_dir, "exhaust"),
                                    (factored_dir, "scale"), (factored_dir, "symbolic")):
                text = (directory / f"{mode}-L2T3Q{q}.log").read_text()
                m = re.search(r"^wider projection: (\d+); extra coordinates: (\d+)$", text, re.M)
                assert m and int(m[1]) >= scores["--scale"][2] and int(m[2]) > 0
                wider.append(m.groups())
            assert len(set(wider)) == 1
            print(f"Q{q}: {scores['--exhaust'][1]} ordered-history edges, {len(reference)} rows, "
                  f"matching counts and shortest depths; wider {wider[0][0]}.")


if __name__ == "__main__":
    main()
