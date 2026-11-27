#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Run live mid-trace regressions through the NDJSON pipe from trace reduction to the
mid-trace checker: check-midtrace.py REDUCTION_BIN MIDTRACE_BIN SOLVER OUTPUT_DIR."""

import argparse
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

CODES = {"invalidBounded": 1, "unknown": 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reduction", type=Path)
    parser.add_argument("midtrace", type=Path)
    parser.add_argument("solver")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=True, parents=True)
    package = Path(__file__).resolve().parents[1]
    packer = package.parents[1] / "scripts" / "pack-trace.py"
    reduction = args.reduction.resolve()
    midtrace = args.midtrace.resolve()

    def pack(name, records):
        path = args.output / f"{name}.msgpack"
        with path.open("wb") as stream:
            subprocess.run(
                [sys.executable, packer],
                input="".join(json.dumps(row) + "\n" for row in records).encode(),
                stdout=stream,
                check=True,
            )
        return path

    def run(binary, *argv, stdin=b"", code=0):
        proc = subprocess.run(
            [binary, *argv], input=stdin, capture_output=True, timeout=60
        )
        if proc.returncode != code:
            raise RuntimeError(
                f"{binary.name} {argv}: exit {proc.returncode}, expected {code}: "
                f"{proc.stdout.decode()} {proc.stderr.decode()}"
            )
        return proc.stdout

    def reduce(path, *options):
        """`consensus-reduction --trace`: one NDJSON line per group."""
        return run(reduction, "--trace", path, *options).decode().splitlines(True)

    def cli(*argv, groups=(), code=0):
        """`consensus-midtrace`, reading `groups` on standard input."""
        return run(midtrace, *argv, stdin="".join(groups).encode(), code=code)

    def check(groups, *options, verdict="validCertified"):
        result = json.loads(
            cli(
                "check",
                "--json",
                "--solver",
                args.solver,
                *options,
                groups=groups,
                code=CODES.get(verdict, 0),
            )
        )
        assert result["schemaVersion"] == 2, result
        assert result["verdict"] == verdict, result
        assert result["certified"] == (verdict == "validCertified"), result
        assert result["groups"] == len(groups), result
        print(len(groups), "groups", *options, verdict)
        return result

    def rejected(binary, *argv, groups=(), why):
        """A usage or input error: exit 2 and the reason on standard error."""
        proc = subprocess.run(
            [binary, *argv],
            input="".join(groups).encode(),
            capture_output=True,
            timeout=60,
        )
        assert proc.returncode == 2, (argv, proc)
        assert why in proc.stderr.decode(), (argv, proc.stderr)
        print("rejected", binary.name, *argv[:1], why)

    def fixture(name):
        path = package / "replay" / "fixtures" / "valid" / f"{name}.ndjson"
        return [json.loads(line) for line in path.read_text().splitlines()]

    state = args.output / "cut.json"
    for name in ("replication", "interleaved"):
        path = pack(name, fixture(name))
        groups = reduce(path)
        # The standard path checks the whole trace; a suffix, like `tail -n K`, is a
        # mid-trace check. Its true state at the cut must replay it.
        for cut in (0, 1, 3, 5):
            state.write_bytes(run(reduction, "true-state", path, str(cut)))
            suffix = groups[cut:]
            print(name, cut, cli("replay-from", state, groups=suffix).decode().strip())
            for invariant in ("on", "off"):
                check(suffix, "--invariant", invariant)
    # The genesis membership is optional, and constrains the cut state when given.
    result = check(groups, "--bootstrap", "0")
    assert result["bootstrap"] == ["0"], result

    # Backbone probing is opt-in; `--backbone 16` first probes at instruction 16.
    result = check(groups, "--backbone", "16")
    assert result["stats"]["probes"] > 0, result

    # A real shell pipe: reduction | tail | check, and a file argument.
    command = " | ".join(
        [
            shlex.join([str(reduction), "--trace", str(path)]),
            "tail -n 5",
            shlex.join([str(midtrace), "check", "--json", "--solver", args.solver]),
        ]
    )
    proc = subprocess.run(
        ["bash", "-c", f"set -o pipefail; {command}"],
        capture_output=True,
        timeout=60,
    )
    assert proc.returncode == 0, (command, proc)
    assert json.loads(proc.stdout)["groups"] == 5, proc.stdout
    print("pipe:", command)
    ndjson = args.output / "interleaved.ndjson"
    ndjson.write_text("".join(groups[-5:]))
    result = json.loads(cli("check", "--json", "--solver", args.solver, ndjson))
    assert result["groups"] == 5, result

    # Each node's clock may run ahead of another's: node 1 logs both receives before
    # node 0 logs the sends, so each receive waits for its send rather than consuming
    # one of the `Q` pre-cut packets.
    check(reduce(path, "--from-cut"), "--Q", "1", "--retry", "0")

    # Inputs that cannot be checked are errors, not verdicts.
    rejected(reduction, "--trace", pack("empty", []), "--from-cut", why="empty capture")
    rejected(reduction, "true-state", path, "999", why="cut 999 exceeds 9 groups")
    rejected(
        reduction, "--trace", path, "--lenient", why="--lenient requires --from-cut"
    )
    rejected(midtrace, "check", why="empty input")
    rejected(midtrace, "check", groups=["\n", " \n"], why="empty input")
    rejected(midtrace, "check", groups=["{\n"], why="line 1")
    rejected(midtrace, "check", "--cut", "1", groups=groups, why="unknown option --cut")
    rejected(midtrace, "replay-from", state, why="empty input")

    window = fixture("replication")[4:]  # Drop the entire bootstrap group.
    assert any(r["msg"].get("function") == "init_as_backup" for r in window)
    window_lines = reduce(pack("window", window), "--from-cut")
    groups = window_lines
    result = check(groups, "--backbone", "1", "--dump-witness", state)
    assert result["stats"]["probes"] > 0
    cli("replay-from", state, groups=groups)

    # The witness names only declared nodes, also inside envelopes.
    witness = json.loads(state.read_text())
    witness["nodes"][0]["votedFor"] = 999
    bad = args.output / "bad-witness.json"
    bad.write_text(json.dumps(witness))
    rejected(midtrace, "replay-from", bad, groups=groups, why="undeclared node id 999")

    # A window starting with an `init_as_backup` hook, whose source is pre-cut.
    groups = reduce(pack("init-window", fixture("replication")[12:]), "--from-cut")
    check(groups, "--dump-witness", state)
    cli("replay-from", state, groups=groups)

    # Mid-group starts and a truncated tail: strictly rejected, but trimmed with
    # `--lenient`. `[:-1]` ends after an optional `commit`, so it is complete.
    for name, events in (
        ("mid-group-5", fixture("replication")[5:]),
        ("mid-group-6", fixture("replication")[6:]),
        ("truncated-tail", fixture("replication")[:17]),
        ("complete-tail", fixture("replication")[:-1]),
    ):
        path = pack(name, events)
        if name != "complete-tail":
            proc = subprocess.run(
                [reduction, "--trace", path, "--from-cut"],
                capture_output=True,
                timeout=60,
            )
            assert proc.returncode == 2, (name, proc)
        groups = reduce(path, "--from-cut", "--lenient")
        check(groups, "--dump-witness", state)
        cli("replay-from", state, groups=groups)
    # A stale witness file is removed, and none written, when the verdict is invalid.
    assert state.exists()
    window[0]["msg"]["state"]["committable_indices"] = [1, 2, 3]
    result = check(
        reduce(pack("mutated", window), "--from-cut"),
        "--dump-witness",
        state,
        verdict="invalidBounded",
    )
    assert result["assumptions"]["retried"]
    assert not state.exists(), "a stale witness survived an invalid check"

    def event(function, node, state=None, **fields):
        return {
            "function": function,
            "state": {"node_id": node, **(state or {})},
            **fields,
        }

    def capture(name, events):
        return pack(
            name, ({"pid": "driver", "m_ts": i, "msg": e} for i, e in enumerate(events))
        )

    def window_groups(name, events, *options):
        """The groups of a window without bootstrap, in causal order."""
        return reduce(capture(name, events), "--from-cut", *options)

    def append_entries(prev, last, commit):
        return dict(
            msg="append_entries",
            term=3,
            prev_idx=prev,
            prev_term=3,
            idx=last,
            leader_commit_idx=commit,
            term_of_idx=3,
            contains_new_view=False,
        )

    # Only the pre-cut payload can supply the signature at absolute log index 1050.
    pre_cut = [
        event(
            "recv_append_entries",
            "1",
            {"last_idx": 1000, "current_view": 3, "leadership_state": "Follower"},
            from_node_id="0",
            packet=append_entries(1000, 1050, 1050),
        ),
        event(
            "send_append_entries_response",
            "1",
            to_node_id="0",
            packet=dict(
                msg="append_entries_response",
                term=3,
                success="OK",
                last_log_idx=1050,
            ),
        ),
        event("nomination", "1", {"commit_idx": 1050}),
    ]
    # Terms are unbounded: one above 2^62 is decoded and replayed exactly.
    big = 4611686018427387905
    groups = window_groups(
        "large-term",
        [
            event(
                "recv_request_vote_response",
                "0",
                {"current_view": big},
                from_node_id="1",
                packet={
                    "msg": "request_vote_response",
                    "term": big,
                    "vote_granted": False,
                },
            ),
            event("nomination", "1", {"current_view": big + 3}),
        ],
    )
    check(groups, "--dump-witness", state)
    assert json.loads(state.read_text())["nodes"][0]["currentTerm"] == big
    cli("replay-from", state, groups=groups)

    # A blank node name cannot be mapped to a model node.
    blank = capture("blank", [event("nomination", "")])
    rejected(reduction, "--trace", blank, "--from-cut", why="blank")
    line = json.loads(groups[0])
    line["node"] = ""
    rejected(midtrace, "check", groups=[json.dumps(line)], why="blank")

    groups = window_groups("pre-cut-append-50", pre_cut)
    result = check(groups, "--dump-witness", state)
    assert not result["assumptions"]["retried"], result
    assert result["stats"]["gapEnumerated"] == 0, result
    cli("replay-from", state, groups=groups)

    # Node 0 is at term 2 at the cut, so its pre-cut term-3 append breaks only
    # the initial message invariant.
    groups = window_groups(
        "stale-sender", [event("nomination", "0", {"current_view": 2}), *pre_cut]
    )
    check(groups, "--invariant", "off", "--dump-witness", state)
    cli("replay-from", "--invariant", "off", state, groups=groups)
    result = check(groups, "--invariant", "on", verdict="invalidBounded")
    assert "message_invariants: 0 -> 1" in result["detail"], result

    # No post-cut sends on this channel: two deliveries require two initial slots.
    receive = event(
        "recv_request_vote_response",
        "0",
        from_node_id="1",
        packet={"msg": "request_vote_response", "term": 3, "vote_granted": False},
    )
    groups = window_groups("two-deliveries", [receive, receive])
    result = check(groups, "--Q", "1", "--retry", "1", verdict="invalidBounded")
    assert not result["assumptions"]["retried"], result
    result = check(groups, "--Q", "1", "--dump-witness", state)
    assert result["assumptions"]["retried"]
    witness = json.loads(state.read_text())
    assert len(witness["network"]) == 2
    cli("replay-from", state, groups=groups)
    witness["network"][0]["target"] = 999
    bad.write_text(json.dumps(witness))
    rejected(midtrace, "replay-from", bad, groups=groups, why="undeclared node id 999")

    # The first bound is refuted without a solver. The retry needs a solver;
    # if it is unavailable its unknown must not become an invalid verdict.
    result = check(groups, "--Q", "1", "--solver", state / "missing", verdict="unknown")
    assert result["assumptions"]["retried"]

    # Pigeonhole: 13 deliveries cannot fit 12 interchangeable initial slots.
    # Without symmetry breaking the solver refutes all 12! slot orders.
    groups = window_groups("pigeonhole", [receive] * 13)
    result = check(groups, "--Q", "12", "--retry", "1", verdict="invalidBounded")
    assert result["stats"]["smtLines"] > 0, result

    # A solver that never answers is killed at `--timeout`, and the verdict is unknown.
    sleepy = args.output / "sleepy-solver"
    sleepy.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys, time\n"
        "open(sys.argv[0] + '.pid', 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    sleepy.chmod(0o755)
    start = time.monotonic()
    result = check(
        window_lines,
        "--timeout",
        "1",
        "--retry",
        "0",
        "--solver",
        sleepy,
        verdict="unknown",
    )
    assert time.monotonic() - start < 10, "the solver time limit was not enforced"
    assert "timed out after 1 s" in result["detail"], result
    pid = int(Path(f"{sleepy}.pid").read_text())
    try:
        os.kill(pid, 0)
        raise AssertionError(f"solver process {pid} survived its time limit")
    except ProcessLookupError:
        pass

    # A solver that floods standard error before answering must not deadlock.
    noisy = args.output / "noisy-solver"
    noisy.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('x' * (1 << 20))\n"
        "sys.stderr.flush()\n"
        "for line in sys.stdin:\n"
        "    if '(check-sat' in line:\n"
        "        print('unknown', flush=True)\n"
    )
    noisy.chmod(0o755)
    result = check(
        window_lines,
        "--retry",
        "0",
        "--solver",
        noisy,
        verdict="unknown",
    )
    assert "stderr: xxx" in result["detail"], result

    leader = {"current_view": 3, "leadership_state": "Leader"}
    events = [
        event("tick", "1"),
        event(
            "replicate",
            "0",
            {**leader, "last_idx": 1, "commit_idx": 0, "committable_indices": []},
        ),
        *(
            event("replicate_entry", "0", seqno=i, globally_committable=True)
            for i in range(2, 5)
        ),
        event(
            "nomination",
            "0",
            {"last_idx": 4, "commit_idx": 0, "committable_indices": [2, 4]},
        ),
    ]
    check(window_groups("three-signatures", events))
    for indices in ([], [2], [4, 2]):
        events[-1]["state"]["committable_indices"] = indices
        check(
            window_groups("missing-signatures", events),
            "--retry",
            "0",
            verdict="invalidBounded",
        )

    def send(prev, last):
        packet = append_entries(prev, last, 128)
        return event("send_append_entries", "0", to_node_id="1", packet=packet)

    tick = event("tick", "0", {**leader, "last_idx": 128, "commit_idx": 128})
    # Both tick actions request end index 128; observe the heartbeat before the batch.
    groups = window_groups(
        "reordered-sends",
        [tick, send(61, 61), tick, send(128, 128), send(61, 128)],
    )
    result = check(groups, "--dump-witness", state)
    log = json.loads(state.read_text())["nodes"][0]["log"]
    assert result["stats"]["gapProbed"] > 0
    assert [entry["term"] for entry in log[60:]] == [3] * 68
    cli("replay-from", state, groups=groups)

    # An orphan follow-on become_leader in a mid-run lenient window must be trimmed
    # rather than halting reduction and dropping later groups on that node.
    orphan_leader = window_groups(
        "orphan-become-leader",
        [
            event("become_candidate", "0"),
            event("become_leader", "0"),
            event(
                "send_append_entries",
                "0",
                to_node_id="1",
                packet=append_entries(1, 1, 1),
            ),
            event("nomination", "0"),
            event("nomination", "0"),
            event("nomination", "1"),
        ],
        "--lenient",
    )
    result = check(orphan_leader)
    assert result["groups"] == 3, result

    # Stale witness files are removed even when check fails before solving (exit 2).
    stale = args.output / "stale-exit2.json"
    stale.write_text("STALE")
    rejected(midtrace, "check", "--dump-witness", stale, why="empty input")
    assert not stale.exists(), "stale witness survived exit 2"

    # A 1-group init_as_backup slice names only the joiner; declaring a silent peer
    # with --node lets it certify without fixing genesis membership.
    solo_init = window_groups(
        "solo-init",
        [
            event(
                "init_as_backup",
                "1",
                {
                    "current_view": 0,
                    "last_idx": 0,
                    "commit_idx": 0,
                    "leadership_state": "None",
                },
                seqno=2,
                view=2,
            ),
            event("become_follower", "1"),
        ],
    )
    check(solo_init, "--retry", "0", verdict="invalidBounded")
    result = check(solo_init, "--node", "0", "--dump-witness", state)
    assert result["declaredNodes"] == ["0", "1"] and result["bootstrap"] == []
    cli("replay-from", state, groups=solo_init)

    # Piping consensus-reduction into head must exit 0 under pipefail (no EPIPE exit 2).
    head_pipe = subprocess.run(
        [
            "bash",
            "-o",
            "pipefail",
            "-c",
            f'{shlex.quote(str(reduction))} --trace {shlex.quote(str(args.output / "replication.msgpack"))} | head -n 2 | {shlex.quote(str(midtrace))} check --solver {shlex.quote(str(args.solver))} --json',
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert head_pipe.returncode == 0, f"head pipe failed: {head_pipe.stderr}"
    assert json.loads(head_pipe.stdout)["verdict"] == "validCertified"


if __name__ == "__main__":
    main()
