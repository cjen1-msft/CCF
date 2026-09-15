#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Derive source-local receive-batch evidence and compare generic/specialised emission."""

from collections import defaultdict
import argparse
import json
from pathlib import Path
import subprocess
import time

from encoding_study import PROJECT, digest, save
from native_origin import reduce_raw
from native_reduction import native_document
from native_run import validate_encoding


def plans_for(case, document, rows, certificate):
    groups = {}
    for group in certificate["preprocessing"]["groups"]:
        if group["rule"] == "group-append-entries-receive":
            groups[group["provenance"][0]["line"]] = group["provenance"]
    receives = defaultdict(list)
    for index, item in enumerate(document["instructions"]):
        if item["kind"] != "receiveAppendEntries":
            continue
        provenance = case["selected_provenance"][index]["provenance"]
        lines = {p["line"] for p in provenance if p.get("function") == "recv_append_entries"}
        if len(lines) != 1:
            raise ValueError("Receive lacks a unique raw source event")
        receives[next(iter(lines))].append(index)
    plans, decisions = [], []
    for line, indices in receives.items():
        if not 1 <= line <= len(rows) or line not in groups:
            raise ValueError("Receive source is outside the audited grouping")
        message = rows[line - 1]["msg"]
        if message["function"] != "recv_append_entries" or message["packet"]["msg"] != "raft_append_entries":
            raise ValueError("Receive provenance points at the wrong event")
        packet, before = message["packet"], message["state"]
        source, destination = message["from_node_id"], before["node_id"]
        group = groups[line]
        response_line = group[-1]["line"]
        if not 1 <= response_line <= len(rows) or group[-1]["function"] != "send_append_entries_response":
            raise ValueError("Audited receive group has no response")
        response = rows[response_line - 1]["msg"]
        executions = [p["line"] for p in group if p["function"] == "execute_append_entries_sync"]
        single_thread = all(rows[p["line"] - 1].get("thread_id") == rows[line - 1].get("thread_id")
                            for p in group)
        reason = "unsupported path or incomplete source-local evidence"
        selected = []
        if (single_thread and response["function"] == "send_append_entries_response"
            and response["packet"]["msg"] == "raft_append_entries_response"
            and response["state"]["node_id"] == destination and response["to_node_id"] == source
            and before["leadership_state"] == "Follower"
            and before["current_view"] == packet["term"]
            and response["state"]["current_view"] == packet["term"]
            and response["packet"]["term"] == packet["term"]
            and response["packet"]["last_log_idx"] == response["state"]["last_idx"]):
            start, finish = packet["prev_idx"], packet["idx"]
            append = (
                start == before["last_idx"] and finish > start
                and response["packet"]["success"] == "OK"
                and response["state"]["last_idx"] == finish
                and len(indices) == finish - start
                and len(executions) == len(indices)
                and before["commit_idx"] <= start
                and all(case["action_kinds"][i] is None or i in indices
                        for i in range(indices[0], indices[-1] + 1))
            )
            reject = (
                before["last_idx"] < start and len(indices) == 1
                and response["packet"]["success"] == "FAIL"
                and response["state"]["last_idx"] == before["last_idx"]
            )
            for offset, index in enumerate(indices):
                item = document["instructions"][index]
                observed = document["instructions"][index - 1] if index else {}
                pattern = observed.get("value", {})
                expected_previous = start + offset if append else start
                execution_line = executions[offset] if append else line
                local = rows[execution_line - 1]["msg"]["state"]
                eligible = (
                    (append or reject)
                    and item["source"] == source and item["destination"] == destination
                    and observed.get("kind") == "queuePattern" and observed.get("index") == 0
                    and observed.get("source") == source and observed.get("destination") == destination
                    and pattern.get("kind") == "appendEntriesRequest"
                    and pattern.get("prevLogIndex") == expected_previous
                    and pattern.get("term") == packet["term"]
                    and pattern.get("leaderCommit") == packet["leader_commit_idx"]
                    and (not append or pattern.get("entriesLength") == 1)
                    and isinstance(pattern.get("entriesLength"), int)
                    and (not append or local["last_idx"] == expected_previous)
                )
                eligible = eligible and (
                    local["node_id"] == destination and local["leadership_state"] == "Follower"
                    and local["current_view"] == packet["term"]
                    and (not append or local["commit_idx"] <= expected_previous)
                )
                if not eligible:
                    selected = []
                    break
                selected.append({
                    "instruction": index, "source": source, "destination": destination,
                    "path": "appendAtEnd" if append else "rejectBeyondEnd",
                    "oldLength": local["last_idx"],
                    "previous": expected_previous, "term": packet["term"],
                    "entriesLength": pattern["entriesLength"],
                    "leaderCommit": pattern["leaderCommit"],
                    "previousTerm": packet["prev_term"] if offset == 0 else None,
                    "oldCommit": local["commit_idx"],
                    "sourceLine": line, "responseLine": response_line, "executionLine": execution_line,
                })
            if selected:
                reason = "complete append-at-end batch" if append else "beyond-end rejection"
                plans.extend(selected)
        decisions.append({
            "source_line": line, "response_line": response_line, "instructions": indices,
            "selected": len(selected), "reason": reason,
        })
    return plans, decisions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--label", default="v2")
    args = parser.parse_args()
    manifest = json.loads((args.corpus / "manifest.json").read_text())
    envelopes = []
    evidence = args.corpus / "c" / f"evidence-{args.label}"
    evidence.mkdir(parents=True, exist_ok=False)
    for case in manifest:
        directory = args.corpus / "inputs" / case["name"]
        details = json.loads((directory / "encoding.json").read_text())
        raw = (directory / "source.ndjson").read_bytes()
        if digest(raw) != case["selected_source_sha256"]:
            raise ValueError("Source trace differs from the corpus")
        origin = reduce_raw(raw)
        complete = native_document(origin.trace, ["0"])
        start, stop = case["start_instruction"], case["stop_instruction"]
        expected = {**complete, "instructions": complete["instructions"][start:stop]}
        if (details["input"] != expected or
            digest(json.dumps(expected, sort_keys=True).encode()) != case["document_sha256"] or
            case["selected_provenance"] != origin.certificate["steps"][start:stop]):
            raise ValueError("Model document and source provenance are not aligned")
        rows = [json.loads(line) for line in raw.splitlines()]
        plans, decisions = plans_for(case, details["input"], rows, origin.certificate)
        envelope = {"input": details["input"], "plans": plans}
        envelopes.append(envelope)
        save(evidence / f'{case["name"]}.json', {"envelope": envelope, "decisions": decisions})
        print(case["name"], "plans", len(plans), flush=True)
    for mode in ("generic", "specialised"):
        started = time.perf_counter()
        output = subprocess.run(
            ["lake", "env", "lean", "--run", "Prototype/TraceEvidenceMain.lean", "--batch", mode],
            cwd=PROJECT, input=json.dumps(envelopes, sort_keys=True, separators=(",", ":")),
            text=True, capture_output=True, check=True,
        )
        encodings = json.loads(output.stdout)
        for case, envelope, details in zip(manifest, envelopes, encodings, strict=True):
            validate_encoding(envelope["input"], details)
            if not envelope["plans"]:
                original = json.loads((args.corpus / "inputs" / case["name"] / "encoding.json").read_text())
                if details["script"] != original["script"]:
                    raise ValueError("No-plan fallback is not the original encoding")
            directory = args.corpus / "variants" / f"evidence-{mode}-{args.label}" / case["name"]
            directory.mkdir(parents=True, exist_ok=False)
            save(directory / "encoding.json", details)
            (directory / "original.smt2").write_text(details["script"])
        save(args.corpus / "variants" / f"evidence-{mode}-{args.label}" / "preparation.json", {
            "module": "TraceEvidenceMain", "mode": mode,
            "source_sha256": digest((PROJECT / "Prototype/TraceEvidenceMain.lean").read_bytes()),
            "dependencies": {
                "scripts/study_trace_evidence.py": digest(Path(__file__).read_bytes()),
                "Prototype/AppendReceive.lean": digest((PROJECT / "Prototype/AppendReceive.lean").read_bytes()),
                "Sparse/NativeParameterizedFrame.lean": digest(
                    (PROJECT / "Sparse/NativeParameterizedFrame.lean").read_bytes()),
            },
            "evidence_sha256": digest(json.dumps(envelopes, sort_keys=True).encode()),
            "evidence_files": {
                case["name"]: {"path": str((evidence / f'{case["name"]}.json').relative_to(args.corpus)),
                               "sha256": digest((evidence / f'{case["name"]}.json').read_bytes()),
                               "plans": len(envelope["plans"])}
                for case, envelope in zip(manifest, envelopes, strict=True)
            },
            "wall_seconds": time.perf_counter() - started,
        })


if __name__ == "__main__":
    main()
