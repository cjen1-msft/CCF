#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Matched operation streams for typed relational arrays, canonical cells, and stores."""

from collections import Counter
import argparse
import json
from pathlib import Path
import random
import re
from statistics import median
import subprocess
import time

from encoding_study import FULL_CYCLE, PROJECT, digest, save, solve


def helpers(root):
    path = root / "native-terms.json"
    source = PROJECT / "Prototype/LedgerSuiteTermsMain.lean"
    pending = [source]
    dependencies = {}
    while pending:
        current = pending.pop()
        name = str(current.relative_to(PROJECT))
        if name in dependencies:
            continue
        dependencies[name] = digest(current.read_bytes())
        for module in re.findall(r"^import\s+([A-Za-z0-9_.]+)\s*$", current.read_text(), re.M):
            target = PROJECT / (module.replace(".", "/") + ".lean")
            if target.is_file():
                pending.append(target)
    for name in ("lean-toolchain", "lake-manifest.json"):
        dependencies[name] = digest((PROJECT / name).read_bytes())
    existing = json.loads(path.read_text()) if path.exists() else {}
    if existing.get("dependency_hashes") != dependencies:
        result = subprocess.run(
            ["lake", "env", "lean", "--run", str(source.relative_to(PROJECT))],
            cwd=PROJECT, capture_output=True, text=True, check=True,
        )
        save(path, {"source_sha256": digest(source.read_bytes()), "dependency_hashes": dependencies,
                    "terms": json.loads(result.stdout)})
    data = json.loads(path.read_text())
    if data["source_sha256"] != digest(source.read_bytes()):
        raise ValueError("Native helper source changed after preparation")
    terms = data["terms"]
    header = terms["header"].removesuffix("(check-sat)\n")
    header += f'(define-sort Entry () {terms["entrySort"]})\n(define-sort Ledger () (Array Int Entry))\n'
    for definition in terms["definitions"]:
        mapping = {p["symbol"]: p["name"] for p in definition["params"]}
        body = re.sub(r"c_[A-Za-z0-9_]+", lambda m: mapping[m[0]], definition["body"])
        params = " ".join(f'({p["name"]} {p["sort"]})' for p in definition["params"])
        header += f'(define-fun {definition["name"]} ({params}) {definition["result"]} {body})\n'
    return header


def plan(workload, count, initial=16, regime="concrete", growing=False, axis="count", seed=0,
         negative=False, negative_position="first", batch_size=1, observe_all=False, equality_kind="paired",
         mixed_negative="final"):
    if count < 1 or initial < 0 or batch_size < 1 or seed < 0 or regime not in {"concrete", "symbolic"}:
        raise ValueError("Invalid workload dimensions")
    if workload != "append" and batch_size != 1:
        raise ValueError("Batch-size control is only for append")
    entries, initial_states, events, observations, distinct = {}, {}, [], [], []
    witness_states = {}

    def new_entry():
        index = len(entries)
        key = f"input_{index}"
        entries[key] = {"term": index + seed, "kind": "transaction", "value": index + seed + 7}
        return key

    def init(refs):
        state = f"state_{len(witness_states)}"
        initial_states[state] = list(refs)
        witness_states[state] = list(refs)
        return state

    def mutate(kind, before, entry=None, target=None):
        state = f"state_{len(witness_states)}"
        event = {"id": len(events), "kind": kind, "before": before, "after": state}
        if kind == "append":
            if isinstance(entry, list):
                event["entries"] = entry
                witness_states[state] = witness_states[before] + entry
            else:
                event["entry"] = entry
                witness_states[state] = witness_states[before] + [entry]
        else:
            event["target"] = target
            witness_states[state] = witness_states[before][:target]
        events.append(event)
        return state

    def compare(left, right, phase=None):
        index = len(events)
        events.append({"id": index, "kind": "equality", "left": left, "right": right, "result": f"equal_{index}"})
        expected = [entries[x] for x in witness_states[left]] == [entries[x] for x in witness_states[right]]
        observation = {"kind": "boolean", "result": f"equal_{index}", "expected": expected}
        if phase:
            observation["phase"] = phase
        observations.append(observation)

    if workload == "equality":
        length, pairs = (count, 1) if axis == "length" else (initial, count)
        if length == 0:
            raise ValueError("Main equality series requires a nonempty live range")
        for index in range(pairs):
            refs = [new_entry() for _ in range(length)]
            other = list(refs)
            if (axis == "count" and index % 2 == 1) or (axis == "length" and equality_kind == "unequal"):
                position = length - 1 if axis == "length" else (0, length // 2, length - 1)[(index // 2) % 3]
                other[position] = new_entry()
                distinct.append([refs[position], other[position]])
            compare(init(refs), init(other))
        # The length-axis companion includes both equal and unequal pairs.
        if axis == "length" and equality_kind == "paired":
            refs = [new_entry() for _ in range(length)]
            other = list(refs)
            other[length - 1] = new_entry()
            distinct.append([refs[-1], other[-1]])
            compare(init(refs), init(other))
    else:
        base = [new_entry() for _ in range(initial)]
        current = init(base)
        if workload == "append":
            for _ in range(count):
                payload = [new_entry() for _ in range(batch_size)]
                current = mutate("append", current, entry=payload[0] if batch_size == 1 else payload)
        elif workload == "rollback":
            if count > initial:
                raise ValueError("Rollback count exceeds starting length")
            for index in range(count):
                current = mutate("rollback", current, target=initial - index - 1)
        elif workload == "mixed":
            right = init(base)
            for _ in range(count):
                length = len(witness_states[current])
                x, y = new_entry(), new_entry()
                distinct.append([x, y])
                current = mutate("append", current, entry=x)
                right = mutate("append", right, entry=y)
                compare(current, right, "unequal")
                current = mutate("rollback", current, target=length)
                current = mutate("append", current, entry=y)
                compare(current, right, "regrowth")
                if not growing:
                    current = mutate("rollback", current, target=length)
                    right = mutate("rollback", right, target=length)
                    compare(current, right, "restored")
        else:
            raise ValueError("Unknown workload")
        observations.append({"kind": "length", "state": current, "expected": len(witness_states[current])})
        refs = witness_states[current]
        # Rollback uses one retained-cell read to hold observation demand fixed.
        positions = range(len(refs)) if workload == "append" or observe_all else range(min(1, len(refs)))
        for index in positions:
            observations.append({"kind": "entry", "state": current, "index": index, "entry": refs[index]})
    if negative:
        if workload in {"mixed", "equality"}:
            if workload == "mixed" and mixed_negative == "retained":
                if initial == 0:
                    raise ValueError("Retained-prefix mutation needs a nonempty prefix")
                next(o for o in observations if o["kind"] == "entry")["not_equal"] = True
            else:
                phase = mixed_negative if workload == "mixed" and mixed_negative != "final" else None
                chosen = next(o for o in reversed(observations)
                              if o["kind"] == "boolean" and (phase is None or o.get("phase") == phase))
                chosen["expected"] = not chosen["expected"]
        elif workload == "append":
            position = (initial if negative_position == "first" else initial + count * batch_size - 1
                        if negative_position == "last" else 0)
            if negative_position == "retained" and initial == 0:
                raise ValueError("Retained-prefix negative needs a nonempty initial ledger")
            chosen = next(o for o in observations if o["kind"] == "entry" and o["index"] == position)
            chosen["not_equal"] = True
        elif initial > count:
            next(o for o in observations if o["kind"] == "entry")["not_equal"] = True
        else:
            next(o for o in observations if o["kind"] == "length")["expected"] += 1
    return {
        "schema": "ledger-suite-stream/v1", "workload": workload, "count": count,
        "initial_length": initial, "regime": regime, "growing": growing, "axis": axis,
        "seed": seed, "negative": negative, "expected": "unsat" if negative else "sat",
        "negative_position": negative_position,
        "mixed_negative": mixed_negative,
        "batch_size": batch_size,
        "observation_scope": "all-live" if observe_all or workload == "append" else "one-live",
        "equality_kind": equality_kind if workload == "equality" and axis == "length" else "alternating",
        "scope": "pure ledger operations; no Raft guards, target/signature search, queues, or auxiliary state",
        "entries": entries, "distinct": distinct, "initial_states": initial_states,
        "events": events, "observations": observations,
        "capacity": max(map(len, witness_states.values())),
        "operation_counts": dict(Counter(e["kind"] for e in events)),
        "appended_entries": sum(len(e["entries"]) if "entries" in e else 1 for e in events if e["kind"] == "append"),
    }


def oracle(stream):
    entries = stream["entries"]
    states = {name: [entries[x] for x in refs] for name, refs in stream["initial_states"].items()}
    values = {}
    if any(entries[a] == entries[b] for a, b in stream["distinct"]):
        raise ValueError("Oracle witness violates a distinct-input condition")
    for event in stream["events"]:
        if event["kind"] == "append":
            payload = event.get("entries", [event["entry"]] if "entry" in event else [])
            states[event["after"]] = states[event["before"]] + [entries[name] for name in payload]
        elif event["kind"] == "rollback":
            states[event["after"]] = states[event["before"]][:event["target"]]
        else:
            values[event["result"]] = states[event["left"]] == states[event["right"]]
    matches = []
    for item in stream["observations"]:
        if item["kind"] == "boolean":
            equal = values[item["result"]] == item["expected"]
        elif item["kind"] == "length":
            equal = len(states[item["state"]]) == item["expected"]
        else:
            equal = states[item["state"]][item["index"]] == entries[item["entry"]]
            if item.get("not_equal"):
                equal = not equal
        matches.append(equal)
    return {"states": states, "booleans": values, "observation_matches": matches, "all_match": all(matches)}


def literal(value):
    term, kind = value["term"], value["kind"]
    if kind == "transaction":
        return f'(make_transaction {term} {value["value"]})'
    if kind == "signature":
        return f"(make_signature {term})"
    if kind in ("configuration", "retirement"):
        return f'(make_{kind} {term} (_ bv{value["value"]} 2))'
    raise ValueError(f"Unknown entry kind: {kind}")


def conjunction(expressions):
    return "(and true " + " ".join(expressions) + ")"


def ordered_items(values, prefix):
    if any(not re.fullmatch(prefix + r"_\d+", name) for name in values):
        raise ValueError(f"Expected generated {prefix} identifiers")
    return sorted(values.items(), key=lambda item: int(item[0].rsplit("_", 1)[1]))


def encode(stream, representation, header, order_seed=None, freeze_inputs=False, projections=None):
    if representation not in ("R", "C", "A"):
        raise ValueError("Unknown representation")
    declarations, groups, state_lengths, cells, producers = [], {}, {}, {}, {}
    dependencies = {}

    def declare(name, sort):
        declarations.append(f"(declare-const {name} {sort})\n")

    for name, value in ordered_items(stream["entries"], "input"):
        declare(name, "Entry")
        conditions = [f"(entry_valid {name})"]
        if stream["regime"] == "concrete" or freeze_inputs:
            conditions.append(f"(= {name} {literal(value)})")
        groups["source_" + name] = conjunction(conditions)
        dependencies["source_" + name] = []
    for index, (left, right) in enumerate(stream["distinct"]):
        name = f"distinct_{index}"
        groups[name] = f"(not (= {left} {right}))"
        dependencies[name] = ["source_" + left, "source_" + right]

    def length(state):
        return "length_" + state

    def read(state, index):
        if representation == "C":
            return cells[state][index]
        return f"(select {state} {index})"

    def new_state(state, size):
        state_lengths[state] = size
        declare(length(state), "Int")
        if representation == "C":
            cells[state] = [f"cell_{state}_{i}" for i in range(size)]
            for cell in cells[state]:
                declare(cell, "Entry")
            valid = [f"(entry_valid {cell})" for cell in cells[state]]
        else:
            declare(state, "Ledger")
            valid = [f"(live_valid {state} {length(state)})"]
        return [f"(<= 0 {length(state)})", f'(<= {length(state)} {stream["capacity"]})', *valid]

    for state, refs in ordered_items(stream["initial_states"], "state"):
        group = "initial_" + state
        conditions = new_state(state, len(refs))
        conditions += [f"(= {length(state)} {len(refs)})"]
        conditions += [f"(= {read(state, i)} {ref})" for i, ref in enumerate(refs)]
        groups[group] = conjunction(conditions)
        dependencies[group] = ["source_" + ref for ref in refs]
        producers[state] = group
    for event in stream["events"]:
        group = f'step_{event["id"]}'
        if event["kind"] == "equality":
            left, right, result = event["left"], event["right"], event["result"]
            declare(result, "Bool")
            if representation == "C":
                size = min(state_lengths[left], state_lengths[right])
                equality = conjunction([f"(= {read(left, i)} {read(right, i)})" for i in range(size)])
            else:
                equality = f"(live_equal {left} {right} {length(left)})"
            groups[group] = f"(= {result} (and (= {length(left)} {length(right)}) {equality}))"
            dependencies[group] = [producers[left], producers[right]]
            producers[result] = group
            continue
        before, after = event["before"], event["after"]
        previous_size = state_lengths[before]
        payload_refs = event.get("entries", [event["entry"]] if "entry" in event else [])
        size = previous_size + len(payload_refs) if event["kind"] == "append" else min(previous_size, event["target"])
        conditions = new_state(after, size)
        dependencies[group] = [producers[before]]
        producers[after] = group
        if event["kind"] == "append":
            conditions.append(f"(= {length(after)} (+ {length(before)} {len(payload_refs)}))")
            dependencies[group].extend("source_" + entry for entry in payload_refs)
            if representation == "R":
                payload = f'payload_{event["id"]}'
                declare(payload, "Ledger")
                conditions += [f"(= (select {payload} {i}) {entry})" for i, entry in enumerate(payload_refs)]
                conditions.append(f"(splice {before} {length(before)} {payload} {len(payload_refs)} {length(before)} {after})")
            elif representation == "A":
                expression = before
                for index, entry in enumerate(payload_refs):
                    position = length(before) if index == 0 else f"(+ {length(before)} {index})"
                    expression = f"(store {expression} {position} {entry})"
                conditions.append(f"(= {after} {expression})")
            else:
                conditions += [f"(= {read(after, i)} {read(before, i)})" for i in range(previous_size)]
                conditions += [f"(= {read(after, previous_size+i)} {entry})" for i, entry in enumerate(payload_refs)]
        else:
            target = event["target"]
            conditions.append(f"(= {length(after)} (ite (<= {length(before)} {target}) {length(before)} {target}))")
            if representation == "C":
                conditions += [f"(= {read(after, i)} {read(before, i)})" for i in range(size)]
            else:
                # Whole-array equality here implements retaining the identical storage,
                # not comparison of two logical ledgers.
                conditions.append(f"(= {after} {before})")
        groups[group] = conjunction(conditions)
    for index, item in enumerate(stream["observations"]):
        name = f"observe_{index}"
        if item["kind"] == "boolean":
            expression = f'(= {item["result"]} {str(item["expected"]).lower()})'
            parents = [producers[item["result"]]]
        elif item["kind"] == "length":
            expression = f'(= {length(item["state"])} {item["expected"]})'
            parents = [producers[item["state"]]]
        else:
            expression = f'(= {read(item["state"], item["index"])} {item["entry"]})'
            if item.get("not_equal"):
                expression = f"(not {expression})"
            parents = [producers[item["state"]], "source_" + item["entry"]]
        groups[name] = expression
        dependencies[name] = parents
    if projections is not None:
        equalities = []
        for state, values in projections["states"].items():
            equalities.append(f"(= {length(state)} {len(values)})")
            equalities.extend(f"(= {read(state, i)} {literal(value)})" for i, value in enumerate(values))
        equalities.extend(f"(= {name} {str(value).lower()})" for name, value in projections["booleans"].items())
        groups["projection_difference"] = f"(not {conjunction(equalities)})"
        dependencies["projection_difference"] = list(producers.values())
    if order_seed is not None:
        random.Random(order_seed).shuffle(declarations)
    body = header + "".join(declarations)
    script = body + "".join(f"(assert (! {expression} :named {name}))\n" for name, expression in groups.items())
    return {
        "script": script, "header": body, "groups": groups, "dependencies": dependencies,
        "representation": representation, "ledger_states": len(state_lengths),
        "live_cells_across_states": sum(state_lengths.values()), "smt_bytes": len(script.encode()),
        "state_lengths": state_lengths, "cell_symbols": cells,
    }


def closure(encoded, core):
    selected = set(core)
    selected.update(name for name in encoded["groups"] if name.startswith("distinct_"))
    pending = list(selected)
    while pending:
        for parent in encoded["dependencies"][pending.pop()]:
            if parent not in selected:
                selected.add(parent)
                pending.append(parent)
    return [name for name in encoded["groups"] if name in selected]


def run(args):
    root = args.output
    root.mkdir(parents=True, exist_ok=args.resume)
    header = helpers(args.helpers)
    configuration = {
        "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        "source_hash": digest(Path(__file__).read_bytes()),
        "solver": subprocess.run([args.z3, "--version"], capture_output=True, text=True, check=True).stdout.strip(),
        "native_helper_sha256": digest(header.encode()),
        "native_dependency_hashes": json.loads((args.helpers / "native-terms.json").read_text())["dependency_hashes"],
    }
    if args.resume:
        previous = json.loads((root / "configuration.json").read_text())
        if previous.get("native_helper_sha256") != configuration["native_helper_sha256"]:
            raise ValueError("Native helper definitions changed before resume")
        for key, value in previous["arguments"].items():
            if key not in {"resume", "compact"} and configuration["arguments"].get(key) != value:
                raise ValueError(f"Resume argument changed: {key}")
        save(root / f"resume-{time.time_ns()}.json", configuration)
        (root / f"resume-source-{time.time_ns()}.py").write_bytes(Path(__file__).read_bytes())
    else:
        save(root / "configuration.json", configuration)
        (root / "source.py").write_bytes(Path(__file__).read_bytes())
    rows = json.loads((root / "samples.json").read_text()) if args.resume and (root / "samples.json").exists() else []
    if args.resume and rows:
        probe = rows[0]
        old_stream = json.loads((root / f'case-{probe["count"]}-{probe["negative"]}' / "stream.json").read_text())
        initial = probe["count"] + 1 if args.initial_from_count else args.initial
        probe_stream = plan(args.workload, probe["count"], initial, args.regime, args.growing,
                            args.axis, args.seed, probe["negative"], args.negative_position,
                            args.batch_size, args.observe_all, args.equality_kind, args.mixed_negative)
        if args.initialization_only:
            probe_stream.update(events=[], observations=[], operation_counts={}, initialization_only=True)
        if probe_stream != old_stream:
            raise ValueError("Resumed generator changes the saved probe stream")
        regenerated = encode(probe_stream, args.representation, header, args.order_seed)
        if digest(regenerated["script"].encode()) != probe["smt_sha256"]:
            raise ValueError("Resumed encoder does not reproduce the saved probe script")
    completed = {(r["count"], r["negative"], r["sample"]) for r in rows}
    stopped = {negative: any(r["negative"] == negative and r["result"]["status"] not in ("sat", "unsat")
                             for r in rows) for negative in (False, True)}
    for count in sorted(set(args.counts)):
        for negative in (False, True):
            if (args.polarity == "positive" and negative) or (args.polarity == "negative" and not negative):
                continue
            if args.initialization_only and negative:
                continue
            if stopped[negative]:
                continue
            if all((count, negative, sample) in completed for sample in range(args.samples)):
                continue
            case_started = time.perf_counter()
            initial = count + 1 if args.initial_from_count else args.initial
            stream = plan(args.workload, count, initial, args.regime, args.growing, args.axis,
                          args.seed, negative, args.negative_position, args.batch_size, args.observe_all,
                          args.equality_kind, args.mixed_negative)
            if args.initialization_only:
                stream["events"] = []
                stream["observations"] = []
                stream["operation_counts"] = {}
                stream["initialization_only"] = True
            expected = oracle(stream)
            if expected["all_match"] == negative:
                raise ValueError("Reference stream has the wrong expected verdict")
            planning_seconds = time.perf_counter() - case_started
            start = time.perf_counter()
            encoded = encode(stream, args.representation, header, args.order_seed)
            emission_seconds = time.perf_counter() - start
            base = root / f"case-{count}-{negative}"
            save(base / "stream.json", stream)
            save(base / "oracle.json", expected)
            save(base / "encoding.json", encoded)
            for sample in range(args.samples):
                if (count, negative, sample) in completed:
                    continue
                query = FULL_CYCLE
                if args.solver_seed:
                    query = f"(set-option :smt.random_seed {args.solver_seed})\n" + query
                result = solve(base / f"run-{sample}", [encoded["script"]], query, args.z3, args.limit, args.profile)
                row = {
                    "count": count, "negative": negative, "sample": sample,
                    "representation": args.representation, "regime": args.regime,
                    "workload": args.workload, "growing": args.growing, "axis": args.axis,
                    "initial": args.initial, "profile": args.profile,
                    "actual_initial": initial, "scope": stream["scope"],
                    "operations": stream["operation_counts"], "capacity": stream["capacity"],
                    "appended_entries": stream["appended_entries"],
                    "final_live_lengths": {
                        state: len(values) for state, values in expected["states"].items()
                        if state not in {e["before"] for e in stream["events"] if e["kind"] != "equality"}
                    },
                    "stream_sha256": digest(json.dumps(stream, sort_keys=True).encode()),
                    "smt_sha256": digest(encoded["script"].encode()), "smt_bytes": encoded["smt_bytes"],
                    "groups": len(encoded["groups"]), "ledger_states": encoded["ledger_states"],
                    "live_cells_across_states": encoded["live_cells_across_states"],
                    "emission_seconds": emission_seconds, "result": result,
                    "planning_seconds": planning_seconds,
                    "first_sample_case_wall_seconds": time.perf_counter() - case_started if sample == 0 else None,
                }
                rows.append(row)
                save(root / "samples.json", rows)
                if args.compact:
                    from compact_ledger_artifacts import compress_file
                    for artifact in (base / "encoding.json", base / f"run-{sample}/request.json",
                                     base / f"run-{sample}/query.smt2"):
                        record = compress_file(artifact)
                        if record is not None:
                            save(artifact.with_suffix(artifact.suffix + ".compression.json"), record)
                print(args.workload, args.representation, args.regime, count, negative,
                      sample, result["status"], result.get("solver_seconds"), flush=True)
                if result["status"] in ("sat", "unsat") and result["status"] != stream["expected"]:
                    raise ValueError("Candidate disagrees with the reference")
                if result["status"] == "error":
                    raise ValueError("Solver error")
                if result["status"] not in ("sat", "unsat"):
                    stopped[negative] = True
                    break
                if result["status"] == "unsat" and not set(result["core"]) <= encoded["groups"].keys():
                    raise ValueError("Unknown source-core labels")
    totals = []
    for count in sorted({row["count"] for row in rows}):
        for negative in (False, True):
            selected = [r for r in rows if r["count"] == count and r["negative"] == negative]
            if not selected:
                continue
            times = [r["result"].get("solver_seconds") for r in selected]
            complete = len(selected) == args.samples and all(t is not None for t in times)
            totals.append({
                "count": count, "negative": negative, "statuses": [r["result"]["status"] for r in selected],
                "median_seconds": median(times) if complete else None,
                "requested_samples": args.samples, "completed_samples": len([t for t in times if t is not None]),
            })
    save(root / "summary.json", totals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--helpers", type=Path, default=PROJECT / "Measurements/encoding-study/matched-suite")
    parser.add_argument("--z3", required=True)
    parser.add_argument("--workload", choices=["append", "rollback", "equality", "mixed"], required=True)
    parser.add_argument("--representation", choices=["R", "C", "A"], required=True)
    parser.add_argument("--regime", choices=["concrete", "symbolic"], default="concrete")
    parser.add_argument("--polarity", choices=["both", "positive", "negative"], default="both")
    parser.add_argument("--counts", nargs="+", type=int)
    parser.add_argument("--initial", type=int)
    parser.add_argument("--initial-from-count", action="store_true")
    parser.add_argument("--observe-all", action="store_true")
    parser.add_argument("--initialization-only", action="store_true")
    parser.add_argument("--axis", choices=["count", "length"], default="count")
    parser.add_argument("--equality-kind", choices=["equal", "unequal", "paired"], default="equal")
    parser.add_argument("--mixed-negative", choices=["final", "unequal", "regrowth", "retained"], default="final")
    parser.add_argument("--growing", action="store_true")
    parser.add_argument("--samples", type=int, default=1)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--order-seed", type=int)
    parser.add_argument("--solver-seed", type=int, default=0)
    parser.add_argument("--negative-position", choices=["first", "last", "retained"], default="first")
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--limit", type=float, default=60)
    args = parser.parse_args()
    if args.initial is None:
        args.initial = 64 if args.workload == "rollback" else 16
    if args.counts is None:
        args.counts = [1, 2, 4, 8, 12, 16, 24, 32, 48, 64] if args.workload == "rollback" else [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
    if args.samples < 1 or args.limit <= 1 or args.seed < 0 or any(n < 1 for n in args.counts):
        parser.error("Positive sizes, samples, and a limit greater than one second required")
    if args.initial_from_count and args.workload != "rollback":
        parser.error("--initial-from-count is a rollback-only control")
    if args.initialization_only and args.workload != "equality":
        parser.error("--initialization-only is an equality control")
    if args.initialization_only and args.polarity == "negative":
        parser.error("Initialization-only controls have no contradictory observation")
    if args.workload == "rollback" and not args.initial_from_count and max(args.counts) > args.initial:
        parser.error("Rollback count exceeds the fixed initial length")
    run(args)


if __name__ == "__main__":
    main()
