#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Native-array vote and term-update prototype, not the full trace validator.

Input is reduced Model observations/actions. The Lean correspondence lives in
Sparse/NativeArrayVote.lean; this JSON adapter and SMT printer are trusted.
Transaction IDs are natural numbers. Log and queue point indices are zero-based.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from native_packets import PACKET_FIELDS, packet_declarations
from native_queue_arrays import QueueArray
from Shared.solver import ValidationError, find_cvc5, run_solver

ROLES = ("none", "follower", "preVoteCandidate", "candidate", "leader")
SOLVER_ARGUMENTS = ("--arrays-exp", "--mbqi")


def fields(value: object, expected: set[str], where: str) -> dict:
    """Reject malformed objects, including unsupported fields."""
    if not isinstance(value, dict) or set(value) != expected:
        raise ValidationError(f"{where}: expected fields {sorted(expected)}")
    return value


def natural(value: object, where: str) -> int:
    """Reject bools and negative, fractional, or string-encoded naturals."""
    if type(value) is not int or value < 0:
        raise ValidationError(f"{where}: expected a natural number")
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Do not let JSON duplicate keys silently discard recorded facts."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


class Encoder:
    """Keep flat references to named array versions across ordered events."""

    def __init__(self, document: object):
        document = fields(document, {"nodes", "bootstrap", "instructions"}, "trace")
        nodes = document["nodes"]
        if (
            not isinstance(nodes, list)
            or not nodes
            or any(not isinstance(node, str) or not node for node in nodes)
            or len(set(nodes)) != len(nodes)
        ):
            raise ValidationError("nodes: expected nonempty, distinct identity strings")
        self.nodes = {node: f"n{i}" for i, node in enumerate(nodes)}
        self.positions = {node: i for i, node in enumerate(nodes)}
        self.width = len(nodes)
        self.bootstrap = self.mask(document["bootstrap"], "bootstrap")
        if not document["bootstrap"]:
            raise ValidationError("bootstrap: Model requires a bootstrap leader member")
        if not isinstance(document["instructions"], list):
            raise ValidationError("instructions: expected a list")
        self.instructions = document["instructions"]
        self.lines = [
            "(set-logic ALL)",
            f"(declare-datatype Node ({' '.join(f'({node})' for node in self.nodes.values())}))",
            f"(define-sort Nodes () (_ BitVec {self.width}))",
            f"(declare-datatype Role ({' '.join(f'(r_{role})' for role in ROLES)}))",
            "(declare-datatype Content ((transaction (tx Int)) (signature) "
            "(reconfiguration (members Nodes)) (retiredCommitted (retired Nodes))))",
            "(declare-datatype Entry ((entry (term Int) (content Content))))",
            "(define-fun entryDomain ((e Entry)) Bool "
            "(and (<= 0 (term e)) (=> ((_ is transaction) (content e)) (<= 0 (tx (content e))))))",
        ]
        self.lines.extend(packet_declarations())
        self.refs = {}
        for name, sort in (
            ("allocated", "Bool"),
            ("role", "Role"),
            ("newFollower", "Bool"),
            ("logLength", "Int"),
            ("commit", "Int"),
            ("currentTerm", "Int"),
            ("logs", "(Array Int Entry)"),
        ):
            self.refs[name] = name + "_0"
            self.lines.append(f"(declare-const {name}_0 (Array Node {sort}))")
        self.log_domains: set[str] = set()
        self.queues: dict[tuple[str, str], QueueArray] = {}
        self.configuration_indices: dict[tuple[str, ...], str] = {}
        self.election_snapshots: dict[tuple[str, ...], tuple[str, str]] = {}
        self.event = 0
        self.clause = 0
        for node in self.nodes.values():
            for name in ("logLength", "commit", "currentTerm"):
                self.lines.append(f"(assert (<= 0 (select {self.refs[name]} {node})))")

    def node(self, value: object, where: str) -> str:
        """Resolve all identities through the explicit exhaustive universe."""
        if not isinstance(value, str) or value not in self.nodes:
            raise ValidationError(f"{where}: undeclared node {value!r}")
        return self.nodes[value]

    def mask(self, value: object, where: str) -> str:
        """Encode a set without imposing a fixed node-count limit."""
        if not isinstance(value, list):
            raise ValidationError(f"{where}: expected an identity list")
        mask = 0
        for node in value:
            self.node(node, where)
            mask |= 1 << self.positions[node]
        return f"(_ bv{mask} {self.width})"

    def assertion(self, formula: str) -> None:
        """Name clauses by reduced-input position for diagnostic attribution."""
        self.lines.append(
            f"(assert (! {formula} :named event_{self.event}_{self.clause}))"
        )
        self.clause += 1

    def read(self, name: str, node: str) -> str:
        """Absent nodes have Model fresh-state values, not arbitrary fields."""
        cell = f"(select {self.refs[name]} {node})"
        if name == "allocated":
            return cell
        default = {
            "role": "r_none",
            "newFollower": "true",
            "logLength": "0",
            "commit": "0",
            "currentTerm": "0",
        }
        return f"(ite {self.read('allocated', node)} {cell} {default[name]})"

    def log(self, node: str) -> str:
        """Constrain natural-valued payloads only within this node's live log."""
        log = f"(select {self.refs['logs']} {node})"
        if node not in self.log_domains:
            self.log_domains.add(node)
            entry = f"(select {log} k)"
            self.assertion(
                f"(forall ((k Int)) (=> (and (<= 0 k) (< k {self.read('logLength', node)})) "
                f"(entryDomain {entry})))"
            )
        return log

    def entry(self, value: object) -> str:
        """Print an exact typed entry; inactive datatype selectors stay unused."""
        value = fields(value, {"term", "content"}, f"instruction {self.event} entry")
        term = natural(value["term"], "entry.term")
        content = value["content"]
        if content == "signature":
            encoded = "signature"
        elif isinstance(content, dict) and len(content) == 1:
            kind, argument = next(iter(content.items()))
            if kind == "transaction":
                encoded = f"(transaction {natural(argument, 'transaction')})"
            elif kind in {"reconfiguration", "retiredCommitted"}:
                encoded = f"({kind} {self.mask(argument, kind)})"
            else:
                raise ValidationError(f"unsupported entry content: {kind}")
        else:
            raise ValidationError(
                "entry.content: expected signature or one typed payload"
            )
        return f"(entry {term} {encoded})"

    def log_key(self, node: str) -> tuple[str, ...]:
        return tuple(
            self.refs[field] for field in ("logs", "logLength", "commit", "allocated")
        ) + (node,)

    def configuration_index(self, node: str) -> str:
        """Share the reader only while its observed state components are unchanged."""
        key = self.log_key(node)
        if key in self.configuration_indices:
            return self.configuration_indices[key]
        log = self.log(node)
        length, commit = self.read("logLength", node), self.read("commit", node)
        current, clip = (f"{name}_{node}_{self.event}" for name in ("current", "clip"))
        for name in (current, clip):
            self.lines.append(f"(declare-const {name} Int)")
        self.assertion(f"(= {clip} (ite (< {commit} {length}) {commit} {length}))")
        config = lambda index: f"(content (select {log} (- {index} 1)))"
        self.assertion(
            f"(and (<= 0 {current}) (<= {current} {clip}) "
            f"(or (= {current} 0) ((_ is reconfiguration) {config(current)})))"
        )
        self.assertion(
            f"(forall ((k Int)) (=> (and (< {current} k) (<= k {clip})) "
            f"(not ((_ is reconfiguration) {config('k')}))))"
        )
        self.configuration_indices[key] = current
        return current

    def active_peer(self, node: str, candidates: str) -> None:
        current = self.configuration_index(node)
        log, length = self.log(node), self.read("logLength", node)
        witness = f"active_witness_{node}_{self.event}"
        self.lines.append(f"(declare-const {witness} Int)")
        config = lambda index: f"(content (select {log} (- {index} 1)))"
        zero = f"(_ bv0 {self.width})"
        other = lambda mask: f"(distinct (bvand {mask} {candidates}) {zero})"
        self.assertion(
            f"(or (and (= {current} 0) {other(self.bootstrap)}) "
            f"(and (<= 1 {witness}) (<= {witness} {length}) (<= {current} {witness}) "
            f"((_ is reconfiguration) {config(witness)}) {other(f'(members {config(witness)})')}))"
        )

    def check_quorum(self, node: str) -> None:
        """Encode the proved current-index and active-peer characterizations."""
        self.assertion(self.read("allocated", node))
        self.assertion(f"(= {self.read('role', node)} r_leader)")
        self.active_peer(node, f"(bvnot (_ bv{1 << int(node[1:])} {self.width}))")
        for name, sort, value in (
            ("role", "Role", "r_follower"),
            ("newFollower", "Bool", "true"),
        ):
            self.store(name, sort, node, value)

    def store(self, name: str, sort: str, node: str, value: str) -> None:
        old = self.refs[name]
        self.refs[name] = f"{name}_{self.event + 1}"
        self.lines.append(f"(declare-const {self.refs[name]} (Array Node {sort}))")
        self.assertion(f"(= {self.refs[name]} (store {old} {node} {value}))")

    def election_snapshot(self, node: str) -> tuple[str, str]:
        key = self.log_key(node)
        if key in self.election_snapshots:
            return self.election_snapshots[key]
        log, length = self.log(node), self.read("logLength", node)
        signature, index, term = (
            f"{name}_{node}_{self.event}"
            for name in ("signature", "last_index", "last_term")
        )
        for name in (signature, index, term):
            self.lines.append(f"(declare-const {name} Int)")
        self.assertion(
            f"(and (<= 0 {signature}) (<= {signature} {length}) "
            f"(or (= {signature} 0) ((_ is signature) (content (select {log} (- {signature} 1))))))"
        )
        self.assertion(
            f"(forall ((k Int)) (=> (and (< {signature} k) (<= k {length})) "
            f"(not ((_ is signature) (content (select {log} (- k 1)))))))"
        )
        commit = self.read("commit", node)
        self.assertion(
            f"(= {index} (ite (< {commit} {signature}) {signature} {commit}))"
        )
        self.assertion(
            f"(= {term} (ite (and (< 0 {index}) (<= {index} {length})) "
            f"(term (select {log} (- {index} 1))) 0))"
        )
        self.election_snapshots[key] = index, term
        return index, term

    def emit_queue(self, queue: QueueArray) -> None:
        for command in queue.commands:
            if command.startswith("(assert "):
                self.assertion(command[len("(assert ") : -1])
            else:
                self.lines.append(command)
        queue.commands.clear()

    def queue(self, source: str, destination: str) -> QueueArray:
        key = source, destination
        if key not in self.queues:
            queue = QueueArray(f"q_{destination}_{source}", "Packet")
            self.queues[key] = queue
            self.emit_queue(queue)
            packet = f"(select {queue.cells} (+ {queue.head} i))"
            self.assertion(
                f"(forall ((i Int)) (=> (and (<= 0 i) (< i {queue.length})) "
                f"(and (= (messageSource {packet}) {source}) (messageDomain {packet}))))"
            )
        return self.queues[key]

    def request_vote(self, source: str, destination: str, pre_vote: bool) -> None:
        self.assertion(self.read("allocated", source))
        self.assertion(self.read("allocated", destination))
        role = "preVoteCandidate" if pre_vote else "candidate"
        self.assertion(f"(= {self.read('role', source)} r_{role})")
        self.assertion(f"(distinct {source} {destination})")
        self.active_peer(source, f"(_ bv{1 << int(destination[1:])} {self.width})")
        index, term = self.election_snapshot(source)
        kind = "requestPreVote" if pre_vote else "requestVoteRequest"
        packet = f"(msg_{kind} {self.read('currentTerm', source)} {term} {index} {source} {destination})"
        queue = self.queue(source, destination)
        queue.send(packet)
        self.emit_queue(queue)

    def packet(self, value: object) -> str:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("kind"), str)
            or value["kind"] not in PACKET_FIELDS
        ):
            raise ValidationError("queuePoint: expected a supported packet kind")
        kind = value["kind"]
        schema = PACKET_FIELDS[kind]
        fields(
            value,
            {"kind", *(name for name, _ in schema if name != "entriesLength")},
            f"instruction {self.event} packet",
        )
        arguments = []
        for name, sort in schema:
            if sort == "Node":
                argument = self.node(value[name], f"packet.{name}")
            elif sort == "Bool":
                if type(value[name]) is not bool:
                    raise ValidationError(f"packet.{name}: expected a bool")
                argument = str(value[name]).lower()
            elif sort == "(Array Int Entry)":
                if not isinstance(value[name], list):
                    raise ValidationError("packet.entries: expected an entry list")
                entries = [self.entry(entry) for entry in value[name]]
                argument = f"observed_entries_{self.event}"
                self.lines.append(f"(declare-const {argument} (Array Int Entry))")
                for index, entry in enumerate(entries):
                    self.assertion(f"(= (select {argument} {index}) {entry})")
            elif name == "entriesLength":
                argument = str(len(value["entries"]))
            else:
                argument = str(natural(value[name], f"packet.{name}"))
            arguments.append(argument)
        return f"(msg_{kind} {' '.join(arguments)})"

    def update_term(self, source: str, destination: str) -> None:
        queue = self.queue(source, destination)
        selected = f"selected_{destination}_{source}_{self.event}"
        self.lines.append(f"(declare-const {selected} Packet)")
        self.assertion(f"(< 0 {queue.length})")
        self.assertion(f"(= {selected} (select {queue.cells} {queue.head}))")
        self.assertion(self.read("allocated", destination))
        self.assertion(
            f"(=> (messageNeedsSource {selected}) "
            f"{self.read('allocated', f'(messageSource {selected})')})"
        )
        term = f"(messageTerm {selected})"
        self.assertion(f"(< {self.read('currentTerm', destination)} {term})")
        for name, sort, value in (
            ("role", "Role", "r_follower"),
            ("currentTerm", "Int", term),
            ("newFollower", "Bool", "true"),
        ):
            self.store(name, sort, destination, value)

    def render(self) -> str:
        """Reject unsupported input rather than silently weakening the trace."""
        for self.event, instruction in enumerate(self.instructions):
            self.clause = 0
            if not isinstance(instruction, dict):
                raise ValidationError(f"instruction {self.event}: expected an object")
            kind = instruction.get("kind")
            supported = {
                "allocated",
                "role",
                "newFollower",
                "logLength",
                "commit",
                "currentTerm",
                "entry",
                "checkQuorum",
                "requestVote",
                "requestPreVote",
                "updateTerm",
                "queueLength",
                "queuePoint",
            }
            if not isinstance(kind, str) or kind not in supported:
                raise ValidationError(
                    f"instruction {self.event}: unsupported kind {kind!r}"
                )
            if kind in {
                "requestVote",
                "requestPreVote",
                "updateTerm",
                "queueLength",
                "queuePoint",
            }:
                expected = {"kind", "source", "destination"}
                if kind in {"queueLength", "queuePoint"}:
                    expected.add("value")
                if kind == "queuePoint":
                    expected.add("index")
                fields(instruction, expected, f"instruction {self.event}")
                source = self.node(
                    instruction["source"], f"instruction {self.event} source"
                )
                destination = self.node(
                    instruction["destination"], f"instruction {self.event} destination"
                )
                if kind in {"requestVote", "requestPreVote"}:
                    self.request_vote(source, destination, kind == "requestPreVote")
                elif kind == "updateTerm":
                    self.update_term(source, destination)
                else:
                    queue = self.queue(source, destination)
                    if kind == "queueLength":
                        queue.observe_length(
                            str(natural(instruction["value"], "queueLength"))
                        )
                    else:
                        queue.point(
                            str(natural(instruction["index"], "queuePoint index")),
                            self.packet(instruction["value"]),
                        )
                    self.emit_queue(queue)
                continue
            expected = {"kind", "node"}
            if kind != "checkQuorum":
                expected.add("value")
            if kind == "entry":
                expected.add("index")
            fields(instruction, expected, f"instruction {self.event}")
            node = self.node(instruction["node"], f"instruction {self.event}")
            if kind == "checkQuorum":
                self.check_quorum(node)
                continue
            value = instruction["value"]
            if kind in {"allocated", "newFollower"}:
                if type(value) is not bool:
                    raise ValidationError(f"instruction {self.event}: expected a bool")
                value = str(value).lower()
            elif kind == "role":
                if not isinstance(value, str) or value not in ROLES:
                    raise ValidationError(
                        f"instruction {self.event}: unknown role {value!r}"
                    )
                value = "r_" + value
            elif kind in {"logLength", "commit", "currentTerm"}:
                value = str(natural(value, f"instruction {self.event}"))
            else:
                index = natural(instruction["index"], f"instruction {self.event} index")
                value = self.entry(value)
                self.assertion(f"(< {index} {self.read('logLength', node)})")
                self.assertion(f"(= (select {self.log(node)} {index}) {value})")
                continue
            self.assertion(f"(= {self.read(kind, node)} {value})")
        return "\n".join(self.lines + ["(check-sat)", ""])


def encode(document: object) -> str:
    """Compile one reduced trace without enumerating log positions."""
    return Encoder(document).render()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--cvc5", type=Path)
    args = parser.parse_args()
    try:
        document = json.loads(
            args.trace.read_text(encoding="utf-8"), object_pairs_hook=unique_object
        )
        script = encode(document)
        cvc5 = find_cvc5(args.cvc5)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        formula = args.output_dir / "trace.smt2"
        formula.write_text(script, encoding="ascii")
        result = run_solver(
            cvc5, formula, args.output_dir, "trace", extra_arguments=SOLVER_ARGUMENTS
        )
    except (ValidationError, OSError, ValueError) as error:
        parser.exit(2, f"native-array prototype: {error}\n")
    print(json.dumps({"status": result.status, "solver_ms": result.wall_time_ms}))


if __name__ == "__main__":
    main()
