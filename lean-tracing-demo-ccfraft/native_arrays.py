#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Native-array control-action prototype, not the full trace validator.

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
MEMBERSHIP_STATES = (
    "active",
    "retirementOrdered",
    "retirementSigned",
    "retirementCompleted",
    "retiredCommitted",
)
PEER_INDICES = ("sentIndex", "matchIndex")
PRE_VOTE_STATUSES = ("capable", "enabled")
GLOBAL_FIELDS = {
    "submittedTxIds": "(Array Int Bool)",
    "hasJoined": "Nodes",
    "preVoteStatus": "(Array Node PreVoteStatus)",
    "retirementCompleted": "(Array Node Nodes)",
}
NODE_FIELDS = {
    "allocated": ("Bool", None),
    "role": ("Role", "r_none"),
    "newFollower": ("Bool", "true"),
    "logLength": ("Int", "0"),
    "commit": ("Int", "0"),
    "currentTerm": ("Int", "0"),
    "logs": ("(Array Int Entry)", None),
    "sentIndex": ("(Array Node Int)", "((as const (Array Node Int)) 0)"),
    "matchIndex": ("(Array Node Int)", "((as const (Array Node Int)) 0)"),
    "votedFor": ("OptionalNode", "noNode"),
    "votesGranted": ("Nodes", "(_ bv0 {width})"),
    "preVotesGranted": ("Nodes", "(_ bv0 {width})"),
    "membershipState": ("MembershipState", "m_active"),
    "retirementIndex": ("OptionalNat", "noNat"),
    "retirementCommittableIndex": ("OptionalNat", "noNat"),
    "retiredCommittedIndex": ("OptionalNat", "noNat"),
}
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


def boolean(value: object, where: str) -> str:
    if type(value) is not bool:
        raise ValidationError(f"{where}: expected a bool")
    return str(value).lower()


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
            f"(declare-datatype MembershipState ({' '.join(f'(m_{state})' for state in MEMBERSHIP_STATES)}))",
            "(declare-datatype OptionalNode ((noNode) (someNode (nodeValue Node))))",
            "(declare-datatype OptionalNat ((noNat) (someNat (natValue Int))))",
            "(declare-datatype PreVoteStatus ((p_capable) (p_enabled)))",
            "(declare-datatype Content ((transaction (tx Int)) (signature) "
            "(reconfiguration (members Nodes)) (retiredCommitted (retired Nodes))))",
            "(declare-datatype Entry ((entry (term Int) (content Content))))",
            "(define-fun entryDomain ((e Entry)) Bool "
            "(and (<= 0 (term e)) (=> ((_ is transaction) (content e)) (<= 0 (tx (content e))))))",
        ]
        self.lines.extend(packet_declarations())
        self.refs = {name: name + "_0" for name in NODE_FIELDS}
        self.declared_fields: set[str] = set()
        self.global_refs: dict[str, str] = {}
        self.log_domains: set[str] = set()
        self.queues: dict[tuple[str, str], QueueArray] = {}
        self.configuration_indices: dict[tuple[str, ...], str] = {}
        self.signature_indices: dict[tuple[str, ...], str] = {}
        self.election_snapshots: dict[tuple[str, ...], tuple[str, str]] = {}
        self.event = 0
        self.clause = 0

    def ensure_field(self, name: str) -> None:
        """Introduce one initial column; later reads keep all intervening stores."""
        if name in self.declared_fields:
            return
        self.declared_fields.add(name)
        sort = NODE_FIELDS[name][0]
        initial = name + "_0"
        self.lines.append(f"(declare-const {initial} (Array Node {sort}))")
        if sort == "Int":
            for node in self.nodes.values():
                self.lines.append(f"(assert (<= 0 (select {initial} {node})))")
        elif name in PEER_INDICES:
            self.lines.append(
                f"(assert (forall ((node Node) (peer Node)) "
                f"(<= 0 (select (select {initial} node) peer))))"
            )
        elif sort == "OptionalNat":
            value = f"(select {initial} node)"
            self.lines.append(
                f"(assert (forall ((node Node)) "
                f"(=> ((_ is someNat) {value}) (<= 0 (natValue {value})))))"
            )

    def node(self, value: object, where: str) -> str:
        """Resolve all identities through the explicit exhaustive universe."""
        if not isinstance(value, str) or value not in self.nodes:
            raise ValidationError(f"{where}: undeclared node {value!r}")
        return self.nodes[value]

    def global_field(self, name: str) -> str:
        if name not in self.global_refs:
            symbol = f"global_{name}_0"
            self.global_refs[name] = symbol
            self.lines.append(f"(declare-const {symbol} {GLOBAL_FIELDS[name]})")
            if name == "submittedTxIds":
                self.lines.append("(declare-const submitted_limit_0 Int)")
                self.assertion("(<= 0 submitted_limit_0)")
                self.assertion(
                    f"(forall ((tx Int)) (=> (or (< tx 0) (<= submitted_limit_0 tx)) "
                    f"(not (select {symbol} tx))))"
                )
        return self.global_refs[name]

    def observe_global(self, kind: str, instruction: dict) -> None:
        expected = {"kind", "value"}
        if kind in {"preVoteStatus", "retirementCompleted"}:
            expected.add("node")
        elif kind == "submittedTxId":
            expected.add("txId")
        fields(instruction, expected, f"instruction {self.event}")
        name = "submittedTxIds" if kind == "submittedTxId" else kind
        observed = self.global_field(name)
        value = instruction["value"]
        if kind == "submittedTxId":
            tx_id = natural(instruction["txId"], "submittedTxId.txId")
            observed = f"(select {observed} {tx_id})"
            value = boolean(value, f"instruction {self.event}")
        else:
            if kind != "hasJoined":
                node = self.node(instruction["node"], f"instruction {self.event} node")
                observed = f"(select {observed} {node})"
            if kind == "preVoteStatus":
                if not isinstance(value, str) or value not in PRE_VOTE_STATUSES:
                    raise ValidationError(f"preVoteStatus: unknown value {value!r}")
                value = "p_" + value
            else:
                value = self.mask(value, kind)
        self.assertion(f"(= {observed} {value})")

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
        self.ensure_field(name)
        cell = f"(select {self.refs[name]} {node})"
        if name == "allocated":
            return cell
        default = NODE_FIELDS[name][1]
        if default is None:
            raise ValueError(f"{name} has no fresh-state scalar read")
        return f"(ite {self.read('allocated', node)} {cell} {default.format(width=self.width)})"

    def log(self, node: str) -> str:
        """Constrain natural-valued payloads only within this node's live log."""
        self.ensure_field("logs")
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

    def active_peer(
        self,
        node: str,
        candidates: str,
        upper: str | None = None,
        alternative: str = "false",
    ) -> None:
        current = self.configuration_index(node)
        log, length = self.log(node), self.read("logLength", node)
        witness = f"active_witness_{node}_{self.event}"
        self.lines.append(f"(declare-const {witness} Int)")
        config = lambda index: f"(content (select {log} (- {index} 1)))"
        zero = f"(_ bv0 {self.width})"
        other = lambda mask: f"(distinct (bvand {mask} {candidates}) {zero})"
        upper = length if upper is None else upper
        self.assertion(
            f"(or {alternative} (and (= {current} 0) {other(self.bootstrap)}) "
            f"(and (<= 1 {witness}) (<= {witness} {length}) (<= {current} {witness}) "
            f"(<= {witness} {upper}) "
            f"((_ is reconfiguration) {config(witness)}) {other(f'(members {config(witness)})')}))"
        )

    def check_quorum(self, node: str) -> None:
        """Encode the proved current-index and active-peer characterizations."""
        self.assertion(self.read("allocated", node))
        self.assertion(f"(= {self.read('role', node)} r_leader)")
        self.active_peer(node, f"(bvnot (_ bv{1 << int(node[1:])} {self.width}))")
        for name, value in (
            ("role", "r_follower"),
            ("newFollower", "true"),
        ):
            self.store(name, node, value)

    def store(self, name: str, node: str, value: str) -> None:
        self.ensure_field(name)
        sort = NODE_FIELDS[name][0]
        old = self.refs[name]
        self.refs[name] = f"{name}_{self.event + 1}"
        self.lines.append(f"(declare-const {self.refs[name]} (Array Node {sort}))")
        self.assertion(f"(= {self.refs[name]} (store {old} {node} {value}))")

    def signature_index(self, node: str) -> str:
        key = self.log_key(node)
        if key in self.signature_indices:
            return self.signature_indices[key]
        log, length = self.log(node), self.read("logLength", node)
        signature = f"signature_{node}_{self.event}"
        self.lines.append(f"(declare-const {signature} Int)")
        self.assertion(
            f"(and (<= 0 {signature}) (<= {signature} {length}) "
            f"(or (= {signature} 0) ((_ is signature) (content (select {log} (- {signature} 1))))))"
        )
        self.assertion(
            f"(forall ((k Int)) (=> (and (< {signature} k) (<= k {length})) "
            f"(not ((_ is signature) (content (select {log} (- k 1)))))))"
        )
        self.signature_indices[key] = signature
        return signature

    def election_snapshot(self, node: str) -> tuple[str, str]:
        key = self.log_key(node)
        if key in self.election_snapshots:
            return self.election_snapshots[key]
        log, length = self.log(node), self.read("logLength", node)
        signature = self.signature_index(node)
        index, term = (
            f"{name}_{node}_{self.event}" for name in ("last_index", "last_term")
        )
        for name in (index, term):
            self.lines.append(f"(declare-const {name} Int)")
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

    def campaign(self, node: str, pre_vote: bool) -> None:
        self.assertion(self.read("allocated", node))
        role = self.read("role", node)
        self.assertion(
            f"(or (= {role} r_follower) (= {role} r_preVoteCandidate) (= {role} r_candidate))"
        )
        self.assertion(
            f"(distinct {self.read('membershipState', node)} m_retiredCommitted)"
        )
        status = "p_enabled" if pre_vote else "p_capable"
        self.assertion(
            f"(= (select {self.global_field('preVoteStatus')} {node}) {status})"
        )
        self_bit = f"(_ bv{1 << int(node[1:])} {self.width})"
        retired = f"(select {self.global_field('retirementCompleted')} {node})"
        alternative = f"(distinct (bvand {retired} {self_bit}) (_ bv0 {self.width}))"
        self.active_peer(node, self_bit, self.signature_index(node), alternative)
        if pre_vote:
            self.store("role", node, "r_preVoteCandidate")
            self.store("preVotesGranted", node, self_bit)
        else:
            term = f"(+ {self.read('currentTerm', node)} 1)"
            for field, value in (
                ("role", "r_candidate"),
                ("currentTerm", term),
                ("votedFor", f"(someNode {node})"),
                ("votesGranted", self_bit),
                ("preVotesGranted", f"(_ bv0 {self.width})"),
            ):
                self.store(field, node, value)

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
                argument = boolean(value[name], f"packet.{name}")
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
        for name, value in (
            ("role", "r_follower"),
            ("currentTerm", term),
            ("newFollower", "true"),
            ("votedFor", "noNode"),
            ("preVotesGranted", f"(_ bv0 {self.width})"),
        ):
            self.store(name, destination, value)

    def observation_value(self, kind: str, value: object) -> str:
        sort = NODE_FIELDS[kind][0]
        if sort == "Bool":
            return boolean(value, f"instruction {self.event}")
        if sort in {"Role", "MembershipState"}:
            choices, prefix = (
                (ROLES, "r") if sort == "Role" else (MEMBERSHIP_STATES, "m")
            )
            if not isinstance(value, str) or value not in choices:
                raise ValidationError(
                    f"instruction {self.event}: unknown {kind} {value!r}"
                )
            return f"{prefix}_{value}"
        if sort == "Nodes":
            return self.mask(value, kind)
        if sort == "OptionalNode":
            return "noNode" if value is None else f"(someNode {self.node(value, kind)})"
        if sort == "OptionalNat":
            return "noNat" if value is None else f"(someNat {natural(value, kind)})"
        return str(natural(value, f"instruction {self.event}"))

    def render(self) -> str:
        """Reject unsupported input rather than silently weakening the trace."""
        for self.event, instruction in enumerate(self.instructions):
            self.clause = 0
            if not isinstance(instruction, dict):
                raise ValidationError(f"instruction {self.event}: expected an object")
            kind = instruction.get("kind")
            supported = (NODE_FIELDS.keys() - {"logs"}) | {
                "entry",
                "checkQuorum",
                "requestVote",
                "requestPreVote",
                "updateTerm",
                "timeout",
                "becomePreVoteCandidate",
                "queueLength",
                "queuePoint",
                "submittedTxId",
                "hasJoined",
                "preVoteStatus",
                "retirementCompleted",
            }
            if not isinstance(kind, str) or kind not in supported:
                raise ValidationError(
                    f"instruction {self.event}: unsupported kind {kind!r}"
                )
            if kind in {
                "submittedTxId",
                "hasJoined",
                "preVoteStatus",
                "retirementCompleted",
            }:
                self.observe_global(kind, instruction)
                continue
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
            if kind not in {"checkQuorum", "timeout", "becomePreVoteCandidate"}:
                expected.add("value")
            if kind == "entry":
                expected.add("index")
            if kind in PEER_INDICES:
                expected.add("peer")
            fields(instruction, expected, f"instruction {self.event}")
            node = self.node(instruction["node"], f"instruction {self.event}")
            if kind == "checkQuorum":
                self.check_quorum(node)
                continue
            if kind in {"timeout", "becomePreVoteCandidate"}:
                self.campaign(node, kind == "becomePreVoteCandidate")
                continue
            value = instruction["value"]
            if kind == "entry":
                index = natural(instruction["index"], f"instruction {self.event} index")
                value = self.entry(value)
                self.assertion(f"(< {index} {self.read('logLength', node)})")
                self.assertion(f"(= (select {self.log(node)} {index}) {value})")
                continue
            observed = self.read(kind, node)
            if kind in PEER_INDICES:
                peer = self.node(instruction["peer"], f"instruction {self.event} peer")
                observed = f"(select {observed} {peer})"
            self.assertion(f"(= {observed} {self.observation_value(kind, value)})")
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
