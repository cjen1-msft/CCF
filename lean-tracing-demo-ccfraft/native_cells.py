# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Experimental finite-cell lowering of native ledger and queue formulas.

All native guards and effects are compiled first. This backend then changes
entry-array and packet-array sorts, and every operation on them, into finite
products. It does not reconstruct a native array through lambdas or bridges.
"""

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import subprocess

import z3

from native_run import validate_encoding
from Shared.solver import ValidationError


@lru_cache(maxsize=16)
def native_normalizer(width):
    result = subprocess.run(
        ["lake", "env", "lean", "--run", "Prototype/CellsTemplateMain.lean", str(width)],
        cwd=Path(__file__).resolve().parent, text=True, capture_output=True, check=True,
    )
    template = z3.parse_smt2_string(result.stdout)[0]
    return template.arg(0), template.arg(1)


def trace_capacities(document, initial_state=None):
    """Conservative capacities from initial extents and the reduced action stream."""
    nodes = document["nodes"]
    bootstrap = document["bootstrap"]
    if len(bootstrap) != 1:
        raise ValidationError("Cells startup requires one explicitly bootstrapped node")
    leader = bootstrap[0]
    initial_length = None
    for item in document["instructions"]:
        if item["kind"] == "logLength" and item["node"] == leader:
            initial_length = item["value"]
            break
        if item["kind"] in {"appendEntries", "receiveAppendEntries", "clientRequest",
                            "changeConfiguration", "signCommittableMessages", "becomeLeader"}:
            raise ValidationError("Bootstrap log length is not observed before its first update")
    if initial_length is None:
        raise ValidationError("Missing initial bootstrap log length")
    if initial_state is None:
        initial_state = {
            "allocated": [leader], "ledger_lengths": {node: initial_length if node == leader else 0 for node in nodes},
            "queues": [],
        }
    if not isinstance(initial_state, dict) or set(initial_state) != {"allocated", "ledger_lengths", "queues"}:
        raise ValidationError("Initial cells state requires allocated, ledger_lengths, and queues")
    allocated = initial_state["allocated"]
    if (not isinstance(allocated, list) or len(set(allocated)) != len(allocated)
        or not set(allocated) <= set(nodes) or leader not in allocated):
        raise ValidationError("Initial allocated identities must be unique, declared, and include bootstrap")
    if not isinstance(initial_state["ledger_lengths"], dict):
        raise ValidationError("Initial ledger_lengths must be an object")
    lengths = dict(initial_state["ledger_lengths"])
    if set(lengths) != set(nodes) or any(type(n) is not int or n < 0 for n in lengths.values()):
        raise ValidationError("Initial ledger lengths must give a natural length for every declared node")
    if any(lengths[node] != 0 for node in nodes if node not in allocated):
        raise ValidationError("Unallocated nodes must have zero initial live length")
    if lengths[leader] != initial_length:
        raise ValidationError("Initial bootstrap length disagrees with its first trace observation")
    original_lengths = dict(lengths)
    peak = max(1, *lengths.values())
    packets = {}
    queue_tails = {(source, destination): 0 for source in nodes for destination in nodes}
    if not isinstance(initial_state["queues"], list):
        raise ValidationError("Initial queues must be a list")
    seen_queues = set()
    for queue in initial_state["queues"]:
        if not isinstance(queue, dict) or set(queue) != {"source", "destination", "length"}:
            raise ValidationError("Each initial queue needs source, destination, and length")
        route = (queue["source"], queue["destination"])
        if route not in queue_tails or route in seen_queues or type(queue["length"]) is not int or queue["length"] < 0:
            raise ValidationError("Invalid or duplicate initial queue extent")
        seen_queues.add(route)
        queue_tails[route] = queue["length"]
    if any(queue_tails.values()):
        raise ValidationError("This raw-trace C version requires empty initial queues; nonempty packet snapshots are not implemented")
    original_queues = dict(queue_tails)
    sends = {"requestVote", "requestPreVote", "appendEntries"}
    receives = {"receiveRequestVote", "receiveRequestVoteResponse",
                "receiveRequestPreVoteResponse", "receiveAppendEntries", "receiveAppendEntriesResponse"}
    observations = {"allocated", "joined", "role", "preVoteStatus", "membershipState",
                    "retirementIndex", "retirementCommittableIndex", "retiredCommittedIndex",
                    "currentTerm", "commit", "logLength", "queuePattern"}
    for index, item in enumerate(document["instructions"]):
        kind = item["kind"]
        if kind == "logLength":
            # Observations constrain the exact current length, not the capacity.
            lengths[item["node"]] = item["value"]
            peak = max(peak, item["value"])
        elif kind == "queuePattern":
            packets[item["source"], item["destination"], item["index"]] = item["value"]
        elif kind in sends:
            queue_tails[item["source"], item["destination"]] += 1
            packets.clear()
        elif kind in receives:
            source, destination = item["source"], item["destination"]
            if kind == "receiveAppendEntries":
                packet = packets.get((source, destination, 0))
                if packet is None or packet.get("kind") != "appendEntriesRequest":
                    raise ValidationError(f"Instruction {index}: no observed append payload extent")
                count = packet.get("entriesLength")
                if type(count) is not int or count < 0:
                    raise ValidationError(f"Instruction {index}: unknown append payload length")
                lengths[destination] += count
                peak = max(peak, lengths[destination], count)
            # A receive produces at most one reply in the native Model.
            queue_tails[destination, source] += 1
            packets.clear()
        elif kind in {"clientRequest", "signCommittableMessages", "changeConfiguration"}:
            node = item.get("node", item.get("source"))
            lengths[node] += 1
            peak = max(peak, lengths[node])
            packets.clear()
        elif kind in {"becomeLeader", "timeout", "becomePreVoteCandidate", "checkQuorum",
                      "advanceCommitIndex", "updateTerm"}:
            if kind == "becomeLeader":
                # Becoming leader appends a new-view entry after truncation.
                lengths[item["node"]] += 1
                peak = max(peak, lengths[item["node"]])
            packets.clear()
        elif kind not in observations:
            raise ValidationError(f"Cells capacity analysis does not support instruction {kind}")
    return {
        "nodes": len(nodes), "ledger": peak, "queue": max(1, max(queue_tails.values())),
        "initial_ledger_lengths": original_lengths,
        "initial_allocated": allocated,
        "initial_queues": [{"source": s, "destination": d, "length": n} for (s, d), n in original_queues.items()],
        "initial_queue_heads": 0,
        "assumptions": "explicit initial allocation and extents; zero queue origins; finite payload representation",
    }


class CellLowering:
    def __init__(self, width, ledger_capacity, queue_capacity):
        if min(width, ledger_capacity, queue_capacity) < 1:
            raise ValidationError("Positive cell capacities required")
        self.width, self.ledger_capacity, self.queue_capacity = width, ledger_capacity, queue_capacity
        self.sorts, self.operations, self.vectors = {}, {}, {}
        self.constants, self.cache = {}, {}
        self.type_counter = 0
        self.quantifiers = 0
        self.vector_selects = 0
        self.type_constraints = {}
        self.normalizations_removed = 0
        self.finite_range_rewrites = 0
        self.normalization_pattern, self.normalization_variable = native_normalizer(width)
        self.free_index_cache = {}
        self.normalizer_cache = {}

    def free_indices(self, expression):
        key = expression.get_id()
        if key in self.free_index_cache:
            return self.free_index_cache[key]
        if z3.is_var(expression):
            result = frozenset([z3.get_var_index(expression)])
        elif z3.is_quantifier(expression):
            count = expression.num_vars()
            result = frozenset(i - count for i in self.free_indices(expression.body()) if i >= count)
        elif z3.is_app(expression):
            result = frozenset().union(*(self.free_indices(child) for child in expression.children()))
        else:
            result = frozenset()
        self.free_index_cache[key] = result
        return result

    @staticmethod
    def entry_sort(sort):
        if sort.kind() != z3.Z3_DATATYPE_SORT or sort.num_constructors() != 1:
            return False
        ctor = sort.constructor(0)
        if str(ctor.name()) != "native_pair" or ctor.arity() != 2 or ctor.domain(0).kind() != z3.Z3_INT_SORT:
            return False
        content = ctor.domain(1)
        if content.kind() != z3.Z3_DATATYPE_SORT or content.num_constructors() != 2:
            return False
        unit = content.constructor(0).domain(0)
        rest = content.constructor(1).domain(0)
        if (unit.kind() != z3.Z3_DATATYPE_SORT or str(unit.constructor(0).name()) != "native_unit"
            or rest.kind() != z3.Z3_DATATYPE_SORT or rest.num_constructors() != 2
            or rest.constructor(0).domain(0).kind() != z3.Z3_INT_SORT):
            return False
        suffix = rest.constructor(1).domain(0)
        return (suffix.kind() == z3.Z3_DATATYPE_SORT and suffix.num_constructors() == 2
                and all(suffix.constructor(i).domain(0).kind() == z3.Z3_BV_SORT for i in (0, 1))
                and suffix.constructor(0).domain(0).size() == suffix.constructor(1).domain(0).size())

    @staticmethod
    def packet_sort(sort):
        if sort.kind() != z3.Z3_DATATYPE_SORT or sort.num_constructors() != 1:
            return False
        ctor = sort.constructor(0)
        return (str(ctor.name()) == "native_pair" and ctor.arity() == 2
                and ctor.domain(0).kind() == z3.Z3_DATATYPE_SORT
                and str(ctor.domain(0).constructor(0).name()) == "native_pair"
                and ctor.domain(1).kind() == z3.Z3_DATATYPE_SORT
                and str(ctor.domain(1).constructor(0).name()) == "native_left")

    @lru_cache(maxsize=None)
    def contains_cells(self, sort):
        if sort.kind() == z3.Z3_ARRAY_SORT:
            return (self.entry_sort(sort.range()) or self.packet_sort(sort.range())
                    or self.contains_cells(sort.range()))
        if sort.kind() == z3.Z3_DATATYPE_SORT:
            return any(self.contains_cells(sort.constructor(c).domain(i))
                       for c in range(sort.num_constructors())
                       for i in range(sort.constructor(c).arity()))
        return False

    def sort(self, old):
        key = old.get_id()
        if key in self.sorts:
            return self.sorts[key]
        if old.kind() == z3.Z3_ARRAY_SORT:
            value = self.sort(old.range())
            if old.domain().kind() == z3.Z3_INT_SORT and self.contains_cells(old):
                count = (self.ledger_capacity if self.entry_sort(old.range()) else
                         self.queue_capacity if self.packet_sort(old.range()) else self.width)
                name = f"Cells_{self.type_counter}"
                self.type_counter += 1
                datatype = z3.Datatype(name)
                datatype.declare(f"{name}_make", *[(f"{name}_{i}", value) for i in range(count)])
                new = datatype.create()
                self.vectors[key] = (new, count, old.range())
            else:
                new = z3.ArraySort(self.sort(old.domain()), value)
        elif old.kind() == z3.Z3_DATATYPE_SORT:
            name = f"Value_{self.type_counter}"
            self.type_counter += 1
            datatype = z3.Datatype(name)
            for c in range(old.num_constructors()):
                ctor = old.constructor(c)
                datatype.declare(f"{name}_c{c}", *[
                    (f"{name}_c{c}_f{i}", self.sort(ctor.domain(i))) for i in range(ctor.arity())
                ])
            new = datatype.create()
            for c in range(old.num_constructors()):
                self.operations[old.constructor(c).get_id()] = new.constructor(c)
                self.operations[old.recognizer(c).get_id()] = new.recognizer(c)
                for i in range(old.constructor(c).arity()):
                    self.operations[old.accessor(c, i).get_id()] = new.accessor(c, i)
        else:
            new = old
        self.sorts[key] = new
        return new

    @lru_cache(maxsize=None)
    def default(self, old):
        new = self.sort(old)
        if old.get_id() in self.vectors:
            _, count, value_sort = self.vectors[old.get_id()]
            return new.constructor(0)(*[self.default(value_sort)] * count)
        if old.kind() == z3.Z3_INT_SORT:
            return z3.IntVal(0)
        if old.kind() == z3.Z3_BOOL_SORT:
            return z3.BoolVal(False)
        if old.kind() == z3.Z3_BV_SORT:
            return z3.BitVecVal(0, old.size())
        if old.kind() == z3.Z3_ARRAY_SORT:
            return z3.K(self.sort(old.domain()), self.default(old.range()))
        if old.kind() == z3.Z3_DATATYPE_SORT:
            ctor = old.constructor(0)
            return new.constructor(0)(*[self.default(ctor.domain(i)) for i in range(ctor.arity())])
        raise ValidationError(f"Unsupported default sort {old}")

    def select(self, old_sort, array, index):
        self.vector_selects += 1
        vector, count, value_sort = self.vectors[old_sort.get_id()]
        index = z3.simplify(index)
        if z3.is_int_value(index):
            n = index.as_long()
            return (array.arg(n) if array.decl() == vector.constructor(0) else vector.accessor(0, n)(array)) if 0 <= n < count else self.default(value_sort)
        value = self.default(value_sort)
        for n in reversed(range(count)):
            value = z3.If(index == n, vector.accessor(0, n)(array), value)
        return value

    @lru_cache(maxsize=None)
    def contains_packets(self, old):
        if self.packet_sort(old):
            return True
        if old.kind() == z3.Z3_ARRAY_SORT:
            return self.contains_packets(old.range())
        return False

    def free_cells(self, old, name):
        new = self.sort(old)
        if old.get_id() in self.vectors:
            _, count, child = self.vectors[old.get_id()]
            return new.constructor(0)(*[self.free_cells(child, f"{name}_{i}") for i in range(count)])
        return z3.Const(name, new)

    def valid(self, old, value):
        new = self.sort(old)
        if self.entry_sort(old):
            term = new.accessor(0, 0)(value)
            content_old = old.constructor(0).domain(1)
            content_sort = self.sort(content_old)
            content = new.accessor(0, 1)(value)
            rest_old = content_old.constructor(1).domain(0)
            rest_sort = self.sort(rest_old)
            rest = content_sort.accessor(1, 0)(content)
            tx = rest_sort.accessor(0, 0)(rest)
            return z3.And(term >= 0, z3.Implies(
                z3.And(content_sort.recognizer(1)(content), rest_sort.recognizer(0)(rest)), tx >= 0))
        if old.get_id() in self.vectors:
            _, count, child = self.vectors[old.get_id()]
            return z3.And(*[self.valid(child, new.accessor(0, i)(value)) for i in range(count)])
        if old.kind() == z3.Z3_DATATYPE_SORT and self.contains_cells(old):
            return z3.And(*[
                z3.Implies(new.recognizer(c)(value), z3.And(*[
                    self.valid(old.constructor(c).domain(i), new.accessor(c, i)(value))
                    for i in range(old.constructor(c).arity())
                    if self.contains_cells(old.constructor(c).domain(i)) or self.entry_sort(old.constructor(c).domain(i))
                ])) for c in range(old.num_constructors())
            ])
        return z3.BoolVal(True)

    def normalized_source(self, expression):
        key = expression.get_id()
        if key in self.normalizer_cache:
            return self.normalizer_cache[key]
        self.normalizer_cache[key] = None
        if not self.entry_sort(expression.sort()) or expression.num_args() != 2:
            return None
        first = expression.arg(0)
        if not z3.is_app(first) or first.decl().kind() != z3.Z3_OP_ITE:
            return None
        source = None
        for term in first.children():
            if (z3.is_app(term) and term.decl().kind() == z3.Z3_OP_DT_ACCESSOR
                and term.num_args() == 1 and self.entry_sort(term.arg(0).sort())):
                source = term.arg(0)
                break
        if source is None:
            return None
        normalized = z3.substitute(self.normalization_pattern, (self.normalization_variable, source))
        result = source if z3.eq(normalized, expression) else None
        self.normalizer_cache[key] = result
        return result

    def visit(self, expression, bound=()):
        key = (expression.get_id(), tuple((i, bound[i].get_id()) for i in sorted(self.free_indices(expression))))
        if key in self.cache:
            return self.cache[key]
        if z3.is_var(expression):
            value = bound[z3.get_var_index(expression)]
        elif z3.is_quantifier(expression):
            if not expression.is_forall():
                raise ValidationError("Native cell lowering only supports universal quantifiers")
            variables = [z3.Const(f"bound_{expression.get_id()}_{i}", self.sort(expression.var_sort(i)))
                         for i in range(expression.num_vars())]
            body = self.visit(expression.body(), tuple(reversed(variables)) + bound)
            self.quantifiers += 1
            value = z3.ForAll(variables, body)
            if len(variables) == 1 and variables[0].sort().kind() == z3.Z3_INT_SORT:
                value = self.finite_forall(expression.body(), body, variables[0], bound, value)
        elif z3.is_int_value(expression) or z3.is_bv_value(expression) or z3.is_true(expression) or z3.is_false(expression):
            value = expression
        elif z3.is_app(expression):
            old_sort = expression.sort()
            self.sort(old_sort)
            kind = expression.decl().kind()
            normalized = self.normalized_source(expression)
            if normalized is not None:
                value = self.visit(normalized, bound)
                self.normalizations_removed += 1
            elif kind == z3.Z3_OP_UNINTERPRETED and expression.num_args() == 0:
                name = str(expression.decl().name())
                constant_key = (name, old_sort.get_id())
                if constant_key not in self.constants:
                    if old_sort.get_id() in self.vectors:
                        self.constants[constant_key] = self.free_cells(old_sort, f"cell_{name}")
                    else:
                        self.constants[constant_key] = z3.Const(name, self.sort(old_sort))
                value = self.constants[constant_key]
                if ((self.contains_cells(old_sort) or self.entry_sort(old_sort))
                    and not self.contains_packets(old_sort)):
                    condition = z3.simplify(self.valid(old_sort, value))
                    if not z3.is_true(condition):
                        self.type_constraints[condition.get_id()] = condition
            else:
                args = [self.visit(child, bound) for child in expression.children()]
                mapped = self.operations.get(expression.decl().get_id())
                if mapped is not None:
                    value = mapped(*args)
                elif kind == z3.Z3_OP_SELECT:
                    array_sort = expression.arg(0).sort()
                    self.sort(array_sort)
                    value = self.select(array_sort, args[0], args[1]) if array_sort.get_id() in self.vectors else z3.Select(*args)
                elif kind == z3.Z3_OP_STORE and old_sort.get_id() in self.vectors:
                    vector, count, _ = self.vectors[old_sort.get_id()]
                    value = vector.constructor(0)(*[
                        z3.If(args[1] == i, args[2], vector.accessor(0, i)(args[0])) for i in range(count)
                    ])
                elif kind == z3.Z3_OP_STORE:
                    value = z3.Store(*args)
                elif kind == z3.Z3_OP_CONST_ARRAY:
                    value = (self.sort(old_sort).constructor(0)(*[args[0]] * self.vectors[old_sort.get_id()][1])
                             if old_sort.get_id() in self.vectors else z3.K(self.sort(old_sort.domain()), args[0]))
                elif kind == z3.Z3_OP_EQ:
                    value = args[0] == args[1]
                elif kind == z3.Z3_OP_ITE:
                    value = z3.If(*args)
                elif kind == z3.Z3_OP_DISTINCT:
                    value = z3.Distinct(*args)
                else:
                    try:
                        value = expression.decl()(*args)
                    except z3.Z3Exception as error:
                        raise ValidationError(f"Unsupported native operation {expression.decl()}: {error}") from error
        else:
            raise ValidationError(f"Unsupported SMT expression: {expression}")
        self.cache[key] = value
        return value

    def finite_forall(self, original, translated, variable, bound, fallback):
        if z3.is_and(original) and z3.is_and(translated):
            return z3.And(*[
                self.finite_forall(a, b, variable, bound, z3.ForAll([variable], b))
                for a, b in zip(original.children(), translated.children(), strict=True)
            ])
        if not z3.is_or(original) or original.num_args() != 2 or not z3.is_not(original.arg(0)):
            return fallback
        pending = [original.arg(0).arg(0)]
        guards = []
        while pending:
            term = pending.pop()
            if z3.is_and(term):
                pending.extend(term.children())
            else:
                guards.append(term)
        is_index = lambda term: z3.is_var(term) and z3.get_var_index(term) == 0
        zero_lower = any(z3.is_le(g) and z3.is_int_value(g.arg(0)) and g.arg(0).as_long() == 0
                         and is_index(g.arg(1)) for g in guards)
        if not zero_lower:
            return fallback
        upper, inclusive = None, False
        for guard in guards:
            if z3.is_not(guard) and z3.is_le(guard.arg(0)) and is_index(guard.arg(0).arg(1)):
                upper, inclusive = guard.arg(0).arg(0), False
                break
            if z3.is_le(guard) and is_index(guard.arg(0)):
                upper, inclusive = guard.arg(1), True
                break
        if upper is None:
            return fallback
        pending = [upper]
        while pending:
            term = pending.pop()
            if is_index(term) or z3.is_quantifier(term):
                return fallback
            if z3.is_app(term):
                pending.extend(term.children())
        # The guard is retained. The original quantified expression remains the
        # fallback if its extent exceeds the enumerated range.
        extent = self.visit(upper, (variable,) + bound)
        cap = max(self.ledger_capacity, self.width)
        finite = z3.And(*[
            z3.substitute(translated, (variable, z3.IntVal(index)))
            for index in range(cap + (1 if inclusive else 0))
        ])
        self.finite_range_rewrites += 1
        return z3.If(extent <= cap, finite, fallback)


def lower(details, capacities, initial=True, progress=None):
    document = details["input"]
    validate_encoding(document, details)
    parsed = z3.parse_smt2_string(details["script"])
    if len(parsed) != len(details["clauses"]):
        raise ValidationError("Native parser changed the assertion count")
    lowering = CellLowering(capacities["nodes"], capacities["ledger"], capacities["queue"])
    converted = []
    for index, clause in enumerate(parsed):
        converted.append(lowering.visit(clause))
        if progress is not None and index % 50 == 0:
            progress(index, len(parsed), len(lowering.cache))
    constraints, source_constraints = [], []
    def initial_fact(name, expression):
        source_constraints.append((name, expression))
        constraints.append((name, lowering.visit(expression)))

    if initial:
        # Initial facts are new explicit trace-contract assumptions, never inferred
        # from a solver model or from later successful receives.
        constants, seen, pending = {}, set(), list(parsed)
        while pending:
            term = pending.pop()
            if term.get_id() in seen:
                continue
            seen.add(term.get_id())
            if z3.is_quantifier(term):
                pending.append(term.body())
            elif z3.is_app(term):
                if term.num_args() == 0 and term.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                    constants[str(term.decl().name())] = term
                pending.extend(term.children())
        allocated = constants.get("c_AIB_0")
        if allocated is None:
            raise ValidationError("Cannot locate native initial allocation column")
        for index, node in enumerate(document["nodes"]):
            initial_fact(f"cells_initial_allocated_{index}",
                         z3.Select(allocated, index) == z3.BoolVal(node in capacities["initial_allocated"]))
        for column, purpose in (("c_AII_3", "ledger"), ("c_AIAII_21", "queue-length"), ("c_AIAII_22", "queue-head")):
            old = constants.get(column)
            if old is None:
                raise ValidationError(f"Cannot locate initial state column {column}")
            for node in range(capacities["nodes"]):
                if purpose == "ledger":
                    expected = capacities["initial_ledger_lengths"][document["nodes"][node]]
                    fact = z3.Select(old, node) == expected
                    initial_fact(f"cells_initial_ledger_{node}", fact)
                else:
                    for peer in range(capacities["nodes"]):
                        expected = 0
                        if purpose == "queue-length":
                            expected = next(q["length"] for q in capacities["initial_queues"]
                                            if q["source"] == document["nodes"][peer]
                                            and q["destination"] == document["nodes"][node])
                        fact = z3.Select(z3.Select(old, node), peer) == expected
                        initial_fact(f"cells_initial_{purpose}_{node}_{peer}", fact)
    named = [(clause["name"], value) for clause, value in zip(details["clauses"], converted, strict=True)] + constraints
    named += [(f"cells_type_{index}", value) for index, value in enumerate(lowering.type_constraints.values())]
    result, clauses = render_dag(named, with_clauses=True)
    z3.parse_smt2_string(result)
    return {
        "schema": "ccfraft-canonical-cells-experiment/v1",
        "input": document, "script": result, "capacities": capacities,
        "source_sha256": hashlib.sha256(details["script"].encode()).hexdigest(),
        "reference_script": details["script"].removesuffix("(check-sat)\n") + "".join(
            f"(assert (! {value.sexpr()} :named {name}))\n" for name, value in source_constraints
        ) + "(check-sat)\n",
        "clauses": clauses,
        "groups": details["groups"],
        "metrics": {"finite_array_sorts": len(lowering.vectors), "compiled_nodes": len(lowering.cache),
                    "remaining_quantifiers": lowering.quantifiers, "finite_selects": lowering.vector_selects,
                    "normalizations_removed": lowering.normalizations_removed,
                    "type_predicates": len(lowering.type_constraints),
                    "finite_range_rewrites": lowering.finite_range_rewrites},
        "assurance": "unproved finite-cell prototype under explicit initial-state and capacity assumptions",
    }


def render_dag(named, with_clauses=False):
    """Share closed subexpressions across source assertions using SMT definitions."""
    constants, sorts, seen, stack = {}, {}, set(), [value for _, value in named]
    while stack:
        value = stack.pop()
        if value.get_id() in seen:
            continue
        seen.add(value.get_id())
        sorts[value.sort().get_id()] = value.sort()
        if z3.is_quantifier(value):
            stack.append(value.body())
        elif z3.is_app(value):
            if value.num_args() == 0 and value.decl().kind() == z3.Z3_OP_UNINTERPRETED:
                constants[value.get_id()] = value
            stack.extend(value.children())
    declarations = z3.Solver()
    declarations.add(*[value == value for value in constants.values()])
    declarations.add(*[
        z3.Const(f"cells_sort_witness_{index}", sort) == z3.Const(f"cells_sort_witness_{index}", sort)
        for index, sort in enumerate(sorts.values())
    ])
    header = declarations.sexpr().split("(assert ", 1)[0]
    cache, definitions = {}, []

    def visit(value):
        if value.get_id() in cache:
            return cache[value.get_id()]
        if z3.is_var(value):
            result = (value, z3.get_var_index(value) + 1)
        elif z3.is_quantifier(value):
            body, needed = visit(value.body())
            bound = [z3.Const(f"dag_bound_{value.get_id()}_{i}", value.var_sort(i))
                     for i in range(value.num_vars())]
            body = z3.substitute_vars(body, *reversed(bound))
            expression = z3.ForAll(bound, body)
            result = (expression, max(0, needed - value.num_vars()))
        elif value.num_args() == 0:
            result = (value, 0)
        else:
            children = [visit(child) for child in value.children()]
            expression = value.decl()(*[child for child, _ in children])
            result = (expression, max(needed for _, needed in children))
        expression, needed = result
        if needed == 0 and (z3.is_quantifier(expression) or expression.num_args() > 0):
            name = f"cells_dag_{len(definitions)}"
            definitions.append(f"(define-fun {name} () {expression.sort().sexpr()} {expression.sexpr()})\n")
            result = (z3.Const(name, expression.sort()), 0)
        cache[value.get_id()] = result
        return result

    assertions, clauses = [], []
    for name, value in named:
        expression, needed = visit(value)
        if needed:
            raise ValidationError("Free de Bruijn variable in compiled assertion")
        assertions.append(f"(assert (! {expression.sexpr()} :named {name}))\n")
        clauses.append({"name": name, "expression": expression.sexpr()})
    result = header + "".join(definitions) + "".join(assertions) + "(check-sat)\n"
    return (result, clauses) if with_clauses else result
