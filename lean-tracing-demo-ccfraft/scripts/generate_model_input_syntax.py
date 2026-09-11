#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Check the ModelInputSyntax generated prefix, or regenerate it with --write.

The default target is relative to this script, not the working directory.
--file selects an existing alternative target. The unique standalone LF-terminated
Trace boundary marker and the manual suffix are preserved byte-for-byte.
This standalone maintenance tool is not a runtime or build dependency.
"""

import argparse
import os
from pathlib import Path
import stat
import sys
import tempfile

DEFAULT_TARGET = Path(__file__).resolve().parents[1] / "Sparse" / "ModelInputSyntax.lean"
MARKER = b"-- Trace boundary."
parts = ["""-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelTrace

set_option autoImplicit false

namespace CCFRaft.Sparse.ModelInputSyntax

open ModelTrace (UnknownNatAssignment)

variable {n : Nat} {left right : UnknownNatAssignment}

inductive NatAtom (n : Nat) where
  | literal (value : Nat)
  | unknown (index : Fin n)
  deriving DecidableEq

def NatAtom.eval (rho : UnknownNatAssignment) : NatAtom n -> Nat
  | .literal value => value
  | .unknown index => rho index.val

def NatAtom.quote (value : Nat) : NatAtom n := .literal value
def NatAtom.atoms (value : NatAtom n) : List (NatAtom n) := [value]
def NatAtom.indices : NatAtom n -> List (Fin n)
  | .literal _ => []
  | .unknown index => [index]

def Same (left right : UnknownNatAssignment) (atoms : List (NatAtom n)) : Prop :=
  forall atom, Membership.mem atoms atom -> atom.eval left = atom.eval right

theorem Same.restrict {atoms subset : List (NatAtom n)} (same : Same left right atoms)
    (contained : forall atom, Membership.mem subset atom -> Membership.mem atoms atom) :
    Same left right subset :=
  fun atom member => same atom (contained atom member)

theorem NatAtom.eval_congr (value : NatAtom n) (same : Same left right value.atoms) :
    value.eval left = value.eval right :=
  same value (by simp [atoms])

@[simp] theorem NatAtom.eval_quote (rho : UnknownNatAssignment) (value : Nat) :
    (NatAtom.quote (n := n) value).eval rho = value := rfl

inductive BoolAtom (n : Nat) where
  | literal (value : Bool)
  | isZero (value : NatAtom n)
  deriving DecidableEq

def BoolAtom.eval (rho : UnknownNatAssignment) : BoolAtom n -> Bool
  | .literal value => value
  | .isZero value => decide (value.eval rho = 0)

def BoolAtom.quote (value : Bool) : BoolAtom n := .literal value
def BoolAtom.atoms : BoolAtom n -> List (NatAtom n)
  | .literal _ => []
  | .isZero value => value.atoms

theorem BoolAtom.eval_congr (value : BoolAtom n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | literal _ => rfl
  | isZero value => simp only [eval, NatAtom.eval_congr value same]

@[simp] theorem BoolAtom.eval_quote (rho : UnknownNatAssignment) (value : Bool) :
    (BoolAtom.quote (n := n) value).eval rho = value := rfl

def optionAtoms {A : Type} (atoms : A -> List (NatAtom n)) : Option A -> List (NatAtom n)
  | none => []
  | some value => atoms value

theorem option_congr {A B : Type} (atoms : A -> List (NatAtom n))
    (eval : UnknownNatAssignment -> A -> B)
    (congruent : forall value, Same left right (atoms value) -> eval left value = eval right value)
    (value : Option A) (same : Same left right (optionAtoms atoms value)) :
    value.map (eval left) = value.map (eval right) := by
  cases value with
  | none => rfl
  | some value => exact congrArg some (congruent value same)

theorem list_congr {A B : Type} (atoms : A -> List (NatAtom n))
    (eval : UnknownNatAssignment -> A -> B)
    (congruent : forall value, Same left right (atoms value) -> eval left value = eval right value)
    (values : List A) (same : Same left right (values.flatMap atoms)) :
    values.map (eval left) = values.map (eval right) := by
  apply List.map_congr_left
  intro value member
  apply congruent value
  exact same.restrict (fun atom present =>
    List.mem_flatMap.mpr (Exists.intro value (And.intro member present)))

def atomSupport (atoms : List (NatAtom n)) : Finset (Fin n) :=
  (atoms.flatMap NatAtom.indices).toFinset

theorem same_of_support (atoms : List (NatAtom n))
    (agree : forall index, Membership.mem (atomSupport atoms) index -> left index.val = right index.val) :
    Same left right atoms := by
  intro atom member
  cases atom with
  | literal _ => rfl
  | unknown index =>
    apply agree index
    exact List.mem_toFinset.mpr (List.mem_flatMap.mpr
      (Exists.intro (.unknown index) (And.intro member (by simp [NatAtom.indices]))))

"""]

# A field kind is an unchanged literal type, syntax type, or fixed list/option of syntax.
syntax = {"NatAtom", "BoolAtom"}


def split(kind):
    if kind.startswith("List "):
        return "list", kind[5:]
    if kind.startswith("Option "):
        return "option", kind[7:]
    return ("syntax", kind) if kind in syntax else ("literal", kind)


def lean_type(kind):
    form, child = split(kind)
    return {"list": f"List ({child} n)", "option": f"Option ({child} n)",
            "syntax": f"{child} n", "literal": child}[form]


def atom_expr(kind, value):
    form, child = split(kind)
    if form == "literal":
        return None
    if form == "list":
        return f"({value}).flatMap {child}.atoms"
    if form == "option":
        return f"optionAtoms {child}.atoms ({value})"
    return f"({value}).atoms"


def evaluation(kind, value, rho="rho", quote=False):
    form, child = split(kind)
    if form == "literal":
        return value
    function = f"{child}.quote" if quote else f"{child}.eval {rho}"
    if form in ("list", "option"):
        return f"({value}).map ({function})"
    return f"({function}) ({value})"


def conjunction_atoms(fields, values):
    return " ++ ".join(f"({a})" for k, v in zip(fields, values) if (a := atom_expr(k, v))) or "[]"


def congruence(name, fields, values):
    proofs = []
    for i, (kind, value) in enumerate(zip(fields, values)):
        form, child = split(kind)
        if form == "literal":
            continue
        function = f"{child}.eval_congr"
        if form == "list":
            function = f"list_congr {child}.atoms {child}.eval {child}.eval_congr"
        if form == "option":
            function = f"option_congr {child}.atoms {child}.eval {child}.eval_congr"
        parts.append(f"  have h{i} := {function} ({value}) (same.restrict (by\n"
                     f"    intro atom member\n    simp [{name}.atoms, member]))\n")
        proofs.append(f"h{i}")
    parts.append(f"  simp only [{name}.eval{''.join(', ' + p for p in proofs)}]\n" if proofs else "  rfl\n")


def record(name, target, fields):
    syntax.add(name)
    parts.append(f"structure {name} (n : Nat) where\n")
    for field, kind in fields:
        parts.append(f"  {field} : {lean_type(kind)}\n")
    parts.append("  deriving DecidableEq\n\n")
    for method, target_type, quoting in [("eval (rho : UnknownNatAssignment)", target, False),
                                         ("quote", f"{name} n", True)]:
        input_type = target if quoting else f"{name} n"
        parts.append(f"def {name}.{method} (value : {input_type}) : {target_type} where\n")
        for field, kind in fields:
            parts.append(f"  {field} := {evaluation(kind, 'value.' + field, quote=quoting)}\n")
        parts.append("\n")
    kinds, values = zip(*[(kind, "value." + field) for field, kind in fields])
    parts.append(f"def {name}.atoms (value : {name} n) : List (NatAtom n) :=\n"
                 f"  {conjunction_atoms(kinds, values)}\n\n")
    parts.append(f"theorem {name}.eval_congr (value : {name} n) (same : Same left right value.atoms) :\n"
                 f"    value.eval left = value.eval right := by\n")
    congruence(name, kinds, values)
    extras = ", List.map_map, Function.comp_def" if any(split(k)[0] == "list" for _, k in fields) else ""
    parts.append(f"\n@[simp] theorem {name}.eval_quote (rho : UnknownNatAssignment) (value : {target}) :\n"
                 f"    ({name}.quote (n := n) value).eval rho = value := by\n"
                 f"  cases value\n  simp [{name}.quote, {name}.eval{extras}]\n\n")


def alternative(name, target, suffix, fields):
    parts.append(f"def {name}.eval{suffix} (rho : UnknownNatAssignment) (value : {name} n) : {target} :=\n"
                 f"  let decoded := value.eval rho\n"
                 "  { " + ", ".join(f"{field} := decoded.{field}" for field, _ in fields) + " }\n\n")
    parts.append(f"def {name}.quote{suffix} (value : {target}) : {name} n :=\n"
                 f"  {name}.quote " + "{ " + ", ".join(f"{f} := value.{f}" for f, _ in fields) + " }\n\n")
    parts.append(f"@[simp] theorem {name}.eval_quote{suffix} (rho : UnknownNatAssignment) (value : {target}) :\n"
                 f"    {name}.eval{suffix} rho ({name}.quote{suffix} (n := n) value) = value := by\n"
                 f"  cases value\n  simp [eval{suffix}, quote{suffix}]\n\n")


def case_names(name, tag, fields):
    if name == "ContentSyntax":
        return [] if not fields else ["txId" if tag == "transaction" else "nodes"]
    if name in ("MessageSyntax", "SummarySyntax"):
        return ["response" if tag.endswith("Response") else "request"]
    if name == "ActionSyntax":
        if tag == "clientRequest":
            return ["node", "transaction"]
        if tag == "changeConfiguration":
            return ["source", "nodes"]
        if tag == "appendEntries":
            return ["source", "destination", "batchEnd"]
        return ["node"] if len(fields) == 1 else ["source", "destination"]
    if tag == "retirementCompleted":
        return ["observer", "retired", "value"]
    if tag == "firstMessage":
        return ["source", "destination", "value"]
    if tag == "submitted":
        return ["transaction", "value"]
    if len(fields) == 1:
        return ["value"]
    return ["destination" if tag == "queueLength" else "node", "value"]


def inductive(name, target, cases):
    syntax.add(name)
    parts.append(f"inductive {name} (n : Nat) where\n")
    for tag, fields, *_ in cases:
        parts.append("  | " + tag + "".join(f" ({v} : {lean_type(k)})"
            for k, v in zip(fields, case_names(name, tag, fields))) + "\n")
    parts.append("  deriving DecidableEq\n\n")
    for method, out, quote in [("eval (rho : UnknownNatAssignment)", target, False),
                                ("quote", f"{name} n", True)]:
        inp = target if quote else f"{name} n"
        parts.append(f"def {name}.{method} : {inp} -> {out}\n")
        for tag, fields, *alt in cases:
            values = case_names(name, tag, fields)
            args = [evaluation(k, v, quote=quote) for k, v in zip(fields, values)]
            if alt:
                child, suffix = alt[0]
                args = [f"{child}.quote{suffix} {values[0]}" if quote else f"{child}.eval{suffix} rho {values[0]}"]
            parts.append(f"  | .{tag}{''.join(' ' + v for v in values)} => .{tag}"
                         + "".join(f" ({a})" for a in args) + "\n")
        parts.append("\n")
    parts.append(f"def {name}.atoms : {name} n -> List (NatAtom n)\n")
    for tag, fields, *_ in cases:
        values = case_names(name, tag, fields)
        binders = [v if split(k)[0] != "literal" else "_" for k, v in zip(fields, values)]
        parts.append(f"  | .{tag}{''.join(' ' + v for v in binders)} => {conjunction_atoms(fields, values)}\n")
    parts.append(f"\ntheorem {name}.eval_congr (value : {name} n) (same : Same left right value.atoms) :\n"
                 "    value.eval left = value.eval right := by\n  cases value with\n")
    for tag, fields, *alt in cases:
        values = case_names(name, tag, fields)
        parts.append(f"  | {tag}{''.join(' ' + v for v in values)} =>\n")
        start = len(parts)
        congruence(name, fields, values)
        if alt:
            child, suffix = alt[0]
            parts[-1] = parts[-1].replace(f"{name}.eval,", f"{name}.eval, {child}.eval{suffix},")
        for i in range(start, len(parts)):
            parts[i] = "".join("  " + line for line in parts[i].splitlines(keepends=True))
    forms = {split(k)[0] for _, fields, *_ in cases for k in fields}
    extras = ", List.map_map, Function.comp_def" if "list" in forms else (
        ", Function.comp_def" if "option" in forms else "")
    parts.append(f"\n@[simp] theorem {name}.eval_quote (rho : UnknownNatAssignment) (value : {target}) :\n"
                 f"    ({name}.quote (n := n) value).eval rho = value := by\n"
                 f"  cases value <;> simp [{name}.quote, {name}.eval{extras}]\n\n")


inductive("ContentSyntax", "EntryContent Node Nat", [
    ("transaction", ["NatAtom"]), ("signature", []),
    ("reconfiguration", ["Finset Node"]), ("retiredCommitted", ["Finset Node"])])
record("EntrySyntax", "Entry Node Nat", [("term", "NatAtom"), ("content", "ContentSyntax")])
record("ConfigurationSyntax", "Configuration Node", [("index", "NatAtom"), ("nodes", "Finset Node")])
header = [("term", "NatAtom")]
endpoints = [("source", "Node"), ("destination", "Node")]
record("AppendRequestSyntax", "AppendEntriesRequest Node Nat", header + [
    ("prevLogIndex", "NatAtom"), ("prevLogTerm", "NatAtom"),
    ("entries", "List EntrySyntax"), ("leaderCommit", "NatAtom")] + endpoints)
record("AppendResponseSyntax", "AppendEntriesResponse Node", header + [
    ("success", "BoolAtom"), ("lastLogIndex", "NatAtom")] + endpoints)
vote = header + [("lastCommittableTerm", "NatAtom"), ("lastCommittableIndex", "NatAtom")] + endpoints
response = header + [("voteGranted", "BoolAtom")] + endpoints
record("VoteRequestSyntax", "RequestVoteRequest Node", vote)
alternative("VoteRequestSyntax", "RequestPreVote Node", "PreVote", vote)
record("VoteResponseSyntax", "RequestVoteResponse Node", response)
alternative("VoteResponseSyntax", "RequestPreVoteResponse Node", "PreVote", response)
record("ProposeRequestSyntax", "ProposeVoteRequest Node", header + endpoints)
packet_cases = [("appendEntriesRequest", ["AppendRequestSyntax"]),
    ("appendEntriesResponse", ["AppendResponseSyntax"]),
    ("requestVoteRequest", ["VoteRequestSyntax"]), ("requestVoteResponse", ["VoteResponseSyntax"]),
    ("requestPreVote", ["VoteRequestSyntax"], ("VoteRequestSyntax", "PreVote")),
    ("requestPreVoteResponse", ["VoteResponseSyntax"], ("VoteResponseSyntax", "PreVote")),
    ("proposeVoteRequest", ["ProposeRequestSyntax"])]
inductive("MessageSyntax", "Message Node Nat", packet_cases)
record("AppendSummarySyntax", "TraceMessageSummary.AppendEntriesSummary Node", header + [
    ("prevLogIndex", "NatAtom"), ("entriesLength", "NatAtom"), ("leaderCommit", "NatAtom")] + endpoints)
inductive("SummarySyntax", "TraceMessageSummary.Summary Node",
          [("appendEntriesRequest", ["AppendSummarySyntax"])] + packet_cases[1:])
inductive("StateObservationSyntax", "TraceStateObservation.Observation Node", [
    ("preVoteStatus", ["Node", "PreVoteStatus"]), ("membershipState", ["Node", "MembershipState"]),
    ("retirementIndex", ["Node", "Option NatAtom"]),
    ("retirementCommittableIndex", ["Node", "Option NatAtom"]),
    ("retiredCommittedIndex", ["Node", "Option NatAtom"]),
    ("retirementCompleted", ["Node", "Node", "BoolAtom"])])
inductive("ActionSyntax", "Action Node Nat", [
    ("clientRequest", ["Node", "NatAtom"]), ("changeConfiguration", ["Node", "Finset Node"]),
    ("appendRetiredCommitted", ["Node"]), ("signCommittableMessages", ["Node"]),
    ("appendEntries", ["Node", "Node", "NatAtom"]), ("receive", ["Node", "Node"]),
    ("advanceCommitIndex", ["Node"]), ("timeout", ["Node"]), ("becomePreVoteCandidate", ["Node"]),
    ("becomeCandidate", ["Node"]), ("requestVote", ["Node", "Node"]),
    ("requestPreVote", ["Node", "Node"]), ("checkQuorum", ["Node"]),
    ("updateTerm", ["Node", "Node"]), ("becomeLeader", ["Node"]),
    ("proposeVote", ["Node", "Node"]), ("advanceCommitIndexAndProposeVote", ["Node", "Node"])])
inductive("ObservationSyntax", "ModelTrace.Observation", [
    ("allocated", ["Node", "BoolAtom"]), ("joined", ["Node", "BoolAtom"]), ("role", ["Node", "Role"]),
    ("currentTerm", ["Node", "NatAtom"]), ("commitIndex", ["Node", "NatAtom"]),
    ("logLength", ["Node", "NatAtom"]), ("submitted", ["NatAtom", "BoolAtom"]),
    ("state", ["StateObservationSyntax"]), ("firstMessage", ["Node", "Node", "Option MessageSyntax"]),
    ("messageSummary", ["SummarySyntax"]), ("queueLength", ["Node", "NatAtom"]),
    ("configurationSnapshot", ["Node", "List ConfigurationSyntax"])])


def split_source(source: bytes) -> tuple[bytes, bytes]:
    source.decode("ascii")
    count = source.count(MARKER)
    if count != 1:
        raise ValueError(f"expected exactly one Trace boundary marker, found {count}")
    prefix, _, suffix = source.partition(MARKER)
    if (prefix and not prefix.endswith(b"\n")) or not suffix.startswith(b"\n"):
        raise ValueError("Trace boundary must be a standalone LF-terminated line")
    return prefix, suffix


def replace_source(path: Path, content: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(content)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="check the prefix without writing (default)")
    modes.add_argument("--write", action="store_true", help="replace a stale generated prefix")
    parser.add_argument("--file", type=Path, default=DEFAULT_TARGET, help="existing target file")
    args = parser.parse_args()
    try:
        path = args.file.resolve(strict=True)
        prefix, suffix = split_source(path.read_bytes())
        expected = "".join(parts).encode("ascii")
        if prefix == expected:
            print(f"Generated prefix is current: {path}")
            return 0
        if not args.write:
            print(f"Generated prefix is stale: {path}; use --write to regenerate.", file=sys.stderr)
            return 1
        replace_source(path, expected + MARKER + suffix)
        print(f"Regenerated prefix; preserved manual suffix: {path}")
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
