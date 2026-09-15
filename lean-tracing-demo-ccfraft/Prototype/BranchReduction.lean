-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Prototype.AppendReceive
import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.BranchPrototype

open Lean NativeEncode NativeSmt

structure NodeFacts where
  allocated : Option Bool := none
  role : Option Role := none
  term : Option Nat := none
  length : Option Nat := none
  dependencies : List Nat := []

private def isObservation {width : PNat} {count : Nat} :
    ParameterizedFrameInstruction width count -> Bool
  | .core (.node (.checkQuorum _)) => false
  | .core (.node _) | .core (.joined ..) | .core (.hasJoined ..)
  | .core (.preVoteStatus ..) | .core (.retirementCompleted ..)
  | .core (.submittedTxId ..) | .core (.queueLength ..)
  | .core (.queuePoint ..) | .core (.queuePattern ..) => true
  | _ => false

private def requestFields {width : PNat} (pattern : NativePacketPattern.Pattern (Fin width) Nat) :
    Option (Nat × Nat × Nat × Nat) := do
  let term <- pattern.header.term
  match pattern.payload with
  | .appendEntriesRequest (some previous) _ (some committed) (some length) _ =>
    some (term, previous, committed, length)
  | _ => none

-- The end observation must force every receive in this bounded block to grow.
-- A successful append can reach at most previous + 1; rejection cannot grow.
private def growthWitness {width : PNat} {count : Nat}
    (source destination : Fin width) (term : Nat)
    (expectedLength : Nat) (ready : Bool) (received index : Nat) :
    List (ParameterizedFrameInstruction width count) -> Option (List Nat)
  | [] => none
  | item :: rest =>
    let continueAt (length : Nat) (ready : Bool) (received : Nat) :=
      (growthWitness source destination term length ready received (index + 1) rest).map
        (index :: ·)
    match item with
    | .core (.receiveAppend sender receiver) =>
      if sender == source && receiver == destination && ready then
        continueAt (expectedLength + 1) false (received + 1)
      else none
    | .core (.queuePattern sender receiver 0 pattern) =>
      if sender == source && receiver == destination then
        match requestFields pattern with
        | some (packetTerm, previous, _, length) =>
          if packetTerm == term && previous == expectedLength && length == 1 then
            continueAt expectedLength true received
          else none
        | none => none
      else continueAt expectedLength ready received
    | .core (.node (.logLength node observed)) =>
      if node == destination && received != 0 then
        if observed == expectedLength then some [index] else none
      else continueAt expectedLength ready received
    | _ =>
      if isObservation item then continueAt expectedLength ready received else none

private def choosePlan {width : PNat} {count : Nat}
    (source destination : Fin width) (facts : NodeFacts)
    (packet : Option (Fin width × Fin width × NativePacketPattern.Pattern (Fin width) Nat × Nat))
    (index : Nat) (remaining : List (ParameterizedFrameInstruction width count)) :
    Option ReceivePlan := do
  unless facts.allocated == some true && facts.role == some .follower do none
  let term <- facts.term
  let length <- facts.length
  let (sender, receiver, pattern, packetIndex) <- packet
  unless sender == source && receiver == destination do none
  let (packetTerm, previous, committed, count) <- requestFields pattern
  unless term == packetTerm do none
  let dependencies := facts.dependencies ++ [packetIndex]
  if length < previous then
    some {
      path := .rejectBeyondEnd
      term := term
      previous := previous
      oldLength := length
      entriesLength := count
      leaderCommit := committed
      dependencies := dependencies }
  else if previous == length && count == 1 then do
    let future <- growthWitness source destination term length true 0 index remaining
    some {
      path := .appendAtEnd
      term := term
      previous := previous
      oldLength := length
      entriesLength := count
      leaderCommit := committed
      dependencies := (dependencies ++ future).eraseDups }
  else none

private def observe {width : PNat} {count : Nat} (index : Nat)
    (nodes : Fin width -> NodeFacts) (item : ParameterizedFrameInstruction width count) :
    Fin width -> NodeFacts :=
  let update (node : Fin width) (facts : NodeFacts) :=
    Function.update nodes node { facts with dependencies := facts.dependencies ++ [index] }
  match item with
  | .core (.node (.allocated node expected)) => update node { nodes node with allocated := some expected }
  | .core (.node (.role node expected)) => update node { nodes node with role := some expected }
  | .core (.node (.currentTerm node expected)) => update node { nodes node with term := some expected }
  | .core (.node (.logLength node expected)) => update node { nodes node with length := some expected }
  | _ => nodes

def encodePrototype (document : Json) (guarded : Bool) : Except String Json := do
  let input <- decodeParameterizedFrameDocument document
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, started) <- (declareNatParameters input.unknowns.size).run initial
  let mut state := started
  let mut groups := #[{ instruction := none, start := 0, stop := state.assertions.size : Group }]
  let mut nodes : Fin input.frame.width -> NodeFacts := fun _ => {}
  let mut packet : Option (Fin input.frame.width × Fin input.frame.width ×
    NativePacketPattern.Pattern (Fin input.frame.width) Nat × Nat) := none
  let mut decisions : Array Json := #[]
  for index in List.finRange input.frame.instructions.size do
    have within : index.val < input.frame.instructions.size := index.isLt
    let item := input.frame.instructions[index.val]
    let start := state.assertions.size
    if isObservation item then
      let (_, next) <- (parameterizedFrameInstruction initial.next item).run state
      state := next
      nodes := observe index.val nodes item
      match item with
      | .core (.queuePattern source destination 0 pattern) =>
        packet := some (source, destination, pattern, index.val)
      | _ => pure ()
    else
      let selected := match item with
        | .core (.receiveAppend source destination) =>
          (choosePlan source destination (nodes destination) packet index.val
            (input.frame.instructions.toList.drop index.val)).map fun plan =>
              (source, destination, plan)
        | _ => none
      match selected with
      | some (source, destination, plan) =>
        let emit := if guarded then guardedReceive source destination plan
          else specialisedReceive source destination plan
        let (_, next) <- emit.run state
        state := next
        let after : NodeFacts := {
          allocated := some true, role := some .follower, term := some plan.term,
          length := some (if plan.path == .appendAtEnd then plan.previous + 1 else plan.oldLength),
          dependencies := (plan.dependencies ++ [index.val]).eraseDups }
        nodes := Function.update (fun _ => {}) destination after
        decisions := decisions.push (Json.mkObj [
          ("instruction", toJson index.val),
          ("path", toJson (if plan.path == .appendAtEnd then "appendAtEnd" else "rejectBeyondEnd")),
          ("previous", toJson plan.previous), ("old_length", toJson plan.oldLength),
          ("dependencies", toJson ((plan.dependencies ++ [index.val]).eraseDups))])
      | none =>
        let (_, next) <- (parameterizedFrameInstruction initial.next item).run state
        state := next
        nodes := fun _ => {}
        match item with
        | .core (.receiveAppend ..) =>
          decisions := decisions.push (Json.mkObj [
            ("instruction", toJson index.val), ("path", toJson "generic"),
            ("reason", toJson "insufficient observation evidence for the prototype paths")])
        | _ => pure ()
      packet := none
    groups := groups.push { instruction := some index.val, start, stop := state.assertions.size }
  let compiled : Compiled := { assertions := state.assertions, groups }
  return Json.mkObj [
    ("schema", toJson "ccfraft-lean-branch-prototype/v1"),
    ("proof_status", toJson "unproved prototype"),
    ("decisions", toJson decisions),
    ("encoding", compiledDetails document compiled)]

end CCFRaft.BranchPrototype
