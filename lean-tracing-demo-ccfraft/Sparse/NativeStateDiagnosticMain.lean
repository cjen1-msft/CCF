-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

private def diagnosticProbe {sort : Ty} (label : String) (expression : Expr sort) : Json :=
  Json.mkObj [
    ("label", toJson label), ("sort", toJson sort.syntax.render),
    ("expression", toJson expression.render),
    ("symbols", toJson (expression.symbols.map fun (ty, id) => Json.mkObj [
      ("name", toJson (symbolName ty id)), ("sort", toJson ty.syntax.render)]))]

private def stateProbes {width : PNat} (state : Encoding width)
    (indices : List Nat) : List Json :=
  let columns := state.toColumns
  [diagnosticProbe "hasJoined" (.free (.bits width) columns.hasJoined)] ++
  (List.finRange width).flatMap fun node =>
    let row := nodeRowSnapshot columns node
    let label := s!"node[{node.val}]"
    [diagnosticProbe s!"{label}.allocated" (allocated columns node.val),
     diagnosticProbe s!"{label}.role" row.role,
     diagnosticProbe s!"{label}.currentTerm" row.currentTerm,
     diagnosticProbe s!"{label}.newFollower" row.newFollower,
     diagnosticProbe s!"{label}.logLength" row.logLength,
     diagnosticProbe s!"{label}.commit" row.commit,
     diagnosticProbe s!"{label}.membershipState" row.membershipState,
     diagnosticProbe s!"{label}.votedFor" row.votedFor,
     diagnosticProbe s!"{label}.votesGranted" row.votesGranted,
     diagnosticProbe s!"{label}.preVotesGranted" row.preVotesGranted,
     diagnosticProbe s!"{label}.retirementIndex" row.retirementIndex,
     diagnosticProbe s!"{label}.retirementCommittableIndex" row.retirementCommittableIndex,
     diagnosticProbe s!"{label}.retiredCommittedIndex" row.retiredCommittedIndex,
     diagnosticProbe s!"{label}.preVoteStatus"
       (.select (.free (.array .int .bool) columns.preVoteStatus) (.integer node.val)),
     diagnosticProbe s!"{label}.retirementCompleted"
       (.select (.free (.array .int (.bits width)) columns.retirementCompleted) (.integer node.val)),
     diagnosticProbe s!"{label}.logStorage" row.logEntries] ++
    indices.map (fun index => diagnosticProbe s!"{label}.log[{index}]"
      (normalizedEntryTerm (.select row.logEntries (.integer index)))) ++
    (List.finRange width).flatMap fun peer =>
      [diagnosticProbe s!"{label}.sentIndex[{peer.val}]" (.select row.sentIndex (.integer peer.val)),
       diagnosticProbe s!"{label}.matchIndex[{peer.val}]" (.select row.matchIndex (.integer peer.val)),
       diagnosticProbe s!"queue[{peer.val}->{node.val}].length"
         (queueScalarTerm columns.queueLength (.integer node.val) (.integer peer.val)),
       diagnosticProbe s!"queue[{peer.val}->{node.val}].headPacket"
         (queueHeadPacketTerm columns peer node)]

private def diagnoseState (document : Json) (after : Option Nat) (indices : List Nat) :
    Except String Json := do
  let input <- decodeParameterizedFrameDocument document
  let checkpoint := after.getD input.frame.instructions.size
  unless checkpoint <= input.frame.instructions.size do
    throw "checkpoint exceeds the instruction count"
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, started) <- (declareNatParameters input.unknowns.size).run initial
  let mut state := started
  let mut selected := started
  for index in List.finRange input.frame.instructions.size do
    have within : index.val < input.frame.instructions.size := index.isLt
    let (_, next) <- (parameterizedFrameInstruction initial.next
      input.frame.instructions[index.val]).run state
    state := next
    if index.val + 1 == checkpoint then
      selected := state
  return Json.mkObj [
    ("schema", toJson "ccfraft-native-state-diagnostic/v1"),
    ("after_instructions", toJson checkpoint),
    ("script", toJson (renderScript state.assertions.toList true)),
    ("probes", toJson (stateProbes selected indices))]

end CCFRaft.NativeEncode

def main (arguments : List String) : IO UInt32 := do
  let text <- (<- IO.getStdin).readToEnd
  let result : Except String Lean.Json := do
    let document <- Lean.Json.parse text
    let after <- match arguments.head? with
      | none | some "final" => pure none
      | some value => match value.toNat? with
        | some index => pure (some index)
        | none => throw "checkpoint must be final or a nonnegative instruction count"
    let indices <- (arguments.drop 1).mapM fun (value : String) =>
      match value.toNat? with
      | some index => pure index
      | none => throw "log indices must be nonnegative integers"
    CCFRaft.NativeEncode.diagnoseState document after indices
  match result with
  | .ok report =>
      IO.println report.compress
      return 0
  | .error error =>
      (<- IO.getStderr).putStrLn s!"state diagnostic: {error}"
      return 2
