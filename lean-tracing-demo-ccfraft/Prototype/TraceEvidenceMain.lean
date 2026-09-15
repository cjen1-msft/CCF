-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Prototype.AppendReceive
import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.TraceEvidencePrototype

open Lean NativeEncode NativeSmt BranchPrototype

def encodeDetails (specialised : Bool) (envelope : Json) : Except String Json := do
  fields envelope ["input", "plans"]
  let document <- field envelope "input"
  let input <- decodeParameterizedFrameDocument document
  let names <- (← (← field document "nodes").getArr?).mapM Json.getStr?
  let plans <- (← (← field envelope "plans").getArr?).mapM fun raw => do
    fields raw ["instruction", "source", "destination", "path", "oldLength", "previous",
      "term", "entriesLength", "leaderCommit", "previousTerm", "oldCommit",
      "sourceLine", "responseLine", "executionLine"]
    let index <- natural (← field raw "instruction")
    unless index < input.frame.instructions.size do throw "plan index outside input"
    let source <- resolve input.frame.width names (← field raw "source")
    let destination <- resolve input.frame.width names (← field raw "destination")
    let path <- match ← (← field raw "path").getStr? with
      | "appendAtEnd" => pure ReceivePath.appendAtEnd
      | "rejectBeyondEnd" => pure ReceivePath.rejectBeyondEnd
      | _ => throw "unsupported evidence path"
    let _ <- natural (← field raw "sourceLine")
    let _ <- natural (← field raw "responseLine")
    let _ <- natural (← field raw "executionLine")
    let plan : ReceivePlan := {
      path
      term := ← natural (← field raw "term")
      previous := ← natural (← field raw "previous")
      oldLength := ← natural (← field raw "oldLength")
      entriesLength := ← natural (← field raw "entriesLength")
      leaderCommit := ← natural (← field raw "leaderCommit")
      dependencies := [index] }
    let previousTerm <- match ← field raw "previousTerm" with
      | .null => pure none
      | value => some <$> natural value
    let oldCommit <- natural (← field raw "oldCommit")
    return (index, source, destination, plan, previousTerm, oldCommit)
  unless (plans.toList.map fun plan => plan.1).Nodup do throw "duplicate evidence plan"
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, started) <- (declareNatParameters input.unknowns.size).run initial
  let mut state := started
  let mut groups := #[{ instruction := none, start := 0, stop := state.assertions.size : Group }]
  for index in List.finRange input.frame.instructions.size do
    let item := input.frame.instructions[index.val]
    let begin := state.assertions.size
    let action := match plans.find? (fun plan => plan.1 == index.val) with
      | none => parameterizedFrameInstruction initial.next item
      | some (_, source, destination, plan, previousTerm, oldCommit) => do
        match item with
        | .core (.receiveAppend sender receiver) =>
          unless sender == source && receiver == destination do throw "evidence route mismatch"
        | _ => throw "evidence does not belong to an AppendEntries receive"
        let before <- get
        let payload := appendRequestPayloadTerm
          (queueHeadPacketTerm before.toColumns source destination)
        match previousTerm with
        | some term => assertion (.equal payload.snd.fst (.integer term))
        | none => pure ()
        assertion (.equal (nodeRowSnapshot before.toColumns destination).commit (.integer oldCommit))
        if specialised then specialisedReceive source destination plan
        else guardedReceive source destination plan
    let (_, next) <- action.run state
    state := next
    groups := groups.push { instruction := some index.val, start := begin, stop := state.assertions.size }
  return compiledDetails document { assertions := state.assertions, groups }

end CCFRaft.TraceEvidencePrototype

def main (arguments : List String) : IO UInt32 := do
  let text <- (← IO.getStdin).readToEnd
  let result := do
    let document <- Lean.Json.parse text
    match arguments with
    | ["--batch", mode] => do
      unless mode == "generic" || mode == "specialised" do throw "invalid evidence mode"
      let outputs <- (← document.getArr?).mapM
        (CCFRaft.TraceEvidencePrototype.encodeDetails (mode == "specialised"))
      return Lean.toJson outputs
    | _ => throw "usage: --batch generic|specialised"
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
