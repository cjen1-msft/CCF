-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Prototype.AppendReceive
import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.EvidenceMiter

open Lean NativeEncode NativeSmt BranchPrototype

def rowEqual {width : PNat} (g s : NodeRowTerms width) : Expr .bool :=
  let liveEqual : Expr .bool := .forall_ .int (
    let index : Term [.int] .int := .bound .here
    implies (all [.le (.integer 0) index, lt index (g.logLength.weaken .int)])
      (.equal (.select (g.logEntries.weaken .int) index)
        (.select (s.logEntries.weaken .int) index)))
  all [
    .equal g.role s.role, .equal g.newFollower s.newFollower,
    .equal g.logLength s.logLength, .equal g.commit s.commit,
    .equal g.currentTerm s.currentTerm, liveEqual,
    .equal g.retirementIndex s.retirementIndex,
    .equal g.retirementCommittableIndex s.retirementCommittableIndex,
    .equal g.retiredCommittedIndex s.retiredCommittedIndex,
    .equal g.votedFor s.votedFor, .equal g.votesGranted s.votesGranted,
    .equal g.preVotesGranted s.preVotesGranted, .equal g.membershipState s.membershipState,
    .equal g.sentIndex s.sentIndex, .equal g.matchIndex s.matchIndex]

def frameEqual (width : PNat) (g s : Columns) : Expr .bool :=
  let column (sort : Ty) (left right : Nat) := .equal (.free sort left) (.free sort right)
  all (
    (List.finRange width).map (fun node =>
      rowEqual (nodeRowSnapshot g node) (nodeRowSnapshot s node)) ++ [
    column (.array .int .bool) g.allocated s.allocated,
    column (.bits width) g.hasJoined s.hasJoined,
    column (.array .int .bool) g.preVoteStatus s.preVoteStatus,
    column (.array .int (.bits width)) g.retirementCompleted s.retirementCompleted,
    column (.array .int .bool) g.submittedTxIds s.submittedTxIds,
    column .int g.submittedTxLimit s.submittedTxLimit,
    column (.array .int (.array .int .int)) g.queueHead s.queueHead,
    column (.array .int (.array .int .int)) g.queueLength s.queueLength,
    column (queueCellsTy width) g.queueCells s.queueCells])

def compare {width : PNat} (name : String) (before : Encoding width)
    (source destination : Fin width) (plan : ReceivePlan) : Except String Json := do
  let (_, generic) <- (guardedReceive source destination plan).run before
  let fork := { generic with toColumns := before.toColumns }
  let (_, specialised) <- (specialisedReceive source destination plan).run fork
  let feasible := compiledDetails Json.null {
    assertions := specialised.assertions,
    groups := #[{ instruction := none, start := 0, stop := specialised.assertions.size }] }
  let (_, final) <- (assertion (.not (frameEqual width generic.toColumns specialised.toColumns))).run specialised
  let details := compiledDetails Json.null {
    assertions := final.assertions,
    groups := #[{ instruction := none, start := 0, stop := final.assertions.size }] }
  return Json.mkObj [("name", toJson name), ("script", ← field details "script"),
    ("feasibleScript", ← field feasible "script")]

def makeCase (name : String) (path : ReceivePath) (oldLength previous : Nat)
    (selfRoute : Bool) : Except String Json := do
  let width : PNat := ⟨2, by decide⟩
  let source : Fin width := ⟨0, by decide⟩
  let destination : Fin width := if selfRoute then source else ⟨1, by decide⟩
  let initial := initialEncoding width {source}
  let (_, before) <- (initialFrameDomains width).run initial
  let plan : ReceivePlan := {
    path, term := 2, oldLength, previous, entriesLength := 1,
    leaderCommit := previous + 1, dependencies := [] }
  compare name before source destination plan

def fixtureCase (envelope : Json) : Except String Json := do
  let document <- field envelope "input"
  let decoded <- decodeParameterizedFrameDocument document
  let plans <- (← field envelope "plans").getArr?
  unless plans.size == 1 do throw "miter fixture requires one plan"
  let raw := plans[0]!
  let index <- natural (← field raw "instruction")
  let path <- match ← (← field raw "path").getStr? with
    | "appendAtEnd" => pure ReceivePath.appendAtEnd
    | "rejectBeyondEnd" => pure ReceivePath.rejectBeyondEnd
    | _ => throw "unsupported miter path"
  let plan : ReceivePlan := {
    path, term := ← natural (← field raw "term"),
    oldLength := ← natural (← field raw "oldLength"),
    previous := ← natural (← field raw "previous"),
    entriesLength := ← natural (← field raw "entriesLength"),
    leaderCommit := ← natural (← field raw "leaderCommit"), dependencies := [] }
  let (_, initial) <- (initialFrameDomains decoded.frame.width).run
    (initialEncoding decoded.frame.width decoded.frame.bootstrap)
  let (_, started) <- (declareNatParameters decoded.unknowns.size).run initial
  let mut before := started
  for item in decoded.frame.instructions.toList.take index do
    let (_, next) <- (parameterizedFrameInstruction initial.next item).run before
    before := next
  match decoded.frame.instructions[index]? with
  | some (.core (.receiveAppend source destination)) =>
    compare (← (← field envelope "name").getStr?) before source destination plan
  | _ => throw "miter index is not a receive"

end CCFRaft.EvidenceMiter

def main (arguments : List String) : IO UInt32 := do
  let text <- if arguments == ["--fixtures"] then (← IO.getStdin).readToEnd else pure ""
  let result : Except String Lean.Json := do
    if arguments == ["--fixtures"] then
      let values <- (← Lean.Json.parse text).getArr?
      return Lean.toJson (← values.mapM CCFRaft.EvidenceMiter.fixtureCase)
    let mut cases := #[]
    for selfRoute in [false, true] do
      for size in [0, 3] do
        let suffix := s!"{size}-{selfRoute}"
        cases := cases.push (← CCFRaft.EvidenceMiter.makeCase
          s!"append-{suffix}" .appendAtEnd size size selfRoute)
        cases := cases.push (← CCFRaft.EvidenceMiter.makeCase
          s!"reject-{suffix}" .rejectBeyondEnd size (size + 2) selfRoute)
    return Lean.toJson cases
  match result with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
