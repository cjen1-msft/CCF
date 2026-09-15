-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.ReceiveTraceValues
import MachineGenerated.TraceEncodingProofs

set_option autoImplicit false

open TraceSmt CCFRaft.ReceiveTraceValues

-- Isolate the exact conditional index clamp used by responseSentValue.
def repeatedNackClamp (count : Nat) : Scalar 0 :=
  Nat.rec (named 0 0 "initial sent index" (literal 2)) (fun index previous =>
    conditionalClamp
      ⟨true, .equal (.named (index + 1) 0 "packet success" (.literal 0)) (.literal 0)⟩
      previous (named 0 1 "match index" (literal 1))
      (named (index + 1) 1 "possible match" (literal 3))) count

def repeatedUnconditionalClamp (count : Nat) : Scalar 0 :=
  Nat.rec (named 0 0 "initial sent index" (literal 2)) (fun index previous =>
    maximum (minimum previous (named (index + 1) 1 "possible match" (literal 3)))
      (named 0 1 "match index" (literal 1))) count

def repeatedStaleAppend (count : Nat) : CCFRaft.TraceEncoding.Frame 0 :=
  let node0 : CCFRaft.Node := ⟨0, by decide⟩
  let node1 : CCFRaft.Node := ⟨1, by decide⟩
  let request : CCFRaft.AppendEntriesRequest CCFRaft.Node (NatTerm 0) :=
    { source := node1, destination := node0, term := 1, prevLogIndex := 0, prevLogTerm := 0,
      entries := [{ term := 1, content := .signature }], leaderCommit := 1 }
  let state : CCFRaft.BoundedTrace.Template 0 :=
    { CCFRaft.initialState with network := fun node => if node = node0 then [.appendEntriesRequest request] else [] }
  let start : CCFRaft.TraceEncoding.Frame 0 :=
    { state, tracking := CCFRaft.TraceEncoding.initialTracking state, pathId := 0 }
  let start := CCFRaft.TraceEncoding.controlFrame 1 (.checkQuorum node0) start
  let start := CCFRaft.TraceEncoding.controlFrame 2 (.timeout node0) start
  Nat.rec start (fun _ before =>
    CCFRaft.TraceEncoding.rememberUnappliedAppend before before node1 node0 request) count

theorem repeatedNackClamp_value (count : Nat) :
    (repeatedNackClamp count).actual = 2 := by
  induction count with
  | zero => rfl
  | succ count ih =>
      change max (min (repeatedNackClamp count).actual 3) 1 = 2
      rw [ih]
      rfl

def graphStats (label : String) (term : NatTerm 0) : List (String × Lean.Json) :=
  let text := term.toSmt
  [(label ++ "_bindings", Lean.toJson term.bindings.length),
   (label ++ "_dag_nodes", Lean.toJson ((text.splitOn "(let ((dag_").length - 1)),
   (label ++ "_bytes", Lean.toJson text.utf8ByteSize)]

def staleFormula (frame : CCFRaft.TraceEncoding.Frame 0) (expected : Bool) : Except String String := do
  let node0 : CCFRaft.Node := ⟨0, by decide⟩
  let result : Expr 0 := .and (.equal (frame.tracking.logLengths node0) (.literal 0))
    (.equal (frame.tracking.commitIndices node0 0) (.literal 0))
  let prepared ← Formula.prepare [
    { label := "entry", clauses := [] },
    { label := "demotion", clauses := [] },
    { label := "election", clauses := [] },
    { label := "observation", clauses := [
      { label := "unchanged values", expression := if expected then result else .not result }] }]
  return prepared.toSmt

def main (args : List String) : IO UInt32 := do
  if args.head? == some "stale" then
    for arg in args.drop 1 do
      let some count := arg.toNat? | return 1
      let frame := repeatedStaleAppend count
      let node0 : CCFRaft.Node := ⟨0, by decide⟩
      let good ← match staleFormula frame true with
        | .ok text => pure text
        | .error message => throw (IO.userError message)
      let bad ← match staleFormula frame false with
        | .ok text => pure text
        | .error message => throw (IO.userError message)
      IO.println (Lean.Json.mkObj
        ([("repetitions", Lean.toJson count), ("smt", Lean.toJson good),
          ("wrong_smt", Lean.toJson bad), ("formula_bytes", Lean.toJson good.utf8ByteSize)] ++
          graphStats "log" (frame.tracking.logLengths node0) ++
          graphStats "commit" (frame.tracking.commitIndices node0 0))).compress
    return 0
  for arg in args do
    match arg.toNat? with
    | none =>
        (← IO.getStderr).putStrLn s!"invalid repetition count: {arg}"
        return 1
    | some count =>
        let value := repeatedNackClamp count
        IO.println (Lean.Json.mkObj
          ([("repetitions", Lean.toJson count),
           ("actual", Lean.toJson value.actual),
           ("unconditional_bindings",
             Lean.toJson (repeatedUnconditionalClamp count).expression.bindings.length)] ++
           graphStats "conditional" value.expression)).compress
  return 0
