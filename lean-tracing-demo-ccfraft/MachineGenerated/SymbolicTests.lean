-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicEntry
import MachineGenerated.SymbolicBounds
import MachineGenerated.SymbolicOperations
import MachineGenerated.SymbolicObservations
import Shared.SymbolicSmt

set_option autoImplicit false

namespace CCFRaft.SymbolicTests

open Symbolic Symbolic.Container SymbolicModel

def numbers : Expr (.seq .nat) := .ofList [.unknown 0, .unknown 1, .unknown 0]
def assignment : Assignment := fun i => if i = 0 then 7 else 3

def regressionFormulas : List (Expr .bool) :=
  let literal : Expr (.seq .nat) := .ofList [.nat 7, .nat 3, .nat 7]
  let isSeven := fun e => Expr.eq e (.nat 7)
  let sumValue : Expr (.sum .nat .bool) := .inr (.bool true)
  [ .eq (.sub (.nat 0) (.nat 1)) (.nat 0),
    .eq numbers literal,
    .eq (.take (.nat 0) numbers) .nil,
    .eq (.take (.nat 99) numbers) literal,
    .eq (.drop (.nat 1) numbers) (.ofList [.nat 3, .nat 7]),
    .eq (.drop (.nat 99) numbers) .nil,
    .eq (.get? numbers (.nat 1)) (.inr (.nat 3)),
    .eq (.get? numbers (.nat 99)) (.inl .unit),
    .eq (.set numbers (.nat 1) (.nat 8)) (.ofList [.nat 7, .nat 8, .nat 7]),
    .eq (.set numbers (.nat 99) (.nat 8)) literal,
    .contains numbers (.nat 7),
    .not (.contains numbers (.nat 8)),
    .not (noDup 3 numbers),
    noDup 0 (.nil : Expr (.seq .nat)),
    .eq (Container.enqueueNoDup numbers (.nat 7)) literal,
    .eq (Container.enqueueNoDup numbers (.nat 8)) (.ofList [.nat 7, .nat 3, .nat 7, .nat 8]),
    .eq (filter 3 isSeven numbers) (.ofList [.nat 7, .nat 7]),
    .eq (removeFirst isSeven 3 numbers) (.ofList [.nat 3, .nat 7]),
    .eq (removeFirst (fun e => .eq e (.nat 9)) 3 numbers) literal,
    .eq (takeFirst isSeven 3 numbers)
      (.inr (.pair (.nat 7) (.ofList [.nat 3, .nat 7]))),
    .eq (takeFirst (fun e => .eq e (.nat 3)) 3 numbers)
      (.inr (.pair (.nat 3) (.ofList [.nat 7, .nat 7]))),
    .eq (takeFirst (fun e => .eq e (.nat 9)) 3 numbers) (.inl .unit),
    prefixEqual (.nat 2) numbers (.ofList [.nat 7, .nat 3, .nat 99]),
    .not (prefixEqual (.nat 3) numbers (.ofList [.nat 7, .nat 3, .nat 99])),
    .eq (.leftD sumValue (.nat 42)) (.nat 42),
    .eq (.rightD sumValue (.bool false)) (.bool true),
    .not sumValue.isLeft,
    .eq (.fst (.pair (.nat 5) (.bool false))) (.nat 5),
    .eq (.snd (.pair (.nat 5) (.bool false))) (.bool false),
    .eq (map 3 (fun e => .add e (.nat 1)) numbers) (.ofList [.nat 8, .nat 4, .nat 8]),
    all 3 (fun e => .lt e (.nat 8)) numbers,
    .not (boundedAll 2 (fun _ => .bool true) numbers) ]

example : regressionFormulas.all (fun e => e.eval assignment) = true := by decide

def bounds : BoundedState.Bounds := ⟨4, 4, 4, 2, 2⟩

def zeroBounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩

def absentWithUnusedTerm : Assignment := fun i => if i = 5 then 999 else 0

example :
    (fresh (capacities zeroBounds) localCodec.ty 1).snd.fst.eval absentWithUnusedTerm = (999 : Nat) := by
  decide

def emptyEntry : CCFRaft.State Node Nat := evalEntry bounds (fun _ => 0) (freshEntry bounds)
def allocatedEntry : CCFRaft.State Node Nat := evalEntry bounds (fun _ => 1) (freshEntry bounds)

def modelRegressions : List (String × Bool) :=
  [ ("all fifteen slots can be absent",
      (List.finRange NODE_COUNT).all (fun n => (emptyEntry.node? n).isNone)),
    ("all fifteen slots can be allocated",
      (List.finRange NODE_COUNT).all (fun n => (allocatedEntry.node? n).isSome)),
    ("unobserved roles are not fixed",
      (List.finRange NODE_COUNT).all (fun n => decide ((allocatedEntry.nodes n).role = .leader))),
    ("unobserved terms are not fixed",
      (List.finRange NODE_COUNT).all (fun n => (allocatedEntry.nodes n).currentTerm == 1)),
    ("entry logs can be nonempty",
      (List.finRange NODE_COUNT).all (fun n => (allocatedEntry.nodes n).log.length == 1)),
    ("entry queues can be nonempty",
      (List.finRange NODE_COUNT).all (fun n => (allocatedEntry.network n).length == 1)),
    ("empty entry obeys full model bounds",
      BoundedState.check bounds (BoundedState.encode emptyEntry)),
    ("allocated entry obeys full model bounds",
      BoundedState.check bounds (BoundedState.encode allocatedEntry)) ]

def packetExamples : List (Message Node Nat) :=
  let zero : Node := ⟨0, by decide⟩
  let one : Node := ⟨1, by decide⟩
  [ .appendEntriesRequest ⟨2, 1, 1, [⟨1, .transaction 3⟩], 1, zero, one⟩,
    .appendEntriesResponse ⟨2, false, 1, one, zero⟩,
    .requestVoteRequest ⟨2, 1, 1, zero, one⟩,
    .requestVoteResponse ⟨2, true, one, zero⟩,
    .requestPreVote ⟨2, 1, 1, zero, one⟩,
    .requestPreVoteResponse ⟨2, false, one, zero⟩,
    .proposeVoteRequest ⟨2, zero, one⟩ ]

def packetRoundtrips : Bool :=
  packetExamples.all fun m => decide (messageCodec.decode assignment (messageCodec.literal m) = m)

def boundRegressions : List (String × Bool) :=
  let zero := zeroBounds
  let missing := localCodec.option.literal none
  let allocated := localCodec.option.literal (some (BoundedState.encodeLocal freshNodeState))
  let noTransactions : BoundedState.Bounds := ⟨0, 1, 1, 1, 1⟩
  let node : Node := ⟨0, by decide⟩
  let request := fun content => messageCodec.literal
    (.appendEntriesRequest ⟨0, 0, 0, [⟨0, content⟩], 0, node, node⟩)
  [ ("absent is not allocated fresh", !(Expr.eq missing allocated).eval assignment),
    ("absent slots do not constrain synthetic defaults", (optionalLocalWithin zero missing).eval assignment),
    ("allocated fresh obeys scalar bounds", !(optionalLocalWithin zero allocated).eval assignment),
    ("fresh all-absent bounds", (stateWithin bounds (freshEntry bounds)).eval (fun _ => 0)),
    ("fresh allocated bounds", (stateWithin bounds (freshEntry bounds)).eval (fun _ => 1)),
    ("normalization preserves bounds",
      (stateWithin bounds (freshEntry bounds)).normalize.eval (fun _ => 1)),
    ("zero bounds allow the all-absent empty state",
      (stateWithin zero (freshEntry zero)).eval (fun _ => 0)),
    ("unused absent payload terms are unconstrained",
      (stateWithin zero (freshEntry zero)).eval absentWithUnusedTerm),
    ("normalized zero bounds preserve unused payloads",
      (stateWithin zero (freshEntry zero)).normalize.eval absentWithUnusedTerm),
    ("queued signatures need no transaction domain",
      (messageWithin noTransactions (request .signature)).eval assignment),
    ("live queued transactions obey the empty transaction domain",
      !(messageWithin noTransactions (request (.transaction 0))).eval assignment) ]

def modelOperationRegressions : Bool :=
  let queue := queueCodec.literal packetExamples
  let source : Node := ⟨1, by decide⟩
  let selected := queueTakeFirst packetExamples.length (nodeCodec.literal source) queue
  let prefixA : Expr logCodec.ty := .ofList [.pair (.nat 1) (.inl (.unknown 0))]
  let prefixB : Expr logCodec.ty := .ofList [.pair (.nat 1) (.inl (.unknown 1))]
  decide ((messageCodec.prod queueCodec).option.decode assignment selected =
    takeFirstFrom source packetExamples) &&
  (packetExamples.all fun m => decide
    (nodeCodec.decode assignment (messageSource (messageCodec.literal m)) = m.source)) &&
  (logPrefixEqual (.nat 1) prefixA prefixB).eval (fun _ => 7) &&
  !(logPrefixEqual (.nat 1) prefixA prefixB).eval assignment

def fifteenNodeAssertions : List (Expr .bool) :=
  let entry := freshEntry bounds
  let node : Node := ⟨0, by decide⟩
  let localState := Expr.rightD (tableGet entry.fst node) (defaultExpr localCodec.ty)
  [ stateWithin bounds entry,
    tableAll (fun slot => slot.isLeft.not) entry.fst,
    .eq localState.fst (roleCodec.literal .leader),
    .eq localState.snd.fst (.nat 2),
    .eq localState.snd.snd.fst.length (.nat 1),
    .eq (tableGet entry.snd.fst node).length (.nat 1) ]

def finiteRegressions : List (Expr .bool) :=
  let index : Expr (Codec.fin 2).ty := .ite (.eq (.unknown 0) (.nat 7))
    ((Codec.fin 2).literal 2) ((Codec.fin 2).literal 0)
  let values : Expr (vectorTy 3 .nat) := tableExpr (fun i => .nat (10 + i.val))
  let bits := (Codec.finset 3).literal {⟨1, by decide⟩}
  let absentIndex := Codec.nat.option.literal none
  let presentIndex := Codec.nat.option.literal (some 0)
  [ .eq (finValue index) (.nat 2),
    .eq (tableSelect values index) (.nat 12),
    setMember bits (.nat 1),
    .not (setMember bits (.nat 3)),
    .not (setMember (setInsert bits (.unknown 1)) (.unknown 1)),
    setMember (setInsert bits (finValue index)) (.nat 2),
    .not (setMember (setErase bits (.nat 1)) (.nat 1)),
    .eq (setInsert bits (.nat 3)) bits,
    observe (.unknown 0) none,
    .not (observe (.unknown 0) (some (.unknown 1))),
    observe presentIndex none,
    observe absentIndex (some absentIndex),
    .not (observe presentIndex (some absentIndex)) ]

def partialPacket : Expr messageCodec.ty :=
  fresh (capacities bounds) messageCodec.ty 10

def partialPacketObservation : Expr .bool :=
  appendRequestMatches partialPacket fun request =>
    .and (observe request.fst (some (.nat 2)))
      (observe request.snd.snd.snd.fst.length (some (.nat 1)))

def partialPacketAssertions (previousTerm : Nat) : List (Expr .bool) :=
  let request := Expr.leftD partialPacket (defaultExpr appendRequestCodec.ty)
  [ messageWithin bounds partialPacket,
    partialPacketObservation,
    .eq request.snd.snd.fst (.nat previousTerm) ]

def firstPacketRegressions : Bool :=
  let source : Node := ⟨0, by decide⟩
  let destination : Node := ⟨1, by decide⟩
  let first := Message.proposeVoteRequest (TxId := Nat) ⟨1, source, destination⟩
  let second := Message.proposeVoteRequest (TxId := Nat) ⟨2, source, destination⟩
  let queue := queueCodec.literal [first, second]
  let matching := fun term => firstFromMatches 2 (nodeCodec.literal source) queue
    (fun message => .eq (messageTerm message) (.nat term))
  (matching 1).eval assignment && !(matching 2).eval assignment &&
    !(firstFromMatches 2 (nodeCodec.literal destination) queue (fun _ => .bool true)).eval assignment

def solverAssertions (caseName : String) : Except String (List (Expr .bool)) :=
  let assign := [Expr.eq (.unknown 0) (.nat 7), Expr.eq (.unknown 1) (.nat 3)]
  match caseName with
  | "operations-sat" => .ok (assign ++ regressionFormulas)
  | "operations-unsat" =>
      .ok (assign ++ [.not (regressionFormulas.foldr Expr.and (.bool true))])
  | "alias-sat" =>
      .ok [.eq (.unknown 0) (.unknown 1),
        .not (noDup 2 (.ofList [.unknown 0, .unknown 1] : Expr (.seq .nat)))]
  | "alias-unsat" =>
      .ok [.eq (.unknown 0) (.unknown 1),
        noDup 2 (.ofList [.unknown 0, .unknown 1] : Expr (.seq .nat))]
  | "packets-sat" =>
      .ok (packetExamples.map fun m => Expr.eq (messageCodec.literal m) (messageCodec.literal m))
  | "entry-15-sat" => .ok fifteenNodeAssertions
  | "entry-15-unsat" =>
      let node : Node := ⟨0, by decide⟩
      let localState := Expr.rightD (tableGet (freshEntry bounds).fst node) (defaultExpr localCodec.ty)
      .ok (fifteenNodeAssertions ++ [.eq localState.snd.snd.fst.length (.nat 3)])
  | "finite-sat" => .ok (assign ++ finiteRegressions)
  | "finite-unsat" => .ok (assign ++ [.not (finiteRegressions.foldr Expr.and (.bool true))])
  | "partial-packet-prev-zero-sat" => .ok (partialPacketAssertions 0)
  | "partial-packet-prev-three-sat" => .ok (partialPacketAssertions 3)
  | "zero-bounds-sat" =>
      .ok [stateWithin zeroBounds (freshEntry zeroBounds), .eq (.unknown 5) (.nat 999)]
  | "zero-bounds-allocated-unsat" =>
      let node : Node := ⟨0, by decide⟩
      .ok [stateWithin zeroBounds (freshEntry zeroBounds),
        (tableGet (freshEntry zeroBounds).fst node).isLeft.not]
  | _ => .error s!"unknown symbolic test case: {caseName}"

def run : IO Unit := do
  for (formula, i) in regressionFormulas.zipIdx do
    unless formula.eval assignment do
      throw (IO.userError s!"symbolic operation regression {i} failed")
  for (name, passed) in modelRegressions do
    unless passed do throw (IO.userError name)
  for (name, passed) in boundRegressions do
    unless passed do throw (IO.userError name)
  unless packetRoundtrips do throw (IO.userError "packet codec roundtrip failed")
  unless modelOperationRegressions do throw (IO.userError "Model operation regression failed")
  unless firstPacketRegressions do throw (IO.userError "first-packet observation selected a later packet")
  for (formula, i) in finiteRegressions.zipIdx do
    unless formula.eval assignment do
      throw (IO.userError s!"symbolic finite selector regression {i} failed")
  IO.println s!"{regressionFormulas.length} operation regressions, {modelRegressions.length + boundRegressions.length} full-state regressions, 7 packet roundtrips and Model adapters passed"
  IO.println s!"15-node entry: {entryWidth bounds} scalar holes, no whole-state alternatives"
  IO.println s!"{finiteRegressions.length} finite-selector and observation regressions, first-packet ordering passed"

end CCFRaft.SymbolicTests

def main (args : List String) : IO Unit :=
  match args with
  | [] => CCFRaft.SymbolicTests.run
  | ["--smt", caseName] =>
      match CCFRaft.SymbolicTests.solverAssertions caseName with
      | .ok formulas => IO.print (Symbolic.script formulas)
      | .error message => throw (IO.userError message)
  | _ => throw (IO.userError "usage: SymbolicTests.lean [--smt CASE]")
