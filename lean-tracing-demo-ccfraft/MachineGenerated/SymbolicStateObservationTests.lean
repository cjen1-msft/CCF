-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicStateObservation
import Lean

set_option autoImplicit false

namespace CCFRaft.SymbolicStateObservation.Tests

open Symbolic SymbolicModel TraceStateObservation

private def node : Node := ⟨1, by decide⟩
private def absent : Node := ⟨14, by decide⟩
private def other : Node := ⟨2, by decide⟩
private def bounds : BoundedState.Bounds := ⟨0, 0, 0, 0, 0⟩
private def memberships : List MembershipState :=
  [.active, .retirementOrdered, .retirementSigned, .retirementCompleted, .retiredCommitted]

private def membership : Expr membershipCodec.ty :=
  memberships.zipIdx.foldr
    (fun (value, index) rest =>
      .ite (.eq (.unknown 0) (.nat index)) (membershipCodec.literal value) rest)
    (membershipCodec.literal .active)

private def optional (tag value : Nat) : Expr Codec.nat.option.ty :=
  .ite (.eq (.unknown tag) (.nat 0))
    (Codec.nat.option.literal none) (.inr (.unknown value))

private def symbolicLocal : Expr localCodec.ty :=
  let seed := localCodec.literal (BoundedState.encodeLocal freshNodeState)
  .pair seed.fst <|
    .pair seed.snd.fst <|
    .pair seed.snd.snd.fst <|
    .pair seed.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.snd.snd.snd.snd.fst <|
    .pair seed.snd.snd.snd.snd.snd.snd.snd.snd.snd.fst <|
    .pair membership (.pair (optional 2 3) (.pair (optional 4 5) (optional 6 7)))

private def entry : Expr (stateCodec bounds.transactionCount).ty :=
  .pair (tableExpr fun n : Node =>
    if n = node then
      .ite (.eq (.unknown 8) (.nat 0)) (.inl .unit) (.inr symbolicLocal)
    else .inl .unit)
    (.pair (tableExpr fun _ : Node => queueCodec.literal [])
    (.pair ((Codec.finset 0).literal {})
    (.pair (nodeSetCodec.literal {})
    (.pair (tableExpr fun _ : Node => .lt (.nat 0) (.unknown 1))
      (tableExpr fun observer : Node => tableExpr fun retired : Node =>
        if observer = absent ∧ retired = node then .lt (.nat 0) (.unknown 9)
        else .bool false)))))

private def assign (values : Array Nat) : Assignment :=
  fun index => values[index]?.getD 0

private def a : Assignment := assign #[0, 0, 0, 0, 1, 0, 1, 37, 1, 0]
private def b : Assignment := assign #[4, 1, 1, 0, 0, 99, 1, 123, 1, 1]
private def missing : Assignment := assign #[4, 1, 1, 99, 1, 88, 1, 77, 0, 1]
private def observations : List (Observation Node) :=
  (memberships.map (.membershipState node)) ++
  [.preVoteStatus node .capable, .preVoteStatus node .enabled,
   .preVoteStatus absent .capable, .preVoteStatus absent .enabled,
   .retirementIndex node none, .retirementIndex node (some 0),
   .retirementCommittableIndex node none, .retirementCommittableIndex node (some 0),
   .retiredCommittedIndex node (some 37), .retiredCommittedIndex node (some 123),
   .retirementCompleted absent node true, .retirementCompleted absent node false,
   .retirementCompleted node absent true, .retirementCompleted node absent false,
   .membershipState absent .active, .membershipState absent .retiredCommitted,
   .retirementIndex absent none, .retirementIndex absent (some 0)]

-- The same expression observes different symbolic fields under each assignment.
#guard (expression bounds entry (.membershipState node .active)).eval a
#guard !(expression bounds entry (.membershipState node .active)).eval b
#guard !(expression bounds entry (.preVoteStatus absent .enabled)).eval a
#guard (expression bounds entry (.preVoteStatus absent .enabled)).eval b
#guard (expression bounds entry (.retirementIndex node none)).eval a
#guard !(expression bounds entry (.retirementIndex node none)).eval b
#guard !(expression bounds entry (.retirementIndex node (some 0))).eval a
#guard (expression bounds entry (.retirementIndex node (some 0))).eval b
#guard (expression bounds entry (.retirementCommittableIndex node (some 0))).eval a
#guard (expression bounds entry (.retirementCommittableIndex node none)).eval b
#guard (expression bounds entry (.retiredCommittedIndex node (some 37))).eval a
#guard (expression bounds entry (.retiredCommittedIndex node (some 123))).eval b
#guard !(expression bounds entry (.retirementCompleted absent node true)).eval a
#guard (expression bounds entry (.retirementCompleted absent node true)).eval b
#guard (expression bounds entry (.retirementCompleted node absent false)).eval b
#guard (expression bounds entry (.retirementCompleted absent other false)).eval b

-- Cross-product checks cover every membership and pre-vote value.
#guard memberships.zipIdx.all fun (actual, index) =>
  memberships.all fun expected =>
    (expression bounds entry (.membershipState node expected)).eval
      (assign #[index, 0, 0, 0, 0, 0, 0, 0, 1]) == decide (actual = expected)
#guard [PreVoteStatus.capable, .enabled].zipIdx.all fun (actual, index) =>
  [PreVoteStatus.capable, .enabled].all fun expected =>
    (expression bounds entry (.preVoteStatus absent expected)).eval
      (assign #[0, index]) == decide (actual = expected)
#guard ([Observation.retirementIndex, Observation.retirementCommittableIndex,
    Observation.retiredCommittedIndex] : List (Node -> Option Nat -> Observation Node)).all
  fun constructor =>
    [none, some 0, some 123].all fun actual =>
      [none, some 0, some 123].all fun expected =>
        let tag := if actual.isSome then 1 else 0
        let value := actual.getD 999
        (expression bounds entry (constructor node expected)).eval
          (assign #[0, 0, tag, value, tag, value, tag, value, 1]) ==
            decide (actual = expected)

-- Absent slots discard inactive payloads, including nonzero retirement indices.
#guard (evalEntry bounds missing entry).node? node |>.isNone
#guard (expression bounds entry (.membershipState node .active)).eval missing
#guard !(expression bounds entry (.membershipState node .retiredCommitted)).eval missing
#guard (expression bounds entry (.retirementIndex node none)).eval missing
#guard (expression bounds entry (.retirementCommittableIndex node none)).eval missing
#guard (expression bounds entry (.retiredCommittedIndex node none)).eval missing
#guard !(expression bounds entry (.retirementIndex node (some 0))).eval missing
#guard (expression bounds entry (.preVoteStatus node .enabled)).eval missing
#guard (expression bounds entry (.retirementCompleted absent node true)).eval missing
#guard !(evalEntry bounds b entry).allocated absent
#guard (localCodec.decode missing (localState entry node)).isNewFollower
#guard !(localCodec.decode missing (defaultExpr localCodec.ty)).isNewFollower

-- No bound premise: these assigned fields deliberately exceed zero bounds.
#guard [a, b, missing].all fun ρ =>
  observations.all fun observation =>
    (expression bounds entry observation).eval ρ ==
      decide (observation.Holds (evalEntry bounds ρ entry))

private def fresh : Expr (stateCodec bounds.transactionCount).ty := freshEntry bounds
#guard (expression bounds fresh (.membershipState node .active)).eval (fun _ => 0)
#guard (expression bounds fresh (.membershipState node .retiredCommitted)).eval (fun _ => 1)
#guard (expression bounds fresh (.retirementIndex node none)).eval (fun _ => 0)
#guard (expression bounds fresh (.retirementIndex node (some 1))).eval (fun _ => 1)
#guard (expression bounds fresh (.preVoteStatus absent .enabled)).eval (fun _ => 0)
#guard (expression bounds fresh (.retirementCompleted absent node true)).eval (fun _ => 0)
#guard (expression bounds fresh (.preVoteStatus absent .capable)).eval (fun _ => 1)
#guard (expression bounds fresh (.retirementCompleted absent node false)).eval (fun _ => 1)

example (bounds : BoundedState.Bounds) (ρ : Assignment)
    (entry : Expr (stateCodec bounds.transactionCount).ty) (observation : Observation Node) :
    (expression bounds entry observation).eval ρ = true ↔
      observation.Holds (evalEntry bounds ρ entry) :=
  expression_correct bounds ρ entry observation

end CCFRaft.SymbolicStateObservation.Tests

run_cmd do
  for theoremName in [
      ``CCFRaft.SymbolicStateObservation.localState_correct,
      ``CCFRaft.SymbolicStateObservation.expression_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
