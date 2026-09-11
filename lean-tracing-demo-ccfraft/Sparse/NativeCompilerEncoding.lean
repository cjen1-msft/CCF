-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeObservationEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure SameReferences {width : PNat} (before after : Encoding width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  role : after.role = before.role
  newFollower : after.newFollower = before.newFollower
  next : after.next = before.next

theorem SameReferences.trans {width : PNat} {first middle last : Encoding width}
    (left : SameReferences first middle) (right : SameReferences middle last) :
    SameReferences first last :=
  ⟨right.bootstrap.trans left.bootstrap, right.role.trans left.role,
    right.newFollower.trans left.newFollower, right.next.trans left.next⟩

theorem bind_run {width : PNat} {firstValue lastValue : Type}
    (first : EncodeM width firstValue) (second : firstValue -> EncodeM width lastValue)
    (before after : Encoding width) (value : lastValue) :
    (first >>= second).run before = .ok (value, after) <->
      exists (intermediate : firstValue) (middle : Encoding width),
        first.run before = .ok (intermediate, middle) /\
          (second intermediate).run middle = .ok (value, after) := by
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind]
  cases step : first before with
  | error error => simp
  | ok pair =>
    rcases pair with ⟨intermediate, middle⟩
    simp

theorem assertion_success {width : PNat} (formula : Expr .bool) (before after : Encoding width)
    (run : (assertion formula).run before = .ok ((), after)) :
    SameReferences before after /\ after.assertions = before.assertions.push formula := by
  simp only [assertion, StateT.run] at run
  split at run
  · cases run
    exact ⟨⟨rfl, rfl, rfl, rfl⟩, rfl⟩
  · contradiction

theorem assert_all_success {width : PNat} (formulas : List (Expr .bool))
    (before after : Encoding width) (run : (assertAll formulas).run before = .ok ((), after)) :
    SameReferences before after /\ after.assertions.toList = before.assertions.toList ++ formulas := by
  induction formulas generalizing before with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    subst after
    exact ⟨⟨rfl, rfl, rfl, rfl⟩, by simp⟩
  | cons formula rest ih =>
    obtain ⟨value, middle, first, second⟩ :=
      (bind_run (assertion formula) (fun _ => assertAll rest) before after ()).mp run
    cases value
    obtain ⟨firstFrame, firstClauses⟩ := assertion_success formula before middle first
    obtain ⟨lastFrame, lastClauses⟩ := ih middle second
    refine ⟨firstFrame.trans lastFrame, ?_⟩
    simp [lastClauses, firstClauses, List.append_assoc]

theorem assert_all_holds {width : PNat} (formulas : List (Expr .bool))
    (before after : Encoding width) (run : (assertAll formulas).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\ Holds formulas assignment := by
  rw [(assert_all_success formulas before after run).2]
  simp [Holds, or_imp, forall_and]

theorem observation_instruction_run {width : PNat}
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before : Encoding width)
    (clauses : List (Expr .bool))
    (emitted : observationClauses before.role before.newFollower item = .ok clauses) :
    (instruction item).run before = (assertAll clauses).run before := by
  cases item <;> simp [observationClauses] at emitted
  all_goals subst clauses; rfl

theorem observation_instruction_success {width : PNat} [Bootstrap (Fin width)]
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before after : Encoding width)
    (clauses : List (Expr .bool))
    (emitted : observationClauses before.role before.newFollower item = .ok clauses)
    (run : (instruction item).run before = .ok ((), after))
    (assignment : Assignment) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (model : State (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.role before.newFollower arrays)
    (represented : NativeArrayCheckQuorum.Rep arrays model)
    (domains : forall node : Fin width, NodeDomain width assignment node.val) :
    SameReferences before after /\
      (Holds after.assertions.toList assignment <->
        Holds before.assertions.toList assignment /\ NativeArrayCheckQuorum.modelFollows model [item]) := by
  rw [observation_instruction_run item before clauses emitted] at run
  refine ⟨(assert_all_success clauses before after run).1, ?_⟩
  rw [assert_all_holds clauses before after run assignment,
    observation_model_correct assignment before.role before.newFollower arrays model columns
      represented domains item clauses emitted]

theorem initial_domains_success {width : PNat} (before after : Encoding width)
    (run : (initialDomains width).run before = .ok ((), after)) (assignment : Assignment) :
    SameReferences before after /\
      (Holds after.assertions.toList assignment <-> Holds before.assertions.toList assignment /\
        (forall node : Fin width, NodeDomain width assignment node.val)) := by
  refine ⟨(assert_all_success (initialAssertions width) before after run).1, ?_⟩
  rw [assert_all_holds (initialAssertions width) before after run assignment,
    initial_assertions_domains]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
