-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCompilerEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem instruction_cases {width : PNat}
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before after : Encoding width)
    (run : (instruction item).run before = .ok ((), after)) :
    (exists node, item = .checkQuorum node /\ (checkQuorum node.val).run before = .ok ((), after)) \/
    (exists clauses, observationClauses before.toNodeColumns item = .ok clauses /\
      (assertAll clauses).run before = .ok ((), after)) := by
  cases item
  case checkQuorum node => exact Or.inl ⟨node, rfl, run⟩
  all_goals
    first
    | exact Or.inr ⟨_, rfl, run⟩
    | contradiction

theorem instruction_holds_before {width : PNat}
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before after : Encoding width)
    (run : (instruction item).run before = .ok ((), after)) (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) : Holds before.assertions.toList assignment := by
  rcases instruction_cases item before after run with ⟨node, _, action⟩ | ⟨clauses, _, asserted⟩
  · exact ((quorum_holds node.val before after action assignment).mp holds).1
  · exact ((assert_all_holds clauses before after asserted assignment).mp holds).1

theorem compile_instructions_holds_before {width : PNat}
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run : (compileInstructions index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  induction items generalizing before index groups with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    simpa only [same] using holds
  | cons item rest ih =>
    cases step : instruction item before with
    | error error =>
      simp [compileInstructions, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructions, StateT.run, step] at run
      exact instruction_holds_before item before middle step assignment (ih middle _ _ run)

theorem observation_cons {width : PNat} [Bootstrap (Fin width)]
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat)
    (rest : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (columns : NodeColumns) (clauses : List (Expr .bool))
    (emitted : observationClauses columns item = .ok clauses) :
    NativeArrayCheckQuorum.follows arrays (item :: rest) <->
      NativeArrayCheckQuorum.follows arrays [item] /\ NativeArrayCheckQuorum.follows arrays rest := by
  cases item <;> simp [observationClauses] at emitted
  all_goals simp [NativeArrayCheckQuorum.follows]

theorem compile_instructions_sound {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run : (compileInstructions index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toNodeColumns arrays)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    NativeArrayCheckQuorum.follows arrays items := by
  induction items generalizing before index groups arrays with
  | nil => trivial
  | cons item rest ih =>
    cases step : instruction item before with
    | error error =>
      simp [compileInstructions, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructions, StateT.run, step] at run
      have middleHolds := compile_instructions_holds_before rest middle after _ _ result run assignment holds
      rcases instruction_cases item before middle step with ⟨node, same, action⟩ | ⟨clauses, emitted, asserted⟩
      · subst item
        obtain ⟨_, enabled, afterColumns⟩ :=
          quorum_native_success node before middle action assignment middleHolds arrays columns sameBootstrap
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [(quorum_success node.val before middle action).bootstrap, sameBootstrap]
        exact ⟨enabled, ih middle _ _ run _ afterColumns bootstrap⟩
      · have frame := (assert_all_success clauses before middle asserted).1
        have observed := (observation_correct assignment before.toNodeColumns arrays columns
          domains item clauses emitted).mp
            ((assert_all_holds clauses before middle asserted assignment).mp middleHolds).2
        have afterColumns : NodeColumnsRep assignment middle.toNodeColumns arrays := by
          simpa only [frame.columns] using columns
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [frame.bootstrap, sameBootstrap]
        exact (observation_cons arrays item rest _ clauses emitted).mpr
          ⟨observed, ih middle _ _ run arrays afterColumns bootstrap⟩

theorem compiled_trace_model {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (initial started final : Encoding width) (index : Nat) (groups result : Array Group)
    (initialColumns : initial.toNodeColumns = {})
    (start : (initialDomains width).run initial = .ok ((), started))
    (run : (compileInstructions index groups items).run started = .ok (result, final))
    (assignment : Assignment) (holds : Holds final.assertions.toList assignment)
    (sameBootstrap : decodeBits initial.bootstrap = INITIAL_CONFIGURATION) :
    exists model : State (Fin width) Nat, NativeArrayCheckQuorum.modelFollows model items := by
  have startedHolds := compile_instructions_holds_before items started final index groups result run assignment holds
  obtain ⟨frame, initialHolds⟩ := initial_domains_success initial started start assignment
  have domains := (initialHolds.mp startedHolds).2
  obtain ⟨arrays, model, columns, represented⟩ :=
    initial_assertions_model width assignment ((initial_assertions_domains width assignment).mpr domains)
  have startedColumns : NodeColumnsRep assignment started.toNodeColumns arrays := by
    simpa only [frame.columns, initialColumns] using columns
  have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
    rw [frame.bootstrap, sameBootstrap]
  exact ⟨model, (NativeArrayCheckQuorum.follows_correct items arrays model represented).mp
    (compile_instructions_sound items started final index groups result run assignment holds arrays
      startedColumns domains bootstrap)⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
