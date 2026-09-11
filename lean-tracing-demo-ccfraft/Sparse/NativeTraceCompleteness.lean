-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAssignmentEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem compile_instructions_complete {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run : (compileInstructions index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toNodeColumns arrays)
    (valid : ReferencesValid before)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (follows : NativeArrayCheckQuorum.follows arrays items) :
    exists extended : Assignment, Holds after.assertions.toList extended := by
  induction items generalizing before index groups assignment arrays with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    exact ⟨assignment, by simpa only [same] using holds⟩
  | cons item rest ih =>
    cases step : instruction item before with
    | error error =>
      simp [compileInstructions, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructions, StateT.run, step] at run
      have afterValid := instruction_references item before middle step valid
      rcases instruction_cases item before middle step with ⟨node, same, action⟩ | ⟨clauses, emitted, asserted⟩
      · subst item
        obtain ⟨enabled, restFollows⟩ := follows
        obtain ⟨extended, agreement, middleHolds, afterColumns⟩ :=
          quorum_complete node before middle action assignment holds arrays columns valid sameBootstrap enabled
        have afterDomains : forall peer : Fin width, NodeDomain width extended peer.val :=
          fun peer => (domains peer).agrees_below before.next assignment extended peer.val valid.minimum agreement
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [(quorum_success node.val before middle action).bootstrap, sameBootstrap]
        exact ih middle _ _ run extended middleHolds _ afterColumns afterValid afterDomains bootstrap restFollows
      · obtain ⟨observed, restFollows⟩ := (observation_cons arrays item rest _ clauses emitted).mp follows
        have frame := (assert_all_success clauses before middle asserted).1
        have middleHolds := (assert_all_holds clauses before middle asserted assignment).mpr
          ⟨holds, (observation_correct assignment before.toNodeColumns arrays columns domains
            item clauses emitted).mpr observed⟩
        have afterColumns : NodeColumnsRep assignment middle.toNodeColumns arrays := by
          simpa only [frame.columns] using columns
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [frame.bootstrap, sameBootstrap]
        exact ih middle _ _ run assignment middleHolds arrays afterColumns afterValid domains bootstrap restFollows

theorem model_compiled_trace {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (initial started final : Encoding width) (index : Nat) (groups result : Array Group)
    (initialColumns : initial.toNodeColumns = {})
    (empty : initial.assertions = #[]) (valid : ReferencesValid initial)
    (start : (initialDomains width).run initial = .ok ((), started))
    (run : (compileInstructions index groups items).run started = .ok (result, final))
    (sameBootstrap : decodeBits initial.bootstrap = INITIAL_CONFIGURATION)
    (model : State (Fin width) Nat) (follows : NativeArrayCheckQuorum.modelFollows model items) :
    exists assignment : Assignment, Holds final.assertions.toList assignment := by
  obtain ⟨assignment, arrays, domainsHold, columns, represented⟩ :=
    model_initial_assertions width Assignment.default model
  have domains := (initial_assertions_domains width assignment).mp domainsHold
  obtain ⟨frame, initialHolds⟩ := initial_domains_success initial started start assignment
  have startedHolds := initialHolds.mpr ⟨by simp [empty, Holds], domains⟩
  have startedColumns : NodeColumnsRep assignment started.toNodeColumns arrays := by
    simpa only [frame.columns, initialColumns] using columns
  have startedValid : ReferencesValid started :=
    ⟨by simpa only [frame.next] using valid.minimum,
      by simpa only [frame.next, frame.role] using valid.role,
      by simpa only [frame.next, frame.newFollower] using valid.newFollower⟩
  have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
    rw [frame.bootstrap, sameBootstrap]
  exact compile_instructions_complete items started final index groups result run assignment startedHolds arrays
    startedColumns startedValid domains bootstrap
      ((NativeArrayCheckQuorum.follows_correct items arrays model represented).mpr follows)

theorem compiled_trace_iff {width : PNat} [Bootstrap (Fin width)]
    (items : List (NativeArrayCheckQuorum.Instruction (Fin width) Nat))
    (initial started final : Encoding width) (index : Nat) (groups result : Array Group)
    (initialColumns : initial.toNodeColumns = {})
    (empty : initial.assertions = #[]) (valid : ReferencesValid initial)
    (start : (initialDomains width).run initial = .ok ((), started))
    (run : (compileInstructions index groups items).run started = .ok (result, final))
    (sameBootstrap : decodeBits initial.bootstrap = INITIAL_CONFIGURATION) :
    (exists assignment : Assignment, Holds final.assertions.toList assignment) <->
      (exists model : State (Fin width) Nat, NativeArrayCheckQuorum.modelFollows model items) := by
  constructor
  · rintro ⟨assignment, holds⟩
    exact compiled_trace_model items initial started final index groups result initialColumns
      start run assignment holds sameBootstrap
  · rintro ⟨model, follows⟩
    exact model_compiled_trace items initial started final index groups result initialColumns
      empty valid start run sameBootstrap model follows

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
