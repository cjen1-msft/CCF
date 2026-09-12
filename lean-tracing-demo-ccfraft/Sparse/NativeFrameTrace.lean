-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameStep

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem compile_frame_sound {width : PNat} [Bootstrap (Fin width)]
    (items : List (FrameInstruction width))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run : (compileInstructionsWith frameInstruction index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    NativeArrayVote.follows frame items := by
  induction items generalizing before index groups frame with
  | nil => trivial
  | cons item rest ih =>
    cases step : frameInstruction item before with
    | error error => simp [compileInstructionsWith, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructionsWith, StateT.run, step] at run
      have middleHolds := compile_with_holds_before frameInstruction frame_instruction_holds_before
        rest middle after _ _ result run assignment holds
      rcases frame_instruction_cases item before middle step with ⟨node, same, action⟩ |
          ⟨clauses, emitted, asserted⟩
      · subst item
        obtain ⟨_, enabled, afterColumns⟩ :=
          frame_quorum_success node before middle action assignment middleHolds frame rep sameBootstrap
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [(quorum_success node.val before middle action).bootstrap, sameBootstrap]
        have restFollows := ih middle _ _ run _ afterColumns bootstrap
        simpa only [NativeArrayVote.follows, NativeArrayCheckQuorum.follows, and_true] using
          And.intro enabled restFollows
      · have references := (assert_all_success clauses before middle asserted).1
        have observed := (frame_observation_correct assignment before.toColumns frame rep
          domains item clauses emitted).mp
            ((assert_all_holds clauses before middle asserted assignment).mp middleHolds).2
        have afterColumns : FrameColumnsRep assignment middle.toColumns frame := by
          simpa only [references.columns] using rep
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [references.bootstrap, sameBootstrap]
        exact (frame_observation_cons frame _ item rest clauses emitted).mpr
          ⟨observed, ih middle _ _ run frame afterColumns bootstrap⟩

theorem compile_frame_complete {width : PNat} [Bootstrap (Fin width)]
    (items : List (FrameInstruction width))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run : (compileInstructionsWith frameInstruction index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (domains : forall node : Fin width, NodeDomain width assignment node.val)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (follows : NativeArrayVote.follows frame items) :
    exists extended : Assignment, Holds after.assertions.toList extended := by
  induction items generalizing before index groups assignment frame with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    exact ⟨assignment, by simpa only [same] using holds⟩
  | cons item rest ih =>
    cases step : frameInstruction item before with
    | error error => simp [compileInstructionsWith, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructionsWith, StateT.run, step] at run
      have afterValid := frame_instruction_references item before middle step valid
      rcases frame_instruction_cases item before middle step with ⟨node, same, action⟩ |
          ⟨clauses, emitted, asserted⟩
      · subst item
        have stepFollows : NativeArrayCheckQuorum.enabled frame.nodes node /\
            NativeArrayVote.follows (frame.nodeStep (.checkQuorum node)) rest := by
          simpa only [NativeArrayVote.follows, NativeArrayCheckQuorum.follows, and_true] using follows
        obtain ⟨extended, agreement, middleHolds, afterColumns⟩ :=
          frame_quorum_complete node before middle action assignment holds frame rep valid sameBootstrap stepFollows.1
        have afterDomains : forall peer : Fin width, NodeDomain width extended peer.val :=
          fun peer => (domains peer).agrees_below before.next assignment extended peer.val valid.minimum agreement
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [(quorum_success node.val before middle action).bootstrap, sameBootstrap]
        exact ih middle _ _ run extended middleHolds _ afterColumns afterValid afterDomains bootstrap stepFollows.2
      · obtain ⟨observed, restFollows⟩ := (frame_observation_cons frame _ item rest clauses emitted).mp follows
        have references := (assert_all_success clauses before middle asserted).1
        have middleHolds := (assert_all_holds clauses before middle asserted assignment).mpr
          ⟨holds, (frame_observation_correct assignment before.toColumns frame rep domains item clauses emitted).mpr observed⟩
        have afterColumns : FrameColumnsRep assignment middle.toColumns frame := by
          simpa only [references.columns] using rep
        have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
          rw [references.bootstrap, sameBootstrap]
        exact ih middle _ _ run assignment middleHolds frame afterColumns afterValid domains bootstrap restFollows

theorem compiled_frame_trace_iff {width : PNat} [Bootstrap (Fin width)]
    (items : List (FrameInstruction width))
    (initial started final : Encoding width) (index : Nat) (groups result : Array Group)
    (initialColumns : initial.toColumns = {}) (empty : initial.assertions = #[])
    (valid : ReferencesValid initial) (start : (initialFrameDomains width).run initial = .ok ((), started))
    (run : (compileInstructionsWith frameInstruction index groups items).run started = .ok (result, final))
    (sameBootstrap : decodeBits initial.bootstrap = INITIAL_CONFIGURATION) :
    (exists assignment : Assignment, Holds final.assertions.toList assignment) <->
      (exists model : State (Fin width) Nat, NativeArrayVote.modelFollows model items) := by
  constructor
  · rintro ⟨assignment, holds⟩
    have startedHolds := compile_with_holds_before frameInstruction frame_instruction_holds_before
      items started final index groups result run assignment holds
    obtain ⟨references, initialHolds⟩ := initial_frame_domains_success initial started start assignment
    obtain ⟨_, domains, submitted⟩ := initialHolds.mp startedHolds
    let frame := initialFrame width assignment domains submitted
    have rep : FrameColumnsRep assignment started.toColumns frame := by
      simpa only [references.columns, initialColumns] using initial_frame_rep width assignment domains submitted
    have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
      rw [references.bootstrap, sameBootstrap]
    exact (NativeArrayVote.exists_iff items).mp
      ⟨frame, initial_frame_valid width assignment domains submitted,
        compile_frame_sound items started final index groups result run assignment holds frame rep domains bootstrap⟩
  · rintro ⟨model, follows⟩
    let frame := NativeArrayVote.Frame.ofModel model
    let assignment := initialFrameAssignment width Assignment.default frame
    have domains := initial_frame_assignment_domains width Assignment.default frame
    have submitted := initial_frame_assignment_submitted_domain width Assignment.default frame
    obtain ⟨references, initialHolds⟩ := initial_frame_domains_success initial started start assignment
    have startedHolds := initialHolds.mpr ⟨by simp [empty, Holds], domains, submitted⟩
    have rep : FrameColumnsRep assignment started.toColumns frame := by
      simpa only [references.columns, initialColumns] using
        initial_frame_assignment_rep width Assignment.default frame (NativeArrayVote.of_model_valid model)
    have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
      rw [references.bootstrap, sameBootstrap]
    exact compile_frame_complete items started final index groups result run assignment startedHolds frame
      rep (valid.same_references references) domains bootstrap
      ((NativeArrayVote.follows_correct items frame model (NativeArrayVote.of_model_rep model)).mpr follows)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
