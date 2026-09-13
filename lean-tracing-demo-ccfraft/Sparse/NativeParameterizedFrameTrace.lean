-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame
import Sparse.NativeNatParametersEncoding
import Sparse.NativeFrameTrace

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

private theorem parameterized_frame_instruction_holds_before {width : PNat}
    {count : Nat} (base : Nat) (item : ParameterizedFrameInstruction width count)
    (before after : Encoding width)
    (run : (parameterizedFrameInstruction base item).run before =
      .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment := by
  cases item with
  | core instruction =>
    exact frame_instruction_holds_before instruction before after run assignment holds
  | clientRequest source transaction =>
    exact client_request_prior_holds source (transaction.term base) before after run
      assignment holds

private theorem parameterized_frame_instruction_references {width : PNat}
    {count : Nat} (base : Nat) (item : ParameterizedFrameInstruction width count)
    (before after : Encoding width)
    (run : (parameterizedFrameInstruction base item).run before =
      .ok ((), after))
    (valid : ReferencesValid before) :
    ReferencesValid after := by
  cases item with
  | core instruction =>
    exact frame_instruction_references instruction before after run valid
  | clientRequest source transaction =>
    exact client_request_references source (transaction.term base) before after run
      valid

private theorem parameterized_frame_instruction_next_mono {width : PNat}
    {count : Nat} (base : Nat) (item : ParameterizedFrameInstruction width count)
    (before after : Encoding width)
    (run : (parameterizedFrameInstruction base item).run before =
      .ok ((), after)) :
    before.next <= after.next := by
  cases item with
  | core instruction =>
    exact frame_instruction_next_mono instruction before after run
  | clientRequest source transaction =>
    rw [client_request_next source (transaction.term base) before after run]
    omega

private theorem parameterized_frame_instruction_bootstrap {width : PNat}
    {count : Nat} (base : Nat) (item : ParameterizedFrameInstruction width count)
    (before after : Encoding width)
    (run : (parameterizedFrameInstruction base item).run before =
      .ok ((), after)) :
    after.bootstrap = before.bootstrap := by
  cases item with
  | core instruction =>
    exact frame_instruction_bootstrap instruction before after run
  | clientRequest source transaction =>
    exact client_request_bootstrap source (transaction.term base) before after run

theorem compile_parameterized_frame_sound {width : PNat} [Bootstrap (Fin width)]
    {count : Nat} (base : Nat) (values : Fin count -> Nat)
    (items : List (ParameterizedFrameInstruction width count))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run :
      (compileInstructionsWith (parameterizedFrameInstruction base)
        index groups items).run before = .ok (result, after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (parameters : NatParametersRep assignment base values) :
    NativeArrayVote.follows frame
      (items.map (ParameterizedFrameInstruction.materialize values)) := by
  induction items generalizing before index groups frame with
  | nil =>
    simp only [List.map_nil, NativeArrayVote.follows]
  | cons item items ih =>
    cases step : parameterizedFrameInstruction base item before with
    | error error =>
      simp [compileInstructionsWith, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructionsWith, StateT.run, step] at run
      have middleHolds :=
        compile_with_holds_before (parameterizedFrameInstruction base)
          (parameterized_frame_instruction_holds_before base) items middle after
          _ _ result run assignment holds
      have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
        rw [parameterized_frame_instruction_bootstrap base item before middle step,
          sameBootstrap]
      cases item with
      | core instruction =>
        simp only [parameterizedFrameInstruction] at step
        let nextGroups := groups.push
          { instruction := some index
            start := before.assertions.size
            stop := middle.assertions.size }
        have singletonRun :
            (compileInstructionsWith frameInstruction index groups [instruction]).run
                before = .ok (nextGroups, middle) := by
          simp [compileInstructionsWith, StateT.run, step, nextGroups]
        simpa only [List.map_cons,
          ParameterizedFrameInstruction.materialize, List.singleton_append] using
          compile_frame_sound_continuation [instruction] before middle index groups
            nextGroups singletonRun assignment middleHolds frame rep sameBootstrap
            (items.map (ParameterizedFrameInstruction.materialize values))
            (fun nextFrame nextRep =>
              ih middle (index + 1) nextGroups run nextFrame nextRep
                bootstrap)
      | clientRequest source transaction =>
        simp only [parameterizedFrameInstruction] at step
        obtain ⟨nextFrame, request, nextRep⟩ :=
          client_request_frame_sound source (transaction.term base)
            (transaction.value values) before middle step assignment
            middleHolds frame rep sameBootstrap
            (transaction.term_eval assignment base values parameters)
        exact ⟨nextFrame, request,
          ih middle (index + 1) _ run nextFrame nextRep bootstrap⟩

theorem compile_parameterized_frame_complete {width : PNat}
    [Bootstrap (Fin width)] {count : Nat}
    (base : Nat) (values : Fin count -> Nat)
    (items : List (ParameterizedFrameInstruction width count))
    (before after : Encoding width) (index : Nat) (groups result : Array Group)
    (run :
      (compileInstructionsWith (parameterizedFrameInstruction base)
        index groups items).run before = .ok (result, after))
    (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame)
    (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (parameters : NatParametersRep assignment base values)
    (parameterBound : base + count <= before.next)
    (follows :
      NativeArrayVote.follows frame
        (items.map (ParameterizedFrameInstruction.materialize values))) :
    exists extended : Assignment,
      exists finalFrame : NativeArrayVote.Frame (Fin width) Nat,
      assignment.AgreesBelow before.next extended /\
        Holds after.assertions.toList extended /\
        FrameColumnsRep extended after.toColumns finalFrame := by
  induction items generalizing before index groups assignment frame with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    exact ⟨assignment, frame, (fun _ _ _ => rfl),
      by simpa only [same] using holds, by simpa only [same] using rep⟩
  | cons item items ih =>
    cases step : parameterizedFrameInstruction base item before with
    | error error =>
      simp [compileInstructionsWith, StateT.run, step] at run
    | ok pair =>
      rcases pair with ⟨value, middle⟩
      cases value
      simp only [compileInstructionsWith, StateT.run, step] at run
      let nextGroups := groups.push
        { instruction := some index
          start := before.assertions.size
          stop := middle.assertions.size }
      have nextValid :=
        parameterized_frame_instruction_references base item before middle step valid
      have nextMono :=
        parameterized_frame_instruction_next_mono base item before middle step
      have bootstrap : decodeBits middle.bootstrap = INITIAL_CONFIGURATION := by
        rw [parameterized_frame_instruction_bootstrap base item before middle step,
          sameBootstrap]
      have finish (middleAssignment : Assignment)
          (nextFrame : NativeArrayVote.Frame (Fin width) Nat)
          (agreement : assignment.AgreesBelow before.next middleAssignment)
          (middleHolds : Holds middle.assertions.toList middleAssignment)
          (nextRep : FrameColumnsRep middleAssignment middle.toColumns nextFrame)
          (restFollows :
            NativeArrayVote.follows nextFrame
              (items.map (ParameterizedFrameInstruction.materialize values))) :
          exists extended : Assignment,
            exists finalFrame : NativeArrayVote.Frame (Fin width) Nat,
            assignment.AgreesBelow before.next extended /\
              Holds after.assertions.toList extended /\
              FrameColumnsRep extended after.toColumns finalFrame := by
        have nextParameters :
            NatParametersRep middleAssignment base values :=
          parameters.agrees_below assignment middleAssignment base before.next
            values parameterBound agreement
        obtain ⟨extended, finalFrame, finalAgreement, finalHolds, finalRep⟩ :=
          ih middle (index + 1) nextGroups run middleAssignment middleHolds
            nextFrame
            nextRep nextValid bootstrap nextParameters
            (parameterBound.trans nextMono) restFollows
        exact ⟨extended, finalFrame,
          agreement.trans (finalAgreement.restrict nextMono), finalHolds,
          finalRep⟩
      cases item with
      | core instruction =>
        simp only [parameterizedFrameInstruction] at step
        have singletonRun :
            (compileInstructionsWith frameInstruction index groups [instruction]).run
                before = .ok (nextGroups, middle) := by
          simp [compileInstructionsWith, StateT.run, step, nextGroups]
        have coreFollows :
            NativeArrayVote.follows frame
              ([instruction] ++
                items.map (ParameterizedFrameInstruction.materialize values)) := by
          simpa only [List.map_cons,
            ParameterizedFrameInstruction.materialize,
            List.singleton_append] using follows
        obtain ⟨middleAssignment, nextFrame, agreement, middleHolds, nextRep,
            restFollows⟩ :=
          compile_frame_complete_continuation [instruction] before middle index
            groups nextGroups singletonRun assignment holds frame rep valid
            sameBootstrap
            (items.map (ParameterizedFrameInstruction.materialize values))
            coreFollows
        exact finish middleAssignment nextFrame agreement middleHolds nextRep
          restFollows
      | clientRequest source transaction =>
        simp only [parameterizedFrameInstruction] at step
        obtain ⟨nextFrame, request, restFollows⟩ := follows
        obtain ⟨middleAssignment, agreement, middleHolds, nextRep⟩ :=
          client_request_complete source (transaction.term base)
            (transaction.value values) before middle step assignment holds
            frame nextFrame rep valid sameBootstrap
            (transaction.term_eval assignment base values parameters) request
        exact finish middleAssignment nextFrame agreement middleHolds nextRep
          restFollows

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
