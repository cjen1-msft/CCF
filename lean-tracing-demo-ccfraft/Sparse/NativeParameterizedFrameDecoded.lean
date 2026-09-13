-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrameTrace
import Sparse.NativeScriptRun

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

def ParameterizedFrameDecoded.ModelConsistent (input : ParameterizedFrameDecoded) : Prop :=
  exists bootstrap : Bootstrap (Fin input.frame.width),
    letI := bootstrap
    INITIAL_CONFIGURATION = input.frame.bootstrap /\
      exists values : Fin input.unknowns.size -> Nat,
        exists model : State (Fin input.frame.width) Nat,
          NativeArrayVote.modelFollows model
            (input.frame.instructions.toList.map
              (ParameterizedFrameInstruction.materialize values))

def ParameterizedFrameDocumentConsistent (document : Json) : Prop :=
  exists input,
    decodeParameterizedFrameDocument document = .ok input /\ input.ModelConsistent

theorem compiled_parameterized_frame_trace_iff
    {width : PNat} [Bootstrap (Fin width)] {count : Nat}
    (items : List (ParameterizedFrameInstruction width count))
    (encoded initialized started final : Encoding width)
    (index : Nat) (groups result : Array Group)
    (initialColumns : encoded.toColumns = {})
    (empty : encoded.assertions = #[])
    (valid : ReferencesValid encoded)
    (initialRun :
      (initialFrameDomains width).run encoded = .ok ((), initialized))
    (declare :
      (declareNatParameters count).run initialized = .ok ((), started))
    (run :
      (compileInstructionsWith
        (parameterizedFrameInstruction initialized.next)
        index groups items).run started = .ok (result, final))
    (sameBootstrap : decodeBits encoded.bootstrap = INITIAL_CONFIGURATION) :
    (exists assignment : Assignment,
      Holds final.assertions.toList assignment) <->
      (exists values : Fin count -> Nat,
        exists model : State (Fin width) Nat,
          NativeArrayVote.modelFollows model
            (items.map (ParameterizedFrameInstruction.materialize values))) := by
  constructor
  · rintro ⟨assignment, finalHolds⟩
    have startedHolds :=
      compile_parameterized_frame_prior_holds initialized.next items started final
        index groups result run assignment finalHolds
    have initializedHolds :=
      declare_nat_parameters_prior_holds count initialized started declare
        assignment startedHolds
    obtain ⟨references, initialHolds⟩ :=
      initial_frame_domains_success encoded initialized initialRun assignment
    obtain ⟨_, domains, submitted⟩ := initialHolds.mp initializedHolds
    obtain ⟨values, parameters⟩ :=
      declare_nat_parameters_sound count initialized started declare assignment
        startedHolds
    let frame := initialFrame width assignment domains submitted
    have initializedRep :
        FrameColumnsRep assignment initialized.toColumns frame := by
      simpa only [references.columns, initialColumns] using
        initial_frame_rep width assignment domains submitted
    have startedRep :
        FrameColumnsRep assignment started.toColumns frame := by
      simpa only [(declare_nat_parameters_success count initialized started
        declare).columns] using initializedRep
    have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
      rw [(declare_nat_parameters_success count initialized started
        declare).bootstrap, references.bootstrap, sameBootstrap]
    exact ⟨values,
      (NativeArrayVote.exists_iff
        (items.map (ParameterizedFrameInstruction.materialize values))).mp
        ⟨frame, initial_frame_valid width assignment domains submitted,
          compile_parameterized_frame_sound initialized.next values items started
            final index groups result run assignment finalHolds frame startedRep
            bootstrap parameters⟩⟩
  · rintro ⟨values, model, follows⟩
    let frame := NativeArrayVote.Frame.ofModel model
    let assignment := initialFrameAssignment width Assignment.default frame
    have domains :=
      initial_frame_assignment_domains width Assignment.default frame
    have submitted :=
      initial_frame_assignment_submitted_domain width Assignment.default frame
    obtain ⟨references, initialHolds⟩ :=
      initial_frame_domains_success encoded initialized initialRun assignment
    have initializedHolds :
        Holds initialized.assertions.toList assignment :=
      initialHolds.mpr ⟨by simp [empty, Holds], domains, submitted⟩
    have initializedRep :
        FrameColumnsRep assignment initialized.toColumns frame := by
      simpa only [references.columns, initialColumns] using
        initial_frame_assignment_rep width Assignment.default frame
          (NativeArrayVote.of_model_valid model)
    have initializedValid : ReferencesValid initialized :=
      valid.same_references references
    obtain ⟨parameterAssignment, parameterAgreement, startedHolds, parameters⟩ :=
      declare_nat_parameters_complete count values initialized started declare
        assignment initializedHolds
    have startedRep :
        FrameColumnsRep parameterAssignment started.toColumns frame :=
      declare_nat_parameters_frame count initialized started declare assignment
        parameterAssignment frame initializedRep initializedValid
        parameterAgreement
    have startedValid : ReferencesValid started :=
      declare_nat_parameters_references count initialized started declare
        initializedValid
    have parameterBound : initialized.next + count <= started.next := by
      rw [(declare_nat_parameters_success count initialized started declare).next]
    have bootstrap : decodeBits started.bootstrap = INITIAL_CONFIGURATION := by
      rw [(declare_nat_parameters_success count initialized started
        declare).bootstrap, references.bootstrap, sameBootstrap]
    obtain ⟨extended, _, _, finalHolds, _⟩ :=
      compile_parameterized_frame_complete initialized.next values items started
        final index groups result run parameterAssignment startedHolds frame
        startedRep startedValid bootstrap parameters parameterBound
        ((NativeArrayVote.follows_correct
          (items.map (ParameterizedFrameInstruction.materialize values))
          frame model (NativeArrayVote.of_model_rep model)).mpr follows)
    exact ⟨extended, finalHolds⟩

theorem compileParameterizedFrameDecoded_script_iff
    (input : ParameterizedFrameDecoded)
    [Bootstrap (Fin input.frame.width)]
    (compiled : Compiled) (named : Bool)
    (sameBootstrap : input.frame.bootstrap = INITIAL_CONFIGURATION)
    (success : compileParameterizedFrameDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment
        (renderScript compiled.assertions.toList named) = some true) <->
      (exists values : Fin input.unknowns.size -> Nat,
        exists model : State (Fin input.frame.width) Nat,
          NativeArrayVote.modelFollows model
            (input.frame.instructions.toList.map
              (ParameterizedFrameInstruction.materialize values))) := by
  cases first :
      (initialFrameDomains input.frame.width).run
        (initialEncoding input.frame.width input.frame.bootstrap) with
  | error message =>
    simp [compileParameterizedFrameDecoded, first, Bind.bind, Except.bind] at success
  | ok pair =>
    rcases pair with ⟨⟨⟩, initialized⟩
    cases declared :
        (declareNatParameters input.unknowns.size).run initialized with
    | error message =>
      simp [compileParameterizedFrameDecoded, first, declared, Bind.bind,
        Except.bind] at success
    | ok pair =>
      rcases pair with ⟨⟨⟩, started⟩
      let groups :=
        #[{ instruction := none
            start := 0
            stop := started.assertions.size : Group }]
      cases trace :
          (compileInstructionsWith
            (parameterizedFrameInstruction initialized.next) 0 groups
            input.frame.instructions.toList).run started with
      | error message =>
        simp [compileParameterizedFrameDecoded, first, declared, groups, trace,
          Bind.bind, Except.bind] at success
      | ok pair =>
        rcases pair with ⟨result, final⟩
        have output :
            { assertions := final.assertions, groups := result : Compiled } =
              compiled := by
          simpa [compileParameterizedFrameDecoded, first, declared, groups,
            trace, Bind.bind, Except.bind, Functor.map, Pure.pure,
            Except.pure] using success
        subst compiled
        simp only [script_text_holds]
        exact
          compiled_parameterized_frame_trace_iff
            input.frame.instructions.toList
            (initialEncoding input.frame.width input.frame.bootstrap)
            initialized started final 0 groups result rfl rfl
            (by constructor <;> simp [initialEncoding]) first declared trace
            (by simpa only [initialEncoding, decode_encode_bits] using
              sameBootstrap)

theorem compileParameterizedFrameDecoded_model_iff
    (input : ParameterizedFrameDecoded) (compiled : Compiled) (named : Bool)
    (success : compileParameterizedFrameDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment
        (renderScript compiled.assertions.toList named) = some true) <->
      input.ModelConsistent := by
  constructor
  · intro satisfied
    letI : Bootstrap (Fin input.frame.width) := {
      configuration := input.frame.bootstrap
      leader := input.frame.bootstrapNonempty.choose
      leader_mem := input.frame.bootstrapNonempty.choose_spec }
    exact ⟨inferInstance, rfl,
      (compileParameterizedFrameDecoded_script_iff input compiled named rfl
        success).mp satisfied⟩
  · rintro ⟨bootstrap, same, follows⟩
    letI := bootstrap
    exact
      (compileParameterizedFrameDecoded_script_iff input compiled named same.symm
        success).mpr follows

theorem compileParameterizedFrame_document_iff
    (document : Json) (compiled : Compiled) (named : Bool)
    (success : compileParameterizedFrame document = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment
        (renderScript compiled.assertions.toList named) = some true) <->
      ParameterizedFrameDocumentConsistent document := by
  cases decoded : decodeParameterizedFrameDocument document with
  | error message =>
    simp [compileParameterizedFrame, decoded, Bind.bind, Except.bind] at success
  | ok input =>
    have compiledInput :
        compileParameterizedFrameDecoded input = .ok compiled := by
      simpa [compileParameterizedFrame, decoded, Bind.bind, Except.bind] using
        success
    rw [compileParameterizedFrameDecoded_model_iff input compiled named
      compiledInput]
    constructor
    · intro consistent
      exact ⟨input, decoded, consistent⟩
    · rintro ⟨other, decodedOther, consistent⟩
      rw [decoded] at decodedOther
      cases Except.ok.inj decodedOther
      exact consistent

theorem encodeParameterizedFrame_document_iff (document : Json) (text : String)
    (success : encodeParameterizedFrame document = .ok text) :
    (exists assignment : Assignment,
      runScriptText assignment text = some true) <->
      ParameterizedFrameDocumentConsistent document := by
  cases compiled : compileParameterizedFrame document with
  | error message =>
    simp [encodeParameterizedFrame, compiled] at success
  | ok output =>
    have same : renderScript output.assertions.toList = text := by
      simpa [encodeParameterizedFrame, compiled] using success
    rw [<- same]
    exact compileParameterizedFrame_document_iff document output false compiled

theorem encodeParameterizedFrameDetails_script
    (document : Json) (compiled : Compiled) (details : Json)
    (compilation : compileParameterizedFrame document = .ok compiled)
    (success : encodeParameterizedFrameDetails document = .ok details) :
    details.getObjVal? "script" =
      .ok (.str (renderScript compiled.assertions.toList true)) := by
  simp [encodeParameterizedFrameDetails, compilation, Bind.bind, Except.bind,
    Pure.pure, Except.pure] at success
  cases success
  rfl

theorem encodeParameterizedFrameDetails_document_iff
    (document details : Json) (text : String)
    (success : encodeParameterizedFrameDetails document = .ok details)
    (script : details.getObjVal? "script" = .ok (.str text)) :
    (exists assignment : Assignment,
      runScriptText assignment text = some true) <->
      ParameterizedFrameDocumentConsistent document := by
  cases compiled : compileParameterizedFrame document with
  | error message =>
    simp [encodeParameterizedFrameDetails, compiled, Bind.bind, Except.bind] at success
  | ok output =>
    rw [encodeParameterizedFrameDetails_script document output details compiled
      success] at script
    have same := Json.str.inj (Except.ok.inj script)
    rw [<- same]
    exact
      compileParameterizedFrame_document_iff document output true compiled

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
