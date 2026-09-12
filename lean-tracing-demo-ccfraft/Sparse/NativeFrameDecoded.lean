-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeFrameTrace
import Sparse.NativeScriptRun

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

def FrameDecoded.ModelConsistent (input : FrameDecoded) : Prop :=
  exists bootstrap : Bootstrap (Fin input.width),
    letI := bootstrap
    INITIAL_CONFIGURATION = input.bootstrap /\
      exists model : State (Fin input.width) Nat,
        NativeArrayVote.modelFollows model input.instructions.toList

def FrameDocumentConsistent (document : Json) : Prop :=
  exists input, decodeFrameDocument document = .ok input /\ input.ModelConsistent

theorem compileFrameDecoded_script_iff (input : FrameDecoded) [Bootstrap (Fin input.width)]
    (compiled : Compiled) (named : Bool) (sameBootstrap : input.bootstrap = INITIAL_CONFIGURATION)
    (success : compileFrameDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      (exists model : State (Fin input.width) Nat,
        NativeArrayVote.modelFollows model input.instructions.toList) := by
  cases first : (initialDomains input.width).run (initialEncoding input.width input.bootstrap) with
  | error message => simp [compileFrameDecoded, first, Bind.bind, Except.bind] at success
  | ok pair =>
    rcases pair with ⟨⟨⟩, started⟩
    let groups := #[{ instruction := none, start := 0, stop := started.assertions.size : Group }]
    cases trace :
        (compileInstructionsWith frameInstruction 0 groups input.instructions.toList).run started with
    | error message =>
      simp [compileFrameDecoded, first, groups, trace, Bind.bind, Except.bind, Functor.map] at success
    | ok pair =>
      rcases pair with ⟨result, final⟩
      have output : { assertions := final.assertions, groups := result : Compiled } = compiled := by
        simpa [compileFrameDecoded, first, groups, trace, Bind.bind, Except.bind, Functor.map,
          Pure.pure, Except.pure] using success
      subst compiled
      simp only [script_text_holds]
      exact compiled_frame_trace_iff input.instructions.toList
        (initialEncoding input.width input.bootstrap) started final 0 groups result rfl rfl
        (by constructor <;> simp [initialEncoding]) first trace
        (by simpa only [initialEncoding, decode_encode_bits] using sameBootstrap)

theorem compileFrameDecoded_model_iff (input : FrameDecoded) (compiled : Compiled) (named : Bool)
    (success : compileFrameDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      input.ModelConsistent := by
  constructor
  · intro satisfied
    letI : Bootstrap (Fin input.width) := {
      configuration := input.bootstrap
      leader := input.bootstrapNonempty.choose
      leader_mem := input.bootstrapNonempty.choose_spec }
    exact ⟨inferInstance, rfl, (compileFrameDecoded_script_iff input compiled named rfl success).mp satisfied⟩
  · rintro ⟨bootstrap, same, follows⟩
    letI := bootstrap
    exact (compileFrameDecoded_script_iff input compiled named same.symm success).mpr follows

theorem compileFrame_document_iff (document : Json) (compiled : Compiled) (named : Bool)
    (success : compileFrame document = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      FrameDocumentConsistent document := by
  cases decoded : decodeFrameDocument document with
  | error message => simp [compileFrame, decoded, Bind.bind, Except.bind] at success
  | ok input =>
    have compiledInput : compileFrameDecoded input = .ok compiled := by
      simpa [compileFrame, decoded, Bind.bind, Except.bind] using success
    rw [compileFrameDecoded_model_iff input compiled named compiledInput]
    constructor
    · intro consistent
      exact ⟨input, decoded, consistent⟩
    · rintro ⟨other, decodedOther, consistent⟩
      rw [decoded] at decodedOther
      cases Except.ok.inj decodedOther
      exact consistent

theorem encodeFrame_document_iff (document : Json) (text : String)
    (success : encodeFrame document = .ok text) :
    (exists assignment : Assignment, runScriptText assignment text = some true) <->
      FrameDocumentConsistent document := by
  cases compiled : compileFrame document with
  | error message => simp [encodeFrame, compiled] at success
  | ok output =>
    have same : renderScript output.assertions.toList = text := by
      simpa [encodeFrame, compiled] using success
    rw [<- same]
    exact compileFrame_document_iff document output false compiled

theorem encodeFrameDetails_script (document : Json) (compiled : Compiled) (details : Json)
    (compilation : compileFrame document = .ok compiled)
    (success : encodeFrameDetails document = .ok details) :
    details.getObjVal? "script" = .ok (.str (renderScript compiled.assertions.toList true)) := by
  simp [encodeFrameDetails, compilation, Bind.bind, Except.bind, Pure.pure, Except.pure] at success
  cases success
  rfl

theorem encodeFrameDetails_document_iff (document details : Json) (text : String)
    (success : encodeFrameDetails document = .ok details)
    (script : details.getObjVal? "script" = .ok (.str text)) :
    (exists assignment : Assignment, runScriptText assignment text = some true) <->
      FrameDocumentConsistent document := by
  cases compiled : compileFrame document with
  | error message => simp [encodeFrameDetails, compiled, Bind.bind, Except.bind] at success
  | ok output =>
    rw [encodeFrameDetails_script document output details compiled success] at script
    have same := Json.str.inj (Except.ok.inj script)
    rw [<- same]
    exact compileFrame_document_iff document output true compiled

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
