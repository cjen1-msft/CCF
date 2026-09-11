-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScriptTrace

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open Lean NativeSmt

def Decoded.ModelConsistent (input : Decoded) : Prop :=
  exists bootstrap : Bootstrap (Fin input.width),
    letI := bootstrap
    INITIAL_CONFIGURATION = input.bootstrap /\
      exists model : State (Fin input.width) Nat,
        NativeArrayCheckQuorum.modelFollows model input.instructions.toList

def DocumentConsistent (document : Json) : Prop :=
  exists input, decodeDocument document = .ok input /\ input.ModelConsistent

theorem compileDecoded_script_iff (input : Decoded) [Bootstrap (Fin input.width)]
    (compiled : Compiled) (named : Bool) (sameBootstrap : input.bootstrap = INITIAL_CONFIGURATION)
    (success : compileDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      (exists model : State (Fin input.width) Nat,
        NativeArrayCheckQuorum.modelFollows model input.instructions.toList) := by
  cases first : (initialDomains input.width).run (initialEncoding input.width input.bootstrap) with
  | error message => simp [compileDecoded, first, Bind.bind, Except.bind] at success
  | ok pair =>
    rcases pair with ⟨⟨⟩, started⟩
    let groups := #[{ instruction := none, start := 0, stop := started.assertions.size : Group }]
    cases trace : (compileInstructions 0 groups input.instructions.toList).run started with
    | error message =>
      simp [compileDecoded, first, groups, trace, Bind.bind, Except.bind, Functor.map] at success
    | ok pair =>
      rcases pair with ⟨result, final⟩
      have output : { assertions := final.assertions, groups := result : Compiled } = compiled := by
        simpa [compileDecoded, first, groups, trace, Bind.bind, Except.bind, Functor.map,
          Pure.pure, Except.pure] using success
      subst compiled
      exact compiled_script_iff input.instructions.toList
        (initialEncoding input.width input.bootstrap) started final 0 groups result named rfl rfl
        (by constructor <;> simp [initialEncoding]) first trace
        (by simpa only [initialEncoding, decode_encode_bits] using sameBootstrap)

theorem compileDecoded_model_iff (input : Decoded) (compiled : Compiled) (named : Bool)
    (success : compileDecoded input = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      input.ModelConsistent := by
  constructor
  · intro satisfied
    letI : Bootstrap (Fin input.width) := {
      configuration := input.bootstrap
      leader := input.bootstrapNonempty.choose
      leader_mem := input.bootstrapNonempty.choose_spec }
    exact ⟨inferInstance, rfl, (compileDecoded_script_iff input compiled named rfl success).mp satisfied⟩
  · rintro ⟨bootstrap, same, follows⟩
    letI := bootstrap
    exact (compileDecoded_script_iff input compiled named same.symm success).mpr follows

theorem compile_document_iff (document : Json) (compiled : Compiled) (named : Bool)
    (success : compile document = .ok compiled) :
    (exists assignment : Assignment,
      runScriptText assignment (renderScript compiled.assertions.toList named) = some true) <->
      DocumentConsistent document := by
  cases decoded : decodeDocument document with
  | error message => simp [compile, decoded, Bind.bind, Except.bind] at success
  | ok input =>
    have compiledInput : compileDecoded input = .ok compiled := by
      simpa [compile, decoded, Bind.bind, Except.bind] using success
    rw [compileDecoded_model_iff input compiled named compiledInput]
    constructor
    · intro consistent
      exact ⟨input, decoded, consistent⟩
    · rintro ⟨other, decodedOther, consistent⟩
      rw [decoded] at decodedOther
      cases Except.ok.inj decodedOther
      exact consistent

theorem encode_document_iff (document : Json) (text : String)
    (success : encode document = .ok text) :
    (exists assignment : Assignment, runScriptText assignment text = some true) <->
      DocumentConsistent document := by
  cases compiled : compile document with
  | error message => simp [encode, compiled] at success
  | ok output =>
    have same : renderScript output.assertions.toList = text := by
      simpa [encode, compiled] using success
    rw [<- same]
    exact compile_document_iff document output false compiled

theorem encodeDetails_script (document : Json) (compiled : Compiled) (details : Json)
    (compilation : compile document = .ok compiled) (success : encodeDetails document = .ok details) :
    details.getObjVal? "script" = .ok (.str (renderScript compiled.assertions.toList true)) := by
  simp [encodeDetails, compilation, Bind.bind, Except.bind, Functor.map, Pure.pure, Except.pure] at success
  cases success
  rfl

theorem encodeDetails_document_iff (document details : Json) (text : String)
    (success : encodeDetails document = .ok details) (script : details.getObjVal? "script" = .ok (.str text)) :
    (exists assignment : Assignment, runScriptText assignment text = some true) <->
      DocumentConsistent document := by
  cases compiled : compile document with
  | error message =>
    simp [encodeDetails, compiled, Bind.bind, Except.bind, Functor.map] at success
  | ok output =>
    rw [encodeDetails_script document output details compiled success] at script
    have same := Json.str.inj (Except.ok.inj script)
    rw [<- same]
    exact compile_document_iff document output true compiled

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
