-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCheckQuorum

set_option autoImplicit false

namespace CCFRaft.NativeArrayFirstMatch

open NativeArrayCheckQuorum

variable {N T : Type}

def FirstMatch (log : Log N T) (predicate : Nat -> Entry N T -> Bool) : Option Nat -> Prop
  | none => forall index, index < log.length -> predicate index (log.entries index) = false
  | some index => index < log.length /\ predicate index (log.entries index) = true /\
      forall earlier, earlier < index -> predicate earlier (log.entries earlier) = false

theorem indexed_decode (log : Log N T) :
    log.decode.zipIdx = List.ofFn (fun index : Fin log.length => (log.entries index, index.val)) := by
  apply List.ext_getElem
  · simp [Log.decode]
  · intro index within otherWithin
    simp [Log.decode]

theorem first_match_correct (log : Log N T) (predicate : Nat -> Entry N T -> Bool)
    (index : Option Nat) :
    FirstMatch log predicate index <->
      ((log.decode.zipIdx).find? fun indexed => predicate indexed.2 indexed.1).map Prod.snd = index := by
  rw [indexed_decode]
  cases index with
  | none =>
    simp [FirstMatch, List.find?_eq_none, List.mem_ofFn]
    constructor
    · intro absent candidate
      exact absent candidate.val candidate.isLt
    · intro absent candidate live
      exact absent ⟨candidate, live⟩
  | some index =>
    constructor
    · rintro ⟨live, hit, earlier⟩
      apply Option.map_eq_some_iff.mpr
      refine ⟨(log.entries index, index), ?_, rfl⟩
      apply List.find?_ofFn_eq_some.mpr
      refine ⟨hit, ⟨index, live⟩, rfl, ?_⟩
      intro candidate before
      simp [earlier candidate.val before]
    · intro found
      obtain ⟨pair, found, sameIndex⟩ := Option.map_eq_some_iff.mp found
      obtain ⟨hit, candidate, samePair, earlier⟩ := List.find?_ofFn_eq_some.mp found
      have same : candidate.val = index := (congrArg Prod.snd samePair).trans sameIndex
      refine ⟨by simpa [same] using candidate.isLt, ?_, ?_⟩
      · simpa [← samePair, same] using hit
      · intro prior before
        have live : prior < log.length := by omega
        have missing := earlier ⟨prior, live⟩ (by change prior < candidate.val; omega)
        simpa using missing

theorem indexed_decode_shift (log : Log N T) (start : Nat) :
    log.decode.zipIdx start =
      log.decode.zipIdx.map (fun indexed => (indexed.1, start + indexed.2)) := by
  apply List.ext_getElem
  · simp
  · intro index within otherWithin
    simp

theorem first_match_shift_correct (log : Log N T) (predicate : Nat -> Entry N T -> Bool)
    (start : Nat) (index : Option Nat) :
    FirstMatch log (fun position entry => predicate (start + position) entry) index <->
      ((log.decode.zipIdx start).find? fun indexed => predicate indexed.2 indexed.1).map Prod.snd =
        index.map (start + ·) := by
  rw [first_match_correct, indexed_decode_shift log start]
  simp only [List.find?_map, Option.map_map]
  have injective : Function.Injective (fun result : Option Nat => result.map (start + ·)) := by
    intro left right same
    cases left <;> cases right <;> simp_all
  let found := log.decode.zipIdx.find? fun indexed => predicate (start + indexed.2) indexed.1
  have transport : found.map Prod.snd = index <->
      (found.map Prod.snd).map (start + ·) = index.map (start + ·) := injective.eq_iff.symm
  simpa only [found, Option.map_map, Function.comp_def] using transport

end CCFRaft.NativeArrayFirstMatch

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayFirstMatch).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
