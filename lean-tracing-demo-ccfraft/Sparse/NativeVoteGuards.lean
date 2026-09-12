-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeVotePacket
import Sparse.NativeMembershipEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def voteLeadingGuards {width : PNat} (columns : Columns) (preVote : Bool)
    (source destination : Fin width) : List (Expr .bool) :=
  [allocated source.val, allocated destination.val,
    .equal (read columns.role source.val (.integer 0))
      (.integer (roleCode (if preVote then .preVoteCandidate else .candidate))),
    .boolean (decide (source ≠ destination))]

def voteScanGuards {width : PNat} (bootstrap : BitVec width)
    (source destination : Fin width) (base : Nat) : List (Expr .bool) :=
  [currentCandidate width source.val base,
    noLaterConfiguration width source.val base,
    activeMemberTerm width bootstrap source.val destination (.free .int base) (.free .int (base + 1)),
    signatureIndexTerm width source.val (.free .int (base + 2))]

def voteGuards {width : PNat} (columns : Columns) (bootstrap : BitVec width) (preVote : Bool)
    (source destination : Fin width) (base : Nat) : List (Expr .bool) :=
  voteLeadingGuards columns preVote source destination ++ voteScanGuards bootstrap source destination base

theorem vote_leading_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (preVote : Bool) (source destination : Fin width) :
    Holds (voteLeadingGuards columns preVote source destination) assignment <->
      (arrays source).isSome = true /\ (arrays destination).isSome = true /\
        (NativeArrayCheckQuorum.get arrays source).role =
          (if preVote then .preVoteCandidate else .candidate) /\ source ≠ destination := by
  simp [Holds, voteLeadingGuards, Term.eval, rep.allocated, rep.role, role_code_eq]

theorem vote_guards_sound {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (preVote : Bool) (source destination : Fin width) (base : Nat)
    (holds : Holds (voteGuards columns bootstrap preVote source destination base) assignment) :
    NativeArrayVote.enabled arrays preVote source destination /\
      exists signature : Nat, assignment .int (base + 2) = (signature : Int) /\
        NativeArrayVote.SignatureIndex (NativeArrayCheckQuorum.get arrays source).log signature := by
  have separated : Holds (voteLeadingGuards columns preVote source destination) assignment /\
      Holds (voteScanGuards bootstrap source destination base) assignment := by
    simpa [voteGuards, Holds, or_imp, forall_and] using holds
  obtain ⟨sourcePresent, destinationPresent, role, different⟩ :=
    (vote_leading_guards_correct assignment columns arrays rep preVote source destination).mp separated.1
  have scans := separated.2
  simp only [Holds, voteScanGuards, List.mem_cons, List.not_mem_nil,
    forall_eq_or_imp, false_implies, implies_true, and_true] at scans
  obtain ⟨current, sameCurrent, currentValid⟩ :=
    (current_index_witness_correct assignment source.val base _ _ (rep.configuration_log source)).mp
      ⟨scans.1, scans.2.1⟩
  have membership := (active_member_term_exact assignment Locals.empty bootstrap source.val destination _ _ current
    (rep.configuration_log source) (.free .int base) (.free .int (base + 1)) sameCurrent).mp scans.2.2.1
  have member : NativeArrayVote.MemberAt (NativeArrayCheckQuorum.get arrays source).log current destination := by
    rcases membership with initial | ⟨index, nodes, _, lower, physical, included⟩
    · exact Or.inl ⟨initial.1, by simpa only [sameBootstrap] using initial.2⟩
    · exact Or.inr ⟨index, nodes, lower, physical, included⟩
  refine ⟨⟨sourcePresent, destinationPresent, role, different, current, currentValid, member⟩, ?_⟩
  exact (signature_index_term_witness assignment Locals.empty source.val _ _
    (rep.configuration_log source) (.free .int (base + 2))).mp scans.2.2.2

theorem vote_guards_complete {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (preVote : Bool) (source destination : Fin width) (base signature : Nat)
    (enabled : NativeArrayVote.enabled arrays preVote source destination)
    (latest : NativeArrayVote.SignatureIndex (NativeArrayCheckQuorum.get arrays source).log signature) :
    exists extended : Assignment, assignment.AgreesBelow base extended /\
      Holds (voteGuards columns bootstrap preVote source destination base) extended /\
      extended .int (base + 2) = (signature : Int) := by
  obtain ⟨sourcePresent, destinationPresent, role, different, current, currentValid, member⟩ := enabled
  let withCurrent := assignment.set .int base (current : Int)
  have currentRep := rep.set_integer base (current : Int)
  have sameCurrent : withCurrent .int base = (current : Int) := by simp [withCurrent, Assignment.set]
  obtain ⟨witness, active⟩ := (active_member_exists_correct withCurrent bootstrap source.val destination base (base + 1)
    (by omega) _ _ current (currentRep.configuration_log source) sameCurrent sameBootstrap).mpr member
  let withWitness := withCurrent.set .int (base + 1) witness
  let extended := withWitness.set .int (base + 2) (signature : Int)
  have extendedRep : NodeColumnsRep extended columns arrays :=
    (currentRep.set_integer (base + 1) witness).set_integer (base + 2) (signature : Int)
  have preservesCurrent : extended .int base = (current : Int) := by
    simp [extended, withWitness, withCurrent, Assignment.set]
  have setsSignature : extended .int (base + 2) = (signature : Int) := by
    simp [extended, Assignment.set]
  have agreement : assignment.AgreesBelow base extended :=
    (assignment.agrees_below_set base .int base (current : Int) (le_refl _)).trans
      ((withCurrent.agrees_below_set base .int (base + 1) witness (by omega)).trans
        (withWitness.agrees_below_set base .int (base + 2) (signature : Int) (by omega)))
  have activeExtended :
      (activeMemberTerm width bootstrap source.val destination (.free .int base) (.free .int (base + 1))).eval
        extended Locals.empty = true := by
    simpa [activeMemberTerm, all, length, read, allocated, entryAt, isConfiguration, members,
      Term.eval, extended, withWitness, withCurrent, Assignment.set] using active
  have currentScans := (current_index_constraints_correct extended source.val base _ _ current
    (extendedRep.configuration_log source) preservesCurrent).mpr currentValid
  have signatureScan := (signature_index_term_correct extended Locals.empty source.val _ _ signature
    (extendedRep.configuration_log source) (.free .int (base + 2))
      (by simpa only [Term.eval] using setsSignature)).mpr latest
  refine ⟨extended, agreement, ?_, setsSignature⟩
  have leading := (vote_leading_guards_correct extended columns arrays extendedRep preVote source destination).mpr
    ⟨sourcePresent, destinationPresent, role, different⟩
  have scans : Holds (voteScanGuards bootstrap source destination base) extended := by
    simpa only [Holds, voteScanGuards, List.mem_cons, List.not_mem_nil,
      forall_eq_or_imp, false_implies, implies_true, and_true] using
      And.intro currentScans.1 (And.intro currentScans.2 (And.intro activeExtended signatureScan))
  simpa [voteGuards, Holds, or_imp, forall_and] using And.intro leading scans

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
