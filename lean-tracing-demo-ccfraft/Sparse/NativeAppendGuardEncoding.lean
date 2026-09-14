-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeAppendGuard
import Sparse.NativeArrayAppend
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem append_frontier_term_correct {width : PNat} (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (source destination : Fin width) :
    (appendFrontierTerm columns source destination).eval assignment Locals.empty =
      (min ((NativeArrayCheckQuorum.get arrays source).sentIndex destination + 1)
        (NativeArrayCheckQuorum.get arrays source).log.length : Nat) := by
  simp only [appendFrontierTerm, Term.eval, rep.sentIndex, rep.length]
  by_cases bound : (NativeArrayCheckQuorum.get arrays source).sentIndex destination + 1 <=
      (NativeArrayCheckQuorum.get arrays source).log.length
  · have boundInt : ((NativeArrayCheckQuorum.get arrays source).sentIndex destination : Int) + 1 <=
        ((NativeArrayCheckQuorum.get arrays source).log.length : Int) := by exact_mod_cast bound
    simp [boundInt, Nat.min_eq_left bound]
  · have boundInt : Not (((NativeArrayCheckQuorum.get arrays source).sentIndex destination : Int) + 1 <=
        ((NativeArrayCheckQuorum.get arrays source).log.length : Int)) := by exact_mod_cast bound
    simp [boundInt, Nat.min_eq_right (by omega : (NativeArrayCheckQuorum.get arrays source).log.length <=
      (NativeArrayCheckQuorum.get arrays source).sentIndex destination + 1)]

theorem append_leading_guards_correct {width : PNat} (assignment : Assignment) (columns : Columns)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (rep : NodeColumnsRep assignment columns arrays) (source destination : Fin width) (batchEnd : Nat) :
    Holds (appendLeadingGuards columns source destination batchEnd) assignment <->
      (arrays source).isSome = true /\ (arrays destination).isSome = true /\
        (NativeArrayCheckQuorum.get arrays source).role = .leader /\ source ≠ destination /\
        appendBatchAllowed ((NativeArrayCheckQuorum.get arrays source).sentIndex destination)
          (NativeArrayCheckQuorum.get arrays source).log.length batchEnd /\
        ((NativeArrayCheckQuorum.get arrays source).membershipState ≠ .retiredCommitted \/
          (NativeArrayCheckQuorum.get arrays source).sentIndex destination < batchEnd) := by
  simp [Holds, appendLeadingGuards, Term.eval, rep.allocated, rep.role,
    append_frontier_term_correct assignment columns arrays rep, rep.membershipState,
    rep.sentIndex, role_code_eq, membership_code_eq, lt, appendBatchAllowed]
  norm_cast
  simp

theorem append_guards_sound {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (source destination : Fin width) (batchEnd base : Nat)
    (holds : Holds (appendGuards columns bootstrap source destination batchEnd base) assignment) :
    NativeArrayAppend.enabled frame source destination batchEnd := by
  have separated : Holds (appendLeadingGuards columns source destination batchEnd) assignment /\
      Holds (appendScanGuards columns bootstrap source destination base) assignment := by
    simpa [appendGuards, Holds, or_imp, forall_and] using holds
  obtain ⟨sourcePresent, destinationPresent, role, different, frontier, retirement⟩ :=
    (append_leading_guards_correct assignment columns frame.nodes rep.nodes source destination batchEnd).mp separated.1
  have scans := separated.2
  simp only [Holds, appendScanGuards, List.mem_cons, List.not_mem_nil,
    forall_eq_or_imp, false_implies, implies_true, and_true] at scans
  obtain ⟨current, sameCurrent, currentValid⟩ :=
    (current_index_witness_correct assignment columns source.val base _ _
      (rep.nodes.configuration_log source)).mp
      ⟨scans.1, scans.2.1⟩
  refine ⟨sourcePresent, destinationPresent, role, different, ?_, frontier, retirement⟩
  have eligible := scans.2.2
  simp only [Term.eval, Bool.or_eq_true] at eligible
  rcases eligible with active | completed
  · have membership := (active_member_term_exact assignment Locals.empty bootstrap columns
      source.val destination _ _ current (rep.nodes.configuration_log source)
      (.free .int base) (.free .int (base + 1)) sameCurrent).mp active
    refine Or.inl ⟨current, currentValid, ?_⟩
    rcases membership with initial | ⟨index, nodes, _, lower, physical, included⟩
    · exact Or.inl ⟨initial.1, by simpa only [sameBootstrap] using initial.2⟩
    · exact Or.inr ⟨index, nodes, lower, physical, included⟩
  · exact Or.inr (by simpa only [rep.retirementCompleted, <- decode_bits_member, decode_encode_bits] using completed)

theorem append_guards_complete {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (source destination : Fin width) (batchEnd : Nat)
    (enabled : NativeArrayAppend.enabled frame source destination batchEnd) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds (appendGuards before.toColumns before.bootstrap source destination batchEnd before.next) extended := by
  obtain ⟨sourcePresent, destinationPresent, role, different, eligible, frontier, retirement⟩ := enabled
  have currentExists : exists current,
      NativeArrayCheckQuorum.CurrentIndex (NativeArrayCheckQuorum.get frame.nodes source).log
        (NativeArrayCheckQuorum.get frame.nodes source).commit current /\
      (NativeArrayVote.MemberAt (NativeArrayCheckQuorum.get frame.nodes source).log current destination \/
        destination ∈ frame.globals.retirementCompleted source) := by
    rcases eligible with ⟨current, valid, member⟩ | completed
    · exact ⟨current, valid, Or.inl member⟩
    · refine ⟨_, (NativeArrayCheckQuorum.current_index_correct _ _ _).mpr rfl, Or.inr completed⟩
  obtain ⟨current, currentValid, eligible⟩ := currentExists
  let withCurrent := assignment.set .int before.next (current : Int)
  have currentRep := rep.nodes.set_integer before.next (current : Int)
  have sameCurrent : withCurrent .int before.next = (current : Int) := by simp [withCurrent, Assignment.set]
  have witnessExists : exists witness : Int,
      (activeMemberTerm width before.bootstrap before.toColumns source.val destination
        (.free .int before.next)
        (.free .int (before.next + 1))).eval (withCurrent.set .int (before.next + 1) witness) Locals.empty = true \/
      destination ∈ frame.globals.retirementCompleted source := by
    rcases eligible with active | completed
    · obtain ⟨witness, accepted⟩ := (active_member_exists_correct withCurrent before.bootstrap
        before.toColumns source.val destination before.next (before.next + 1) (by omega)
        _ _ current (currentRep.configuration_log source)
        sameCurrent sameBootstrap).mpr active
      exact ⟨witness, Or.inl accepted⟩
    · exact ⟨0, Or.inr completed⟩
  obtain ⟨witness, eligible⟩ := witnessExists
  let extended := withCurrent.set .int (before.next + 1) witness
  have agreement : assignment.AgreesBelow before.next extended :=
    (assignment.agrees_below_set before.next .int before.next (current : Int) (le_refl _)).trans
      (withCurrent.agrees_below_set before.next .int (before.next + 1) witness (by omega))
  have extendedRep := rep.agrees_below before assignment extended frame valid agreement
  have preservesCurrent : extended .int before.next = (current : Int) := by
    simp [extended, withCurrent, Assignment.set]
  have leading := (append_leading_guards_correct extended before.toColumns frame.nodes extendedRep.nodes
    source destination batchEnd).mpr ⟨sourcePresent, destinationPresent, role, different, frontier, retirement⟩
  have currentScans := (current_index_constraints_correct extended before.toColumns source.val
    before.next _ _ current
    (extendedRep.nodes.configuration_log source) preservesCurrent).mpr currentValid
  have lastGuard :
      (Term.or (activeMemberTerm width before.bootstrap before.toColumns source.val destination
        (.free .int before.next)
        (.free .int (before.next + 1)))
        (.bit (.select (.free (.array .int (.bits width)) before.retirementCompleted)
          (.integer source.val)) destination)).eval extended Locals.empty = true := by
    simp only [Term.eval, Bool.or_eq_true]
    rcases eligible with active | completed
    · exact Or.inl active
    · exact Or.inr (by simpa only [extendedRep.retirementCompleted, <- decode_bits_member, decode_encode_bits] using completed)
  have scans : Holds (appendScanGuards before.toColumns before.bootstrap source destination before.next) extended := by
    simpa only [Holds, appendScanGuards, List.mem_cons, List.not_mem_nil,
      forall_eq_or_imp, false_implies, implies_true, and_true] using
      And.intro currentScans.1 (And.intro currentScans.2 lastGuard)
  refine ⟨extended, agreement, ?_⟩
  simpa [appendGuards, Holds, or_imp, forall_and] using And.intro leading scans

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
