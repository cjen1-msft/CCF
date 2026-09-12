-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaignGuard
import Sparse.NativeFrameColumns

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

theorem campaign_leading_guards_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (preVote : Bool) (node : Fin width) :
    Holds (campaignLeadingGuards columns preVote node) assignment <->
      (frame.nodes node).isSome = true /\
        ((NativeArrayCheckQuorum.get frame.nodes node).role = .follower \/
          (NativeArrayCheckQuorum.get frame.nodes node).role = .preVoteCandidate \/
          (NativeArrayCheckQuorum.get frame.nodes node).role = .candidate) /\
        (NativeArrayCheckQuorum.get frame.nodes node).membershipState ≠ .retiredCommitted /\
        frame.globals.preVoteStatus node = (if preVote then .enabled else .capable) := by
  simp [Holds, campaignLeadingGuards, Term.eval, rep.nodes.allocated, rep.nodes.role,
    rep.nodes.membershipState, rep.preVoteStatus, role_code_eq, membership_code_eq, pre_vote_bit_eq]

theorem campaign_guards_sound {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment columns frame) (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (preVote : Bool) (node : Fin width) (base : Nat)
    (holds : Holds (campaignGuards columns bootstrap preVote node base) assignment) :
    NativeArrayVote.campaignEnabled frame preVote node := by
  have separated : Holds (campaignLeadingGuards columns preVote node) assignment /\
      Holds (campaignScanGuards columns bootstrap node base) assignment := by
    simpa [campaignGuards, Holds, or_imp, forall_and] using holds
  obtain ⟨present, role, membership, status⟩ :=
    (campaign_leading_guards_correct assignment columns frame rep preVote node).mp separated.1
  have scans := separated.2
  simp only [Holds, campaignScanGuards, List.mem_cons, List.not_mem_nil,
    forall_eq_or_imp, false_implies, implies_true, and_true] at scans
  obtain ⟨current, sameCurrent, currentValid⟩ :=
    (current_index_witness_correct assignment node.val base _ _ (rep.nodes.configuration_log node)).mp
      ⟨scans.1, scans.2.1⟩
  obtain ⟨signature, sameSignature, latest⟩ :=
    (signature_index_term_witness assignment Locals.empty node.val _ _
      (rep.nodes.configuration_log node) (.free .int (base + 1))).mp scans.2.2.1
  refine ⟨present, role, membership, status, current, currentValid, signature, latest, ?_⟩
  have eligible := scans.2.2.2
  simp only [Term.eval, Bool.or_eq_true] at eligible
  rcases eligible with active | completed
  · exact Or.inl (campaign_member_term_sound assignment Locals.empty bootstrap sameBootstrap
      node _ _ current signature (rep.nodes.configuration_log node)
      (.free .int base) (.free .int (base + 1)) (.free .int (base + 2)) sameCurrent sameSignature active)
  · exact Or.inr (by simpa only [rep.retirementCompleted, <- decode_bits_member, decode_encode_bits] using completed)

theorem campaign_guards_complete {width : PNat} [Bootstrap (Fin width)]
    (before : Encoding width) (assignment : Assignment) (frame : NativeArrayVote.Frame (Fin width) Nat)
    (rep : FrameColumnsRep assignment before.toColumns frame) (valid : ReferencesValid before)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION)
    (preVote : Bool) (node : Fin width)
    (enabled : NativeArrayVote.campaignEnabled frame preVote node) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds (campaignGuards before.toColumns before.bootstrap preVote node before.next) extended := by
  obtain ⟨present, role, membership, status, current, currentValid, signature, latest, eligible⟩ := enabled
  let withCurrent := assignment.set .int before.next (current : Int)
  let withSignature := withCurrent.set .int (before.next + 1) (signature : Int)
  have signatureRep := (rep.nodes.set_integer before.next (current : Int)).set_integer
    (before.next + 1) (signature : Int)
  have currentValue : withSignature .int before.next = (current : Int) := by
    simp [withSignature, withCurrent, Assignment.set]
  have signatureValue : withSignature .int (before.next + 1) = (signature : Int) := by
    simp [withSignature, Assignment.set]
  have witnessExists : exists witness : Int,
      (campaignMemberTerm width before.bootstrap node (.free .int before.next)
        (.free .int (before.next + 1)) (.free .int (before.next + 2))).eval
          (withSignature.set .int (before.next + 2) witness) Locals.empty = true \/
        node ∈ frame.globals.retirementCompleted node := by
    rcases eligible with active | completed
    · obtain ⟨witness, accepted⟩ := campaign_member_term_complete withSignature before.bootstrap
        sameBootstrap node _ _ current signature (signatureRep.configuration_log node)
        before.next currentValue signatureValue active
      exact ⟨witness, Or.inl accepted⟩
    · exact ⟨0, Or.inr completed⟩
  obtain ⟨witness, eligible⟩ := witnessExists
  let extended := withSignature.set .int (before.next + 2) witness
  have agreement : assignment.AgreesBelow before.next extended :=
    (assignment.agrees_below_set before.next .int before.next (current : Int) (le_refl _)).trans
      ((withCurrent.agrees_below_set before.next .int (before.next + 1) (signature : Int) (by omega)).trans
        (withSignature.agrees_below_set before.next .int (before.next + 2) witness (by omega)))
  have extendedRep := rep.agrees_below before assignment extended frame valid agreement
  have preservesCurrent : extended .int before.next = (current : Int) := by
    simp [extended, withSignature, withCurrent, Assignment.set]
  have preservesSignature : extended .int (before.next + 1) = (signature : Int) := by
    simp [extended, withSignature, Assignment.set]
  have leading := (campaign_leading_guards_correct extended before.toColumns frame extendedRep preVote node).mpr
    ⟨present, role, membership, status⟩
  have currentScans := (current_index_constraints_correct extended node.val before.next _ _ current
    (extendedRep.nodes.configuration_log node) preservesCurrent).mpr currentValid
  have signatureScan := (signature_index_term_correct extended Locals.empty node.val _ _ signature
    (extendedRep.nodes.configuration_log node) (.free .int (before.next + 1))
      (by simpa only [Term.eval] using preservesSignature)).mpr latest
  have lastGuard :
      (Term.or (campaignMemberTerm width before.bootstrap node (.free .int before.next)
        (.free .int (before.next + 1)) (.free .int (before.next + 2)))
        (.bit (.select (.free (.array .int (.bits width)) before.retirementCompleted)
          (.integer node.val)) node)).eval extended Locals.empty = true := by
    simp only [Term.eval, Bool.or_eq_true]
    rcases eligible with active | completed
    · exact Or.inl active
    · exact Or.inr (by simpa only [extendedRep.retirementCompleted, <- decode_bits_member, decode_encode_bits] using completed)
  have scans : Holds (campaignScanGuards before.toColumns before.bootstrap node before.next) extended := by
    simpa only [Holds, campaignScanGuards, List.mem_cons, List.not_mem_nil,
      forall_eq_or_imp, false_implies, implies_true, and_true] using
      And.intro currentScans.1 (And.intro currentScans.2 (And.intro signatureScan lastGuard))
  refine ⟨extended, agreement, ?_⟩
  simpa [campaignGuards, Holds, or_imp, forall_and] using And.intro leading scans

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
