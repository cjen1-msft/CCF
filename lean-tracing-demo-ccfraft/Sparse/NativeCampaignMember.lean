-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeMembershipEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def campaignMemberTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (columns : Columns) (node : Fin width)
    (current signature witness : Term context .int) : Term context .bool :=
  .or (.and (.equal current (.integer 0)) (.bit (.bits bootstrap) node))
    (.and (activeMemberTerm width bootstrap columns node.val node current witness)
      (.le witness signature))

theorem campaign_member_term_exact {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (bootstrap : BitVec width)
    (columns : Columns) (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (committed current signature : Nat)
    (rep : ConfigurationLogRep assignment columns node.val log committed)
    (position latest witness : Term context .int)
    (sameCurrent : position.eval assignment locals = (current : Int))
    (sameSignature : latest.eval assignment locals = (signature : Int)) :
    (campaignMemberTerm width bootstrap columns node position latest witness).eval assignment locals = true <->
      ((current = 0 /\ node ∈ decodeBits bootstrap) \/
        exists (index : Nat) (nodes : Finset (Fin width)), witness.eval assignment locals = (index : Int) /\
          current <= index /\ index <= signature /\
          NativeArrayCheckQuorum.Reconfiguration log index nodes /\ node ∈ nodes) := by
  simp only [campaignMemberTerm, Term.eval, Bool.or_eq_true, Bool.and_eq_true,
    decide_eq_true_eq, sameCurrent, sameSignature, Int.natCast_eq_zero, <- decode_bits_member]
  rw [active_member_term_exact assignment locals bootstrap columns node.val node log committed current rep
    position witness sameCurrent]
  constructor
  · rintro (initial | ⟨initial | ⟨index, nodes, same, lower, physical, included⟩, upper⟩)
    · exact Or.inl initial
    · exact Or.inl initial
    · refine Or.inr ⟨index, nodes, same, lower, ?_, physical, included⟩
      exact Int.ofNat_le.mp (show (index : Int) <= (signature : Int) by simpa only [same] using upper)
  · rintro (initial | ⟨index, nodes, same, lower, upper, physical, included⟩)
    · exact Or.inl initial
    · refine Or.inr ⟨Or.inr ⟨index, nodes, same, lower, physical, included⟩, ?_⟩
      rw [same]
      exact Int.ofNat_le.mpr upper

theorem campaign_member_term_sound {context : List Ty} {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (locals : Locals context) (bootstrap : BitVec width)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (columns : Columns) (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (committed current signature : Nat)
    (rep : ConfigurationLogRep assignment columns node.val log committed)
    (position latest witness : Term context .int)
    (sameCurrent : position.eval assignment locals = (current : Int))
    (sameSignature : latest.eval assignment locals = (signature : Int))
    (accepted : (campaignMemberTerm width bootstrap columns node position latest witness).eval
      assignment locals = true) :
    NativeArrayVote.CampaignAt log current signature node := by
  rcases (campaign_member_term_exact assignment locals bootstrap columns node log committed
    current signature rep
    position latest witness sameCurrent sameSignature).mp accepted with
      initial | ⟨index, nodes, _, lower, upper, physical, included⟩
  · exact Or.inl ⟨initial.1, by simpa only [sameBootstrap] using initial.2⟩
  · exact Or.inr ⟨index, nodes, lower, upper, physical, included⟩

theorem campaign_member_term_complete {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (columns : Columns)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (node : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (committed current signature : Nat)
    (rep : ConfigurationLogRep assignment columns node.val log committed)
    (base : Nat) (sameCurrent : assignment .int base = (current : Int))
    (sameSignature : assignment .int (base + 1) = (signature : Int))
    (eligible : NativeArrayVote.CampaignAt log current signature node) :
    exists witness : Int,
      (campaignMemberTerm width bootstrap columns node (.free .int base) (.free .int (base + 1))
        (.free .int (base + 2))).eval (assignment.set .int (base + 2) witness) Locals.empty = true := by
  have exactAt (value : Int) :=
    campaign_member_term_exact (assignment.set .int (base + 2) value) Locals.empty
      bootstrap columns node log committed current signature (rep.set_integer (base + 2) value)
      (.free .int base) (.free .int (base + 1)) (.free .int (base + 2))
      (by simp [Term.eval, Assignment.set, sameCurrent])
      (by simp [Term.eval, Assignment.set, sameSignature])
  rcases eligible with initial | ⟨index, nodes, lower, upper, physical, included⟩
  · exact ⟨0, (exactAt 0).mpr (Or.inl ⟨initial.1, by simpa only [sameBootstrap] using initial.2⟩)⟩
  · refine ⟨index, (exactAt index).mpr (Or.inr ⟨index, nodes, ?_, lower, upper, physical, included⟩)⟩
    simp [Term.eval, Assignment.set]

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
