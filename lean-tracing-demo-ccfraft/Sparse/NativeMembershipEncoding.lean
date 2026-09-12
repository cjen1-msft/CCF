-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeQuorumEncoding
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def activeMemberTerm {context : List Ty} (width : PNat) (bootstrap : BitVec width)
    (node : Nat) (peer : Fin width) (current witness : Term context .int) : Term context .bool :=
  .or (.and (.equal current (.integer 0)) (.bit (.bits bootstrap) peer))
    (all [.le (.integer 1) witness, .le current witness, .le witness (length node),
      isConfiguration (.snd (entryAt width node (.sub witness (.integer 1)))),
      .bit (members (.snd (entryAt width node (.sub witness (.integer 1))))) peer])

theorem active_member_term_exact {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (bootstrap : BitVec width)
    (node : Nat) (peer : Fin width) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (committed current : Nat) (rep : ConfigurationLogRep assignment node log committed)
    (position witness : Term context .int) (sameCurrent : position.eval assignment locals = (current : Int)) :
    (activeMemberTerm width bootstrap node peer position witness).eval assignment locals = true <->
      ((current = 0 /\ peer ∈ decodeBits bootstrap) \/
        exists (index : Nat) (nodes : Finset (Fin width)), witness.eval assignment locals = (index : Int) /\
          current <= index /\ NativeArrayCheckQuorum.Reconfiguration log index nodes /\ peer ∈ nodes) := by
  simp only [activeMemberTerm, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq, sameCurrent, rep.length_at,
    and_true, Int.natCast_eq_zero, <- decode_bits_member]
  apply or_congr Iff.rfl
  constructor
  · rintro ⟨positive, lower, within, configuration, member⟩
    have nonnegative : 0 <= witness.eval assignment locals :=
      le_trans (show (0 : Int) <= 1 by decide) positive
    let index := (witness.eval assignment locals).toNat
    have sameWitness : witness.eval assignment locals = (index : Int) :=
      (Int.toNat_of_nonneg nonnegative).symm
    have positiveNat : 0 < index := by
      have bound : (1 : Int) <= (index : Int) := by simpa only [sameWitness] using positive
      have boundNat : 1 <= index := Int.ofNat_le.mp bound
      omega
    have withinNat : index <= log.length :=
      Int.ofNat_le.mp (show (index : Int) <= (log.length : Int) by simpa only [sameWitness] using within)
    have lowerNat : current <= index :=
      Int.ofNat_le.mp (show (current : Int) <= (index : Int) by simpa only [sameWitness] using lower)
    obtain ⟨nodes, physical, included⟩ :=
      (reconfiguration_payload_at_correct assignment locals node log committed rep
        index positiveNat withinNat (.sub witness (.integer 1))
        (by simp [Term.eval, sameWitness]) (fun nodes => peer ∈ nodes)).mp ⟨configuration, member⟩
    exact ⟨index, nodes, sameWitness, lowerNat, physical, included⟩
  · rintro ⟨index, nodes, sameWitness, lower, physical, member⟩
    have decoded := (reconfiguration_payload_at_correct assignment locals node log committed rep
      index physical.1 physical.2.1 (.sub witness (.integer 1))
      (by simp [Term.eval, sameWitness]) (fun nodes => peer ∈ nodes)).mpr ⟨nodes, physical, member⟩
    refine ⟨?_, ?_, ?_, decoded.1, decoded.2⟩
    · rw [sameWitness]
      exact Int.ofNat_le.mpr (show 1 <= index by have positive := physical.1; omega)
    · rw [sameWitness]
      exact Int.ofNat_le.mpr lower
    · rw [sameWitness]
      exact Int.ofNat_le.mpr physical.2.1

theorem active_member_exists_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (node : Nat) (peer : Fin width)
    (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (sameCurrent : assignment .int currentId = (current : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists value : Int, (activeMemberTerm width bootstrap node peer (.free .int currentId) (.free .int witnessId)).eval
      (assignment.set .int witnessId value) Locals.empty = true) <->
      NativeArrayVote.MemberAt log current peer := by
  have currentPreserved (value : Int) :
      (.free .int currentId : Expr .int).eval (assignment.set .int witnessId value) Locals.empty = (current : Int) := by
    simp [Term.eval, Assignment.set, different, sameCurrent]
  constructor
  · rintro ⟨value, accepted⟩
    have decoded := (active_member_term_exact (assignment.set .int witnessId value) Locals.empty
      bootstrap node peer log committed current (rep.set_integer witnessId value)
      (.free .int currentId) (.free .int witnessId) (currentPreserved value)).mp accepted
    rcases decoded with initial | ⟨index, nodes, _, lower, physical, member⟩
    · exact Or.inl ⟨initial.1, by simpa only [sameBootstrap] using initial.2⟩
    · exact Or.inr ⟨index, nodes, lower, physical, member⟩
  · rintro (⟨zero, member⟩ | ⟨index, nodes, lower, physical, member⟩)
    · refine ⟨0, (active_member_term_exact (assignment.set .int witnessId 0) Locals.empty
        bootstrap node peer log committed current (rep.set_integer witnessId 0)
        (.free .int currentId) (.free .int witnessId) (currentPreserved 0)).mpr (Or.inl ⟨zero, ?_⟩)⟩
      simpa only [sameBootstrap] using member
    · refine ⟨index, (active_member_term_exact (assignment.set .int witnessId index) Locals.empty
        bootstrap node peer log committed current (rep.set_integer witnessId index)
        (.free .int currentId) (.free .int witnessId) (currentPreserved index)).mpr
          (Or.inr ⟨index, nodes, ?_, lower, physical, member⟩)⟩
      simp [Term.eval, Assignment.set]

theorem active_member_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (bootstrap : BitVec width) (node : Nat) (peer : Fin width)
    (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (state : NodeState (Fin width) Nat)
    (sameLog : state.log = log.decode) (rep : ConfigurationLogRep assignment node log state.commitIndex)
    (sameCurrent : assignment .int currentId = ((currentConfiguration state).index : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists value : Int, (activeMemberTerm width bootstrap node peer (.free .int currentId) (.free .int witnessId)).eval
      (assignment.set .int witnessId value) Locals.empty = true) <-> peer ∈ activeNodeUnion state :=
  (active_member_exists_correct assignment bootstrap node peer currentId witnessId different log state.commitIndex
    (currentConfiguration state).index rep sameCurrent sameBootstrap).trans
      (NativeArrayVote.member_at_correct log state peer sameLog)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
