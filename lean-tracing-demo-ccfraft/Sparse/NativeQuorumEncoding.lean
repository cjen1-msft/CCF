-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure ConfigurationLogRep {width : PNat} (assignment : Assignment) (columns : Columns) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat) : Prop where
  length : (NativeEncode.length columns node : Expr .int).eval assignment Locals.empty = (log.length : Int)
  commit : (NativeEncode.commit columns node : Expr .int).eval assignment Locals.empty = (committed : Int)
  contents : forall index, index < log.length ->
    decodeContent
      ((assignment (.array .int (.array .int (entryTy width))) columns.logEntries node index).2) =
      (log.entries index).content

theorem ConfigurationLogRep.length_at {context : List Ty} {width : PNat}
    {assignment : Assignment} {columns : Columns} {node : Nat}
    {log : NativeArrayCheckQuorum.Log (Fin width) Nat}
    {committed : Nat} (rep : ConfigurationLogRep assignment columns node log committed)
    (locals : Locals context) :
    (NativeEncode.length columns node : Term context .int).eval assignment locals = (log.length : Int) := by
  simpa only [NativeEncode.length, read, allocated, Term.eval] using rep.length

theorem ConfigurationLogRep.commit_at {context : List Ty} {width : PNat}
    {assignment : Assignment} {columns : Columns} {node : Nat}
    {log : NativeArrayCheckQuorum.Log (Fin width) Nat}
    {committed : Nat} (rep : ConfigurationLogRep assignment columns node log committed)
    (locals : Locals context) :
    (NativeEncode.commit columns node : Term context .int).eval assignment locals = (committed : Int) := by
  simpa only [NativeEncode.commit, read, allocated, Term.eval] using rep.commit

theorem ConfigurationLogRep.set_integer {width : PNat}
    {assignment : Assignment} {columns : Columns} {node : Nat}
    {log : NativeArrayCheckQuorum.Log (Fin width) Nat}
    {committed : Nat} (rep : ConfigurationLogRep assignment columns node log committed)
    (id : Nat) (value : Int) :
    ConfigurationLogRep (assignment.set .int id value) columns node log committed := by
  constructor
  · simpa [NativeEncode.length, read, allocated, Term.eval, Assignment.set] using rep.length
  · simpa [NativeEncode.commit, read, allocated, Term.eval, Assignment.set] using rep.commit
  · intro index within
    simpa [Assignment.set] using rep.contents index within

theorem reconfiguration_at_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (columns : Columns) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed) (index : Nat)
    (positive : 0 < index) (within : index <= log.length) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int) - 1) :
    (isConfiguration (.snd (entryAt width columns node position))).eval assignment locals = true <->
      exists nodes, NativeArrayCheckQuorum.Reconfiguration log index nodes := by
  rw [configuration_exists]
  have index_cast : (index : Int) - 1 = ((index - 1 : Nat) : Int) := by omega
  simp only [entryAt, Term.eval, same, index_cast]
  have contents := rep.contents (index - 1) (by omega)
  dsimp only [entryTy] at contents
  rw [contents]
  simp [NativeArrayCheckQuorum.Reconfiguration, positive, within]

theorem reconfiguration_payload_at_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (columns : Columns) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed) (index : Nat)
    (positive : 0 < index) (within : index <= log.length) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int) - 1)
    (predicate : Finset (Fin width) -> Prop) :
    ((isConfiguration (.snd (entryAt width columns node position))).eval assignment locals = true /\
      predicate (decodeBits ((members (.snd (entryAt width columns node position))).eval assignment locals))) <->
      (exists nodes, NativeArrayCheckQuorum.Reconfiguration log index nodes /\ predicate nodes) := by
  have decoded :
      (exists nodes, decodeContent ((.snd (entryAt width columns node position) : Term context (contentTy width)).eval
        assignment locals) = .reconfiguration nodes /\ predicate nodes) <->
      ((isConfiguration (.snd (entryAt width columns node position))).eval assignment locals = true /\
        predicate (decodeBits ((members (.snd (entryAt width columns node position))).eval assignment locals))) := by
    simp only [configuration_decoding, and_assoc, exists_and_left, exists_eq_left']
  rw [<- decoded]
  have index_cast : (index : Int) - 1 = ((index - 1 : Nat) : Int) := by omega
  simp only [entryAt, Term.eval, same, index_cast]
  have contents := rep.contents (index - 1) (by omega)
  dsimp only [entryTy] at contents
  rw [contents]
  simp [NativeArrayCheckQuorum.Reconfiguration, positive, within]

theorem current_candidate_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed)
    (same : assignment .int currentId = (current : Int)) :
    (currentCandidate width columns node currentId).eval assignment Locals.empty = true <->
      (current <= min committed log.length /\
        (current = 0 \/ exists nodes, NativeArrayCheckQuorum.Reconfiguration log current nodes)) := by
  simp only [currentCandidate, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, same, rep.length, rep.commit,
    and_true]
  by_cases zero : current = 0
  · simp [zero]
  · by_cases within : current <= log.length
    · have physical := reconfiguration_at_correct assignment Locals.empty columns node log committed rep
        current (by omega) within (.sub (.free .int currentId) (.integer 1))
        (by simp [Term.eval, same])
      simp only [physical]
      simp [zero, within]
    · simp [show ¬(current : Int) <= (log.length : Int) by omega, within]

theorem no_later_configuration_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed)
    (same : assignment .int currentId = (current : Int)) :
    (noLaterConfiguration width columns node currentId).eval assignment Locals.empty = true <->
      (forall candidate nodes, current < candidate -> candidate <= min committed log.length ->
        ¬NativeArrayCheckQuorum.Reconfiguration log candidate nodes) := by
  simp only [noLaterConfiguration, Term.eval, decide_eq_true_eq]
  conv_lhs =>
    intro candidate
    rw [implies_eval]
  simp only [all, List.foldr_cons, List.foldr_nil, Term.eval, Bool.and_eq_true, and_true,
    lt, Term.eval, Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not, not_le,
    Locals.cons, same, rep.length_at, rep.commit_at]
  constructor
  · intro excludes candidate nodes lower upper physical
    have live : candidate <= log.length := (le_min_iff.mp upper).2
    have encoded := (reconfiguration_at_correct assignment (Locals.empty.cons (candidate : Int))
      columns node log committed rep candidate (by omega) live (.sub (.bound .here) (.integer 1))
      (by simp [Term.eval, Locals.cons])).mpr ⟨nodes, physical⟩
    have lowerInt : (current : Int) < (candidate : Int) := by exact_mod_cast lower
    have liveInt : (candidate : Int) <= (log.length : Int) := by exact_mod_cast live
    have commitInt : (candidate : Int) <= (committed : Int) := by
      exact_mod_cast (le_min_iff.mp upper).1
    have rejected := excludes (candidate : Int) ⟨lowerInt, liveInt, commitInt⟩
    simp [encoded] at rejected
  · intro excludes candidate bounds
    rcases bounds with ⟨lower, within, beforeCommit⟩
    have nonnegative : 0 <= candidate := le_trans (Int.natCast_nonneg current) (le_of_lt lower)
    have sameNat : (candidate.toNat : Int) = candidate := Int.toNat_of_nonneg nonnegative
    have lowerNat : current < candidate.toNat := by
      exact_mod_cast (show (current : Int) < (candidate.toNat : Int) by simpa [sameNat] using lower)
    have live : candidate.toNat <= log.length := by
      exact_mod_cast (show (candidate.toNat : Int) <= (log.length : Int) by simpa [sameNat] using within)
    have upper : candidate.toNat <= min committed log.length := by
      apply le_min _ live
      exact_mod_cast (show (candidate.toNat : Int) <= (committed : Int) by
        simpa [sameNat] using beforeCommit)
    have physical := reconfiguration_at_correct assignment (Locals.empty.cons candidate)
      columns node log committed rep candidate.toNat (by omega) live (.sub (.bound .here) (.integer 1))
      (by simp [Term.eval, Locals.cons, sameNat])
    have absent : ¬(exists nodes, NativeArrayCheckQuorum.Reconfiguration log candidate.toNat nodes) := by
      rintro ⟨nodes, found⟩
      exact excludes candidate.toNat nodes lowerNat upper found
    cases observed : (isConfiguration (.snd (entryAt width columns node
      (.sub (.bound .here) (.integer 1))))).eval assignment (Locals.empty.cons candidate) <;>
      simp_all

theorem current_index_constraints_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed)
    (same : assignment .int currentId = (current : Int)) :
    ((currentCandidate width columns node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width columns node currentId).eval assignment Locals.empty = true) <->
      NativeArrayCheckQuorum.CurrentIndex log committed current := by
  rw [current_candidate_correct assignment columns node currentId log committed current rep same,
    no_later_configuration_correct assignment columns node currentId log committed current rep same]
  simp only [NativeArrayCheckQuorum.CurrentIndex, and_assoc]

theorem current_index_witness_correct {width : PNat}
    (assignment : Assignment) (columns : Columns) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed) :
    ((currentCandidate width columns node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width columns node currentId).eval assignment Locals.empty = true) <->
      (exists current : Nat, assignment .int currentId = (current : Int) /\
        NativeArrayCheckQuorum.CurrentIndex log committed current) := by
  constructor
  · intro accepted
    have candidate := accepted.1
    simp only [currentCandidate, all, List.foldr_cons, List.foldr_nil, Term.eval,
      Bool.and_eq_true, decide_eq_true_eq] at candidate
    have nonnegative := candidate.1
    have same := (Int.toNat_of_nonneg nonnegative).symm
    exact ⟨_, same, (current_index_constraints_correct assignment columns node currentId log committed
      (assignment .int currentId).toNat rep same).mp accepted⟩
  · rintro ⟨current, same, correct⟩
    exact (current_index_constraints_correct assignment columns node currentId log committed current rep same).mpr correct

theorem current_configuration_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment columns node log committed)
    (same : assignment .int currentId = (current : Int)) :
    ((currentCandidate width columns node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width columns node currentId).eval assignment Locals.empty = true) <->
      (currentConfigurationAt log.decode committed).index = current :=
  (current_index_constraints_correct assignment columns node currentId log committed current rep same).trans
    (NativeArrayCheckQuorum.current_index_correct log committed current)

theorem other_configuration_exact {width : PNat}
    (assignment : Assignment) (columns : Columns) (bootstrap : BitVec width) (node : Fin width)
    (currentId witnessId : Nat) (log : NativeArrayCheckQuorum.Log (Fin width) Nat)
    (committed current : Nat) (rep : ConfigurationLogRep assignment columns node.val log committed)
    (sameCurrent : assignment .int currentId = (current : Int)) :
    (otherConfiguration width bootstrap columns node.val currentId witnessId).eval assignment Locals.empty = true <->
      ((current = 0 /\ ((decodeBits bootstrap).erase node).Nonempty) \/
        exists (index : Nat) (nodes : Finset (Fin width)), assignment .int witnessId = (index : Int) /\ current <= index /\
          NativeArrayCheckQuorum.Reconfiguration log index nodes /\ (nodes.erase node).Nonempty) := by
  simp only [otherConfiguration, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.or_eq_true, Bool.and_eq_true, Bool.not_eq_true', decide_eq_false_iff_not,
    decide_eq_true_eq, sameCurrent, rep.length, and_true, Int.natCast_eq_zero,
    other_bits_correct]
  apply or_congr Iff.rfl
  constructor
  · rintro ⟨positive, lower, within, configuration, other⟩
    have nonnegative : 0 <= assignment .int witnessId := le_trans (by decide : (0 : Int) <= 1) positive
    let index := (assignment .int witnessId).toNat
    have sameWitness : assignment .int witnessId = (index : Int) :=
      (Int.toNat_of_nonneg nonnegative).symm
    have positiveNat : 0 < index := by
      have bound : (1 : Int) <= (index : Int) := by simpa only [sameWitness] using positive
      have boundNat : 1 <= index := by exact_mod_cast bound
      omega
    have withinNat : index <= log.length := by
      exact_mod_cast (show (index : Int) <= (log.length : Int) by simpa only [sameWitness] using within)
    have lowerNat : current <= index := by
      exact_mod_cast (show (current : Int) <= (index : Int) by simpa only [sameWitness] using lower)
    have decoded := (reconfiguration_payload_at_correct assignment Locals.empty columns node.val log committed rep
      index positiveNat withinNat (.sub (.free .int witnessId) (.integer 1))
      (by simp [Term.eval, sameWitness]) (fun nodes => (nodes.erase node).Nonempty)).mp
        ⟨configuration, other⟩
    rcases decoded with ⟨nodes, physical, peer⟩
    exact ⟨index, nodes, sameWitness, lowerNat, physical, peer⟩
  · rintro ⟨index, nodes, sameWitness, lower, physical, peer⟩
    have decoded := (reconfiguration_payload_at_correct assignment Locals.empty columns node.val log committed rep
      index physical.1 physical.2.1 (.sub (.free .int witnessId) (.integer 1))
      (by simp [Term.eval, sameWitness]) (fun nodes => (nodes.erase node).Nonempty)).mpr
        ⟨nodes, physical, peer⟩
    refine ⟨?_, ?_, ?_, decoded.1, decoded.2⟩
    · rw [sameWitness]
      exact Int.ofNat_le.mpr (show 1 <= index by have positive := physical.1; omega)
    · rw [sameWitness]
      exact Int.ofNat_le.mpr lower
    · rw [sameWitness]
      exact Int.ofNat_le.mpr physical.2.1

theorem other_configuration_exists_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (bootstrap : BitVec width) (node : Fin width)
    (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment columns node.val log committed)
    (sameCurrent : assignment .int currentId = (current : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists value : Int, (otherConfiguration width bootstrap columns node.val currentId witnessId).eval
      (assignment.set .int witnessId value) Locals.empty = true) <->
      NativeArrayCheckQuorum.OtherAt log current node := by
  have currentPreserved (value : Int) :
      (assignment.set .int witnessId value) .int currentId = (current : Int) := by
    simp [Assignment.set, different, sameCurrent]
  constructor
  · rintro ⟨value, accepted⟩
    have decoded := (other_configuration_exact (assignment.set .int witnessId value) columns bootstrap
      node currentId witnessId log committed current (rep.set_integer witnessId value)
      (currentPreserved value)).mp accepted
    rcases decoded with initial | physical
    · refine Or.inl ⟨initial.1, ?_⟩
      simpa [sameBootstrap, Finset.Nonempty, Finset.mem_erase, and_comm] using initial.2
    · rcases physical with ⟨index, nodes, _, lower, configuration, other⟩
      refine Or.inr ⟨index, nodes, lower, configuration, ?_⟩
      simpa [Finset.Nonempty, Finset.mem_erase, and_comm] using other
  · intro enabled
    rcases enabled with initial | physical
    · refine ⟨0, (other_configuration_exact (assignment.set .int witnessId 0) columns bootstrap
        node currentId witnessId log committed current (rep.set_integer witnessId 0)
        (currentPreserved 0)).mpr (Or.inl ⟨initial.1, ?_⟩)⟩
      simpa [sameBootstrap, Finset.Nonempty, Finset.mem_erase, and_comm] using initial.2
    · rcases physical with ⟨index, nodes, lower, configuration, other⟩
      refine ⟨index, (other_configuration_exact (assignment.set .int witnessId index) columns bootstrap
        node currentId witnessId log committed current (rep.set_integer witnessId index)
        (currentPreserved index)).mpr (Or.inr ⟨index, nodes, ?_, lower, configuration, ?_⟩)⟩
      · simp [Assignment.set]
      · simpa [Finset.Nonempty, Finset.mem_erase, and_comm] using other

theorem configuration_guards_exists_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (columns : Columns) (bootstrap : BitVec width) (node : Fin width)
    (currentId witnessId : Nat) (different : currentId ≠ witnessId)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment columns node.val log committed)
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION) :
    (exists (currentValue : Int) (witnessValue : Int),
      let extended := (assignment.set .int currentId currentValue).set .int witnessId witnessValue
      (currentCandidate width columns node.val currentId).eval extended Locals.empty = true /\
      (noLaterConfiguration width columns node.val currentId).eval extended Locals.empty = true /\
      (otherConfiguration width bootstrap columns node.val currentId witnessId).eval extended Locals.empty = true) <->
      (exists current, NativeArrayCheckQuorum.CurrentIndex log committed current /\
        NativeArrayCheckQuorum.OtherAt log current node) := by
  constructor
  · rintro ⟨currentValue, witnessValue, candidate, latest, other⟩
    let base := assignment.set .int currentId currentValue
    let extended := base.set .int witnessId witnessValue
    have repBase := rep.set_integer currentId currentValue
    have repExtended := repBase.set_integer witnessId witnessValue
    obtain ⟨current, sameCurrent, correct⟩ :=
      (current_index_witness_correct extended columns node.val currentId log committed repExtended).mp
        ⟨candidate, latest⟩
    have sameBase : base .int currentId = (current : Int) := by
      simpa [base, extended, Assignment.set, different] using sameCurrent
    exact ⟨current, correct,
      (other_configuration_exists_correct base columns bootstrap node currentId witnessId different
        log committed current repBase sameBase sameBootstrap).mp ⟨witnessValue, other⟩⟩
  · rintro ⟨current, correct, other⟩
    let base := assignment.set .int currentId current
    have repBase := rep.set_integer currentId current
    have sameBase : base .int currentId = (current : Int) := by simp [base, Assignment.set]
    obtain ⟨witnessValue, accepted⟩ :=
      (other_configuration_exists_correct base columns bootstrap node currentId witnessId different
        log committed current repBase sameBase sameBootstrap).mpr other
    have sameExtended : (base.set .int witnessId witnessValue) .int currentId = (current : Int) := by
      simp [base, Assignment.set, different]
    have selected := (current_index_constraints_correct (base.set .int witnessId witnessValue)
      columns node.val currentId log committed current (repBase.set_integer witnessId witnessValue)
      sameExtended).mpr correct
    exact ⟨current, witnessValue, selected.1, selected.2, accepted⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
