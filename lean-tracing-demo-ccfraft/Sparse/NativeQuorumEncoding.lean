-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeEncodeProofs

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure ConfigurationLogRep {width : PNat} (assignment : Assignment) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat) : Prop where
  length : (NativeEncode.length node : Expr .int).eval assignment Locals.empty = (log.length : Int)
  commit : (NativeEncode.commit node : Expr .int).eval assignment Locals.empty = (committed : Int)
  contents : forall index, index < log.length ->
    decodeContent ((assignment (.array .int (.array .int (entryTy width))) 6 node index).2) =
      (log.entries index).content

theorem ConfigurationLogRep.length_at {context : List Ty} {width : PNat}
    {assignment : Assignment} {node : Nat} {log : NativeArrayCheckQuorum.Log (Fin width) Nat}
    {committed : Nat} (rep : ConfigurationLogRep assignment node log committed)
    (locals : Locals context) :
    (NativeEncode.length node : Term context .int).eval assignment locals = (log.length : Int) := by
  simpa only [NativeEncode.length, read, allocated, Term.eval] using rep.length

theorem ConfigurationLogRep.commit_at {context : List Ty} {width : PNat}
    {assignment : Assignment} {node : Nat} {log : NativeArrayCheckQuorum.Log (Fin width) Nat}
    {committed : Nat} (rep : ConfigurationLogRep assignment node log committed)
    (locals : Locals context) :
    (NativeEncode.commit node : Term context .int).eval assignment locals = (committed : Int) := by
  simpa only [NativeEncode.commit, read, allocated, Term.eval] using rep.commit

theorem reconfiguration_at_correct {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment node log committed) (index : Nat)
    (positive : 0 < index) (within : index <= log.length) (position : Term context .int)
    (same : position.eval assignment locals = (index : Int) - 1) :
    (isConfiguration (.snd (entryAt width node position))).eval assignment locals = true <->
      exists nodes, NativeArrayCheckQuorum.Reconfiguration log index nodes := by
  rw [configuration_exists]
  have index_cast : (index : Int) - 1 = ((index - 1 : Nat) : Int) := by omega
  simp only [entryAt, Term.eval, same, index_cast]
  have contents := rep.contents (index - 1) (by omega)
  dsimp only [entryTy] at contents
  rw [contents]
  simp [NativeArrayCheckQuorum.Reconfiguration, positive, within]

theorem current_candidate_correct {width : PNat}
    (assignment : Assignment) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (same : assignment .int currentId = (current : Int)) :
    (currentCandidate width node currentId).eval assignment Locals.empty = true <->
      (current <= min committed log.length /\
        (current = 0 \/ exists nodes, NativeArrayCheckQuorum.Reconfiguration log current nodes)) := by
  simp only [currentCandidate, all, List.foldr_cons, List.foldr_nil, Term.eval,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, same, rep.length, rep.commit,
    and_true]
  by_cases zero : current = 0
  · simp [zero]
  · by_cases within : current <= log.length
    · have physical := reconfiguration_at_correct assignment Locals.empty node log committed rep
        current (by omega) within (.sub (.free .int currentId) (.integer 1))
        (by simp [Term.eval, same])
      simp only [physical]
      simp [zero, within]
    · simp [show ¬(current : Int) <= (log.length : Int) by omega, within]

theorem no_later_configuration_correct {width : PNat}
    (assignment : Assignment) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (same : assignment .int currentId = (current : Int)) :
    (noLaterConfiguration width node currentId).eval assignment Locals.empty = true <->
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
      node log committed rep candidate (by omega) live (.sub (.bound .here) (.integer 1))
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
      node log committed rep candidate.toNat (by omega) live (.sub (.bound .here) (.integer 1))
      (by simp [Term.eval, Locals.cons, sameNat])
    have absent : ¬(exists nodes, NativeArrayCheckQuorum.Reconfiguration log candidate.toNat nodes) := by
      rintro ⟨nodes, found⟩
      exact excludes candidate.toNat nodes lowerNat upper found
    cases observed : (isConfiguration (.snd (entryAt width node
      (.sub (.bound .here) (.integer 1))))).eval assignment (Locals.empty.cons candidate) <;>
      simp_all

theorem current_index_constraints_correct {width : PNat}
    (assignment : Assignment) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (same : assignment .int currentId = (current : Int)) :
    ((currentCandidate width node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width node currentId).eval assignment Locals.empty = true) <->
      NativeArrayCheckQuorum.CurrentIndex log committed current := by
  rw [current_candidate_correct assignment node currentId log committed current rep same,
    no_later_configuration_correct assignment node currentId log committed current rep same]
  simp only [NativeArrayCheckQuorum.CurrentIndex, and_assoc]

theorem current_index_witness_correct {width : PNat}
    (assignment : Assignment) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed : Nat)
    (rep : ConfigurationLogRep assignment node log committed) :
    ((currentCandidate width node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width node currentId).eval assignment Locals.empty = true) <->
      (exists current : Nat, assignment .int currentId = (current : Int) /\
        NativeArrayCheckQuorum.CurrentIndex log committed current) := by
  constructor
  · intro accepted
    have candidate := accepted.1
    simp only [currentCandidate, all, List.foldr_cons, List.foldr_nil, Term.eval,
      Bool.and_eq_true, decide_eq_true_eq] at candidate
    have nonnegative := candidate.1
    have same := (Int.toNat_of_nonneg nonnegative).symm
    exact ⟨_, same, (current_index_constraints_correct assignment node currentId log committed
      (assignment .int currentId).toNat rep same).mp accepted⟩
  · rintro ⟨current, same, correct⟩
    exact (current_index_constraints_correct assignment node currentId log committed current rep same).mpr correct

theorem current_configuration_model_correct {width : PNat} [Bootstrap (Fin width)]
    (assignment : Assignment) (node currentId : Nat)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (committed current : Nat)
    (rep : ConfigurationLogRep assignment node log committed)
    (same : assignment .int currentId = (current : Int)) :
    ((currentCandidate width node currentId).eval assignment Locals.empty = true /\
      (noLaterConfiguration width node currentId).eval assignment Locals.empty = true) <->
      (currentConfigurationAt log.decode committed).index = current :=
  (current_index_constraints_correct assignment node currentId log committed current rep same).trans
    (NativeArrayCheckQuorum.current_index_correct log committed current)

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
