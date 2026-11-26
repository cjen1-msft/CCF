module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepBatchCases
import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepPrefixCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA

set_option maxRecDepth 8192

private theorem sender [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
    (n : NodeID) (st : NodeState) (xs : List AppendEntryInput)
    (path : (reach% step_appendBatch_summary_mem_append_inl[15]) f t c n st xs)
    (guard : st.role = .primary ∧ ¬st.isRetiredCommitted n ∧ xs ≠ [])
    (i : Nat) (bound : i ≤ st.log.length) :
    (reach% step_termAt_take_zero_pos[10]) f t c i st.log.length := by
  let q : AppendEntriesRequest := ⟨st.currentTerm, i, termAt st.log i, [], 0⟩
  let e : Model.Envelope := ⟨n, n+1, .appendEntriesRequest q⟩
  have sent : AEFrom n st.currentTerm st.commitIndex st.log e :=
    ⟨rfl, Nat.succ_ne_self _, q, rfl, rfl, bound, rfl, List.nil_prefix, Nat.zero_le _⟩
  have b := DeepBatchCases.batch n st [e] (by simpa using sent)
  have empty := DeepBatchCases.batch n st [] (by simp)
  have adv : Advance n st st := .inl rfl
  have noLater : ∀ msg : Model.Envelope, msg ∈ [] → msg.source = n ∧
      msg.payload = .proposeRequestVoteRequest st.currentTerm := by simp
  have append : (reach% step_termAt_take_zero_pos[10,5,4]) f t c n st.currentTerm
      st.commitIndex st.commitIndex st.log st.log e := by
    right; left
    exact ⟨st, xs, path, guard, guard.1, guard.2, guard, st, [e], b, st, [], ⟨adv, noLater⟩,
      adv, noLater, b.1, b.2, [], ⟨st.sentIndex, by simp⟩, st.sentIndex, ⟨by simp, by simp⟩,
      by simp, by simp, by simp, by simp, empty, rfl, rfl, .inl guard.1, Nat.le_refl _,
      rfl, rfl, rfl, rfl, rfl⟩
  have previous : (reach% step_termAt_take_zero_pos[10,5]) f t c st.log st.log i := by
    iterate 9 right
    have parts : e.payload = .appendEntriesRequest q ∧ q.term = st.currentTerm ∧
        q.prevLogIndex ≤ st.log.length ∧ q.prevLogTerm = termAt st.log q.prevLogIndex ∧
        q.entries <+: st.log.drop q.prevLogIndex ∧ q.primaryCommit ≤ st.commitIndex :=
      ⟨rfl, rfl, bound, rfl, List.nil_prefix, Nat.zero_le _⟩
    exact ⟨n, _, _, _, e, append, sent.1, sent.2, sent.2.1, sent.2.2,
      q, parts, parts.1, parts.2, parts.2.1, parts.2.2, parts.2.2.1, parts.2.2.2,
      parts.2.2.2.1, parts.2.2.2.2, parts.2.2.2.2.1, parts.2.2.2.2.2, sent,
      List.prefix_refl _, Nat.le_refl _, rfl⟩
  iterate 12 right
  exact ⟨_, _, previous, List.prefix_refl _, bound, rfl⟩

private def column (zero : Bool) : Classes.StepBranch :=
  if zero then .termAt_take_zero_pos else .termAt_take_zero_neg

private def check (s : Step) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed &&
    match x.event with
    | .internal (.append xs) => decide (x.base.pre.role = .primary ∧
        ¬x.base.pre.isRetiredCommitted x.base.actor ∧ xs ≠ [] ∧ 0 < x.base.pre.log.length)
    | _ => false

private theorem correct (s : Step) (zero : Bool) (yes : check s = true) :
    label s (.step (column zero)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed, yes⟩ := yes
  have root := DeepInputCases.summary c fun was =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp was))
  split at yes <;> try contradiction
  rename_i xs ev
  obtain ⟨r, nr, ne, pos⟩ := of_decide_eq_true yes
  have ev := (X.event_eq ok).trans ev
  rw [← View.pre_eq ok.1, ← View.actor_eq ok.1] at nr
  rw [← View.pre_eq ok.1] at pos r
  have path : (reach% step_appendBatch_summary_mem_append_inl[15]) s.frame s.after c c.actor c.pre xs :=
    ⟨c.event, ⟨_, c.tr, root, rfl, rfl, rfl⟩, _, ev, ev, rfl⟩
  have get := sender c.actor c.pre xs path ⟨r, nr, ne⟩
  refine (label_true s _).mpr ((sig_iff c _).mpr ?_)
  cases zero with
  | true =>
    iterate 10 right
    exact Or.inl ⟨_, get 0 (Nat.zero_le _), Nat.zero_le _⟩
  | false =>
    iterate 10 right
    exact Or.inl ⟨1, _, get 1 pos, by decide, pos⟩

open DeepSchedules FrontierRows in
def certificates : List Certificate :=
  [true,false].map fun z =>
    checked (column z) (selected divergent (by unfold Run.valid; decide) 0)
      check (by decide +kernel) (correct · z)

end ConsensusCoverage.DeepPrefixCases
