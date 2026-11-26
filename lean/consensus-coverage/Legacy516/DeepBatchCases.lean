module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.DeepSchedules
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepBatchCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

inductive BatchCase where
  | retained | retired | oldSend | newSend

def BatchCase.column : BatchCase → Classes.StepBranch
  | .retained => .appendBatch_summary_role_inl
  | .retired => .appendBatch_summary_role_inr
  | .oldSend => .appendBatch_summary_mem_append_inl
  | .newSend => .appendBatch_summary_mem_append_inr

private def sent (n : NodeID) (st : NodeState) : Model.Envelope :=
  ⟨n, n+1, .appendEntriesRequest ⟨st.currentTerm, 0, termAt st.log 0, [], 0⟩⟩

private theorem fromState (n : NodeID) (st : NodeState) :
    AEFrom n st.currentTerm st.commitIndex st.log (sent n st) :=
  ⟨rfl, Nat.succ_ne_self _, _, rfl, rfl, Nat.zero_le _, rfl, List.nil_prefix, Nat.zero_le _⟩

private theorem batch (n : NodeID) (st : NodeState) (msgs : List Model.Envelope)
    (hs : ∀ e, e ∈ msgs → AEFrom n st.currentTerm st.commitIndex st.log e) :
    BatchState n st st msgs :=
  ⟨⟨[], st.sentIndex, by simp, fun _ h => (List.not_mem_nil h).elim⟩, hs⟩

private def endState (n : NodeID) (st : NodeState) : NodeState :=
  {st with role := .none, commitIndex := highestCommittableIndex st n}

private theorem ends (n : NodeID) (st : NodeState) (can : st.commitIndex < highestCommittableIndex st n) :
    Advance n st (endState n st) :=
  .inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, can, rfl, .inr rfl⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
  (n : NodeID) (st : NodeState) (xs : List AppendEntryInput)
  (path : (reach% step_appendBatch_summary_mem_append_inl[15]) f t c n st xs)
  (guard : st.role = .primary ∧ ¬st.isRetiredCommitted n ∧ xs ≠ [])
include path guard

-- The proof's continuation ranges over any batch/advance satisfying its contract.
-- The old-send list and the later nomination list are separate existential witnesses.
local macro "batch_context " path:ident guard:ident st:ident b:ident adv:ident later:ident : tactic => `(tactic|
  refine ⟨_, _, _, $path, $guard, ($guard).1, ($guard).2, $guard,
    $st, _, $b, _, _, ⟨$adv, $later⟩, $adv, $later, ($b).1, ($b).2,
    [], ⟨($st).sentIndex, by simp⟩, ($st).sentIndex, ⟨by simp, by simp⟩, by simp, by simp, ?_⟩)

private theorem member :
    step_appendBatch_summary_mem_append_inl f t c ∧ step_appendBatch_summary_mem_append_inr f t c := by
  have empty := batch n st [] (by simp)
  have b := batch n st [sent n st] (by simpa using fromState n st)
  have adv : Advance n st st := .inl rfl
  have noLater : ∀ e : Model.Envelope, e ∈ [] → e.source = n ∧
      e.payload = .proposeRequestVoteRequest st.currentTerm := by simp
  let e : Model.Envelope := ⟨n, n+1, .proposeRequestVoteRequest st.currentTerm⟩
  have nominated : ∀ msg : Model.Envelope, msg ∈ [e] → msg.source = n ∧
      msg.payload = .proposeRequestVoteRequest st.currentTerm := by simp [e]
  constructor <;> iterate 15 right
  · left
    batch_context path guard st b adv noLater
    exact ⟨sent n st, by simp, by simp, empty, rfl, rfl, Nat.le_refl _, .inl guard.1⟩
  · left
    batch_context path guard st empty adv nominated
    exact ⟨e, by simp, by simp, empty, rfl, rfl, .inl guard.1, Nat.le_refl _⟩

private theorem roles (post : NodeState) (adv : Advance n st post) :
    (post.role = st.role → step_appendBatch_summary_role_inl f t c) ∧
    (post.role = .none → step_appendBatch_summary_role_inr f t c) := by
  have empty := batch n st [] (by simp)
  have b := batch n st [sent n st] (by simpa using fromState n st)
  have noLater : ∀ e : Model.Envelope, e ∈ [] → e.source = n ∧
      e.payload = .proposeRequestVoteRequest st.currentTerm := by simp
  have fromPost : AEFrom n post.currentTerm post.commitIndex post.log (sent n st) :=
    adv.term.symm ▸ (fromState n st).extend (adv.log ▸ List.prefix_refl _) adv.commit_le
  obtain ⟨q, payload, ok⟩ := fromPost.ok
  constructor <;> intro role <;> iterate 44 right
  all_goals
    left
    batch_context path guard st b adv noLater
    exact ⟨sent n st, by simp, by simp, q, ⟨payload, ok⟩, payload, ok, role,
      adv.term, adv.log, adv.commit_le, fromPost, empty⟩
end

private def needAdvance : BatchCase → Bool
  | .retired => true
  | _ => false

def check (s : Step) (k : BatchCase) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x => x.base.changed &&
    match x.event with
    | .internal (.append xs) =>
        decide (x.base.pre.role = .primary ∧ ¬x.base.pre.isRetiredCommitted x.base.actor ∧ xs ≠ [] ∧
          (needAdvance k = true → x.base.pre.commitIndex < highestCommittableIndex x.base.pre x.base.actor))
    | _ => false

theorem correct (s : Step) (k : BatchCase) (yes : check s k = true) : label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, Bool.and_eq_true] at yes
  obtain ⟨changed, yes⟩ := yes
  have root := DeepInputCases.summary c fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  split at yes <;> try contradiction
  rename_i xs ev
  obtain ⟨r, nr, ne, can⟩ := of_decide_eq_true yes
  have ev := (X.event_eq ok).trans ev
  rw [← View.pre_eq ok.1, ← View.actor_eq ok.1] at nr can
  rw [← View.pre_eq ok.1] at r
  have path : (reach% step_appendBatch_summary_mem_append_inl[15]) s.frame s.after c c.actor c.pre xs :=
    ⟨c.event, ⟨_, c.tr, root, rfl, rfl, rfl⟩, _, ev, ev, rfl⟩
  have guard := And.intro r (And.intro nr ne)
  refine (label_true s _).mpr ((sig_iff c _).mpr ?_)
  cases k with
  | oldSend => exact (member _ _ _ path guard).1
  | newSend => exact (member _ _ _ path guard).2
  | retained => exact (roles _ _ _ path guard c.pre (.inl rfl)).1 rfl
  | retired => exact (roles _ _ _ path guard _ (ends _ _ (can rfl))).2 rfl

open FrontierRows DeepSchedules in
local macro "batch_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (BatchCase.column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (correct · $k))

open DeepSchedules in
def certificates : List Certificate :=
  [batch_at .retained divergent 0, batch_at .retired retiringFlush 10,
   batch_at .oldSend retiringFlush 10, batch_at .newSend retiringFlush 10]

end ConsensusCoverage.DeepBatchCases
