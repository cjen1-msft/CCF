module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.DeepReceiveCases
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersA.ReplyRole

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
open Lean Elab Command

set_option maxRecDepth 16384
set_option maxHeartbeats 1000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

inductive Branch where | same | followerRole | noneRole | follower | retired

def column : Branch → Classes.StepBranch
  | .same => .appendEntriesRequest_summary_role_inl
  | .followerRole => .appendEntriesRequest_summary_role_inr_inl
  | .noneRole => .appendEntriesRequest_summary_role_inr_inr
  | .follower => .appendEntriesRequest_summary_follower_inl
  | .retired => .appendEntriesRequest_summary_follower_inr

def test (_ : NodeID) (pre : NodeState) (ev : Event) (_ : NodeState) : Bool :=
  match ev with
  | .receive _ (.appendEntriesRequest q) => decide (pre.currentTerm < q.term)
  | _ => false

def reader : Reader := actorRead test

run_cmd liftTermElabM do
  for n in #[``step_appendEntriesRequest_summary_role_inl,``step_appendEntriesRequest_summary_role_inr_inl,
      ``step_appendEntriesRequest_summary_role_inr_inr,``step_appendEntriesRequest_summary_follower_inl,
      ``step_appendEntriesRequest_summary_follower_inr] do
    HandReadersBFactor.compile n

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem changed {n q} (ev : c.event = .receive n (.appendEntriesRequest q))
    (higher : c.pre.currentTerm < q.term) : ¬ Now f c.actor c.post := by
  obtain bump | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
  case inr => exact (Nat.not_le_of_lt higher stable.1).elim
  have ran := c.tr.ran
  change (step _ _ _ c.event).run {} = _ at ran
  rw [ev] at ran
  simp only [step,receive,Bool.false_eq_true,false_and,ite_false,bump.2] at ran
  obtain ⟨_,_,facts⟩ := aeReply c.actor n (bumpedState c.pre q.term) q (Nat.le_refl _) _ _ _ ran
  intro old
  have eq := congrArg NodeState.currentTerm (c.now_pre old)
  exact (Nat.ne_of_lt higher) (eq.symm.trans facts.1)

private theorem suffices_higher (k : Branch) {n q} (ev : c.event = .receive n (.appendEntriesRequest q))
    (higher : c.pre.currentTerm < q.term) : sig c (column k) := by
  have root := DeepInputCases.summary c (changed c ev higher)
  have build := DeepReceiveCases.request c root n q ev higher
  cases k
  all_goals first
    | exact build .sameRole (by decide) (by decide)
    | exact build .followerRole (by decide) (by decide)
    | exact build .noneRole (by decide) (by decide)
    | exact build .follower (by decide) (by decide)
    | exact build .retired (by decide) (by decide)
end

private theorem needs_higher (s : Step) (k : Branch) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (column k) → ∃ n q, s.context.event = .receive n (.appendEntriesRequest q) ∧
      s.context.pre.currentTerm < q.term := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have no := HandReadersBGate.quiet s
  intro h
  cases k
  all_goals
    first
    | have p := ((HandReadersBFactor.Exact.step_appendEntriesRequest_summary_role_inl _ _ _ no).mp h).2
    | have p := ((HandReadersBFactor.Exact.step_appendEntriesRequest_summary_role_inr_inl _ _ _ no).mp h).2
    | have p := ((HandReadersBFactor.Exact.step_appendEntriesRequest_summary_role_inr_inr _ _ _ no).mp h).2
    | have p := ((HandReadersBFactor.Exact.step_appendEntriesRequest_summary_follower_inl _ _ _ no).mp h).2
    | have p := ((HandReadersBFactor.Exact.step_appendEntriesRequest_summary_follower_inr _ _ _ no).mp h).2
    obtain ⟨_,_,n,q,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,bump,_⟩ := p
    exact ⟨n,q,ev,bump.1⟩

def exactReader (k : Branch) : Exact (column k) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true, show holds s (.step (column k)) ↔ sig s.context (column k) from sig_iff _ _,
      reader,actorRead_at]
    constructor
    · intro h
      obtain ⟨_,q,ev,higher⟩ := needs_higher s k h
      simpa only [ev,test,decide_eq_true_eq] using higher
    · intro yes
      unfold test at yes
      split at yes
      · exact suffices_higher s.context k (by assumption) (of_decide_eq_true yes)
      · contradiction

end ConsensusCoverage.HandReadersA.ReplyRole
