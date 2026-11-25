module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkA.Request

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile AssistReplyA

set_option maxHeartbeats 2000000
set_option maxRecDepth 16384

open Lean Elab Command in
run_cmd liftTermElabM do
  for n in #[``step_aeReply_summary_rest_inl,``step_aeReply_summary_rest_inr] do
    Factor.compile n

def restColumn (positive : Bool) : Classes.StepBranch :=
  if positive then .aeReply_summary_rest_inr else .aeReply_summary_rest_inl

private def good (positive : Bool) (_ : NodeID) (st : NodeState) (q : AppendEntriesRequest) : Bool :=
  let z := observed st q
  !positive || decide (q.term = z.currentTerm ∧ z.commitIndex ≤ q.prevLogIndex ∧ appendEntryMatchesLog z q)

private theorem restIff (s : Step) (positive : Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (restColumn positive) ↔ HandReadersBGate.Source s.context ∧ ∃ src q,
      s.context.event = .receive src (.appendEntriesRequest q) ∧ good positive s.context.actor s.context.pre q := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  cases positive
  all_goals first
    | rw [show sig s.context (restColumn false) = step_aeReply_summary_rest_inl _ _ _ from rfl,
        Factor.Split.step_aeReply_summary_rest_inl_iff,
        HandReadersBFactor.Exact.step_aeReply_summary_rest_inl _ _ _ (HandReadersBGate.quiet s)]
    | rw [show sig s.context (restColumn true) = step_aeReply_summary_rest_inr _ _ _ from rfl,
        Factor.Split.step_aeReply_summary_rest_inr_iff,
        HandReadersBFactor.Exact.step_aeReply_summary_rest_inr _ _ _ (HandReadersBGate.quiet s)]
  all_goals
    apply and_congr_right
    intro _
    constructor
  case false.mp =>
    rintro (⟨_,src,_,_,_,q,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩ |
      ⟨_,src,_,_,_,q,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩,_⟩) <;> exact ⟨src,q,ev,rfl⟩
  case true.mp =>
    rintro (⟨_,src,_,_,_,q,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,obs,_,_,_,rfl⟩,rest⟩ |
      ⟨_,src,_,_,_,q,_,⟨⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,obs,_,_,_,rfl⟩,rest⟩)
    all_goals
      obtain ⟨_,_,_,_,_,_,_,_,_,_,ack,_⟩ := rest
      refine ⟨src,q,ev,?_⟩
      simp only [good,Bool.not_true,Bool.false_or,decide_eq_true_eq]
      rw [show observed s.context.pre q = _ from obs.2]
      exact ⟨ack.1,ack.2.1,ack.2.2.1⟩
  all_goals
    rintro ⟨src,q,ev,yes⟩
    let z := observed c.pre q
    have path : ∃ event, (c.actor = c.tr.actor ∧ c.pre = c.tr.pre ∧ event = c.tr.event) ∧
        ∃ msg, event = .receive src msg ∧ event = .receive src msg ∧ msg = .appendEntriesRequest q :=
      ⟨_,⟨rfl,rfl,rfl⟩,_,ev,ev,rfl⟩
    have logEq : z.log = c.pre.log := Concrete.observeTerm_log _ _
    have commitEq : z.commitIndex = c.pre.commitIndex := Concrete.observeTerm_commitIndex _ _
    have termLe : c.pre.currentTerm ≤ z.currentTerm := by
      obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
      · rw [show z = _ from raised.2]; exact Nat.le_of_lt raised.1
      · rw [show z = _ from stable.2]; exact Nat.le_refl _
  case false.mpr =>
    have nack : ∀ msg ∈ ([] : List Model.Envelope), msg.source = c.actor ∧
        ∃ p, msg.payload = .appendEntriesResponse p ∧ p.success = false := by simp
    have h : AEReply c.actor src z q z [] := ⟨rfl,rfl,rfl,.inl rfl,fun _ => rfl,.inl ⟨rfl,rfl,nack⟩⟩
    obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
    case inl =>
      refine .inl ⟨c.actor,src,c.pre,z,z,q,[],⟨path,raised,raised.1,raised.2,?_,raised.2⟩,?_⟩
      · simpa only [← raised.2] using h
      exact ⟨h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,
        ⟨rfl,rfl,nack⟩,rfl,⟨rfl,nack⟩,rfl,nack,logEq,commitEq,termLe,h⟩
    case inr =>
      exact .inr ⟨c.actor,src,c.pre,z,z,q,[],⟨path,stable,stable.1,stable.2,
        (show z = c.pre from stable.2) ▸ h,stable.2⟩,
        h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,
        ⟨rfl,rfl,nack⟩,rfl,⟨rfl,nack⟩,rfl,nack,logEq,commitEq,termLe,h⟩
  case true.mpr =>
    obtain ⟨same,safe,matched⟩ := of_decide_eq_true (show decide (_ ∧ _ ∧ _) = true from yes)
    let l := acceptLog z.log q
    let j := max z.commitIndex (maxCommittableIndexUpTo l (min q.primaryCommit (q.prevLogIndex + q.entries.length)))
    let a := {z with role := .follower,log := l,commitIndex := j}
    let e : Model.Envelope := ⟨c.actor,src,.appendEntriesResponse ⟨z.currentTerm,true,q.prevLogIndex+q.entries.length⟩⟩
    have packet := And.intro (Eq.refl [e]) (And.intro (show e.source = c.actor from rfl)
      (And.intro (show e.target = src from rfl) (Eq.refl e.payload)))
    have delivered : ∃ p, [e] = [p] ∧ p.source = c.actor ∧ p.target = src ∧ p.payload = e.payload := ⟨e,packet⟩
    have ack := And.intro same (And.intro safe (And.intro matched (And.intro (show a.log = acceptLog z.log q from rfl)
      (And.intro (show a.commitIndex = max z.commitIndex (maxCommittableIndexUpTo a.log (min q.primaryCommit
        (q.prevLogIndex+q.entries.length))) from rfl) delivered))))
    have h : AEReply c.actor src z q a [e] := ⟨rfl,rfl,rfl,.inr (.inl rfl),fun no => Role.noConfusion no,.inr ack⟩
    obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
    · left
      refine ⟨c.actor,src,c.pre,z,a,q,[e],⟨path,raised,raised.1,raised.2,?_,raised.2⟩,?_⟩
      · simpa only [← raised.2] using h
      · exact ⟨h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,
          ack,same,ack.2,safe,ack.2.2,matched,ack.2.2.2,rfl,ack.2.2.2.2,rfl,⟨e,packet⟩,e,packet,
          rfl,packet.2,rfl,packet.2.2,rfl,rfl,logEq,commitEq,termLe,h⟩
    · right
      refine ⟨c.actor,src,c.pre,z,a,q,[e],⟨path,stable,stable.1,stable.2,?_,stable.2⟩,?_⟩
      · simpa only [← (show z = c.pre from stable.2)] using h
      · exact ⟨h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,
          ack,same,ack.2,safe,ack.2.2,matched,ack.2.2.2,rfl,ack.2.2.2.2,rfl,⟨e,packet⟩,e,packet,
          rfl,packet.2,rfl,packet.2.2,rfl,rfl,logEq,commitEq,termLe,h⟩

def restReader (positive : Bool) : Exact (restColumn positive) :=
  exactOfTail _ (good positive) (restIff · positive)

end ConsensusCoverage.HandReadersTrunkA.Request
