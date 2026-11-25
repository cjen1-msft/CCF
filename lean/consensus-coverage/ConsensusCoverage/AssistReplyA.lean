module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistReplyA

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses QueueSamplesA
set_option maxRecDepth 8192
set_option maxHeartbeats 700000

private abbrev observed (st : NodeState) (r : AppendEntriesRequest) := observeTerm st (.appendEntriesRequest r)
private abbrev stepsDown (z : NodeState) (r : AppendEntriesRequest) :=
  r.term = z.currentTerm ∧ (z.role = .candidate ∨ z.role = .preVoteCandidate)
private abbrev prepared (z : NodeState) (r : AppendEntriesRequest) :=
  if stepsDown z r then becomeAwareOfNewTerm z r.term else z

structure Seed [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (self src : NodeID) (st : NodeState) (r : AppendEntriesRequest) : Prop where
  call : (reach% step_aeReply_conflict_none[15]) f t c self src (observed st r) r
  residual : ∀ after sent, AEReply self src (observed st r) r after sent →
    (reach% step_aeReply_summary_rest_inl[6]) f t c self src st (observed st r) after r sent
  lo : r.term ≤ (observed st r).currentTerm
  log : (observed st r).log = st.log
  commit : (observed st r).commitIndex = st.commitIndex
  term : st.currentTerm ≤ (observed st r).currentTerm

theorem seed [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t} {x : XView}
    (ok : x.Matches c) (fresh : x.base.changed = true) {n r}
    (ev : x.event = .receive n (.appendEntriesRequest r)) :
    Seed c x.base.actor n x.base.pre r := by
  let self := x.base.actor
  let st := x.base.pre
  have path : (reach% step_appendEntriesRequest_summary_role_inl[15]) f t c self st n r :=
    ⟨x.event,⟨t,c.tr,ReceiveCasesB.changedSummary ok fresh,(X.tr_actor_eq ok).symm,(X.tr_pre_eq ok).symm,
      (X.tr_event_eq ok).symm⟩,_,ev,ev,rfl⟩
  obtain raised | stable := observe_bumping st (message := .appendEntriesRequest r) trivial
  · refine ⟨.inl ⟨st,path,raised,raised.1,raised.2,raised.2⟩,?_,?_,?_,?_,?_⟩
    · intro after sent reply
      change AEReply self n (observed st r) r after sent at reply
      rw [show observed st r = _ from raised.2] at reply
      exact .inr (.inl ⟨path,raised,raised.1,raised.2,reply,raised.2⟩)
    all_goals rw [show observed x.base.pre r = _ from raised.2]
    all_goals first | rfl | exact Nat.le_refl _ | exact Nat.le_of_lt raised.1
  · refine ⟨?_,?_,?_,?_,?_,?_⟩
    · rw [show observed x.base.pre r = _ from stable.2]
      exact .inr ⟨path,stable.1,stable.2⟩
    · intro after sent reply
      rw [show observed x.base.pre r = _ from stable.2] at reply ⊢
      exact .inr (.inr (.inr ⟨path,stable,stable.1,stable.2,reply,rfl⟩))
    all_goals rw [show observed x.base.pre r = _ from stable.2]
    all_goals first | rfl | exact stable.1 | exact Nat.le_refl _

private def restCheck (s : Step) (positive : Bool) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    match x.event with
    | .receive _ (.appendEntriesRequest r) =>
      let z := observed x.base.pre r
      x.base.changed && (!positive || decide (r.term = z.currentTerm ∧ z.commitIndex ≤ r.prevLogIndex ∧ appendEntryMatchesLog z r))
    | _ => false

private theorem rest [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t} {self src st r}
    (s : Seed c self src st r) (pos : Bool) (good : pos = true →
      r.term = (observed st r).currentTerm ∧ (observed st r).commitIndex ≤ r.prevLogIndex ∧ appendEntryMatchesLog (observed st r) r) :
    sig c (if pos then .aeReply_summary_rest_inr else .aeReply_summary_rest_inl) := by
  let z := observed st r
  obtain ⟨_,residual,_,logEq,commitEq,termLe⟩ := s
  cases pos with
  | false =>
    have h : AEReply self src z r z [] :=
      ⟨rfl,rfl,rfl,.inl rfl,fun _ => rfl,.inl ⟨rfl,rfl,by simp⟩⟩
    have nack : ∀ e ∈ ([] : List Model.Envelope), e.source = self ∧ ∃ p, e.payload = .appendEntriesResponse p ∧ p.success = false :=
      fun _ h => (List.not_mem_nil h).elim
    iterate 6 right
    left
    exact ⟨self,src,st,z,z,r,[],residual _ _ h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,
      h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,⟨rfl,rfl,nack⟩,rfl,⟨rfl,nack⟩,rfl,nack,logEq,commitEq,termLe,h⟩
  | true =>
    have ⟨same,safe,match_⟩ := good rfl
    let l := acceptLog z.log r
    let j := max z.commitIndex (maxCommittableIndexUpTo l (min r.primaryCommit (r.prevLogIndex + r.entries.length)))
    let a := {z with role := .follower, log := l, commitIndex := j}
    let e : Model.Envelope := ⟨self,src,.appendEntriesResponse ⟨z.currentTerm,true,r.prevLogIndex + r.entries.length⟩⟩
    have packet := And.intro (Eq.refl [e]) (And.intro (show e.source = self from rfl)
      (And.intro (show e.target = src from rfl) (Eq.refl e.payload)))
    have delivered : ∃ p, [e] = [p] ∧ p.source = self ∧ p.target = src ∧ p.payload = e.payload := ⟨e,packet⟩
    have ack := And.intro same (And.intro safe (And.intro match_ (And.intro (show a.log = acceptLog z.log r from rfl)
      (And.intro (show a.commitIndex = max z.commitIndex (maxCommittableIndexUpTo a.log (min r.primaryCommit
        (r.prevLogIndex + r.entries.length))) from rfl) delivered))))
    have h : AEReply self src z r a [e] := ⟨rfl,rfl,rfl,.inr (.inl rfl),fun impossible => Role.noConfusion impossible,.inr ack⟩
    iterate 6 right
    left
    exact ⟨self,src,st,z,a,r,[e],residual _ _ h,h.1,h.2,h.2.1,h.2.2,h.2.2.1,h.2.2.2,h.2.2.2.1,
      h.2.2.2.2,h.2.2.2.2.1,h.2.2.2.2.2,ack,same,ack.2,safe,ack.2.2,match_,ack.2.2.2,
      rfl,ack.2.2.2.2,rfl,⟨e,packet⟩,e,packet,rfl,packet.2,rfl,packet.2.2,rfl,rfl,logEq,commitEq,termLe,h⟩

private theorem restSound (s : Step) (p : Bool) (yes : restCheck s p = true) :
    label s (.step (if p then .aeReply_summary_rest_inr else .aeReply_summary_rest_inl)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [restCheck,made,Option.any_some] at yes
  split at yes <;> try contradiction
  rename_i n r ev
  obtain ⟨fresh,g⟩ := Bool.and_eq_true_iff.mp yes
  apply (label_true _ _).mpr
  apply (sig_iff _ _).mpr
  exact rest (seed ok fresh ev) p (fun h => by simpa [h] using g)

open DeepSchedulesB in
def certificates : List Certificate :=
  [checked _ (firstAck.atStep 1) (restCheck · false) (by decide +kernel) (restSound · false),
   checked _ (firstAck.atStep 1) (restCheck · true) (by decide +kernel) (restSound · true)]

end ConsensusCoverage.AssistReplyA
