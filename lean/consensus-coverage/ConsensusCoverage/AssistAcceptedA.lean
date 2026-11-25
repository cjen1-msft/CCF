module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.AssistAcceptedA

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile ReadersAtoms GuardedDomain SolvedWitnesses FollowerFoldCasesB QueueSamplesA
set_option maxRecDepth 8192

private abbrev base (s : NodeState) (q : AppendEntriesRequest) : NodeState :=
  {prepared s q with primaryKnown := true}
private abbrev extra (st : NodeState) (q : AppendEntriesRequest) := q.entries.drop (st.log.length - q.prevLogIndex)
private abbrev bound (st : NodeState) (q : AppendEntriesRequest) :=
  maxCommittableIndexUpTo (st.log ++ extra st q) (limit q)
private def middle (self : NodeID) (st : NodeState) (q : AppendEntriesRequest) : NodeState :=
  (extra st q).foldl (fun z e =>
    let z := {z with log := z.log ++ [e]}
    if e.content.isSignature then z.recordCommit self (max z.commitIndex (maxCommittableIndexUpTo z.log (limit q)))
    else z) st

inductive Case where | advance | retain | same | retired
def column : Case → Classes.StepBranch
  | .advance => .advance_le_total_inl
  | .retain => .advance_le_total_inr
  | .same => .handleAppendEntiresFromPrimary_eq_roleCase__inl
  | .retired => .handleAppendEntiresFromPrimary_eq_roleCase__inr

private def guard (k : Case) (self : NodeID) (st : NodeState) (q : AppendEntriesRequest) : Bool :=
  match k with
  | .advance => decide (0 < max st.commitIndex (bound st q) ∧ st.commitIndex ≤ bound st q)
  | .retain => decide (0 < max st.commitIndex (bound st q) ∧ bound st q ≤ st.commitIndex)
  | .same => decide ((handleAppendEntiresFromPrimary self st q).1.role = (middle self st q).role)
  | .retired => decide ((handleAppendEntiresFromPrimary self st q).1.role = .none)

private instance (s : NodeState) : Decidable (Direct.CommitFrontier s) := by unfold Direct.CommitFrontier; infer_instance

private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    match x.event with
    | .receive _ (.appendEntriesRequest q) =>
      let st := x.base.pre
      decide (x.base.changed = true ∧ Direct.CommitFrontier st ∧ Direct.CommitFrontier (observed st q) ∧
        Direct.CommitFrontier (prepared st q) ∧ ¬q.term < (prepared st q).currentTerm ∧
        appendEntryMatchesLog (prepared st q) q ∧ (prepared st q).commitIndex ≤ q.prevLogIndex ∧
        firstTermConflictIndex (base st q) q = none) && guard k x.base.actor (base st q) q
    | _ => false

private theorem accepted [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {x : XView} (ok : x.Matches c) {n q} (ev : x.event = .receive n (.appendEntriesRequest q))
    (fresh : x.base.changed = true) (initial : Direct.CommitFrontier x.base.pre)
    (seen : Direct.CommitFrontier (observed x.base.pre q)) (ready : Direct.CommitFrontier (prepared x.base.pre q))
    (current : ¬q.term < (prepared x.base.pre q).currentTerm) (matching : appendEntryMatchesLog (prepared x.base.pre q) q)
    (safe : (prepared x.base.pre q).commitIndex ≤ q.prevLogIndex) (clear : firstTermConflictIndex (base x.base.pre q) q = none) :
    (reach% step_advance_le_total_inl[0,0]) f t c x.base.actor (base x.base.pre q) q := by
  let m := Message.appendEntriesRequest q
  have start : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0,0]) f t c
      x.base.actor x.base.pre x.event x.base.post x.outputs :=
    ⟨c.post_now,c.post_now,c.post_now,fun old => Bool.noConfusion (fresh.symm.trans ((View.old_post ok.1).mp old)),
      (X.tr_actor_eq ok).symm,(X.tr_pre_eq ok).symm,(X.tr_event_eq ok).symm,
      (X.tr_post_eq ok).symm,(X.outputs_eq ok).symm⟩
  have recv : (reach% step_fromLeader_loop_entries_cons[0,0,0,0,0]) f t c x.base.actor x.base.pre n m :=
    ⟨x.event,x.base.post,x.outputs,start,ev,X.run_for ok ev.symm,initial,X.run_eq ok⟩
  have obs : (reach% step_fromLeader_loop_entries_cons[0,0,0,0]) f t c x.base.actor (observed x.base.pre q) q :=
    ⟨x.base.pre,n,m,recv,fun h => Bool.noConfusion h.1,rfl,fun h => Bool.noConfusion h.1,initial,seen,rfl⟩
  left
  refine ⟨_,obs,fun h => h.elim current (· matching),?_,clear,clear,seen,ready,safe,rfl⟩
  rintro (below | bad)
  · exact Nat.not_lt_of_ge safe below
  · simp [clear] at bad

private theorem branches [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (k : Case) {self st q} (seed : (reach% step_advance_le_total_inl[0,0]) f t c self st q)
    (fr : Direct.CommitFrontier st) (condition : guard k self st q = true) : sig c (column k) := by
  have extended : Direct.CommitFrontier {st with log := st.log ++ extra st q} :=
    fr.extend (List.prefix_append _ _)
  obtain ⟨d,r,v,eq,choices⟩ := Ledger.handleAppendEntiresFromPrimary_eq self st q
  have entered : (reach% step_advance_le_total_inl[0]) f t c st (st.log ++ extra st q) (limit q) :=
    ⟨self,q,seed,d,⟨r,v,eq,choices⟩,r,⟨v,eq,choices⟩,v,⟨eq,choices⟩,eq,choices,fr,rfl,rfl⟩
  have roleEntry : (reach% step_handleAppendEntiresFromPrimary_eq_roleCase__inl[0]) f t c self st q := ⟨seed,fr⟩
  obtain ⟨j,a,b,h,fold,roles,lo,hi⟩ := Ledger.fromLeader_loop self (limit q) (extra st q) st
  let mid := {st with log := st.log ++ extra st q, commitIndex := j, retiredCommittedIndex := a, role := b, primaryKnown := h}
  have midEq : middle self st q = mid := fold
  let stop := max mid.commitIndex (maxCommittableIndexUpTo mid.log (limit q))
  obtain ⟨ar,br,hr,recEq,or'⟩ := Ledger.NodeState.recordCommit_eq self mid stop
  have roleEq : (handleAppendEntiresFromPrimary self st q).1.role = br := by
    change ((middle self st q).recordCommit self (max (middle self st q).commitIndex
      (maxCommittableIndexUpTo (middle self st q).log (limit q)))).role = br
    rw [midEq]
    exact congrArg NodeState.role recEq
  cases k <;> simp only [guard,decide_eq_true_eq] at condition
  case advance => exact ⟨_,_,_,entered,condition.1,condition.2,extended⟩
  case retain => exact ⟨_,_,_,entered,condition.1,condition.2,extended⟩
  case same | retired =>
    left
    refine ⟨_,_,_,roleEntry,j,⟨_,_,_,fold,roles,lo,hi⟩,a,⟨_,_,fold,roles,lo,hi⟩,b,
      ⟨_,fold,roles,lo,hi⟩,h,⟨fold,roles,lo,hi⟩,fold,⟨roles,lo,hi⟩,roles,⟨lo,hi⟩,lo,hi,ar,
      ⟨br,hr,recEq,or'⟩,hr,?_,?_⟩
    first
    | rw [roleEq,midEq] at condition; exact condition ▸ recEq
    | rw [roleEq] at condition; exact condition ▸ recEq
    first | exact .inl trivial | exact .inr trivial

private theorem sound (s : Step) (k : Case) (yes : check s k = true) : label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some] at yes
  split at yes <;> try contradiction
  rename_i n q ev
  simp only [Bool.and_eq_true,decide_eq_true_eq] at yes
  obtain ⟨⟨fresh,initial,seen,ready,current,matchLog,safe,clear⟩,g⟩ := yes
  exact (label_true _ _).mpr ((sig_iff _ _).mpr
    (branches k (accepted ok ev fresh initial seen ready current matchLog safe clear) ready g))

open DeepSchedulesB in
local macro "witness " k:term:arg r:term:arg i:num : term =>
  `(checked (column $k) (DeepSchedulesB.Replay.atStep $r $i) (check · $k)
      (by decide +kernel) (sound · $k))

open DeepSchedulesB in
def certificates : List Certificate :=
  [witness .same firstAck 1,witness .retired retireOnHeartbeat 6,
   witness .advance copyCommit 4,witness .retain doomed 16]

end ConsensusCoverage.AssistAcceptedA
