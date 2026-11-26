module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.DeepHandlerCases
import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepAcceptedCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ReadersAtoms GuardedDomain SolvedWitnesses ActionProfile QueueSamplesA

set_option maxRecDepth 8192

private instance (a b : NodeState) (r : AppendEntriesRequest) : Decidable (Accepted a r b) := by
  unfold Accepted
  infer_instance

private def Aligned (a b : List Entry) : Prop :=
  ∀ j, 0 < j → j ≤ a.length → j ≤ b.length → termAt a j = termAt b j → a.take j = b.take j

private theorem origin [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
    {v : NodeID} {r : AppendEntriesRequest} (changed : ¬ Now f c.actor c.post)
    (ev : c.event = .receive v (.appendEntriesRequest r)) (accepted : Accepted c.pre r c.post) :
    ∃ l, (reach% step_acceptLog_eq_conflict_none[0]) f t c c.pre.log l r ∧
      r.prevLogIndex ≤ l.length ∧ c.pre.log.take r.prevLogIndex = l.take r.prevLogIndex ∧
      r.entries <+: l.drop r.prevLogIndex ∧ Aligned c.pre.log l := by
  have inner : (reach% step_acceptLog_eq_conflict_none[0,0,1]) f t c c v r :=
    ⟨⟨c.post_now,changed,rfl⟩,c.post_now,c.post_now,ev,accepted,Subsingleton.elim _ _,
      c.post_now,(fun h => ⟨⟨_,h⟩,fun _ _ => h⟩),rfl⟩
  have caller : (reach% step_acceptLog_eq_conflict_none[0,0]) f t c c v r := .inr ⟨inner,ev,accepted,rfl⟩
  obtain ⟨env,ok,src,tgt,msg⟩ := c.received_ok ev
  obtain ⟨l,info⟩ := c.accept_shape ev accepted
  obtain ⟨evidence,bound,_,_,prev⟩ := info
  obtain ⟨ne,led,canon,ps,term,entries,back⟩ := id evidence
  have aligned : Aligned c.pre.log l := by
    intro j pos left right same
    obtain ⟨a,ca,la,ea⟩ := c.inv.anchor _ _ j c.pre_now pos left
    obtain ⟨b,cb,lb,eb⟩ := (c.inv.copyLog canon).anchor j pos right
    rw [same] at ca
    rw [ea,eb]
    exact take_eq_take_of_comparable (c.inv.chains _ _ _ ca cb) la lb
  have a := accepted
  obtain ⟨_,_,_,pf,_,logEq,_⟩ := a
  have shape := acceptLog_eq pf ps prev entries aligned
  rw [← logEq] at shape
  have packet := And.intro ok (And.intro src (And.intro tgt msg))
  refine ⟨l,?_,ps,prev,entries,aligned⟩
  split at shape <;> rename_i same
  all_goals
    first
    | have _ : c.pre.log.take (r.prevLogIndex+r.entries.length) = l.take (r.prevLogIndex+r.entries.length) := same
      left
    | right
    exact ⟨v,caller,env,packet,ok,packet.2,src,packet.2.2,tgt,msg,evidence,ne,led,canon,ps,term,entries,back,
      accepted.1,accepted.2,accepted.2.1,accepted.2.2,accepted.2.2.1,accepted.2.2.2,pf,
      accepted.2.2.2.2,accepted.2.2.2.2.1,accepted.2.2.2.2.2,logEq,accepted.2.2.2.2.2.2,
      same,ev,accepted,bound,aligned,prev,shape,rfl⟩

inductive Case where | none | some | empty | nonempty | fits | extend | tip | overlaps

def column : Case → Classes.StepBranch
  | .none => .acceptLog_eq_conflict_none
  | .some => .acceptLog_eq_conflict_some
  | .empty => .acceptLog_eq_eq_zero_or_pos_inl
  | .nonempty => .acceptLog_eq_eq_zero_or_pos_inr
  | .fits => .acceptLog_eq_long_pos
  | .extend => .acceptLog_eq_long_neg
  | .tip => .acceptLog_eq_eq_or_lt_of_le_inl
  | .overlaps => .acceptLog_eq_eq_or_lt_of_le_inr

private def guard (k : Case) (a : List Entry) (r : AppendEntriesRequest) : Prop :=
  match k with
  | .some => conflictIndex a r = some 3
  | .none | .empty => conflictIndex a r = none
  | .nonempty => conflictIndex a r = none ∧ r.prevLogIndex+r.entries.length ≤ a.length ∧ 0 < r.entries.length
  | .fits => conflictIndex a r = none ∧ r.prevLogIndex+r.entries.length ≤ a.length
  | .extend => conflictIndex a r = none ∧ ¬r.prevLogIndex+r.entries.length ≤ a.length
  | .tip => conflictIndex a r = none ∧ ¬r.prevLogIndex+r.entries.length ≤ a.length ∧ r.prevLogIndex = a.length
  | .overlaps => conflictIndex a r = none ∧ ¬r.prevLogIndex+r.entries.length ≤ a.length ∧ r.prevLogIndex < a.length

private instance (k : Case) (a : List Entry) (r : AppendEntriesRequest) : Decidable (guard k a r) :=
  by cases k <;> unfold guard <;> infer_instance

private def check (s : Step) (k : Case) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let r := DeepHandlerCases.request x.event
    decide (x.base.changed = true ∧ x.event = .receive (DeepHandlerCases.sender x.event) (.appendEntriesRequest r) ∧
      Accepted x.base.pre r x.base.post ∧ guard k x.base.pre.log r)

theorem sound (s : Step) (k : Case) (passed : check s k = true) : label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,decide_eq_true_eq] at passed
  obtain ⟨changed,ev,acc,cnd⟩ := passed
  rw [← View.pre_eq ok.1,← View.post_eq ok.1] at acc
  rw [← View.pre_eq ok.1] at cnd
  let r := DeepHandlerCases.request x.event
  have event := (X.event_eq ok).trans ev
  have fresh : ¬ Now s.frame c.actor c.post := fun h =>
    Bool.noConfusion (changed.symm.trans ((View.old_post ok.1).mp h))
  obtain ⟨l,root,ps,prev,entries,aligned⟩ := origin c fresh event acc
  have pf : r.prevLogIndex ≤ c.pre.log.length := acc.2.2.2.1
  have eq_ := List.prefix_iff_eq_take.mp entries
  have bound : r.prevLogIndex+r.entries.length ≤ l.length := Nat.add_le_of_le_sub' ps
    (Nat.le_trans entries.length_le (Nat.le_of_eq List.length_drop))
  have take : l.take (r.prevLogIndex+r.entries.length) = l.take r.prevLogIndex ++ r.entries := by
    rw [List.take_add,← eq_]
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | none | some =>
    left
    first
    | exact ⟨_,l,r,root,r.term,r.prevLogIndex,r.prevLogTerm,r.entries,r.primaryCommit,pf,ps,prev,entries,
        cnd,cnd,pf,prev,aligned,eq_,bound,take,ps,entries⟩
    | exact ⟨_,l,r,root,r.term,r.prevLogIndex,r.prevLogTerm,r.entries,r.primaryCommit,pf,ps,prev,entries,
        3,cnd,cnd,pf,prev,aligned,eq_,bound,take,ps,entries⟩
  | empty =>
    iterate 14 right
    left
    have no_ : conflictIndex c.pre.log ⟨0,0,0,[],0⟩ = none := by simp [conflictIndex]
    exact ⟨_,l,r,root,0,0,0,[],0,Nat.zero_le _,Nat.zero_le _,rfl,by simp,no_,no_,Nat.zero_le _,
      rfl,pf,prev,aligned,rfl,Nat.zero_le _,rfl,by simp,by simp,ps,entries⟩
  | nonempty | fits | extend | tip | overlaps =>
    have none_ : conflictIndex c.pre.log r = none := cnd.1
    have absent := Option.map_eq_none_iff.mp none_
    have overlap (offset : Nat) (lt : offset < r.entries.length) (inf : r.prevLogIndex+offset < c.pre.log.length) :
        (c.pre.log[r.prevLogIndex+offset]).term =
          (l[r.prevLogIndex+offset]'(Nat.lt_of_lt_of_le (Nat.add_lt_add_left lt _) bound)).term := by
      have member : ((c.pre.log[r.prevLogIndex+offset],r.entries[offset]),r.prevLogIndex+1+offset)
          ∈ ((c.pre.log.drop r.prevLogIndex).zip r.entries).zipIdx (r.prevLogIndex+1) := by
        apply List.mem_iff_getElem.mpr
        refine ⟨offset,?_,?_⟩
        · simp only [List.length_zipIdx,List.length_zip,List.length_drop]
          exact Nat.lt_min.mpr ⟨Nat.lt_sub_iff_add_lt'.mpr inf,lt⟩
        simp
      have same := List.find?_eq_none.mp absent _ member
      simp only [Bool.not_eq_true,bne_eq_false_iff_eq] at same
      rw [same]
      congr 1
      rw [List.getElem_of_eq eq_]
      simp [r]
    first
    | iterate 14 right
      left
      exact ⟨_,l,r,root,r.term,r.prevLogIndex,r.prevLogTerm,r.entries,r.primaryCommit,pf,ps,prev,entries,none_,none_,
        cnd.2.1,cnd.2.2,pf,prev,aligned,eq_,bound,take,absent,overlap,ps,entries⟩
    | left
      exact ⟨_,l,r,root,r.term,r.prevLogIndex,r.prevLogTerm,r.entries,r.primaryCommit,pf,ps,prev,entries,none_,none_,
        cnd.2,pf,prev,aligned,eq_,bound,take,absent,overlap,ps,entries⟩
    | left
      have differ : c.pre.log.take (r.prevLogIndex+r.entries.length) ≠ l.take (r.prevLogIndex+r.entries.length) := by
        intro same
        have lengths := congrArg List.length same
        rw [List.length_take,List.length_take,Nat.min_eq_left bound] at lengths
        exact cnd.2.1 (lengths ▸ Nat.min_le_right _ _)
      first
      | exact ⟨_,l,r,root,r.term,r.prevLogIndex,r.prevLogTerm,r.entries,r.primaryCommit,pf,ps,prev,entries,none_,none_,
          cnd.2.1,cnd.2.2,pf,prev,aligned,eq_,bound,take,absent,overlap,differ,ps,entries⟩
      | have eq : r.prevLogIndex = c.pre.log.length := cnd.2.2
        have short_ : ¬r.prevLogIndex+r.entries.length ≤ c.pre.log.length := cnd.2.1
        have beyond : ¬c.pre.log.length+r.entries.length ≤ c.pre.log.length := by rwa [eq] at short_
        refine ⟨_,l,r,root,r.term,r.prevLogTerm,r.entries,r.primaryCommit,Nat.le_refl _,?_,?_,?_,?_,?_,?_,
          pf,prev,aligned,?_,?_,?_,?_,?_,?_,ps,entries⟩
        all_goals first | exact beyond | simpa only [← eq] using ps | simpa only [← eq] using prev
                        | simpa only [← eq] using entries | simpa only [← eq] using none_
                        | simpa only [← eq] using cnd.2.1 | simpa only [← eq] using eq_
                        | simpa only [← eq] using bound | simpa only [← eq] using take
                        | simpa only [← eq] using absent | simpa only [← eq] using differ
                        | intro off _ outside; omega

open FrontierRows DeepSchedules in
private def overlapAt (wake : Bool) : Option Step := do
  let timeouts : List FrontierRows.Command := if wake then [.input 1 (.timeout .election)] else []
  let r := { overlappingBatch with schedule := overlappingBatch.schedule.take 5 ++ timeouts ++ [.deliver 0 1] }
  let picks := if wake then [(1,1),(4,1)] else [(1,1)]
  let steps ← JointWitnesses.recordedAt r (by change overlappingBatch.valid; unfold Run.valid; decide) picks
  return (← steps.getLast?).val

open FrontierRows DeepSchedules in
local macro "accept_at " k:term:arg sc:term:arg i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $i)
    (check · $k) (by decide +kernel) (sound · $k))

open DeepSchedules in
def certificates : List Certificate :=
  [accept_at .none installLater 1,accept_at .some divergent 11,accept_at .empty installLater 1,
   checked (column .nonempty) (overlapAt true) (check · .nonempty) (by decide +kernel) (sound · .nonempty),
   accept_at .fits installLater 8,accept_at .extend installLater 1,accept_at .tip installLater 1,
   checked (column .overlaps) (overlapAt false) (check · .overlaps) (by decide +kernel) (sound · .overlaps)]

end ConsensusCoverage.DeepAcceptedCases
