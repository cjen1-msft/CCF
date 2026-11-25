module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model.Node
import all ConsensusCoverage.HandReadersAObserve
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElectionB.Frontier

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger SolvedWitnesses
open AssistReplyA HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

private abbrev W (pre : NodeState) (q : AppendEntriesRequest) := prepared (observed pre q) q
private abbrev B (pre : NodeState) (q : AppendEntriesRequest) : NodeState := { W pre q with primaryKnown := true }
private abbrev Pass (pre : NodeState) (q : AppendEntriesRequest) :=
  let w := W pre q
  ¬(q.term < w.currentTerm ∨ ¬appendEntryMatchesLog w q) ∧
    ¬(q.prevLogIndex < w.commitIndex ∨ (firstTermConflictIndex (B pre q) q).isSome ∧ !w.isNewFollower)
@[expose] public def adjusted (pre : NodeState) (q : AppendEntriesRequest) : NodeState :=
  let z := observeTerm pre (.appendEntriesRequest q)
  let w := if q.term = z.currentTerm ∧ (z.role = .candidate ∨ z.role = .preVoteCandidate) then
    becomeAwareOfNewTerm z q.term else z
  let b := {w with primaryKnown := true}
  match firstTermConflictIndex b q with
  | none => b
  | some j => {b with log := b.log.take (j-1),isNewFollower := false}

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private abbrev Named (self : NodeID) (z : NodeState) (q : AppendEntriesRequest) :=
  (reach% step_maxCommittableIndexBounded_values_cons[15,0,0,0,0]) f t c self z q
private abbrev Erased (z : NodeState) (q : AppendEntriesRequest) :=
  (reach% step_maxCommittableIndexBounded_values_nil[15,0,0,0,0]) f t c z q
private abbrev FromLeader (self : NodeID) (z : NodeState) (q : AppendEntriesRequest) :=
  (reach% step_maxCommittableIndexBounded_values_cons[15,0,0,0]) f t c self z q

private theorem seen (q : AppendEntriesRequest) : Direct.CommitFrontier (observed c.pre q) :=
  (c.inv.frontier _ _ c.pre_now).of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)

private theorem ready (q : AppendEntriesRequest) : Direct.CommitFrontier (W c.pre q) := by
  unfold W prepared
  split <;> exact (seen c q).of_log rfl rfl

private theorem reduced {z q} (h : Erased c z q) :
    ¬Now f c.actor c.post ∧ ∃ src, c.event = .receive src (.appendEntriesRequest q) ∧ z = observed c.pre q := by
  obtain ⟨self,st,src,_,rcv,_,rfl,_,_,_,rfl⟩ := h
  obtain ⟨fresh,_,rfl,ev⟩ := (Observe.receive_iff c).mp rcv
  exact ⟨fresh,src,ev,rfl⟩

private theorem named {z q self} (h : Named c self z q) :
    self = c.actor ∧ ¬Now f c.actor c.post ∧ ∃ src, c.event = .receive src (.appendEntriesRequest q) ∧ z = observed c.pre q := by
  obtain ⟨st,src,_,rcv,_,rfl,_,_,_,rfl⟩ := h
  obtain ⟨fresh,id,rfl,ev⟩ := (Observe.receive_iff c).mp rcv
  exact ⟨id,fresh,src,ev,rfl⟩

private theorem both {src q} (fresh : ¬Now f c.actor c.post) (ev : c.event = .receive src (.appendEntriesRequest q)) :
    Named c c.actor (observed c.pre q) q ∧ Erased c (observed c.pre q) q := by
  have rcv := (Observe.receive_iff c).mpr ⟨fresh,rfl,rfl,ev⟩
  have direct : Named c c.actor (observed c.pre q) q := ⟨c.pre,src,_,rcv,fun h => Bool.noConfusion h.1,rfl,
    fun h => Bool.noConfusion h.1,c.inv.frontier _ _ c.pre_now,seen c q,rfl⟩
  exact ⟨direct,c.actor,direct⟩

private abbrev Good (q : AppendEntriesRequest) := ¬Now f c.actor c.post ∧
  (∃ src, c.event = .receive src (.appendEntriesRequest q)) ∧ Pass c.pre q

theorem erased_iff : (reach% step_maxCommittableIndexBounded_values_nil[15,0,0,0]) f t c ↔
    ∃ q, ¬Now f c.actor c.post ∧ (∃ src, c.event = .receive src (.appendEntriesRequest q)) ∧ Pass c.pre q := by
  constructor
  · rintro (⟨z,q,o,a,p,_⟩ | ⟨z,q,o,a,p,_⟩) <;>
      obtain ⟨fresh,src,ev,rfl⟩ := reduced c o <;> exact ⟨q,fresh,⟨src,ev⟩,a,p⟩
  · rintro ⟨q,fresh,⟨src,ev⟩,a,p⟩
    have o := (both c fresh ev).2
    have safe : (W c.pre q).commitIndex ≤ q.prevLogIndex := Nat.le_of_not_lt fun lt => p (.inl lt)
    cases eq : firstTermConflictIndex (B c.pre q) q with
    | none => exact .inl ⟨_,q,o,a,p,eq,eq,seen c q,ready c q,safe⟩
    | some j => exact .inr ⟨_,q,o,a,p,j,eq,eq,seen c q,ready c q,safe,firstTermConflictIndex_ge eq⟩

private theorem named_iff {self st q} : FromLeader c self st q ↔
    Good c q ∧ self = c.actor ∧ st = adjusted c.pre q := by
  constructor
  · rintro (⟨z,o,a,p,eq,_,_,_,_,rfl⟩ | ⟨z,o,a,p,j,eq,_,_,_,_,_,rfl⟩)
    all_goals
      obtain ⟨id,fresh,src,ev,rfl⟩ := named c o
      exact ⟨⟨fresh,⟨src,ev⟩,a,p⟩,id,by simp only [adjusted,eq]⟩
  · rintro ⟨⟨fresh,⟨src,ev⟩,a,p⟩,rfl,rfl⟩
    have o := (both c fresh ev).1
    have safe : (W c.pre q).commitIndex ≤ q.prevLogIndex := Nat.le_of_not_lt fun lt => p (.inl lt)
    cases eq : firstTermConflictIndex (B c.pre q) q with
    | none => exact .inl ⟨_,o,a,p,eq,eq,seen c q,ready c q,safe,by simp only [adjusted,eq]⟩
    | some j => exact .inr ⟨_,o,a,p,j,eq,eq,seen c q,ready c q,safe,firstTermConflictIndex_ge eq,
        by simp only [adjusted,eq]⟩

private theorem valid {q} (h : Good c q) : Direct.CommitFrontier (adjusted c.pre q) := by
  have safe : (W c.pre q).commitIndex ≤ q.prevLogIndex := Nat.le_of_not_lt fun lt => h.2.2.2 (.inl lt)
  cases eq : firstTermConflictIndex (B c.pre q) q with
  | none =>
    simp only [adjusted,eq]
    exact (ready c q).of_log rfl rfl
  | some j =>
    simp only [adjusted,eq]
    have ge := firstTermConflictIndex_ge eq
    exact ((ready c q).keep (count := j-1) (Nat.le_trans safe (Nat.le_sub_of_add_le ge)) (suffix := [])).of_log
      (by simp) rfl

private abbrev resultLog (st : NodeState) (q : AppendEntriesRequest) :=
  st.log ++ q.entries.drop (st.log.length-q.prevLogIndex)

theorem log_iff {log limit} : (reach% step_maxCommittableIndexBounded_values_cons[15,0]) f t c log limit ↔
    ∃ q, (¬Now f c.actor c.post ∧ (∃ src, c.event = .receive src (.appendEntriesRequest q)) ∧ Pass c.pre q) ∧
      log = resultLog (adjusted c.pre q) q ∧ limit = min q.primaryCommit (q.prevLogIndex + q.entries.length) := by
  constructor
  · rintro ⟨st,⟨self,q,src,rest⟩,_⟩
    obtain ⟨good,_,rfl⟩ := (named_iff c).mp src
    refine ⟨q,good,?_,?_⟩
    all_goals
      repeat' first | exact rest | exact rest.1
                    | change _ ∧ _ at rest; obtain ⟨_,rest⟩ := rest
                    | change Exists _ at rest; obtain ⟨_,rest⟩ := rest
  · rintro ⟨q,good,rfl,rfl⟩
    let st := adjusted c.pre q
    obtain ⟨ret,role,known,eq,roles⟩ := handleAppendEntiresFromPrimary_eq c.actor st q
    have src := (named_iff c).mpr ⟨good,rfl,rfl⟩
    have front := valid c good
    refine ⟨st,⟨c.actor,q,src,ret,⟨role,known,eq,roles⟩,role,⟨known,eq,roles⟩,known,⟨eq,roles⟩,
      eq,roles,front,rfl,rfl⟩,?_⟩
    exact front.extend (List.prefix_append _ _)

theorem last_iff (log : List Entry) : (reach% step_maxCommittableIndexBounded_values_cons[15]) f t c log ↔
    ∃ q, ¬Now f c.actor c.post ∧ (∃ src, c.event = .receive src (.appendEntriesRequest q)) ∧ Pass c.pre q ∧
      log = (resultLog (adjusted c.pre q) q).take (min q.primaryCommit (q.prevLogIndex + q.entries.length)) := by
  constructor
  · rintro ⟨raw,limit,call,rfl⟩
    obtain ⟨q,⟨changed,ev,ok⟩,rfl,rfl⟩ := (log_iff c).mp call
    exact ⟨q,changed,ev,ok,rfl⟩
  · rintro ⟨q,changed,ev,ok,rfl⟩
    exact ⟨_,_,(log_iff c).mpr ⟨q,⟨changed,ev,ok⟩,rfl,rfl⟩,rfl⟩

theorem scan_iff (P : List Entry → Prop) :
    (∃ log, (reach% step_maxCommittableIndexBounded_values_cons[15]) f t c log ∧ P log) ↔
    ∃ q, ¬Now f c.actor c.post ∧ (∃ src, c.event = .receive src (.appendEntriesRequest q)) ∧ Pass c.pre q ∧
      P ((resultLog (adjusted c.pre q) q).take (min q.primaryCommit (q.prevLogIndex + q.entries.length))) := by
  constructor
  · rintro ⟨_,hit,p⟩
    obtain ⟨q,ch,ev,ok,rfl⟩ := (last_iff c _).mp hit
    exact ⟨q,ch,ev,ok,p⟩
  · rintro ⟨q,ch,ev,ok,p⟩
    exact ⟨_,(last_iff c _).mpr ⟨q,ch,ev,ok,rfl⟩,p⟩

end
end ConsensusCoverage.HandReadersElectionB.Frontier
