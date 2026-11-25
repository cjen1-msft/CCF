module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionGrant
import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.DeepRankingCases
import all ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.Rank

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open ActionProfile SolvedWitnesses HandReadersA ReadersAtoms ReadersShapes GuardedDomain
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

inductive Kind where | ahead | tied | older | same

def column : Kind → Classes.StepBranch
  | .ahead => .rankAtGrant_up_to_date_inl
  | .tied => .rankAtGrant_up_to_date_inr
  | .older => .rankAtGrant_term_inl
  | .same => .rankAtGrant_term_inr

def cut (kind : Kind) (st : NodeState) (r : RequestVoteRequest) (k : Nat) : Bool :=
  let t := maxCommittableTerm st.log
  let tied := r.lastCommittableTerm == t && decide (maxCommittableIndex st.log ≤ r.lastCommittableIndex)
  match kind with
  | .ahead => decide (t < r.lastCommittableTerm)
  | .tied => tied
  | .older => tied && decide (k < t)
  | .same => tied && (k == t)

def view (kind : Kind) (x : XView) (pick : NodeState → Nat → Bool := fun _ _ => true) : Bool :=
  let hist := x.base.before :: x.base.past
  let elect := electionExact x.base.after x.base.before x.base.past x.base.actor
    x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex
  let req := LogFacts.requestAt x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex
  let candidates := replayRequests (requestHistory x)
  x.base.before.nodes.any fun (v,st) => x.base.after.nodes.any fun (w,post) =>
    decide (v = w ∧ st.currentTerm ≤ post.currentTerm) && post.votedFor.any fun n =>
      Grant.checkSide .recorded v n ((observations hist n).any (·.currentTerm == post.currentTerm)) &&
      (observations hist v).any fun o => decide (o.currentTerm < post.currentTerm) &&
        (signatureIndices o.log).any fun i =>
          (pick st i && decide (termAt o.log i = o.currentTerm ∧ o.log.take i <+: st.log)) &&
          ((elect && decide (n = x.base.actor ∧ post.currentTerm = x.base.post.currentTerm) &&
            cut kind st req o.currentTerm) ||
          candidates.any fun r => cut kind st r o.currentTerm && !grantedIn hist v n post.currentTerm r)

def reader (kind : Kind) : Reader := fun cfg before act after past =>
  (ofXAction cfg before after past act).any (view kind)

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Evidence (kind : Kind) := ∃ v n term r k l i st post,
  RankSites.Input c v n term r k l i ∧
  (v,st) ∈ f.current.nodes ∧ (v,post) ∈ t.nodes ∧ st.currentTerm ≤ term ∧
  post.currentTerm = term ∧ post.votedFor = some n ∧ l.take i <+: st.log ∧ cut kind st r k = true

omit [Config.InitialConfiguration] in
private theorem cut_up (kind) {st r k} (h : cut kind st r k = true) : voteLogUpToDate st r := by
  cases kind <;> simp only [cut, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at h
  all_goals first | exact .inl h | exact .inr h | exact .inr h.1

set_option maxHeartbeats 2000000 in
private theorem necessary (kind : Kind) (h : sig c (column kind)) : Evidence c kind := by
  cases kind
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    obtain ⟨v,n,term,r,k,l,i,site,st,_,post,edge,_,_,_,_,_,_,_,_,_,_,sub,_,mode⟩ := h
    refine ⟨v,n,term,r,k,l,i,st,post,RankSites.necessary c ?_,edge.1,edge.2.1,edge.2.2.1,
      edge.2.2.2.1,edge.2.2.2.2.1,sub,?_⟩
    · repeat' first | exact site | exact Or.inl site | apply Or.inr
    · simp only [cut,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq]
      first | exact mode.1 | exact ⟨mode.1,mode.2.2.2.1⟩

private theorem sufficient (kind : Kind) (h : Evidence c kind) : sig c (column kind) := by
  obtain ⟨v,n,term,r,k,l,i,st,post,input,pre,now,le,termEq,vote,sub,guard⟩ := h
  have which := RankSites.sufficient c input
  obtain ⟨_,hit,_,seen,_,signed,atI⟩ := input
  have up := cut_up kind guard
  have edge := And.intro pre (And.intro now (And.intro le (And.intro termEq (And.intro vote up))))
  have kept := isSignatureAt_of_prefix sub (isSignatureAt_take_of_le Nat.le.refl signed)
  have within := Nat.le_of_eq (List.length_take_of_le (signature_bound signed)).symm
  have maxIdx := signatureIndex_le_maxCommittableIndex kept
  have mono := termAt_mono (c.inv.sorted v st pre) maxIdx (maxCommittableIndexBounded _)
  have rank : k ≤ maxCommittableTerm st.log := by
    rwa [termAt_of_prefix sub within,termAt_take Nat.le.refl,atI] at mono
  cases kind <;> rcases which with site | site
  all_goals
    first
    | left; refine ⟨v,n,term,r,k,l,i,site,?_⟩
    | right; left; refine ⟨v,n,term,r,k,l,i,site,?_⟩
    refine ⟨st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,edge.2.2.2,termEq,⟨vote,up⟩,
      vote,up,sub,rank,?_⟩
    simp only [cut,Bool.and_eq_true,decide_eq_true_eq,beq_iff_eq] at guard
    first
    | exact ⟨guard,hit,seen,signed,atI,within,kept,maxIdx,mono⟩
    | exact ⟨guard,guard.1,guard.2,hit,seen,signed,atI,within,kept,maxIdx,mono⟩
    | exact ⟨guard.1,guard.1.1,guard.1.2,guard.2,hit,seen,signed,atI,within,kept,maxIdx,mono⟩

private theorem fresh_iff {x : XView} (ok : x.Matches c) (kind : Kind) {v n k a : Nat} {st : NodeState}
    (mem : (v,st) ∈ f.current.nodes) :
    (replayRequests (requestHistory x)).any (fun r => cut kind st r a &&
      !grantedIn (x.base.before :: x.base.past) v n k r) = true ↔
      ∃ r, cut kind st r a = true ∧ ¬f.logs.grant v n k r := by
  have m := (X.before_eq ok) ▸ mem
  have hist : (v,st) ∈ histNodes (requestHistory x) := mem_histNodes (by simp [requestHistory]) m
  have kt : maxCommittableTerm st.log ∈ requestTerms (requestHistory x) :=
    List.mem_append_left _ (List.mem_map_of_mem (f := fun (_,s) => maxCommittableTerm s.log) hist)
  have ki : maxCommittableIndex st.log ∈ requestIndices (requestHistory x) :=
    List.mem_append_left _ (List.mem_map_of_mem (f := fun (_,s) => maxCommittableIndex s.log) hist)
  have equiv (r : RequestVoteRequest) : cut kind st r a = true ↔
      cut kind st (replayRequestRep (requestHistory x) r) a = true := by
    have ⟨_,lt,eq⟩ := cutRep_same r.lastCommittableTerm kt
    have ⟨le,_,_⟩ := cutRep_same r.lastCommittableIndex ki
    cases kind <;> simp only [cut,replayRequestRep,requestRep,Bool.and_eq_true,beq_iff_eq,
      decide_eq_true_eq,eq_comm (a := r.lastCommittableTerm),eq_comm (a := cutRep _ _),lt,eq,le]
  rw [replayRequests_bound (history := requestHistory x) (P := fun r =>
    cut kind st r a = true ∧ ¬f.logs.grant v n k r) (fun r =>
      and_congr (equiv r) (not_congr (request_grant_before ok v n k r).symm))]
  simp only [List.any_eq_true,Bool.and_eq_true,Bool.not_eq_true',Bool.eq_false_iff,X.grant_before ok]

abbrev Selected (kind : Kind) (pick : NodeState → Nat → Bool) := ∃ v n term r k l i st post,
  RankSites.Input c v n term r k l i ∧
  (v,st) ∈ f.current.nodes ∧ (v,post) ∈ t.nodes ∧ st.currentTerm ≤ term ∧
  post.currentTerm = term ∧ post.votedFor = some n ∧ l.take i <+: st.log ∧ cut kind st r k = true ∧ pick st i

theorem selected_iff {x : XView} (ok : x.Matches c) (kind : Kind) (pick : NodeState → Nat → Bool) :
    view kind x pick = true ↔ Selected c kind pick := by
  have elect : Grant.Election c ↔ electionExact x.base.after x.base.before x.base.past x.base.actor
      x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex = true := by
    simp only [Grant.Election,X.elect_now ok,View.actor_eq ok.1,View.pre_eq ok.1,View.post_eq ok.1,true_and]
  have req : Grant.Request c = LogFacts.requestAt x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex := by
    simp only [Grant.Request,View.post_eq ok.1,View.pre_eq ok.1]
  have before := congrArg (·.nodes) (X.before_eq ok)
  have after := congrArg (·.nodes) (X.after_eq ok)
  simp only [view,List.any_eq_true (p := fun _ : NodeID × NodeState => _),Prod.exists,
    Bool.and_eq_true,decide_eq_true_eq,Option.any_eq_true,Bool.or_eq_true,Grant.side_iff c ok,
    ← elect,← req,List.any_eq_true (p := fun _ : Observation => _),List.any_eq_true (p := fun _ : Nat => _),
    ← sig_index]
  simp only [← before,← after,← View.actor_eq ok.1,← View.post_eq ok.1]
  constructor
  · rintro ⟨v,st,m,_,post,m',⟨rfl,le⟩,n,vote,side,⟨a,l⟩,seen,lt,i,signed,⟨pass,atI,sub⟩,route⟩
    have obs := (X.seen_before ok ..).mpr seen
    rcases route with ⟨⟨win,hn,ht⟩,guard⟩ | fresh
    · exact ⟨v,n,_,_,a,l,i,st,post,⟨.inr ⟨win,hn,ht,rfl⟩,⟨st,post,m,m',le,rfl,vote,cut_up _ guard⟩,
        side,obs,lt,signed,atI⟩,m,m',le,rfl,vote,sub,guard,pass⟩
    · obtain ⟨r,guard,ng⟩ := (fresh_iff c ok kind m).mp fresh
      exact ⟨v,n,_,r,a,l,i,st,post,⟨.inl ng,⟨st,post,m,m',le,rfl,vote,cut_up _ guard⟩,
        side,obs,lt,signed,atI⟩,m,m',le,rfl,vote,sub,guard,pass⟩
  · rintro ⟨v,n,term,r,a,l,i,st,post,⟨route,_,sup,obs,lt,signed,atI⟩,m,m',le,rfl,vote,sub,guard,pass⟩
    refine ⟨v,st,m,v,post,m',⟨rfl,le⟩,n,vote,sup,⟨a,l⟩,(X.seen_before ok ..).mp obs,lt,
      i,signed,⟨pass,atI,sub⟩,?_⟩
    rcases route with ng | ⟨elect,eq,term,rfl⟩
    · exact .inr ((fresh_iff c ok kind m).mpr ⟨r,guard,ng⟩)
    · exact .inl ⟨⟨elect,eq,term⟩,guard⟩

private theorem view_iff {x : XView} (ok : x.Matches c) (kind : Kind) :
    view kind x = true ↔ Evidence c kind := by
  rw [selected_iff c ok]
  simp only [Selected,Evidence,and_true]
end

def exactReader (kind : Kind) : Exact (column kind) where
  eval := reader kind
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [reader,made,Option.any_some,view_iff s.context ok,label_true,holds,sig_iff]
    exact ⟨necessary s.context kind,sufficient s.context kind⟩

end ConsensusCoverage.HandReadersElection.Rank
