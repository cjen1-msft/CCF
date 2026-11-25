module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.QueueSamplesA
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.ReadersAtoms
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepRankingCases

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open Ledger
open ReadersAtoms GuardedDomain ActionProfile QueueSamplesA

set_option maxRecDepth 8192

inductive Case where | retained | lost | ahead | tied | older | same | positive | equal | short

def column : Case → Classes.StepBranch
  | .retained => .rankAtGrant_persist_inl
  | .lost => .rankAtGrant_persist_inr
  | .ahead => .rankAtGrant_up_to_date_inl
  | .tied => .rankAtGrant_up_to_date_inr
  | .older => .rankAtGrant_term_inl
  | .same => .rankAtGrant_term_inr
  | .positive => .termAt_mono_eq_zero_or_pos_inr
  | .equal => .termAt_mono_eq_or_lt_of_le_inl
  | .short => .termAt_mono_eq_or_lt_of_le_inr

private def request (x : XView) : RequestVoteRequest :=
  match x.event with
  | .receive _ (.requestVoteRequest r) => r
  | _ => LogFacts.requestAt x.base.post.currentTerm x.base.post.log x.base.post.commitIndex

private def mode (k : Case) (st : NodeState) (r : RequestVoteRequest) (o : Observation) (i : Nat) : Prop :=
  let sub := o.log.take i <+: st.log
  let eq := r.lastCommittableTerm = maxCommittableTerm st.log ∧ r.lastCommittableIndex ≥ maxCommittableIndex st.log
  match k with
  | .retained | .positive => sub
  | .lost => ¬sub
  | .ahead => sub ∧ r.lastCommittableTerm > maxCommittableTerm st.log
  | .tied => sub ∧ eq
  | .older => sub ∧ eq ∧ o.currentTerm < maxCommittableTerm st.log
  | .same => sub ∧ eq ∧ o.currentTerm = maxCommittableTerm st.log
  | .equal => sub ∧ i = maxCommittableIndex st.log
  | .short => sub ∧ i < maxCommittableIndex st.log

private instance (k : Case) (st : NodeState) (r : RequestVoteRequest) (o : Observation) (i : Nat) :
    Decidable (mode k st r o i) := by cases k <;> unfold mode <;> infer_instance

private def test (x : XView) (k : Case) (i : Nat) : Bool :=
  let v := x.base.actor
  let st := x.base.pre
  let w := x.base.post
  let n := w.votedFor.getD 0
  let t := w.currentTerm
  let r := request x
  let before := x.base.before :: x.base.past
  decide (grantedIn (x.base.after :: before) v n t r = true ∧
    ¬grantedIn before v n t r = true ∧ st.currentTerm ≤ t ∧ w.votedFor = some n ∧ voteLogUpToDate st r) &&
  (observations before v).any fun o =>
    decide (o.currentTerm < t ∧ isSignatureAt o.log i = true ∧ termAt o.log i = o.currentTerm ∧ mode k st r o i)

private def check (s : Step) (k : Case) (i : Nat) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any (test · k i)

local macro "grant_fields " v:term:arg n:term:arg t:term:arg r:term:arg o:term:arg i:term:arg
    root:term:arg st:term:arg w:term:arg before:term:arg now:term:arg le:term:arg
    voted:term:arg up:term:arg : tactic =>
  `(tactic| refine ⟨$v,$n,$t,$r,($o).currentTerm,($o).log,$i,$root,$st,
      ⟨$w,$before,$now,$le,rfl,$voted,$up⟩,$w,⟨$before,$now,$le,rfl,$voted,$up⟩,$before,
      ⟨$now,$le,rfl,$voted,$up⟩,$now,⟨$le,rfl,$voted,$up⟩,$le,⟨rfl,$voted,$up⟩,rfl,
      ⟨$voted,$up⟩,$voted,$up,?_⟩)

theorem sound (s : Step) (k : Case) (i : Nat) (okTest : check s k i = true) :
    label s (.step (column k)) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨x,made,ok⟩ := ofXAction_matches s
  simp only [check,made,Option.any_some,test,Bool.and_eq_true,decide_eq_true_eq,List.any_eq_true] at okTest
  obtain ⟨⟨post,fresh,le,vote,up⟩,o,mem,lt,sig_,atI,h⟩ := okTest
  let st := x.base.pre
  let w := x.base.post
  let v := x.base.actor
  let n := w.votedFor.getD 0
  let t := w.currentTerm
  let r := request x
  have preMem : (v,st) ∈ s.frame.current.nodes := by
    dsimp only [v,st]
    rw [← View.actor_eq ok.1,← View.pre_eq ok.1]; exact c.pre_now
  have postMem : (v,w) ∈ s.after.nodes := by
    dsimp only [v,w]
    rw [← View.actor_eq ok.1,← View.post_eq ok.1]; exact c.post_now
  have g := (X.grant_after ok v n t r).mpr post
  have ng := fun h' => fresh ((X.grant_before ok v n t r).mp h')
  have gRoot : (reach% step_rankAtGrant_persist_inl[0,0]) _ _ c v n t r := ⟨⟨g,ng⟩,g⟩
  obtain ⟨p,eq,real_,sup⟩ := g.resolve_left ng
  obtain rfl : s.frame.current = p := Option.some.inj eq
  have seen := (X.seen_before ok v o.currentTerm o.log).mpr mem
  have stamp := (c.grantFactsBefore v n t r g).1.1
  have root : (reach% step_rankAtGrant_persist_inl[0]) _ _ c v n t r o.currentTerm o.log i := by
    refine ⟨t,gRoot,⟨_,rfl,real_,sup⟩,_,⟨rfl,real_,sup⟩,rfl,⟨real_,sup⟩,real_,sup,
      rfl,.rfl,real_,st,⟨w,preMem,postMem,le,rfl,vote,up⟩,w,⟨preMem,postMem,le,rfl,vote,up⟩,
      preMem,⟨postMem,le,rfl,vote,up⟩,postMem,⟨le,rfl,vote,up⟩,le,⟨rfl,vote,up⟩,
      rfl,⟨vote,up⟩,vote,up,_,.inl seen,lt,sig_,atI,seen,g,stamp,rfl,rfl⟩
  have kept (sub : o.log.take i <+: st.log) := isSignatureAt_of_prefix sub
    (isSignatureAt_take_of_le Nat.le.refl sig_)
  have within : i ≤ (o.log.take i).length := Nat.le_of_eq (List.length_take_of_le (signature_bound sig_)).symm
  have pos := signature_pos sig_
  have sorted := c.inv.sorted v st preMem
  have maxBound := maxCommittableIndexBounded st.log
  have from_ (sub : o.log.take i <+: st.log) := signatureIndex_le_maxCommittableIndex (kept sub)
  have mono (sub : o.log.take i <+: st.log) := termAt_mono sorted (from_ sub) maxBound
  have rank (sub : o.log.take i <+: st.log) : o.currentTerm ≤ maxCommittableTerm st.log := by
    have fact := mono sub
    rwa [termAt_of_prefix sub within,termAt_take Nat.le.refl,atI] at fact
  apply (label_true s _).mpr
  apply (sig_iff c _).mpr
  cases k with
  | retained | lost | ahead | tied | older | same =>
    left
    grant_fields v n t r o i root st w preMem postMem le vote up
    first
    | exact ⟨h,seen,sig_,atI,real_⟩
    | exact ⟨(c.inv.persist v st o i preMem seen sig_).resolve_left h,seen,sig_,atI,real_⟩
    | exact ⟨h.1,rank h.1,h.2,real_,seen,sig_,atI,within,kept h.1,from_ h.1,mono h.1⟩
    | exact ⟨h.1,rank h.1,h.2,h.2.1,h.2.2,real_,seen,sig_,atI,within,kept h.1,from_ h.1,mono h.1⟩
    | exact ⟨h.1,rank h.1,h.2.1,h.2.1.1,h.2.1.2,h.2.2,real_,seen,sig_,atI,within,
        kept h.1,from_ h.1,mono h.1⟩
  | positive | equal | short =>
    have sub : o.log.take i <+: st.log := by first | exact h | exact h.1
    have caller : (reach% step_termAt_mono_eq_zero_or_pos_inr[0]) _ _ c st.log i (maxCommittableIndex st.log) := by
      refine ⟨v,n,t,r,_,_,root,st,⟨w,preMem,postMem,le,rfl,vote,up⟩,w,
        ⟨preMem,postMem,le,rfl,vote,up⟩,preMem,⟨postMem,le,rfl,vote,up⟩,postMem,
        ⟨le,rfl,vote,up⟩,le,⟨rfl,vote,up⟩,rfl,⟨vote,up⟩,vote,up,sub,seen,sig_,atI,within,
        kept sub,from_ sub,real_,rfl,rfl⟩
    left
    first
    | exact ⟨_,_,_,caller,pos,from_ sub,maxBound,sorted⟩
    | exact ⟨_,_,_,caller,pos,h.2,from_ sub,maxBound,sorted⟩
    | exact ⟨_,_,h.2.symm ▸ caller,pos,Nat.le_refl _,h.2.symm ▸ maxBound,sorted⟩

open FrontierRows DeepSchedules in
local macro "rank_at " k:term:arg sc:term:arg offset:num i:num : term =>
  `(checked (column $k) (selected $sc (by unfold Run.valid; decide) $offset)
    (check · $k $i) (by decide +kernel) (sound · $k $i))

open DeepSchedules in
def certificates : List Certificate :=
  [rank_at .retained divergent 7 2,rank_at .lost lossGrant 18 3,rank_at .ahead (threeTerms false) 17 2,
   rank_at .tied divergent 7 2,rank_at .older (threeTerms true) 19 2,rank_at .same divergent 7 2,
   rank_at .positive divergent 7 2,rank_at .equal divergent 7 2,rank_at .short (threeTerms true) 19 2]

end ConsensusCoverage.DeepRankingCases
