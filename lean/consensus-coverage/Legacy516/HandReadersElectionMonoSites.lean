module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.ReachPath
public meta import Lean
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersElection.MonoSites

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger
open HandReadersA SolvedWitnesses
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

open Lean Meta Elab Term in
local elab "monoSites% " a:term:arg* : term => do
  let root := ``step_termAt_mono_eq_zero_or_pos_inr
  let names := ReachPath.children root.getPrefix (← getConstInfo root).value!
  let mut arms := #[]
  for site in names do
    let name := mkIdent site
    arms := arms.push (← elabTerm (← `($name $a*)) (some (.sort .zero)))
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

abbrev Sites (log : List Entry) (i j : Nat) := monoSites% f t c log i j
abbrev Campaign := sig c .campaign_votes_campaign_inl
abbrev Ranked (log : List Entry) (i j : Nat) := ∃ v n term r k l st post,
  RankSites.Input c v n term r k l i ∧
  (v,st) ∈ f.current.nodes ∧ (v,post) ∈ t.nodes ∧ st.currentTerm ≤ term ∧
  post.currentTerm = term ∧ post.votedFor = some n ∧ voteLogUpToDate st r ∧
  l.take i <+: st.log ∧ log = st.log ∧ j = maxCommittableIndex st.log

private theorem frontier : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
  obtain zero | pos := Nat.eq_zero_or_pos c.pre.commitIndex
  · rw [zero]; exact Nat.zero_le _
  · exact signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 pos)

local macro "along " h:term : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

omit [Config.InitialConfiguration] in
private theorem no_short {l log : List Entry} {k j t : Nat}
    (hi : t < termAt log k) (short : k < j) (len : (l.take j).length = j)
    (atJ : termAt (l.take j) j = t) (atK : termAt (l.take j) k = termAt log k)
    (sorted : (l.take j).Pairwise (fun a b => a.term ≤ b.term)) : False := by
  have mono := termAt_mono sorted (Nat.le_of_lt short) (Nat.le_of_eq len.symm)
  rw [atK,atJ] at mono
  exact Nat.not_le_of_gt hi mono

set_option maxHeartbeats 2500000 in
theorem necessary {log i j} (h : Sites c log i j) : Ranked c log i j ∨
    Campaign c ∧ log = c.pre.log ∧ i = maxCommittableIndex c.pre.log ∧ j = i := by
  repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨v,n,term,r,k,l,site,st,_,post,edge,_,_,_,_,_,_,_,_,_,_,sub,rest⟩ := h
      refine .inl ⟨v,n,term,r,k,l,st,post,RankSites.necessary c ?_,edge.1,edge.2.1,edge.2.2.1,
        edge.2.2.2.1,edge.2.2.2.2.1,edge.2.2.2.2.2,sub,by along rest,by along rest⟩
      repeat' first | exact site | exact Or.inl site | apply Or.inr
    | obtain ⟨g,n,k,b,later,d,bound,idx,l,r,_,rest⟩ := h
      apply False.elim
      apply no_short (l := l) (log := r) (k := max d (maxCommittableIndex r)) (j := j) (t := k) <;> along rest
    | obtain ⟨st,⟨parent,_,_,rfl⟩,_,_,rfl,rfl,rfl⟩ := h
      refine .inr ⟨?_,rfl,rfl,Nat.max_eq_right (frontier c)⟩
      obtain ⟨cand,src,role,logAlt,log,commitAlt,commit,alts,fresh,active,parts,incr,token,vote,vs,
        _,_,camp,termEq,voteEq,_,_⟩ := parent
      repeat' first
        | exact ⟨cand,src,role,logAlt,log,commitAlt,commit,alts,fresh,active,parts,incr,token,vote,vs,camp,termEq,voteEq⟩
        | exact .inl ⟨cand,src,role,logAlt,log,commitAlt,commit,alts,fresh,active,parts,incr,token,vote,vs,camp,termEq,voteEq⟩
        | apply Or.inr

theorem campaign_site (h : Campaign c) :
    (reach% step_termAt_mono_eq_zero_or_pos_inr[11]) f t c c.pre.log (maxCommittableIndex c.pre.log) (maxCommittableIndex c.pre.log) ∨
    (reach% step_termAt_mono_eq_zero_or_pos_inr[12]) f t c c.pre.log (maxCommittableIndex c.pre.log) (maxCommittableIndex c.pre.log) := by
  obtain ⟨yes,here⟩ := CampaignRows.necessary c true true h
  obtain ⟨cand,camp,term,vote,src⟩ := CampaignRows.supply c true here
  obtain ⟨role,log,commit,alts⟩ := id camp
  have fresh := alts.resolve_right fun other => by
    have lt := of_decide_eq_true yes
    have same := other.2.1
    omega
  have all := And.intro log (And.intro commit alts)
  have mem : c.actor ∈ cand.votesGranted := fresh.2.2.2 ▸ CCF.Finset.mem_singleton.mpr rfl
  rcases src with src | src
  · left; right
    refine ⟨c.pre,⟨?_,c.term_le,vote.trans fresh.2.2.1,rfl⟩,c.pre_sorted,c.frontier_pre,rfl,rfl,(Nat.max_eq_right (frontier c)).symm⟩
    exact ⟨cand,src,role,all,log,all.2,commit,alts,fresh,fresh.1,fresh.2,fresh.2.1,fresh.2.2,fresh.2.2.1,
      fresh.2.2.2,c.actor,mem,camp,term,vote,rfl,term⟩
  · right
    refine ⟨c.pre,⟨?_,c.term_le,vote.trans fresh.2.2.1,rfl⟩,c.pre_sorted,c.frontier_pre,rfl,rfl,(Nat.max_eq_right (frontier c)).symm⟩
    exact ⟨cand,src,role,all,log,all.2,commit,alts,fresh,fresh.1,fresh.2,fresh.2.1,fresh.2.2,fresh.2.2.1,
      fresh.2.2.2,c.actor,mem,camp,term,vote,rfl,term⟩
end

end ConsensusCoverage.HandReadersElection.MonoSites
