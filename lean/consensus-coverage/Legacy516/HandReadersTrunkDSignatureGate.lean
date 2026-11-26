module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDSignatureData
import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersElectionRank
import all ConsensusCoverage.HandReadersElectionRankSites
import all ConsensusCoverage.HandReadersAElection
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersOtherTransferSites

namespace ConsensusCoverage.HandReadersTrunkD.Signed

open Consensus Model Model.Node Proofs Safety HandReadersElection HandReadersA SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private abbrev allPairs : Pairs.Test := fun _ _ _ _ _ _ => true

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Gate := ElectStep f t c.actor c.post.currentTerm c.pre.log c.pre.commitIndex ∨ Pairs.Evidence c allPairs

private theorem electionGate {n k l i} (e : ElectStep f t n k l i) : Gate c := by
  obtain ⟨rfl,hl,hi,_,hk,_⟩ := c.electStep e
  exact .inl (by simpa only [hl,hi,hk] using e)

private theorem winGate (w : Wins c.actor c.pre c.event c.post) : Gate c := .inl (c.wins_elect w)

private theorem ticketGate {n st k b i} (h : Pairs.CommitSite c n st k b i) : Gate c := by
  have ticket := (Pairs.ticket_iff c).mp h
  obtain ⟨node,later,log,commit,e,lt,_⟩ := ticket.2.2
  exact .inr ⟨_,_,_,_,_,_,.inr ⟨n,st,node,later,ticket,rfl,e,lt⟩,rfl⟩

theorem rank_partition : step_rankAtGrant_persist_inl f t c ↔ Rank.Evidence c .ahead ∨ Rank.Evidence c .tied := by
  constructor
  · intro h
    repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨v,n,term,r,k,l,i,site,st,_,post,edge,_,_,_,_,_,_,_,_,_,_,sub,_⟩ := h
      have input : RankSites.Input c v n term r k l i := by
        apply RankSites.necessary c
        repeat' first | exact site | exact Or.inl site | apply Or.inr
      obtain high | tie := edge.2.2.2.2.2
      · exact .inl ⟨_,_,_,_,_,_,_,_,_,input,edge.1,edge.2.1,edge.2.2.1,edge.2.2.2.1,edge.2.2.2.2.1,sub,decide_eq_true high⟩
      · exact .inr ⟨_,_,_,_,_,_,_,_,_,input,edge.1,edge.2.1,edge.2.2.1,edge.2.2.2.1,edge.2.2.2.2.1,sub,by simpa [Rank.cut] using tie⟩
  · rintro (h | h)
    all_goals
      obtain ⟨v,n,term,r,k,l,i,st,post,input,pre,now,le,stamp,vote,sub,cut⟩ := h
      have which := RankSites.sufficient c input
      obtain ⟨_,hit,_,seen,_,signed,atI⟩ := input
      have up := Rank.cut_up _ cut
      have edge := And.intro pre (And.intro now (And.intro le (And.intro stamp (And.intro vote up))))
      rcases which with site | site
      all_goals first
        | left; exact ⟨_,_,_,_,_,_,_,site,st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,edge.2.2.2,stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,hit⟩
        | right; left; exact ⟨_,_,_,_,_,_,_,site,st,⟨post,edge⟩,post,edge,pre,edge.2,now,edge.2.2,le,edge.2.2.2,stamp,⟨vote,up⟩,vote,up,sub,seen,signed,atI,hit⟩
end

private meta partial def guard (ticket : Name) (c p h : Expr) : MetaM Expr := do
  if p.getAppFn.constName?.any (fun n=>n.getPrefix == (``step_rankAtGrant_persist_inl).getPrefix && n.getString!.startsWith "reach_") then
    return ←guard ticket c ((←getConstInfo p.getAppFn.constName!).value!.beta p.getAppArgs) h
  HandReadersOther.Transfer.unpack [] p h #[] fun vs=>do
    for v in vs do
      let ty ←inferType v
      if ty.isAppOf ``ElectStep then return ←mkAppM ``electionGate #[c,v]
      if ty.isAppOf ``Wins then return ←mkAppM ``winGate #[c,v]
      if ty.getAppFn.constName? == some ticket then
        return ←mkAppM ``ticketGate #[c,v]
    for v in vs do
      let ty ←inferType v
      if ty.getAppFn.constName?.any (fun name=>name.getPrefix == (``step_rankAtGrant_persist_inl).getPrefix && name.getString!.startsWith "reach_") then
        return ←guard ticket c ((←getConstInfo ty.getAppFn.constName!).value!.beta ty.getAppArgs) v
    throwError "historical signed branch without a finite election or commit ticket"

run_cmd liftTermElabM do
  let n := ``NonRanking
  let ticket ←ReachPath.resolve (←`(reachPath|step_core_covered_pos[0,0]))
  lambdaTelescope (←getConstInfo n).value! fun xs p=>do
    withLocalDeclD `h (mkAppN (mkConst n) xs) fun h=>do
      let dst ←mkAppM ``Gate #[xs[3]!]
      let v←mkLambdaFVars (xs.push h) (←mkExpectedTypeHint (←guard ticket xs[3]! p h) dst)
      addDecl (.thmDecl {name:=(`ConsensusCoverage.HandReadersTrunkD.Signed)++`nonRankingGate,levelParams:=[],type:=←inferType v,value:=v})

def gate : Reader := fun cfg pre act post hist=> Election.reader cfg pre act post hist ||
  Pairs.reader allPairs cfg pre act post hist

theorem gateAt (s : ActionProfile.Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    gate s.cfg s.before s.act s.after s.past = true ↔ Gate s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [gate,Bool.or_eq_true,Pairs.reader_iff]
  apply or_congr_left
  rw [show Election.reader = Election.exactReader.eval from rfl,←Election.exactReader.eq_label s,ActionProfile.label_true,
    ActionProfile.holds,sig_iff]
  exact Election.iff_election s.context

end ConsensusCoverage.HandReadersTrunkD.Signed
