module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCVoteRoute
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkCExtension
import all ConsensusCoverage.HandReadersTrunkCRoleStrict
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.VoteSites

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkB ActionProfile
open Lean Meta Elab Command

set_option maxRecDepth 16384
set_option maxHeartbeats 1500000

-- Keep the two deterministic middle-state inputs separate from the four
-- campaign continuations, which also bind a candidate and an election result.
run_cmd liftTermElabM do
  for (n,pre,ca) in [( ``HandReadersBFactor.Tail.step_votedFor_advance_inl,`BaseId,`CampId),
      (``HandReadersBFactor.Tail.step_votedFor_advance_inr,`BaseStrict,`CampStrict)] do
    lambdaTelescope (←getConstInfo n).value! fun xs p => do
      let arms := HandReadersBFactor.disjuncts p
      unless arms.length == 6 do throwError "unexpected vote projection routes"
      for (name,ls) in [(pre,arms.take 2),(ca,arms.drop 2)] do
        let v ←mkLambdaFVars xs (HandReadersTrunkA.Factor.disj ls)
        addDecl (.defnDecl {
          name := `ConsensusCoverage.HandReadersTrunkC.VoteSites ++ name,levelParams := [],type := ←inferType v
          value := v,hints := .abbrev,safety := .safe })

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Base (k : Bool) := if k then BaseStrict f t c else BaseId f t c
private abbrev Camp (k : Bool) := if k then CampStrict f t c else CampId f t c
private abbrev Voted := ∃ v, c.pre.votedFor = some v

private theorem baseUpper (k : Bool) : Base c k → Match.test k c.actor c.pre c.event c.post ∧ Voted c := by
  cases k <;> rintro (batch | response)
  case false.inl =>
    obtain ⟨_,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,v,vote,_⟩,_⟩ := batch
    refine ⟨?_,v,vote⟩
    rw [show c.event = .internal (.append xs) from ev]; simp [Match.test,Match.Grow]
  case true.inl =>
    obtain ⟨_,m,_,⟨_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_,primary,_,_,app,_,batch,_,_,_,_,_,_,_,_,_,_,_,_,
      _,v,vote,_,_,_,_,_,eq⟩,strict,_⟩ := batch
    subst m
    refine ⟨?_,v,vote⟩
    rw [show c.event = .internal (.append xs) from ev]
    obtain ⟨⟨es,si,eq,_⟩,_⟩ := batch
    exact decide_eq_true fun _ => Extension.normalize c primary es si app eq (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1)
  case false.inr =>
    obtain ⟨_,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,leader,yes,stamp,_,_,_,_,_,v,vote,_⟩,_⟩ := response
    refine ⟨?_,v,vote⟩
    rw [show c.event = .receive src (.appendEntriesResponse r) from ev]
    exact decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),by simpa using leader,
      yes,stamp,by simp [Match.Grow]⟩
  case true.inr =>
    obtain ⟨_,m,_,⟨_,src,r,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,pass,_,_,_,leader,yes,stamp,_,_,_,_,_,v,vote,_,_,eq⟩,strict,_⟩ := response
    subst m
    refine ⟨?_,v,vote⟩
    rw [show c.event = .receive src (.appendEntriesResponse r) from ev]
    exact decide_eq_true ⟨Classical.byContradiction (fun no => pass ⟨trivial,no⟩),by simpa using leader,
      yes,stamp,fun _ => strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1⟩

local macro "batch_vote " site:ident v:ident voted:ident : tactic => `(tactic|
  (obtain ⟨_,xs,call,g,p,gn,g',app,sent,b,later,pair,a,packs,b1,b2,es,ex,si,ex',eq,terms,_,_,_,start,term,log,role,le,meq⟩ := $site:term
   obtain ⟨ev,id,rest⟩ := call
   obtain ⟨self,pre,event⟩ := id
   exact ⟨_,xs,⟨ev,⟨self,pre,event⟩,rest⟩,g,p,gn,g',app,sent,b,later,pair,a,packs,b1,b2,es,ex,si,ex',eq,terms,
     term,$v,by rw [pre]; exact $voted,start,term,log,role,le,meq⟩))

local macro "ack_vote " site:ident v:ident voted:ident : tactic => `(tactic|
  (obtain ⟨_,src,r,call,pass,obs,lo,stable,primary,yes,same,sent,nom,a,msgs,_,_,term,quiet,no,meq⟩ := $site:term
   obtain ⟨ev,⟨self,pre,event⟩,rest⟩ := call
   exact ⟨_,src,r,⟨ev,⟨self,pre,event⟩,rest⟩,pass,obs,lo,stable,primary,yes,same,sent,nom,a,msgs,
     term,$v,by rw [pre]; exact $voted,quiet,no,meq⟩))

private theorem baseLower (k : Bool) (good : Match.test k c.actor c.pre c.event c.post) (voted : Voted c) : Base c k := by
  obtain ⟨v,hv⟩ := voted
  have h := (Match.tail_iff c k).mpr good
  cases k
  · rcases h with ⟨n,m,site,a⟩ | ⟨n,m,site,a⟩
    · left; refine ⟨n,m,?_,a⟩; batch_vote site v hv
    · right; refine ⟨n,m,?_,a⟩; ack_vote site v hv
  · rcases h with ⟨n,m,post,site,strict,a⟩ | ⟨n,m,post,site,strict,a⟩
    · left; refine ⟨n,m,post,?_,strict,a⟩; batch_vote site v hv
    · right; refine ⟨n,m,post,?_,strict,a⟩; ack_vote site v hv

local macro "campaign_pre " h:ident : tactic => `(tactic|
  first
  | (obtain ⟨⟨_,⟨_,pre,_⟩,_⟩,_⟩ := $h:term; exact pre)
  | (obtain ⟨_,_,⟨_,⟨_,pre,_⟩,_⟩,_⟩ := $h:term; exact pre)
  | (obtain ⟨_,⟨_,⟨_,pre,_⟩,_⟩,_⟩ := $h:term; exact pre))

private theorem noStrict (h : Camp c true) : False := by
  rcases h with h | h | h | h
  all_goals
    obtain ⟨_,m,_,⟨pre,cand,_,_,call,_,_,_,_,_,_,_,_,camp,_,_,_,_,_,_,_,_,_,meq⟩,strict,_⟩ := h
    exact RoleSites.campaign c (by campaign_pre call) camp meq
      (strict.2.2.2.2.2.2.2.1 ▸ strict.2.2.2.2.2.2.1)

private theorem strictIff : HandReadersBFactor.Tail.step_votedFor_advance_inr f t c ↔
    Match.test true c.actor c.pre c.event c.post ∧ Voted c := by
  change (_ ∨ _ ∨ Camp c true) ↔ _
  rw [←or_assoc,or_iff_left (noStrict c)]
  exact ⟨baseUpper c true, fun ⟨g,v⟩ => baseLower c true g v⟩

end

def strict : Exact .votedFor_advance_inr where
  eval := fun cfg pre act post past => (Match.reader true).eval cfg pre act post past &&
    actorRead (fun _ st _ _ => st.votedFor.isSome) cfg pre act post past
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff]
    change step_votedFor_advance_inr _ _ _ ↔ (SummaryRows.gated _ _ _ _ _ _ && actorRead _ _ _ _ _ _) = true
    rw [HandReadersTrunkA.Factor.Split.step_votedFor_advance_inr_iff,
      HandReadersBFactor.Exact.step_votedFor_advance_inr _ _ _ (HandReadersBGate.quiet s),strictIff,
      Bool.and_eq_true,SummaryRows.gated,Bool.and_eq_true,actorRead_at,actorRead_at,HandReadersBGate.live,
      Option.isSome_iff_exists]
    change (_ ∧ _ ∧ ∃ _, _) ↔ (_ ∧ _) ∧ ∃ _, _
    grind

end ConsensusCoverage.HandReadersTrunkC.VoteSites
