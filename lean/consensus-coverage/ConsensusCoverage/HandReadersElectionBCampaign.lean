module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersACampaign
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReachPath
public meta import ConsensusCoverage.PinnedClasses
public meta import Lean

namespace ConsensusCoverage.HandReadersElectionB.Campaign

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
set_option maxRecDepth 16384
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

local macro "spine " h:ident : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

open Lean Meta Elab Command Term in
local elab "factorCampaigns" : command => liftTermElabM do
  let nil := ``step_maxCommittableIndexBounded_values_nil
  let cons := ``step_maxCommittableIndexBounded_values_cons
  let votes := ``step_campaign_votes_campaign_inl
  let deps := fun n => do return ReachPath.children votes.getPrefix (←getConstInfo n).value!
  let vs ←deps votes
  for q in [nil,cons] do
    for a in ←deps q do
      for b in ←deps a do
        for n in ←deps b do
          let children ←deps n
          unless children.size == 1 && vs.contains children[0]! do continue
          let parent := children[0]!
          let i := vs.idxOf parent
          if i == 0 then continue
          let branches ←deps parent
          lambdaTelescope (←getConstInfo n).value! fun xs _ => do
            let ctx := xs.extract 0 4
            let c := xs[3]!
            let stem := ctx.push c
            let guard := fun k => mkAppN (Lean.mkConst k) stem
            let origin := branches.pop.foldr (fun ch p => mkApp2 (Lean.mkConst ``Or) (guard ch) p)
              (guard branches.back!)
            let pre ←mkAppM ``Ctx.pre #[c]
            let post ←mkAppM ``Ctx.post #[c]
            let k ←mkAppM ``NodeState.currentTerm #[post]
            let lt ←mkAppM ``LT.lt #[←mkAppM ``NodeState.currentTerm #[pre],k]
            let won ←mkAppM ``Wins #[←mkAppM ``Ctx.actor #[c],pre,←mkAppM ``Ctx.event #[c],post]
            let data := ctx ++ (if q == nil then #[] else #[c,k])
            let ty ← mkAppM ``Iff #[mkAppN (Lean.mkConst n) data,
              mkApp2 (Lean.mkConst ``And) origin (mkApp2 (Lean.mkConst ``And) won lt)]
            let pr ← `(by
              unfold $(mkIdent n):ident
              constructor
              · rintro ⟨cand,site,_,_,_,_,_,_,_,_,_,inc,_,_,_,v,_,camp,term,_⟩
                unfold $(mkIdent parent):ident at site
                repeat' (change _ ∨ _ at site; rcases site with site | site)
                all_goals
                  refine ⟨?_,by spine site,?_⟩
                  · first | exact site.1 | exact Or.inl site.1 | exact Or.inr site.1
                  · omega
              · rintro ⟨origin,win,lt⟩
                obtain ⟨cand,pack⟩ := Wins.facts win
                obtain ⟨camp,q,log,term,voted,matched,role,le⟩ := id pack
                obtain ⟨r,l,d,alt⟩ := id camp
                have ⟨floor,phase⟩ := Ctx.campaign_three _ camp
                have fresh := alt.resolve_right fun old => by have := old.2.1; omega
                obtain ⟨v,m⟩ := HandReadersA.CampaignRows.voter_of_quorum q
                refine ⟨cand,?_,r,⟨l,d,alt⟩,l,⟨d,alt⟩,d,alt,fresh,fresh.1,fresh.2,
                  fresh.2.1,fresh.2.2,fresh.2.2.1,fresh.2.2.2,v,m,camp,term,?_⟩
                · unfold $(mkIdent parent):ident
                  all_goals first
                    | assumption
                    | exact ⟨origin,pack,camp,pack.2,q,pack.2.2,log,pack.2.2.2,term,pack.2.2.2.2,voted,
                        pack.2.2.2.2.2,matched,pack.2.2.2.2.2.2,role,le,r,l,d,alt,floor,phase,v,m,win,rfl⟩
                    | rcases origin with origin | origin
                      · left; repeat' first | assumption | rfl | exact ⟨v,m,win,rfl⟩ | apply And.intro
                      · right; repeat' first | assumption | rfl | exact ⟨v,m,win,rfl⟩ | apply And.intro
                · first | exact voted | exact ⟨voted,rfl,term⟩)
            let g ←mkFreshExprSyntheticOpaqueMVar ty
            let `(term| by $tac:tacticSeq) := pr | throwUnsupportedSyntax
            let goals ←Tactic.run g.mvarId! <| Tactic.withoutRecover (Tactic.evalTactic tac)
            unless goals.isEmpty do throwError "campaign {i}: {←goals[0]!.getType}"
            let name := ((`ConsensusCoverage.HandReadersElectionB.Campaign).str
              (if q == nil then "erased" else "named")).appendIndexAfter i
            addDecl (.thmDecl {
              name,levelParams := [],type := ←mkForallFVars ctx ty,value := ←mkLambdaFVars ctx (←instantiateMVars g) })

set_option maxHeartbeats 2500000 in
factorCampaigns

end ConsensusCoverage.HandReadersElectionB.Campaign
