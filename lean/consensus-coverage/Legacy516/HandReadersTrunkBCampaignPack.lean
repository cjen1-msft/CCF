module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor

namespace ConsensusCoverage.HandReadersTrunkB.CampaignRows

open Consensus Model Model.Node Proofs Safety SolvedWitnesses
open Lean Meta Elab Command

set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

run_cmd liftTermElabM do
  HandReadersTrunkBFactor.query ``step_campaign_summary_result_inr
    `ConsensusCoverage.HandReadersTrunkB.CampaignRows.CampaignCall

abbrev Effect := NodeID → NodeState → NodeState → NodeState → Event → List Model.Envelope → Prop

private def onCandidate (p : NodeID → NodeState → NodeState → Event → List Model.Envelope → Prop) : Effect :=
  fun self pre cand next ev sent => next = cand ∧ p self pre cand ev sent

private theorem pinNext (r : Effect) (p : NodeID → NodeState → NodeState → Event → List Model.Envelope → Prop) :
    (∃ n b c e s, r n b c c e s ∧ p n b c e s) ↔
    ∃ n b c a e s, r n b c a e s ∧ onCandidate p n b c a e s :=
  ⟨fun ⟨n,b,c,e,s,src,h⟩ => ⟨n,b,c,c,e,s,src,rfl,h⟩,
    fun ⟨n,b,c,_,e,s,src,rfl,h⟩ => ⟨n,b,c,e,s,src,h⟩⟩

private theorem pushOr (r p q : Effect) :
    (∃ n b c a e s, r n b c a e s ∧ (p n b c a e s ∨ q n b c a e s)) ↔
    (∃ n b c a e s, r n b c a e s ∧ p n b c a e s) ∨ ∃ n b c a e s, r n b c a e s ∧ q n b c a e s := by
  constructor
  · rintro ⟨n,b,c,a,e,s,src,l | h⟩
    · exact .inl ⟨n,b,c,a,e,s,src,l⟩
    · exact .inr ⟨n,b,c,a,e,s,src,h⟩
  · rintro (⟨n,b,c,a,e,s,src,l⟩ | ⟨n,b,c,a,e,s,src,h⟩)
    · exact ⟨n,b,c,a,e,s,src,.inl l⟩
    · exact ⟨n,b,c,a,e,s,src,.inr h⟩

meta section

private partial def binders (p : Expr) (xs : Array Expr) : MetaM (Name × Expr × Bool) := do
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `x (p.getArg! 0) fun x => binders (p.appArg!.beta #[x]) (xs.push x)
  unless p.isAppOf ``And do throwError "unguarded campaign"
  let r := (p.getArg! 0).getAppFn.constName!
  let k ← mkLambdaFVars xs p.appArg!
  if xs.size == 5 then return (r, ←mkAppM ``onCandidate #[k],true)
  unless xs.size == 6 do throwError "unexpected campaign arguments"
  return (r,k,false)

private def disjoin (ps : List Expr) : MetaM Expr := do
  forallTelescopeReducing (←inferType ps.head!) fun xs _ => do
    let vals := ps.map (·.beta xs)
    mkLambdaFVars xs (vals.dropLast.foldr (fun a b => mkApp2 (mkConst ``Or) a b) vals.getLast!)

private def pack (n : Name) : MetaM Unit := do
  lambdaTelescope (←getConstInfo n).value! fun xs body => do
    let arms := (HandReadersBFactor.disjuncts body).toArray
    let base ← lambdaTelescope (←getConstInfo ``step_campaign_summary_result_inr).value! fun _ b =>
      pure (HandReadersBFactor.disjuncts b).length
    let batches := arms.size / base
    unless batches * base == arms.size do throwError "misaligned campaign origins"
    let guards ← (List.range batches).mapM fun j => do
      let (_,g,_) ← binders arms[j*base]! #[]
      return g
    let name := (`ConsensusCoverage.HandReadersTrunkB.CampaignRows.Packed).str n.getString!
    let clean ← disjoin guards
    addDecl (.defnDecl {
      name, levelParams := [], type := mkConst ``Effect
      value := clean, hints := .abbrev, safety := .safe})
    let lhs := mkAppN (mkConst n) xs
    let rhs := mkAppN (mkConst ``CampaignCall) (xs.push (mkConst name))
    let some expanded ← unfoldDefinition? rhs | throwError "opaque campaign"
    let origins := (HandReadersBFactor.disjuncts expanded).toArray
    let mut bridges := #[]
    for i in [:base] do
      let mut row := #[]
      for j in [:batches] do
        let (r,g,pin) ← binders arms[j*base+i]! #[]
        unless ←isDefEq g guards[j]! do throwError "nonuniform local campaign guard"
        let src := mkAppN (mkConst r) xs
        let bridge ← if pin then mkAppM ``pinNext #[src,g.appArg!]
          else pure (mkApp (mkConst ``Iff.rfl) arms[j*base+i]!)
        row := row.push bridge
      bridges := bridges.push row
    let mut fws := #[]
    for h : j in [:arms.size] do
      let i := j % base
      let k := j / base
      let f ← withLocalDeclD `h arms[j] fun v => do
        let val ←mkAppM ``Iff.mp #[bridges[i]![k]!,v]
        let (r,_,_) ← binders arms[j] #[]
        let src := mkAppN (mkConst r) xs
        let rec intoRow (idx : Nat) (gs : List Expr) (v : Expr) : MetaM Expr := do
          match gs with
          | g::j'::rest =>
            let right ← disjoin (j'::rest)
            let eq ← mkAppM ``pushOr #[src,g,right]
            let p := (←inferType eq).appArg!
            let branch ← if idx == 0 then mkAppOptM ``Or.inl #[none,some p.appArg!,some v]
              else mkAppOptM ``Or.inr #[some (p.getArg! 0),none,some (←intoRow (idx-1) (j'::rest) v)]
            mkAppM ``Iff.mpr #[eq,branch]
          | _ => pure v
        let val ←intoRow k guards val
        mkLambdaFVars #[v] (←HandReadersBFactor.into expanded val i base)
      fws := fws.push f
    let fw ←withLocalDeclD `h lhs fun h => do
      mkLambdaFVars #[h] (←HandReadersBFactor.outOf body h rhs fws.toList)
    let mut bws := #[]
    for h : i in [:base] do
      let (r,_,_) ← binders arms[i]! #[]
      let src := mkAppN (mkConst r) xs
      let f ← withLocalDeclD `h origins[i]! fun v => do
        let emit (j : Nat) (v : Expr) := do
          let val ←mkAppM ``Iff.mpr #[bridges[i]![j]!,v]
          HandReadersBFactor.into body val (j*base+i) arms.size
        let rec fromRow (gs : List Expr) (j : Nat) (v : Expr) : MetaM Expr := do
          match gs with
          | g::g'::rest =>
            let eq ←mkAppM ``pushOr #[src,g,←disjoin (g'::rest)]
            let p := (←inferType eq).appArg!
            let a ←withLocalDeclD `l (p.getArg! 0) fun l => do mkLambdaFVars #[l] (←emit j l)
            let b ←withLocalDeclD `r p.appArg! fun r => do mkLambdaFVars #[r] (←fromRow (g'::rest) (j+1) r)
            return ConsensusCoverage.ProofWalk.casesOr p (←mkAppM ``Iff.mp #[eq,v]) lhs a b
          | _ => emit j v
        mkLambdaFVars #[v] (←fromRow guards 0 v)
      bws := bws.push f
    let bw ←withLocalDeclD `h rhs fun h => do
      mkLambdaFVars #[h] (←HandReadersBFactor.outOf expanded h lhs bws.toList)
    addDecl (.thmDecl {
      name := (`ConsensusCoverage.HandReadersTrunkB.CampaignRows.PackIff).str n.getString!
      levelParams := [],type := ←mkForallFVars xs (←mkAppM ``Iff #[lhs,rhs])
      value := ←mkLambdaFVars xs (←mkAppM ``Iff.intro #[fw,bw])})
end

run_cmd liftTermElabM do
  for n in [``step_campaign_summary_result_inl,``step_campaign_summary_result_inr,
      ``step_campaign_summary_campaign_inl,``step_campaign_summary_campaign_inr,``step_campaign_summary_role_inl,
      ``step_campaign_summary_started_inl,``step_campaign_summary_started_inr_inl,``step_campaign_summary_started_inr_inr] do
    pack n

end ConsensusCoverage.HandReadersTrunkB.CampaignRows
