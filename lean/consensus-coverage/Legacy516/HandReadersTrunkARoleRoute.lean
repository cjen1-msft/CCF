module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersTrunkA.Request

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses AssistReplyA
open Lean Meta Elab Command

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev At (p : NodeID → NodeID → NodeState → AppendEntriesRequest → Prop) :=
  ∃ src q, c.event = .receive src (.appendEntriesRequest q) ∧ p c.actor src (observed c.pre q) q

private theorem four (p : NodeID → NodeID → NodeState → AppendEntriesRequest → Prop) :
    (∃ n src z q, Call f t c n src z q ∧ p n src z q) ↔ At c p := by
  constructor
  · rintro ⟨n,src,z,q,co,h⟩
    obtain ⟨rfl,ev,rfl⟩ := (call_iff c _ _ _ _).mp co
    exact ⟨src,q,ev,h⟩
  · rintro ⟨src,q,ev,h⟩
    exact ⟨_,src,_,q,(call_iff c _ _ _ _).mpr ⟨rfl,ev,rfl⟩,h⟩

private theorem eitherAt (p q : NodeID → NodeID → NodeState → AppendEntriesRequest → Prop) :
    At c p ∨ At c q ↔ At c (fun n src z r => p n src z r ∨ q n src z r) := by
  constructor
  · rintro (⟨src,r,ev,h⟩ | ⟨src,r,ev,h⟩)
    · exact ⟨src,r,ev,.inl h⟩
    · exact ⟨src,r,ev,.inr h⟩
  · rintro ⟨src,r,ev,h | h⟩
    · exact .inl ⟨src,r,ev,h⟩
    · exact .inr ⟨src,r,ev,h⟩
end

run_cmd liftTermElabM do
  HandReadersBFactor.compile ``step_aeReply_role_inl
  let name := HandReadersBFactor.factorName ``step_aeReply_role_inl
  lambdaTelescope (←getConstInfo name).value! fun xs p => do
    let a := (HandReadersBFactor.disjuncts p)[2]!
    withLocalDeclD `z (a.getArg! 0) fun z => do
      let b := a.appArg!.beta #[z]
      withLocalDeclD `q (b.getArg! 0) fun q => do
        let value ← mkLambdaFVars (xs ++ #[z,q]) ((b.appArg!.beta #[q]).getArg! 0)
        addDecl (.defnDecl {
          name := `ConsensusCoverage.HandReadersTrunkA.Request.CallTwo,levelParams := []
          type := ←inferType value,value,hints := .abbrev,safety := .safe })

private theorem two [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (p : NodeState → AppendEntriesRequest → Prop) :
    (∃ z q, CallTwo f t c z q ∧ p z q) ↔ At c (fun _ _ z q => p z q) := by
  constructor
  · rintro ⟨z,q,(⟨_,⟨_,⟨rfl,rfl⟩,src,_,ev,_,rfl⟩,obs,_,_,rfl⟩ |
      ⟨⟨_,⟨rfl,rfl⟩,src,_,ev,_,rfl⟩,_,stable⟩),h⟩
    · refine ⟨src,q,ev,?_⟩
      change p (observeTerm c.tr.pre (.appendEntriesRequest q)) q
      rwa [obs.2]
    · refine ⟨src,q,ev,?_⟩
      change p (observeTerm c.tr.pre (.appendEntriesRequest q)) q
      rwa [stable]
  · rintro ⟨src,q,ev,h⟩
    refine ⟨_,q,?_,h⟩
    obtain raised | stable := observe_bumping c.pre (message := .appendEntriesRequest q) trivial
    · exact .inl ⟨_,⟨_,⟨rfl,rfl⟩,src,_,ev,ev,rfl⟩,raised,raised.1,raised.2,raised.2⟩
    · rw [show observed c.pre q = _ from stable.2]
      exact .inr ⟨⟨_,⟨rfl,rfl⟩,src,_,ev,ev,rfl⟩,stable.1,stable.2⟩

meta def localRole (n : Name) := (`ConsensusCoverage.HandReadersTrunkA.Request.Route).str n.getString!
meta def localRoleIff (n : Name) := (localRole n).appendAfter "_iff"

private meta partial def peel (c a : Expr) (vs : Array Expr) : MetaM (Expr × Expr) := do
  if a.isAppOf ``Exists then
    return ←withLocalDeclD `w (a.getArg! 0) fun x => peel c (a.appArg!.beta #[x]) (vs.push x)
  let body ← mkLambdaFVars vs a.appArg!
  let proof ← mkAppM (if vs.size == 4 then ``four else ``two) #[c,body]
  return ((←inferType proof).appArg!.appArg!,proof)

meta def compileRole (n : Name) : MetaM Unit := do
  let name := HandReadersBFactor.factorName n
  unless (←getEnv).contains name do HandReadersBFactor.compile n
  lambdaTelescope (←getConstInfo name).value! fun xs p => do
    let c := xs[3]!
    let arms ← (HandReadersBFactor.disjuncts p).mapM fun a => peel c a #[]
    let mut pred := arms.getLast!.1
    let mut pf := arms.getLast!.2
    for (v,h) in arms.dropLast.reverse do
      let combo ← mkAppM ``eitherAt #[c,v,pred]
      pred := (←inferType combo).appArg!.appArg!
      pf ← mkAppM ``Iff.trans #[←mkAppM ``or_congr #[h,pf],combo]
    let clean ← lambdaTelescope pred fun vs _ => mkLambdaFVars vs (mkAppN pred vs).headBeta
    let localName := localRole n
    addDecl (.defnDecl {
      name := localName,levelParams := [],type := ←inferType clean,value := clean,hints := .abbrev,safety := .safe })
    let ty ←mkAppM ``Iff #[mkAppN (mkConst name) xs,←mkAppM ``At #[c,mkConst localName]]
    addDecl (.thmDecl {
      name := localRoleIff n,levelParams := [],type := ←mkForallFVars xs ty,value := ←mkLambdaFVars xs pf })

run_cmd liftTermElabM do
  for n in #[``step_aeReply_role_inl,``step_aeReply_role_inr,``step_aeReply_wRole_inl,``step_aeReply_wRole_inr] do
    compileRole n

end ConsensusCoverage.HandReadersTrunkA.Request
