module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkARoleRoute
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.SolvedWitnesses
public meta import ConsensusCoverage.HandReadersTrunkARoleRoute

namespace ConsensusCoverage.HandReadersTrunkC.Reply

open Consensus.Model Consensus.Model.Node
open Lean Meta Elab Command SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 2400000

private theorem combine {a b c : Prop} (ha : a → c) (hb : b → c) : a ∨ b → c := fun h => h.elim ha hb

private theorem mapFour (R : NodeID → NodeID → NodeState → AppendEntriesRequest → Prop)
    {p : NodeID → NodeID → NodeState → AppendEntriesRequest → Prop} {q : NodeState → AppendEntriesRequest → Prop}
    (h : ∀ n a z r, p n a z r → q z r) :
    (∃ n a z r, R n a z r ∧ p n a z r) → ∃ n a z r, R n a z r ∧ q z r :=
  fun ⟨n,a,z,r,hc,hp⟩ => ⟨n,a,z,r,hc,h n a z r hp⟩

private theorem mapTwo (R : NodeState → AppendEntriesRequest → Prop)
    {p q : NodeState → AppendEntriesRequest → Prop} (h : ∀ z r, p z r → q z r) :
    (∃ z r, R z r ∧ p z r) → ∃ z r, R z r ∧ q z r :=
  fun ⟨z,r,hc,hp⟩ => ⟨z,r,hc,h z r hp⟩

meta section

private partial def project (target p h : Expr) : MetaM Expr := do
  if p == target then return h
  if p.isAppOf ``And then
    let ((a,ha),(b,hb)) := ProofWalk.conjuncts p h
    if a == target then return ha
    return ←project target b hb
  if p.isAppOf ``Exists then
    return ←withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := p.appArg!.beta #[w]
      withLocalDeclD `hw q fun hw => do
        let sub ←mkLambdaFVars #[w,hw] (←project target q hw)
        return ProofWalk.casesExists p h target sub
  throwError "missing request guard at end of projection"

private partial def suffix (n : Name) (pos : Bool) (arm : Expr) (vs : Array Expr) : MetaM (Name × Expr × Expr) := do
  if arm.isAppOf ``Exists then
    return ←withLocalDeclD arm.appArg!.bindingName! (arm.getArg! 0) fun w => suffix n pos (arm.appArg!.beta #[w]) (vs.push w)
  let root := (arm.getArg! 0).getAppFn.constName!
  let guard ←unfoldDefinition? (mkApp2 (mkConst ``AssistReplyA.stepsDown) vs[vs.size-2]! vs.back!)
  let guard := if pos then guard.get! else mkNot guard.get!
  let tail := arm.appArg!
  let tgt ← mkLambdaFVars (vs.extract (vs.size-2) vs.size) guard
  unless (←getEnv).contains n do
    let pf ← withLocalDeclD `h tail fun h => do mkLambdaFVars (vs.push h) (←project guard tail h)
    addDecl (.thmDecl { name := n,levelParams := [],type := ←inferType pf,value := pf })
  let p ←mkLambdaFVars vs tail
  return (root,tgt,mkApp3 (mkConst (if vs.size == 4 then ``mapFour else ``mapTwo)) (mkConst root) p tgt)

def boundName (n : Name) := ((`ConsensusCoverage.HandReadersTrunkC.Reply.Bound).str n.getString!).appendAfter "_bound"

private def compileUpper (n : Name) (pos : Bool) : MetaM Unit := do
  lambdaTelescope (←getConstInfo n).value! fun xs body => do
    let arms := HandReadersBFactor.disjuncts body
    let callers := ReachPath.children n.getPrefix body
    let first := ReachPath.children n.getPrefix arms.head!
    let width := 1 + ((arms.drop 1).takeWhile (fun a => ReachPath.children n.getPrefix a != first)).length
    let bn := boundName n
    let mut bounds := #[]
    let mut seen : Std.HashMap Name Nat := {}
    let mut per := #[]
    for (a,i) in arms.zipIdx do
      let hname := bn.str s!"local{i/width}"
      let (r,_,f) ←suffix hname pos a #[]
      let op := mkApp4 f.getAppFn (mkAppN (mkConst r) xs) (f.getArg! 1) f.appArg! (mkConst hname)
      unless seen.contains r do
        let ty ←inferType op
        seen := seen.insert r bounds.size
        bounds := bounds.push ty.bindingBody!
      per := per.push (r,op)
    unless callers.size == bounds.size do throwError "unexpected unguarded caller"
    let disj := bounds.toList.dropLast.foldr (fun a b => mkApp2 (mkConst ``Or) a b) bounds.back!
    addDecl (.defnDecl {
      name := bn,levelParams := [],type := ←mkForallFVars xs (mkSort .zero)
      value := ←mkLambdaFVars xs disj,hints := .abbrev,safety := .safe })
    let target := mkAppN (mkConst bn) xs
    let mut intro := #[]
    for h : i in [:bounds.size] do
      intro := intro.push (←withLocalDeclD `h bounds[i] fun x => do
        mkLambdaFVars #[x] (←HandReadersBFactor.into disj x i bounds.size))
    let mut full := mkConst ``False
    let mut pf := mkConst ``False.elim [.zero]
    for (a,i) in arms.zipIdx.reverse do
      let (r,op) := per[i]!
      let g := seen[r]!
      let proof := mkAppN (mkConst ``Function.comp [.zero,.zero,.zero]) #[a,bounds[g]!,target,intro[g]!,op]
      if i+1 == arms.length then pf := proof; full := a
      else
        pf := mkAppN (mkConst ``combine) #[a,full,target,proof,pf]
        full := mkApp2 (mkConst ``Or) a full
    addDecl (.thmDecl {
      name := bn.appendAfter "_necessary",levelParams := []
      type := ←mkForallFVars xs (←mkArrow (mkAppN (mkConst n) xs) target)
      value := ←mkLambdaFVars xs pf })
    HandReadersTrunkA.Request.compileRole bn

end

run_cmd liftTermElabM do
  compileUpper ``step_aeReply_stepDown_pos true
  compileUpper ``step_aeReply_stepDown_neg false

end ConsensusCoverage.HandReadersTrunkC.Reply
