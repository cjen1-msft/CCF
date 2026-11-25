module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBReflect
public import ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersElectionBReflect
public meta import ConsensusCoverage.HandReadersBFactor
public meta import ConsensusCoverage.ReachPath
public meta import Lean

namespace ConsensusCoverage.HandReadersElectionB.PrefixParts

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option Elab.async false

private abbrev Pred := List Entry → List Entry → Nat → Prop
private abbrev Pack (fwd : Bool) (p : Pred) := ∃ l r i, p l r i ∧
  (if fwd then l <+: r else r <+: l) ∧ i ≤ l.length ∧ i ≤ r.length

private theorem split (a b : Pred) (d : Bool) : Pack d (fun l r i => a l r i ∨ b l r i) ↔ Pack d a ∨ Pack d b := by
  constructor
  · rintro ⟨l,r,i,h | h,tail⟩
    · exact .inl ⟨l,r,i,h,tail⟩
    · exact .inr ⟨l,r,i,h,tail⟩
  · rintro (⟨l,r,i,h,tail⟩ | ⟨l,r,i,h,tail⟩)
    · exact ⟨l,r,i,.inl h,tail⟩
    · exact ⟨l,r,i,.inr h,tail⟩

private theorem strip (p : Pred) (d : Bool) : (∃ l r i, p l r i ∧
    (if d then l <+: r else r <+: l) ∧ (l <+: r ∨ r <+: l) ∧ i ≤ l.length ∧ i ≤ r.length) ↔ Pack d p := by
  constructor
  · rintro ⟨l,r,i,h,dir,_,bounds⟩; exact ⟨l,r,i,h,dir,bounds⟩
  · rintro ⟨l,r,i,h,dir,bounds⟩
    refine ⟨l,r,i,h,dir,?_,bounds⟩
    cases d <;> first | exact .inl dir | exact .inr dir

public meta section
open Lean Meta Elab Command

inductive Class where | direct | agreement | anchor
  deriving BEq, Inhabited

structure Atom where
  name : Name
  family : Class
  site : Nat
  offset : Nat
  deriving Inhabited

def scope := `ConsensusCoverage.HandReadersElectionB.PrefixParts
def splitName (forward : Bool) := (if forward then scope ++ `Forward else scope ++ `Reverse) ++ `partition
def shardScope (j : Nat) := (scope ++ `Group).appendIndexAfter j
def batch (site : Nat) := if site < 2 then 0 else if site < 5 then 1 else if site < 9 then 2 else 3
def groupName (j : Nat) (forward : Bool) := (shardScope j).str (if forward then "forward" else "reverse")

private def children (n : Name) : MetaM (Array Name) := do
  return ReachPath.children n.getPrefix (←getConstInfo n).value!

private partial def alternatives (e : Expr) : List Expr :=
  if e.isAppOf ``Or then alternatives (e.getArg! 0) ++ alternatives e.appArg! else [e]

def atoms (forward : Bool) : MetaM (Array Atom) := do
  let q := ``step_take_eq_take_of_comparable_comparable_inl
  let agree ← children ``step_agree_or_contained_lt_or_ge_inl
  let core ← children ``step_core_covered_pos
  let mut out := #[]
  for (n,i) in (← children q).zipIdx do
    for (e,j) in (alternatives (←getConstInfo n).value!.getLambdaBody).zipIdx do
      let cs := ReachPath.children q.getPrefix e
      let family := if cs.any agree.contains then Class.agreement else if cs.any core.contains then .anchor else .direct
      let name := (((scope.str (if forward then "forward" else "reverse")).appendIndexAfter i).appendIndexAfter j)
      out := out.push ⟨name,family,i,j⟩
  return out

def disj (args : List Expr) : Expr := args.dropLast.foldr (mkApp2 (mkConst ``Or)) args.getLast!

private partial def splitLeaf (params xyz : Array Expr) (body : Expr) (forward : Bool) (i j : Nat) :
    MetaM (Expr × Nat) := do
  let pred := fun e => mkLambdaFVars xyz e
  if body.isAppOf ``Or then
    let l := body.getArg! 0
    let r := body.appArg!
    let initial ← mkAppM ``split #[←pred l,←pred r,toExpr forward]
    let (left,k) ← splitLeaf params xyz l forward i j
    let (right,k) ← splitLeaf params xyz r forward i k
    return (←mkAppM ``Iff.trans #[initial,←mkAppM ``or_congr #[left,right]],k)
  let n := (((scope.str (if forward then "forward" else "reverse")).appendIndexAfter i).appendIndexAfter j)
  let lhs ← mkAppM ``Pack #[toExpr forward,←pred body]
  let expanded := (←unfoldDefinition? lhs).get!
  addDecl (.defnDecl {
    name := n,levelParams := [],type := ←mkForallFVars params (mkSort .zero),
    value := ←mkLambdaFVars params expanded,hints := .abbrev,safety := .safe })
  return (←mkAppM ``Iff.refl #[mkAppN (mkConst n) params],j+1)

private def partition (forward : Bool) : MetaM Unit := do
  let q := if forward then ``step_take_eq_take_of_comparable_comparable_inl else ``step_take_eq_take_of_comparable_comparable_inr
  let sites ← children q
  lambdaTelescope (←getConstInfo q).value! fun params _ => do
    -- Separate the caller alternatives before quantifying the logs: their
    -- finite witness sources differ even when their outer signatures agree.
    let mut arms := #[]
    for (n,i) in sites.zipIdx do
      let p := mkAppN (mkConst n) params
      let split ← forallTelescope (←inferType p) fun xyz _ => do
        let body := (←getConstInfo n).value!.beta (params ++ xyz)
        return (←splitLeaf params xyz body forward i 0).1
      let strip ←mkAppM ``strip #[p,toExpr forward]
      arms := arms.push (←mkAppM ``Iff.trans #[strip,split])
    let mut iff := arms.back!
    for arm in arms.pop.reverse do iff ← mkAppM ``or_congr #[arm,iff]
    let rhs := (←inferType iff).appArg!
    addDecl (.thmDecl {
      name := splitName forward,levelParams := [],
      type := ←mkForallFVars params (←mkAppM ``Iff #[mkAppN (mkConst q) params,rhs]),
      value := ←mkLambdaFVars params iff })

def compileBatch (j : Nat) : MetaM Unit := do
  let mut ns := #[]
  for d in [true,false] do
    for a in ←atoms d do
      if a.family == .direct && batch a.site == j then ns := ns.push a.name
  Reflect.compile (shardScope j) ns #[]
  for d in [true,false] do
    let roster := (←atoms d).filter fun a => a.family == .direct && batch a.site == j
    lambdaTelescope (←getConstInfo roster[0]!.name).value! fun xs _ => do
      withLocalDeclD `x (Lean.mkConst ``ReadersAtoms.XView) fun x => do
        let okTy ←mkAppM ``ReadersAtoms.XView.Matches #[x,xs[3]!]
        withLocalDeclD `ok okTy fun ok => do
          let mut values := #[]
          let mut certs := #[]
          let runArgs := #[xs[0]!,x]
          let proofArgs := (xs.push x).push ok
          for a in roster do
            let ns := shardScope j ++ `R
            values := values.push (mkAppN (Lean.mkConst (ns.str a.name.getString!)) runArgs)
            certs := certs.push (mkAppN (Lean.mkConst (ns.str (a.name.getString! ++ "_iff"))) proofArgs)
          let n := groupName j d
          ReadersCompiler.addReader (.defnDecl {
            name := n,levelParams := [],type := ←mkForallFVars runArgs (Lean.mkConst ``Bool),
            value := ←mkLambdaFVars runArgs (values.pop.foldr (mkApp2 (Lean.mkConst ``Bool.or)) values.back!),
            hints := .regular 0,safety := .safe })
          let mut cert := certs.back!
          for p in certs.pop.reverse do cert ← mkAppM ``ReadersAtoms.or_cert #[p,cert]
          let props := roster.toList.map fun a => mkAppN (Lean.mkConst a.name) xs
          addDecl (.thmDecl {
            name := n.appendAfter "_iff",levelParams := [],
            type := ←mkForallFVars proofArgs (←mkAppM ``Iff #[←mkEq (mkAppN (Lean.mkConst n) runArgs)
              (toExpr true),disj props]),value := ←mkLambdaFVars proofArgs cert })

end

open Lean Elab Command in
run_cmd liftTermElabM do
  partition true
  partition false

end ConsensusCoverage.HandReadersElectionB.PrefixParts
