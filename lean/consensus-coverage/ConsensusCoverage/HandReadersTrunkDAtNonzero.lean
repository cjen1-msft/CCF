module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDAtZero
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.DeepPrefixCases
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.PromotionImpossibleB
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Prefix

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

private theorem appendNonzero [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (app : App c) : step_termAt_take_zero_neg f t c := by
  obtain ⟨_,ev⟩ := app
  let s := HandReadersTrunkA.Batch.seed c ev
  have role : c.pre.role = .primary := s.guards.1
  have len : 1 ≤ s.before.log.length := List.length_pos_iff.mpr (c.inv.leader_logs _ _ c.pre_now role)
  have h := DeepPrefixCases.sender s.self s.before s.contents s.entered s.guards 1 len
  iterate 10 right
  exact .inl ⟨1,_,h,by decide,len⟩

private theorem moveBound {i n a b : Nat} (left : i = a) (le : a ≤ b) (right : n = b) : i ≤ n :=
  left ▸ right ▸ le

private theorem forgetIndex {R : Nat → Nat → Prop} :
    (∃ i n, R i n ∧ ¬i = 0 ∧ i ≤ n) → ∃ i n, R i n :=
  fun ⟨i,n,h,_,_⟩ => ⟨i,n,h⟩

private theorem recoverIndex [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (R : Nat → Nat → Prop) (pos : ∀ i n, R i n → App c ∨ 0 < i) (bound : ∀ i n, R i n → i ≤ n)
    (inject : (∃ i n, R i n ∧ ¬i = 0 ∧ i ≤ n) → step_termAt_take_zero_neg f t c) :
    (∃ i n, R i n) → step_termAt_take_zero_neg f t c := by
  rintro ⟨i,n,h⟩
  exact (pos i n h).elim (appendNonzero c) (fun nz => inject ⟨i,n,h,Nat.ne_of_gt nz,bound i n h⟩)

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Prefix
private def boundName (r : Name) := (ns++`Bounds).str r.getString!

private def equalities (v : Expr) (fs : PromotionImpossibleB.Fields) : MetaM (Array (Expr × Expr)) := do
  let mut out := #[(v,←mkEqRefl v)]
  for (p,h) in fs do
    if p.isAppOfArity ``Eq 3 then
      if p.getArg! 1 == v then out := out.push (p.appArg!,h)
      else if p.appArg! == v then out := out.push (p.getArg! 1,←mkEqSymm h)
  return out

private def bound (i n : Expr) (fs : PromotionImpossibleB.Fields) : MetaM Expr := do
  let is ←equalities i fs
  let ns ←equalities n fs
  for (a,ha) in is do
    for (b,hb) in ns do
      if a == b then return ←mkAppM ``moveBound #[ha,←mkAppM ``Nat.le_refl #[a],hb]
      for (p,h) in fs do
        if p.isAppOf ``LE.le && p.getAppArgs[p.getAppNumArgs-2]! == a && p.appArg! == b then
          return ←mkAppM ``moveBound #[ha,h,hb]
  throwError "no prefix bound for {i} <= {n}"

run_cmd liftTermElabM do
  let q := ``step_termAt_take_zero_neg
  let rs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  for r in rs do
    lambdaTelescope (←getConstInfo r).value! fun xs body=>do
      let site := mkAppN (mkConst r) xs
      let i := xs[4]!
      let n := xs[5]!
      withLocalDeclD `site site fun h=>do
        let v ←PromotionImpossibleB.withFields body h #[] (bound i n)
        let pf ←mkLambdaFVars (xs.push h) (←mkExpectedTypeHint v (←mkAppM ``LE.le #[i,n]))
        addDecl (.thmDecl {name:=boundName r,levelParams:=[],type:=←inferType pf,value:=pf})

-- The callers supply the prefix bound. Their only unbounded choice here is
-- the input index: an origin at zero forces an append, which also supplies one.
run_cmd liftTermElabM do
  let q := ``step_termAt_take_zero_neg
  lambdaTelescope (←getConstInfo q).value! fun xs body=>do
    let rs := ReachPath.children q.getPrefix body
    let pred := mkAppN (mkConst q) xs
    let mut rows := []
    let mut forwards := []
    let mut backwards := []
    let arms := HandReadersBFactor.disjuncts body
    for (r,k) in rs.zipIdx do
      let call := mkAppN (mkConst r) xs
      let row ←withLocalDeclD `i (mkConst ``Nat) fun i=>do
        withLocalDeclD `n (mkConst ``Nat) fun n=>do
          let ex ←mkAppM ``Exists #[←mkLambdaFVars #[n] (mkApp2 call i n)]
          mkAppM ``Exists #[←mkLambdaFVars #[i] ex]
      rows := rows++[row]
      forwards := forwards++[mkApp (mkConst ``forgetIndex) call]
      let src := mkAppN (mkConst (certName r)) xs
      let len := mkAppN (mkConst (boundName r)) xs
      let inj ←withLocalDeclD `arm arms[k]! fun a=>do
        mkLambdaFVars #[a] (←HandReadersBFactor.into body a k arms.length)
      let back := mkAppN (mkConst ``recoverIndex) (xs++#[call,src,len,inj])
      backwards := backwards++[back]
    let any := HandReadersTrunkA.Factor.disj rows
    let decl := ns++`AnyIndex
    let val ←mkLambdaFVars xs any
    addDecl (.defnDecl {name:=decl,levelParams:=[],type:=←inferType val,value:=val,hints:=.abbrev,safety:=.safe})
    let dest := mkAppN (mkConst decl) xs
    let lifted ←forwards.zipIdx.mapM fun (fw,k)=>withLocalDeclD `h arms[k]! fun h=>do
      mkLambdaFVars #[h] (←HandReadersBFactor.into any (mkApp fw h) k arms.length)
    let mp ←withLocalDeclD `h pred fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf body h dest lifted)
    let mpr ←withLocalDeclD `h dest fun h=>do mkLambdaFVars #[h] (←HandReadersBFactor.outOf any h pred backwards)
    let pf ←mkLambdaFVars xs (←mkAppM ``Iff.intro #[mp,mpr])
    addDecl (.thmDecl {name:=ns++`nonzero_iff_anyIndex,levelParams:=[],type:=←inferType pf,value:=pf})
end

end ConsensusCoverage.HandReadersTrunkD.Prefix
