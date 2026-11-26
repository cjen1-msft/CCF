module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean

namespace ConsensusCoverage.CensusQueueBool
public meta section
open Lean Meta Elab Tactic

private unsafe def evalBoolCode (e : Expr) : MetaM Bool :=
  evalExpr Bool (mkConst ``Bool) e (checkMeta := false)

@[implemented_by evalBoolCode] private def searchBool (e : Expr) : MetaM Bool :=
  return (← whnf e).isConstOf ``Bool.true

private unsafe def evalNatCode (e : Expr) : MetaM Nat :=
  evalExpr Nat (mkConst ``Nat) e (checkMeta := false)

@[implemented_by evalNatCode] private def searchNat (e : Expr) : MetaM Nat :=
  return (← getNatValue? e).getD 0

private def truth (e : Expr) := mkEq e (mkConst ``Bool.true)

private partial def build (raw : Expr) (fuel : Nat) : MetaM Expr := do
  let e := raw.headBeta
  if fuel > 0 then
    let next := fuel - 1
    if e.isAppOfArity ``Bool.or 2 || e.isAppOfArity ``Bool.and 2 then
      let a := e.getArg! 0
      let b := e.getArg! 1
      if e.isAppOf ``Bool.or then
        let left ← searchBool a
        let h ← build (if left then a else b) next
        let intro := if left then ``Or.inl else ``Or.inr
        let side := mkApp3 (mkConst intro) (← truth a) (← truth b) h
        return ← mkEqMPR (mkApp2 (mkConst ``Bool.or_eq_true) a b) side
      let both := mkApp4 (mkConst ``And.intro) (← truth a) (← truth b) (← build a next) (← build b next)
      return ← mkEqMPR (mkApp2 (mkConst ``Bool.and_eq_true) a b) both
    if e.isAppOfArity ``List.any 3 then
      let args := e.getAppArgs
      let values := args[1]!
      let pred := args[2]!
      let j ← searchNat (← mkAppM ``List.findIdx #[pred, values])
      let j := mkNatLit j
      let length ← mkAppM ``List.length #[values]
      let fin ← mkAppOptM ``Fin.mk #[length, j, ← mkDecideProof (← mkAppM ``LT.lt #[j, length])]
      let value ← mkAppM ``List.get #[values, fin]
      let member ← mkAppM ``List.get_mem #[values, fin]
      let atom ← build (pred.beta #[value]) next
      let body ← mkAppM ``And.intro #[member, ← mkExpectedTypeHint atom (← truth (pred.beta #[value]))]
      let iff ← mkAppOptM ``List.any_eq_true #[args[0]!, pred, values]
      let target := (← inferType iff).appArg!
      let witness ← mkAppOptM ``Exists.intro #[args[0]!, target.appArg!, value, body]
      return ← mkAppM ``Iff.mpr #[iff, witness]
    if let some n := e.getAppFn.constName? then
      if n.getPrefix matches .str _ "R" then
        if let some body ← unfoldDefinition? e then return ← build body next
  unless ← searchBool e do throwError "the selected Boolean atom is false: {e.getAppFn}"
  return ← mkExpectedTypeHint (← mkEqRefl (mkConst ``Bool.true)) (← truth e)

/-- Search by evaluation, then give the kernel a disjunct or an explicit
list element/member proof instead of making it scan all earlier failures. -/
elab "queue_bool" : tactic => withMainContext do
  let g ← getMainGoal
  let goal ← g.getType
  unless goal.isAppOfArity ``Eq 3 && (goal.getArg! 0).isConstOf ``Bool &&
      goal.appArg!.isConstOf ``Bool.true do throwError "expected a concrete Boolean = true"
  g.assign (← build (goal.getArg! 1) 48)
  replaceMainGoal []
end
end ConsensusCoverage.CensusQueueBool
