module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
public import ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

/-! Eliminate witnesses fixed by an equation instead of searching for them.
Both directions are proved, and calls to shared generated predicates stay shared. -/

namespace ConsensusCoverage.SolvedWitnesses

private theorem fixed {α : Sort u} {P : α → Prop} (v : α) (pin : ∀ x, P x → x = v) :
    (∃ x, P x) ↔ P v :=
  ⟨fun ⟨x, h⟩ => pin x h ▸ h, fun h => ⟨v, h⟩⟩

meta section

open Lean Meta Elab Command

private structure Stats where
  visited : Std.HashSet Name := {}
  fixed : Nat := 0
  retained : Nat := 0
  reflexive : Nat := 0
private abbrev Gen := StateRefT Stats MetaM
private abbrev Changed := Expr × Expr -- new predicate and (old ↔ new)

private def target (n : Name) := `ConsensusCoverage.SolvedWitnesses ++ Name.mkSimple n.getString!
private def iffName (n : Name) := (target n).appendAfter "_iff"

private def ident (p : Expr) : MetaM Changed := return (p, mkApp (mkConst ``Iff.refl) p)

private def trans (h : Expr) (next : Changed) : MetaM Changed :=
  return (next.1, ← mkAppM ``Iff.trans #[h, next.2])

/-- An equation may cross another existential only if the replacement doesn't
mention that inner witness. Never assume a condition from just one disjunct. -/
private partial def findPin (x p h : Expr) : MetaM (Option (Expr × Expr)) := do
  if p.isAppOfArity ``Eq 3 then
    let a := p.getArg! 1
    let b := p.getArg! 2
    if a == x && !b.containsFVar x.fvarId! then return some (b, h)
    if b == x && !a.containsFVar x.fvarId! then return some (a, ← mkEqSymm h)
  if p.isAppOfArity ``And 2 then
    let lhs := p.getArg! 0
    let rhs := p.getArg! 1
    let args := #[some lhs, some rhs, some h]
    if let some v ← findPin x lhs (← mkAppOptM ``And.left args) then return some v
    return ← findPin x rhs (← mkAppOptM ``And.right args)
  if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
    let pred := p.appArg!
    return ← withLocalDeclD pred.bindingName! pred.bindingDomain! fun w => do
      let body := pred.beta #[w]
      withLocalDeclD `hw body fun hw => do
        let some (rhs, eq) ← findPin x body hw | return none
        if rhs.containsFVar w.fvarId! then return none
        return some (rhs, ← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hw] eq])
  return none

mutual

private partial def normalize (p : Expr) : Gen Changed := do
  if p.isAppOfArity ``And 2 || p.isAppOfArity ``Or 2 then
    let a ← normalize (p.getArg! 0)
    let b ← normalize (p.getArg! 1)
    let isAnd := p.isAppOfArity ``And 2
    let combined := mkApp2 p.getAppFn a.1 b.1
    let congr ← mkAppM (if isAnd then ``and_congr else ``or_congr) #[a.2, b.2]
    if a.1 == b.1 then
      return ← trans congr (a.1, ← mkIffOfEq (← mkAppM (if isAnd then ``and_self else ``or_self) #[a.1]))
    if isAnd && a.1.isConstOf ``True then
      return ← trans congr (b.1, ← mkIffOfEq (← mkAppM ``true_and #[b.1]))
    if isAnd && b.1.isConstOf ``True then
      return ← trans congr (a.1, ← mkIffOfEq (← mkAppM ``and_true #[a.1]))
    return (combined, congr)
  if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
    let pred := p.appArg!
    return ← withLocalDeclD pred.bindingName! pred.bindingDomain! fun x => do
      let body := pred.beta #[x]
      let pin ← withLocalDeclD `h body fun h => do
        let some (rhs, eq) ← findPin x body h | return none
        return some (rhs, ← mkLambdaFVars #[x,h] eq)
      if let some (rhs, eq) := pin then
        modify fun st => { st with fixed := st.fixed + 1 }
        let h ← mkAppOptM ``fixed #[some pred.bindingDomain!, some pred, some rhs, some eq]
        return ← trans h (← normalize (pred.beta #[rhs]))
      modify fun st => { st with retained := st.retained + 1 }
      let b ← normalize body
      let q ← mkLambdaFVars #[x] b.1
      return (mkApp2 p.getAppFn pred.bindingDomain! q, ← mkAppM ``exists_congr #[← mkLambdaFVars #[x] b.2])
  if p.isAppOfArity ``Eq 3 && p.getArg! 1 == p.getArg! 2 then
    modify fun st => {st with reflexive := st.reflexive + 1}
    return (mkConst ``True, ← mkAppM ``iff_true_intro #[← mkEqRefl (p.getArg! 1)])
  if let .const n@(.str ns name) ls := p.getAppFn then
    if ns == `ConsensusCoverage.PinnedClasses && name.startsWith "reach_" then
      compilePred n
      return (mkAppN (mkConst (target n) ls) p.getAppArgs, mkAppN (mkConst (iffName n) ls) p.getAppArgs)
  ident p

private partial def compilePred (n : Name) : Gen Unit := do
  if (← get).visited.contains n then return
  let ci ← getConstInfo n
  lambdaTelescope ci.value! fun xs p => do
    let (q, iff) ← normalize p
    let value ← mkLambdaFVars xs q
    addDecl <| .defnDecl {
      name := target n, levelParams := ci.levelParams, type := ci.type, value, hints := .abbrev, safety := .safe }
    let ls := ci.levelParams.map mkLevelParam
    let old := mkAppN (mkConst n ls) xs
    let new := mkAppN (mkConst (target n) ls) xs
    addDecl <| .thmDecl {
      name := iffName n, levelParams := ci.levelParams,
      type := ← mkForallFVars xs (mkApp2 (mkConst ``Iff) old new), value := ← mkLambdaFVars xs iff }
  modify fun st => {st with visited := st.visited.insert n}

end

private def compile : MetaM Unit := do
  let ci ← getConstInfo ``PinnedClasses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope ci.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do throwError "unexpected pinned dispatcher"
    let names ← (args.extract 2 args.size).mapM fun arm => do
      unless arm.getAppArgs == xs.extract 0 4 do throwError "unexpected pinned arm {arm}"
      let some n := arm.getAppFn.constName? | throwError "expected pinned constant"
      return n
    let (_, stats) ← (names.forM compilePred).run {}
    let ls := ci.levelParams.map mkLevelParam
    let params := xs.extract 0 4
    let value := mkAppN body.getAppFn ((args.extract 0 2) ++ names.map fun n => mkAppN (mkConst (target n) ls) params)
    let new := `ConsensusCoverage.SolvedWitnesses.dispatch
    addDecl <| .defnDecl {
      name := new, levelParams := ci.levelParams, type := ci.type,
      value := ← mkLambdaFVars xs value, hints := .abbrev, safety := .safe }
    let ty := mkApp2 (mkConst ``Iff) (mkAppN (mkConst ci.name ls) xs) (mkAppN (mkConst new ls) xs)
    let motive ← mkLambdaFVars #[xs[4]!] ty
    let proof := mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero])
      (#[motive, xs[4]!] ++ names.map fun n => mkAppN (mkConst (iffName n) ls) params)
    addDecl <| .thmDecl {
      name := new.appendAfter "_iff", levelParams := ci.levelParams,
      type := ← mkForallFVars xs ty, value := ← mkLambdaFVars xs proof }
    logInfo m!"solved witnesses: {names.size} questions, {stats.visited.size} shared predicates; \
      {stats.fixed} existential bindings eliminated, {stats.retained} retained, {stats.reflexive} reflexive tests"

end

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

local elab "solve_pinned_witnesses" : command => Lean.Elab.Command.liftTermElabM compile
solve_pinned_witnesses

open Consensus Consensus.Proofs Consensus.Proofs.Safety

public def sig [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (b : Classes.StepBranch) : Prop := dispatch f t c b

public theorem sig_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (b : Classes.StepBranch) : PinnedClasses.sig c b ↔ sig c b := dispatch_iff f t c b

end ConsensusCoverage.SolvedWitnesses
