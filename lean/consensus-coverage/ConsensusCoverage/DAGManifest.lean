module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Classes
public meta import ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.Classes
meta import Lean

/-!
# Typed DAG manifest & unsupported-atom frontier for the frozen 255 schema

Inspects the generated `Classes` DAG (`step_*` and `reach_*`) **without unfolding
callees**, recording:
- topological order of all live `reach_*` definitions (bottom-up compilation order),
- structural template grouping (how many distinct relational query shapes exist),
- per-reach existential domain & positive-guard classification,
- ranked frontier of the highest-impact blocking atoms / binder domains weighted by
  how many step roots and how many of the 60 strict-trunk columns depend on them.

This drives the bottom-up relational query compiler (`ReachCompiler`) so every new
compilation rule is prioritized by actual trunk/root fan-out.
-/

namespace ConsensusCoverage.DAGManifest

open Lean Meta ConsensusCoverage ConsensusCoverage.Classes ConsensusCoverage.ClauseQuestions

public structure ReachSummary where
  name : String
  numArms : Nat
  directDeps : List String
  templateId : Nat
  deriving Repr, Inhabited

public structure StepSummary where
  name : String
  inStrictTrunk : Bool
  numArms : Nat
  transitiveReaches : Nat
  maxDepth : Nat
  deriving Repr, Inhabited

public structure FrontierEntry where
  kind : String
  domainOrAtom : String
  reachCount : Nat
  blockedSteps : Nat
  blockedStrictTrunk : Nat
  deriving Repr, Inhabited

public structure ManifestStats where
  stepCount : Nat
  liveReachCount : Nat
  distinctReachTemplates : Nat
  totalStepArms : Nat
  distinctStepArmTemplates : Nat
  strictTrunkCount : Nat
  strictTrunkMinReaches : Nat
  strictTrunkMaxReaches : Nat
  deriving Repr, Inhabited

meta section

private def headName (e : Expr) : String :=
  match e.getAppFn with
  | .const n _ => n.toString
  | .forallE .. => "Pi"
  | .bvar _ => "bvar"
  | _ => "other"

private partial def stripLambdas (e : Expr) : Expr :=
  if e.isLambda then stripLambdas e.bindingBody! else e

private partial def collectOrArms (e : Expr) : Array Expr :=
  if e.isAppOfArity ``Or 2 then
    collectOrArms (e.getArg! 0) ++ collectOrArms (e.getArg! 1)
  else
    #[e]

private partial def positiveGuardKind (e : Expr) (i : Nat := 0) : Option String := Id.run do
  if e.isAppOfArity ``And 2 then
    return (positiveGuardKind (e.getArg! 0) i).orElse fun _ => positiveGuardKind (e.getArg! 1) i
  if e.isAppOfArity ``Exists 2 && e.appArg!.isLambda then
    return positiveGuardKind e.appArg!.bindingBody! (i + 1)
  let x := mkBVar i
  let outer := fun (v : Expr) => !(List.range (i + 1)).any (fun j => v.hasLooseBVar j)
  if e.isAppOfArity ``Eq 3 then
    if (e.getArg! 1 == x && outer e.appArg!) || (e.appArg! == x && outer (e.getArg! 1)) then
      return some "eq_pin"
  if e.isAppOfArity ``HEq 4 then
    if (e.getArg! 1 == x && outer (e.getArg! 3)) || (e.getArg! 3 == x && outer (e.getArg! 1)) then
      return some "heq_pin"
  if e.isAppOfArity ``Membership.mem 5 && e.appArg! == x &&
      (e.getArg! 1).isAppOf ``List && outer (e.getArg! 3) then
    return some "list_mem"
  if (e.isAppOfArity ``LE.le 4 || e.isAppOfArity ``LT.lt 4) &&
      (e.getArg! 0).isConstOf ``Nat && e.getArg! 2 == x && outer e.appArg! then
    return some "nat_bound"
  if e.isAppOf ``Consensus.Proofs.Safety.Now then
    let args := e.getAppArgs
    if args.size ≥ 2 && (args[args.size - 1]! == x || args[args.size - 2]! == x) then
      return some "now_pair"
  return none

private partial def unguardedDomains (e : Expr) : Array String :=
  if e.isAppOfArity ``Exists 2 && (e.getArg! 1).isLambda then
    let dom := e.getArg! 0
    let body := (e.getArg! 1).bindingBody!
    let here :=
      match positiveGuardKind body with
      | some _ => #[]
      | none =>
        let tag :=
          if dom.isAppOf ``List then s!"List:{headName dom.appArg!}"
          else headName dom
        #[tag]
    here ++ unguardedDomains body
  else if e.isAppOfArity ``And 2 || e.isAppOfArity ``Or 2 then
    unguardedDomains (e.getArg! 0) ++ unguardedDomains (e.getArg! 1)
  else if e.isAppOfArity ``Not 1 then
    unguardedDomains e.appArg!
  else if e.isForall then
    unguardedDomains e.bindingDomain! ++ unguardedDomains e.bindingBody!
  else
    #[]

private def abstractReaches (ns : Name) (e : Expr) : Expr :=
  let deps := e.getUsedConstants.filter fun x =>
    x.getPrefix == ns && x.getString!.startsWith "reach_"
  let numbered := deps.zipIdx
  e.replace fun t => do
    let name ← t.constName?
    let (_, idx) ← numbered.find? (·.1 == name)
    return mkConst (.num `reach_slot idx)

/-- Compute the frozen-255 DAG manifest and ranked unsupported-domain frontier. -/
public def computeManifest : MetaM (ManifestStats × Array FrontierEntry) := do
  let env ← getEnv
  let ns := `ConsensusCoverage.Classes
  -- Collect direct reach dependencies for every reach_* and step_* declaration.
  let mut reachDeps : Std.HashMap String (Array String) := {}
  let mut reachUnguarded : Std.HashMap String (Array String) := {}
  let mut reachTemplates : Std.HashMap Expr Nat := {}
  let mut stepDeps : Std.HashMap String (Array String) := {}
  let mut stepUnguarded : Std.HashMap String (Array String) := {}
  let mut stepArmTemplates : Std.HashMap Expr Nat := {}
  let mut totalStepArms := 0
  let mut stepNames : Array String := #[]
  for (n, c) in env.constants.toList do
    unless n.getPrefix == ns do continue
    let k := n.getString!
    let .defnInfo d := c | continue
    let deps := d.value.getUsedConstants.filterMap fun x =>
      if x.getPrefix == ns && x.getString!.startsWith "reach_" then some x.getString! else none
    let body := stripLambdas d.value
    let ug := unguardedDomains body
    if k.startsWith "reach_" then
      reachDeps := reachDeps.insert k deps
      reachUnguarded := reachUnguarded.insert k ug
    else if k.startsWith "step_" then
      stepNames := stepNames.push k
      stepDeps := stepDeps.insert k deps
      stepUnguarded := stepUnguarded.insert k ug
      let arms := collectOrArms body
      totalStepArms := totalStepArms + arms.size
      for a in arms do
        let tmpl := abstractReaches ns a
        unless stepArmTemplates.contains tmpl do
          stepArmTemplates := stepArmTemplates.insert tmpl stepArmTemplates.size
  -- Compute transitive reach closure per step root and mark live reaches.
  let mut liveReaches : Std.HashSet String := {}
  let mut stepClosure : Std.HashMap String (Std.HashSet String) := {}
  for s in stepNames do
    let mut seen : Std.HashSet String := {}
    let mut todo := stepDeps.getD s #[]
    while let some r := todo.back? do
      todo := todo.pop
      if seen.contains r then continue
      seen := seen.insert r
      liveReaches := liveReaches.insert r
      for d in reachDeps.getD r #[] do
        unless seen.contains d do todo := todo.push d
    stepClosure := stepClosure.insert s seen
  -- Count live reach templates.
  for r in liveReaches.toList do
    if let some (.defnInfo d) := env.find? (ns ++ Name.mkSimple r) then
      let tmpl := abstractReaches ns d.value
      unless reachTemplates.contains tmpl do
        reachTemplates := reachTemplates.insert tmpl reachTemplates.size
  -- Identify strict trunk step names via ClauseQuestions.trunk.
  let mut strictSet : Std.HashSet String := {}
  for b in FullProfile.stepBranches do
    if ClauseQuestions.trunk b then
      let s := (reprStr b).replace "ConsensusCoverage.Classes.StepBranch." "step_"
      strictSet := strictSet.insert s
  let mut minTrunk := 1000000
  let mut maxTrunk := 0
  for s in strictSet.toList do
    let sz := (stepClosure.getD s {}).size
    if sz < minTrunk then minTrunk := sz
    if sz > maxTrunk then maxTrunk := sz
  -- Rank unguarded domains by (blockedStrictTrunk, blockedSteps, reachCount).
  let mut domReaches : Std.HashMap String (Std.HashSet String) := {}
  for r in liveReaches.toList do
    for dom in reachUnguarded.getD r #[] do
      domReaches := domReaches.insert dom ((domReaches.getD dom {}).insert r)
  let mut domSteps : Std.HashMap String (Std.HashSet String) := {}
  let mut domTrunk : Std.HashMap String (Std.HashSet String) := {}
  for s in stepNames do
    let mut sDoms : Std.HashSet String := {}
    for dom in stepUnguarded.getD s #[] do
      sDoms := sDoms.insert dom
    for r in (stepClosure.getD s {}).toList do
      for dom in reachUnguarded.getD r #[] do
        sDoms := sDoms.insert dom
    let isTrunk := strictSet.contains s
    for dom in sDoms.toList do
      domSteps := domSteps.insert dom ((domSteps.getD dom {}).insert s)
      if isTrunk then
        domTrunk := domTrunk.insert dom ((domTrunk.getD dom {}).insert s)
  let mut frontier : Array FrontierEntry := #[]
  for (dom, steps) in domSteps.toList do
    frontier := frontier.push {
      kind := "unguarded_exists"
      domainOrAtom := dom
      reachCount := (domReaches.getD dom {}).size
      blockedSteps := steps.size
      blockedStrictTrunk := (domTrunk.getD dom {}).size
    }
  let sortedFrontier := frontier.qsort fun a b =>
    if a.blockedStrictTrunk != b.blockedStrictTrunk then a.blockedStrictTrunk > b.blockedStrictTrunk
    else if a.blockedSteps != b.blockedSteps then a.blockedSteps > b.blockedSteps
    else a.reachCount > b.reachCount
  let stats : ManifestStats := {
    stepCount := stepNames.size
    liveReachCount := liveReaches.size
    distinctReachTemplates := reachTemplates.size
    totalStepArms
    distinctStepArmTemplates := stepArmTemplates.size
    strictTrunkCount := strictSet.size
    strictTrunkMinReaches := minTrunk
    strictTrunkMaxReaches := maxTrunk
  }
  return (stats, sortedFrontier)

end

end ConsensusCoverage.DAGManifest
