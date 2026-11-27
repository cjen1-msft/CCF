module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
public import ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

/-!
# Bottom-up parameter-pin normalizer over the frozen-255 reach DAG

Unlike `SolvedWitnesses`, which only solves equations local to a single `reach_k`
definition, `ReachCore` walks all 1,648 `SolvedWitnesses.reach_*` definitions in
topological order (bottom-up from depth 0 to depth 22) and:

1. Rewrites every direct child `reach_j` call into `core_j (unpinned...) ∧ (pin equalities)`
   **without ever unfolding `core_j`** (preserving DAG sharing).
2. Eliminates every existential binder newly pinned by homogeneous `Eq` or
   type-matching `HEq` (including `LocalTransition` after `after_1 = after` is solved).
3. Factors out parameters of `reach_k` that are functionally pinned across all disjuncts,
   exposing a smaller `core_k` together with an opaque kernel-checked equivalence
   `reach_k_iff : SolvedWitnesses.reach_k ... ↔ core_k ... ∧ (pin equalities)`.
4. Applies the same non-unfolding rewrite to all 255 `step_*` roots, exporting
   `ReachCore.sig` and `ReachCore.sig_iff : SolvedWitnesses.sig c b ↔ ReachCore.sig c b`.
-/

namespace ConsensusCoverage.ReachCore

open Consensus Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

private theorem fixedEq {α : Sort u} {P : α → Prop} (v : α) (pin : ∀ x, P x → x = v) :
    (∃ x, P x) ↔ P v :=
  ⟨fun ⟨x, h⟩ => pin x h ▸ h, fun h => ⟨v, h⟩⟩

private theorem fixedHEq {α : Sort u} {P : α → Prop} (v : α) (pin : ∀ x, P x → HEq x v) :
    (∃ x, P x) ↔ P v :=
  fixedEq v fun x h => eq_of_heq (pin x h)

private theorem heq_self_iff_true {α : Sort u} (a : α) : HEq a a ↔ True :=
  iff_true_intro (HEq.refl a)

private theorem and_true_iff (p : Prop) : (p ∧ True) ↔ p := ⟨And.left, fun h => ⟨h, trivial⟩⟩
private theorem true_and_iff (p : Prop) : (True ∧ p) ↔ p := ⟨And.right, fun h => ⟨trivial, h⟩⟩
private theorem and_self_iff (p : Prop) : (p ∧ p) ↔ p := ⟨And.left, fun h => ⟨h, h⟩⟩
private theorem or_self_iff (p : Prop) : (p ∨ p) ↔ p := ⟨fun h => h.elim id id, Or.inl⟩

meta section

open Lean Meta Elab Command

private def srcNs := `ConsensusCoverage.SolvedWitnesses
private def dstNs := `ConsensusCoverage.ReachCore

private def coreName (n : Name) : Name := dstNs ++ Name.mkSimple (n.getString!.replace "reach_" "core_")
private def stepName (n : Name) : Name := dstNs ++ Name.mkSimple n.getString!
private def iffName (n : Name) : Name := (dstNs ++ Name.mkSimple n.getString!).appendAfter "_iff"

private structure ReachInfo where
  /-- Core constant name (`core_k`). -/
  core : Name
  /-- Equivalence theorem `SolvedWitnesses.reach_k ... ↔ core_k ... ∧ pins`. -/
  iffThm : Name
  /-- Extra param indices (0-based into `extra`, i.e., `4 + i` in full args) that stay in `core`. -/
  keptIdxs : Array Nat
  /-- Number of extra params in original `SolvedWitnesses.reach_k`. -/
  nExtra : Nat
  /-- Number of pinned params factored out. -/
  nPinned : Nat

private structure Stats where
  infos : Std.HashMap Name ReachInfo := {}
  elimEq : Nat := 0
  elimHEq : Nat := 0
  factoredParams : Nat := 0
  zeroCoreReaches : Nat := 0
  totalReaches : Nat := 0

private abbrev Gen := StateRefT Stats MetaM
private abbrev Changed := Expr × Expr -- (newProp, old ↔ new)

private def ident (p : Expr) : MetaM Changed :=
  return (p, mkApp (mkConst ``Iff.refl) p)

private def chain (h : Expr) (next : Changed) : MetaM Changed :=
  return (next.1, ← mkAppM ``Iff.trans #[h, next.2])

/-- Find a pin `x = rhs` or `HEq x rhs` entailed by `p` (crossing `And` and `Exists`,
and crossing `Or` only if every disjunct pins `x` to the same `rhs`!). -/
private partial def findPin (x p h : Expr) (allowHEq : Bool := true) :
    MetaM (Option (Expr × Expr × Bool)) := do
  -- Returns `(rhs, proofOfEqOrHEq, isHEq)`
  if p.isAppOfArity ``Eq 3 then
    let a := p.getArg! 1
    let b := p.getArg! 2
    if a == x && !b.containsFVar x.fvarId! then return some (b, h, false)
    if b == x && !a.containsFVar x.fvarId! then return some (a, ← mkEqSymm h, false)
  if allowHEq && p.isAppOfArity ``HEq 4 then
    let a := p.getArg! 1
    let b := p.getArg! 3
    if a == x && !b.containsFVar x.fvarId! then
      if ← (try isDefEq (← inferType a) (← inferType b) catch _ => pure false) then
        return some (b, ← mkAppM ``eq_of_heq #[h], false)
      else
        return some (b, h, true)
    if b == x && !a.containsFVar x.fvarId! then
      let hsym ← mkAppM ``HEq.symm #[h]
      if ← (try isDefEq (← inferType b) (← inferType a) catch _ => pure false) then
        return some (a, ← mkAppM ``eq_of_heq #[hsym], false)
      else
        return some (a, hsym, true)
  if p.isAppOfArity ``And 2 then
    let lhs := p.getArg! 0
    let rhs := p.getArg! 1
    let args := #[some lhs, some rhs, some h]
    if let some v ← findPin x lhs (← mkAppOptM ``And.left args) allowHEq then return some v
    return ← findPin x rhs (← mkAppOptM ``And.right args) allowHEq
  if p.isAppOfArity ``Or 2 then
    let lhs := p.getArg! 0
    let rhs := p.getArg! 1
    let leftRes ← withLocalDeclD `hl lhs fun hl => do
      let some (r1, eq1, isH1) ← findPin x lhs hl allowHEq | return none
      return some (r1, ← mkLambdaFVars #[hl] eq1, isH1)
    let some (r1, fn1, isH1) := leftRes | return none
    let rightRes ← withLocalDeclD `hr rhs fun hr => do
      let some (r2, eq2, isH2) ← findPin x rhs hr allowHEq | return none
      if isH1 != isH2 then return none
      if r1 != r2 then
        unless ← (try isDefEq r1 r2 catch _ => pure false) do return none
      return some (← mkLambdaFVars #[hr] eq2)
    let some fn2 := rightRes | return none
    let eq ← mkAppM ``Or.elim #[h, fn1, fn2]
    return some (r1, eq, isH1)
  if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
    let pred := p.appArg!
    return ← withLocalDeclD pred.bindingName! pred.bindingDomain! fun w => do
      let body := pred.beta #[w]
      withLocalDeclD `hw body fun hw => do
        let some (rhs, eq, isH) ← findPin x body hw allowHEq | return none
        if rhs.containsFVar w.fvarId! then return none
        return some (rhs, ← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hw] eq], isH)
  return none

/-- Phase 1: rewrite direct child `SolvedWitnesses.reach_j` calls using their `reach_j_iff`
(keeping `core_j` opaque!), eliminate newly pinned existentials (`Eq` and `HEq`), and
clean up trivial `a = a`, `HEq a a`, `True ∧ P`, `P ∧ P`, `P ∨ P`. -/
private partial def normBody (p : Expr) : Gen Changed := do
  if p.isAppOfArity ``And 2 || p.isAppOfArity ``Or 2 then
    let a ← normBody (p.getArg! 0)
    let b ← normBody (p.getArg! 1)
    let isAnd := p.isAppOf ``And
    let combined := mkApp2 p.getAppFn a.1 b.1
    let congr ← mkAppM (if isAnd then ``and_congr else ``or_congr) #[a.2, b.2]
    if a.1 == b.1 then
      return ← chain congr (a.1, ← mkAppM (if isAnd then ``and_self_iff else ``or_self_iff) #[a.1])
    if isAnd && a.1.isConstOf ``True then
      return ← chain congr (b.1, ← mkAppM ``true_and_iff #[b.1])
    if isAnd && b.1.isConstOf ``True then
      return ← chain congr (a.1, ← mkAppM ``and_true_iff #[a.1])
    return (combined, congr)
  if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
    let pred := p.appArg!
    let dom := pred.bindingDomain!
    let (bodyNorm, bodyIff, pinInfo) ← withLocalDeclD pred.bindingName! dom fun x => do
      let b0 := pred.beta #[x]
      let (b1, iff1) ← normBody b0
      let pin ← withLocalDeclD `hx b1 fun hx => do
        -- Only eliminate homogeneous (or type-matching HEq -> Eq) pins for existentials!
        let some (rhs, eq, isH) ← findPin x b1 hx true | return none
        if isH then return none
        return some (rhs, ← mkLambdaFVars #[x, hx] eq)
      return (← mkLambdaFVars #[x] b1, ← mkLambdaFVars #[x] iff1, pin)
    let step1 ← mkAppM ``exists_congr #[bodyIff]
    let p1 := mkApp2 p.getAppFn dom bodyNorm
    if let some (rhs, pinProof) := pinInfo then
      modify fun st => { st with elimEq := st.elimEq + 1 }
      let step2 ← mkAppOptM ``fixedEq #[some dom, some bodyNorm, some rhs, some pinProof]
      let step12 ← mkAppM ``Iff.trans #[step1, step2]
      return ← chain step12 (← normBody (bodyNorm.beta #[rhs]))
    return (p1, step1)
  if p.isAppOfArity ``Eq 3 && p.getArg! 1 == p.getArg! 2 then
    return (mkConst ``True, ← mkAppM ``iff_true_intro #[← mkEqRefl (p.getArg! 1)])
  if p.isAppOfArity ``HEq 4 && p.getArg! 1 == p.getArg! 3 then
    return (mkConst ``True, ← mkAppM ``heq_self_iff_true #[p.getArg! 1])
  if let .const n@(.str ns name) ls := p.getAppFn then
    if ns == srcNs && name.startsWith "reach_" then
      if let some info := (← get).infos.get? n then
        let iffPrf := mkAppN (mkConst info.iffThm ls) p.getAppArgs
        let iffTy ← inferType iffPrf
        -- iffTy = `old ↔ new`
        let newP := iffTy.getArg! 1
        return (newP, iffPrf)
  ident p

/-- Helper: build `P₁ ∧ (P₂ ∧ ...)` (right-associated) and its intro/destructor proofs. -/
private def mkAndList (ps : List Expr) : Expr :=
  match ps with
  | [] => mkConst ``True
  | [a] => a
  | a :: rest => mkAnd a (mkAndList rest)

/-- Given `body` over `xs = base ++ extra`, iteratively find extra parameters that are
functionally pinned to expressions mentioning only `base` + remaining unpinned parameters,
provided no remaining unpinned parameter's type depends on a pinned parameter.
Returns `(keptIdxs, pins : Array (Nat × Expr × Bool))` where `pins` is in left-to-right
parameter order, each `(extraIdx, rhs, isHEq)`. -/
private def selectPinnedParams (base extra : Array Expr) (body : Expr) :
    MetaM (Array Nat × Array (Nat × Expr × Bool)) := do
  -- First, for each extra param `i`, check if `body` entails a pin `extra[i] = rhs` (or HEq)
  -- where `rhs` mentions ONLY `base` (indices 0..3) — super clean and guarantees zero cycles
  -- and lets us peel dependent Eq -> HEq chains cleanly!
  let baseSet : Std.HashSet FVarId := base.foldl (fun s x => s.insert x.fvarId!) {}
  let mut pinned : Std.HashMap Nat (Expr × Bool) ← withLocalDeclD `hb body fun hb => do
    let mut m : Std.HashMap Nat (Expr × Bool) := {}
    for i in [:extra.size] do
      let x := extra[i]!
      if let some (rhs, _, isH) ← findPin x body hb true then
        let fvs := (collectFVars {} rhs).fvarIds
        if fvs.all baseSet.contains then
          m := m.insert i (rhs, isH)
    return m
  -- Reject any pinned parameter `i` if some UNPINNED parameter `j > i` has a type mentioning `extra[i]`.
  let mut changed := true
  while changed do
    changed := false
    for j in [:extra.size] do
      if pinned.contains j then continue
      let ty ← inferType extra[j]!
      let fvs := (collectFVars {} ty).fvarIds
      for i in [:j] do
        if pinned.contains i && fvs.contains extra[i]!.fvarId! then
          pinned := pinned.erase i
          changed := true
  let mut kept : Array Nat := #[]
  let mut pins : Array (Nat × Expr × Bool) := #[]
  for i in [:extra.size] do
    match pinned.get? i with
    | some (rhs, isH) => pins := pins.push (i, rhs, isH)
    | none => kept := kept.push i
  return (kept, pins)

/-- Substitute pinned parameters `(xᵢ := rhsᵢ)` sequentially into `body`, using `Eq.ndrec` /
`eq_of_heq` so dependent types stay kernel-valid!
Proves: `∀ (hpins : pin₁ ∧ ... ∧ pinₚ), body ↔ bodySubst`! -/
private def withLocalDeclsDList (tys : List Expr) (k : Array Expr → MetaM α)
    (acc : Array Expr := #[]) : MetaM α :=
  match tys with
  | [] => k acc
  | ty :: rest => withLocalDeclD `hp ty fun h => withLocalDeclsDList rest k (acc.push h)

/-- Build `bodySubst` (with pinned params replaced by their `rhs`s) and prove
`∀ (hp₁ : pinProp₁) ... (hpₚ : pinPropₚ), body ↔ bodySubst` using sequential `Eq.ndrec` /
`eq_of_heq` over fresh fvar hypotheses so dependent `Eq` → `HEq` chains typecheck cleanly. -/
private partial def buildSubstIff (extra : Array Expr) (pins : List (Nat × Expr × Bool))
    (pinProps : List Expr) (body : Expr) : MetaM (Expr × Expr) := do
  let rec substOnly (e : Expr) : List (Nat × Expr × Bool) → Expr
    | [] => e
    | (idx, rhs, _) :: rest => substOnly (e.replaceFVars #[extra[idx]!] #[rhs]) rest
  let bodySubst := substOnly body pins
  let prf ← withLocalDeclsDList pinProps fun pinFVars => do
    let inner ← buildSubstIffProof extra pins body bodySubst pinFVars.toList
    mkLambdaFVars pinFVars inner
  return (bodySubst, prf)
where
  buildSubstIffProof (extra' : Array Expr) (rem : List (Nat × Expr × Bool))
      (curBody curSubst : Expr) (pinHyps : List Expr) : MetaM Expr := do
    match rem, pinHyps with
    | [], [] =>
      return mkApp (mkConst ``Iff.refl) curBody
    | (idx, rhs, _) :: rest, hp :: restHyps =>
      let x := extra'[idx]!
      let hpTy ← inferType hp
      let eqPrf ← if hpTy.isAppOfArity ``HEq 4 then
          mkAppM ``eq_of_heq #[hp]
        else
          pure hp
      let laterVars := extra'.extract (idx + 1) extra'.size
      let goal ← mkAppM ``Iff #[curBody, curSubst]
      let innerTy ← mkForallFVars (laterVars ++ restHyps.toArray) goal
      let motive ← mkLambdaFVars #[x] innerTy
      let atRhs := innerTy.replaceFVars #[x] #[rhs]
      let prfAtRhs ← forallBoundedTelescope atRhs (some (laterVars.size + restHyps.length)) fun ys _ => do
        let newLater := ys.extract 0 laterVars.size
        let newHyps := ys.extract laterVars.size ys.size
        let mut extra'' := extra'
        for k in [:laterVars.size] do
          extra'' := extra''.set! (idx + 1 + k) newLater[k]!
        let nextBody := (curBody.replaceFVars #[x] #[rhs]).replaceFVars laterVars newLater
        let nextSubst := curSubst.replaceFVars laterVars newLater
        let sub ← buildSubstIffProof extra'' rest nextBody nextSubst newHyps.toList
        mkLambdaFVars ys sub
      let transported ← mkAppOptM ``Eq.ndrec #[none, some rhs, some motive, some prfAtRhs, some x,
        some (← mkEqSymm eqPrf)]
      return mkAppN transported (laterVars ++ restHyps.toArray)
    | _, _ => throwError "ReachCore: internal pin/hyp length mismatch"

/-- Extract proof of `pinProp` from `h : body` using `findPin`. -/
private def provePinFromBody (x : Expr) (isH : Bool) (body h : Expr) : MetaM Expr := do
  let some (_, prf, isH') ← findPin x body h true
    | throwError "ReachCore: failed to re-extract pin for {x}"
  if isH && !isH' then
    mkAppM ``heq_of_eq #[prf]
  else if !isH && isH' then
    mkAppM ``eq_of_heq #[prf]
  else
    pure prf

private def compileReach (n : Name) : Gen Unit := do
  let ci ← getConstInfo n
  lambdaTelescope ci.value! fun xs rawBody => do
    let base := xs.extract 0 4
    let extra := xs.extract 4 xs.size
    -- Phase 1: rewrite direct child reaches and eliminate newly pinned existentials
    let (body1, iff1) ← normBody rawBody
    -- Phase 2: factor out functionally pinned parameters
    let (keptIdxs, pins) ← selectPinnedParams base extra body1
    let keptVars := keptIdxs.map (extra[·]!)
    let coreParams := base ++ keptVars
    let cName := coreName n
    let iName := iffName n
    let ls := ci.levelParams.map mkLevelParam
    if pins.isEmpty then
      -- No parameters factored; core_k takes all xs directly
      let coreVal ← mkLambdaFVars xs body1
      addDecl <| .defnDecl {
        name := cName, levelParams := ci.levelParams, type := ← inferType coreVal,
        value := coreVal, hints := .abbrev, safety := .safe }
      let oldApp := mkAppN (mkConst n ls) xs
      let newApp := mkAppN (mkConst cName ls) xs
      addDecl <| .thmDecl {
        name := iName, levelParams := ci.levelParams,
        type := ← mkForallFVars xs (mkApp2 (mkConst ``Iff) oldApp newApp),
        value := ← mkLambdaFVars xs iff1 }
      modify fun st => { st with
        infos := st.infos.insert n ⟨cName, iName, keptIdxs, extra.size, 0⟩
        totalReaches := st.totalReaches + 1
        zeroCoreReaches := st.zeroCoreReaches + (if keptIdxs.isEmpty then 1 else 0) }
    else
      -- Build pin propositions: `Eq extra[i] rhs` or `HEq extra[i] rhs`
      let pinProps ← pins.mapM fun (idx, rhs, isH) => do
        if isH then mkHEq extra[idx]! rhs else mkEq extra[idx]! rhs
      let (bodySubst, substIffFn) ← buildSubstIff extra pins.toList pinProps.toList body1
      -- Clean trivial `a = a` / `HEq a a` / `True ∧ P` in `bodySubst`
      let (coreBody, iffClean) ← normBody bodySubst
      let coreVal ← mkLambdaFVars coreParams coreBody
      addDecl <| .defnDecl {
        name := cName, levelParams := ci.levelParams, type := ← inferType coreVal,
        value := coreVal, hints := .abbrev, safety := .safe }
      let coreApp := mkAppN (mkConst cName ls) coreParams
      let rhsConj := mkAndList (coreApp :: pinProps.toList)
      -- Prove `body1 ↔ coreBody ∧ pinProps`
      let fwd ← withLocalDeclD `h1 body1 fun h1 => do
        let pinPrfs ← pins.mapM fun (idx, _, isH) =>
          provePinFromBody extra[idx]! isH body1 h1
        let substIff := mkAppN substIffFn pinPrfs
        let hSubst ← mkAppM ``Iff.mp #[substIff, h1]
        let hCore ← mkAppM ``Iff.mp #[iffClean, hSubst]
        -- Pack `hCore :: pinPrfs` into right-associated `And.intro`
        let allPrfs := #[hCore] ++ pinPrfs
        let mut acc := allPrfs.back!
        for j in (List.range (allPrfs.size - 1)).reverse do
          acc ← mkAppM ``And.intro #[allPrfs[j]!, acc]
        mkLambdaFVars #[h1] acc
      let bwd ← withLocalDeclD `hr rhsConj fun hr => do
        -- Unpack `hr` into `hCore` and `pinPrfs`
        let mut cur := hr
        let hCore ← mkAppM ``And.left #[cur]
        cur ← mkAppM ``And.right #[cur]
        let mut pinPrfs : Array Expr := #[]
        for j in [:pins.size] do
          if j + 1 == pins.size then
            pinPrfs := pinPrfs.push cur
          else
            pinPrfs := pinPrfs.push (← mkAppM ``And.left #[cur])
            cur ← mkAppM ``And.right #[cur]
        let hSubst ← mkAppM ``Iff.mpr #[iffClean, hCore]
        let substIff := mkAppN substIffFn pinPrfs
        let h1 ← mkAppM ``Iff.mpr #[substIff, hSubst]
        mkLambdaFVars #[hr] h1
      let iff2 ← mkAppM ``Iff.intro #[fwd, bwd]
      let iffTotal ← mkAppM ``Iff.trans #[iff1, iff2]
      let oldApp := mkAppN (mkConst n ls) xs
      addDecl <| .thmDecl {
        name := iName, levelParams := ci.levelParams,
        type := ← mkForallFVars xs (mkApp2 (mkConst ``Iff) oldApp rhsConj),
        value := ← mkLambdaFVars xs iffTotal }
      modify fun st => { st with
        infos := st.infos.insert n ⟨cName, iName, keptIdxs, extra.size, pins.size⟩
        factoredParams := st.factoredParams + pins.size
        totalReaches := st.totalReaches + 1
        zeroCoreReaches := st.zeroCoreReaches + (if keptIdxs.isEmpty then 1 else 0) }

private def compileStep (n : Name) : Gen Unit := do
  let ci ← getConstInfo n
  lambdaTelescope ci.value! fun xs rawBody => do
    let (body1, iff1) ← normBody rawBody
    let sName := stepName n
    let iName := iffName n
    let val ← mkLambdaFVars xs body1
    addDecl <| .defnDecl {
      name := sName, levelParams := ci.levelParams, type := ← inferType val,
      value := val, hints := .abbrev, safety := .safe }
    let ls := ci.levelParams.map mkLevelParam
    let oldApp := mkAppN (mkConst n ls) xs
    let newApp := mkAppN (mkConst sName ls) xs
    addDecl <| .thmDecl {
      name := iName, levelParams := ci.levelParams,
      type := ← mkForallFVars xs (mkApp2 (mkConst ``Iff) oldApp newApp),
      value := ← mkLambdaFVars xs iff1 }

private def compileAll : MetaM Unit := do
  let env ← getEnv
  -- Collect all reaches and topologically sort them bottom-up
  let mut reachDeps : Std.HashMap Name (Array Name) := {}
  let mut reaches : Array Name := #[]
  for (n, c) in env.constants.toList do
    unless n.getPrefix == srcNs && n.getString!.startsWith "reach_" do continue
    let .defnInfo d := c | continue
    reaches := reaches.push n
    let deps := d.value.getUsedConstants.filter fun x =>
      x.getPrefix == srcNs && x.getString!.startsWith "reach_"
    reachDeps := reachDeps.insert n deps
  let mut placed : Std.HashSet Name := {}
  let mut topo : Array Name := #[]
  let mut changed := true
  while changed do
    changed := false
    for r in reaches do
      if placed.contains r then continue
      if (reachDeps.getD r #[]).all placed.contains then
        placed := placed.insert r
        topo := topo.push r
        changed := true
  unless topo.size == reaches.size do
    throwError "ReachCore: cycle detected ({topo.size}/{reaches.size})"

  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope ci.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "ReachCore: unexpected SolvedWitnesses.dispatch"
    let stepNames ← (args.extract 2 args.size).mapM fun arm => do
      let some n := arm.getAppFn.constName? | throwError "ReachCore: expected step constant"
      return n
    let (_, st) ← (do
      for r in topo do compileReach r
      for s in stepNames do compileStep s).run {}
    let ls := ci.levelParams.map mkLevelParam
    let params := xs.extract 0 4
    let dispVal := mkAppN body.getAppFn ((args.extract 0 2) ++
      stepNames.map fun n => mkAppN (mkConst (stepName n) ls) params)
    let dispName := dstNs ++ `dispatch
    addDecl <| .defnDecl {
      name := dispName, levelParams := ci.levelParams, type := ci.type,
      value := ← mkLambdaFVars xs dispVal, hints := .abbrev, safety := .safe }
    let ty := mkApp2 (mkConst ``Iff) (mkAppN (mkConst ci.name ls) xs) (mkAppN (mkConst dispName ls) xs)
    let motive ← mkLambdaFVars #[xs[4]!] ty
    let proof := mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero])
      (#[motive, xs[4]!] ++ stepNames.map fun n => mkAppN (mkConst (iffName n) ls) params)
    addDecl <| .thmDecl {
      name := dispName.appendAfter "_iff", levelParams := ci.levelParams,
      type := ← mkForallFVars xs ty, value := ← mkLambdaFVars xs proof }
    logInfo m!"ReachCore: {st.totalReaches} reaches ({st.zeroCoreReaches} 0-arity cores), \
      {st.factoredParams} params factored, {st.elimEq} existentials eliminated; \
      {stepNames.size} step roots normalized"

end

local elab "build_reach_core" : command => Lean.Elab.Command.liftTermElabM compileAll
build_reach_core

public def sig [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (b : Classes.StepBranch) : Prop := dispatch f t c b

public theorem sig_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    (b : Classes.StepBranch) : SolvedWitnesses.sig c b ↔ sig c b := dispatch_iff f t c b

end ConsensusCoverage.ReachCore
