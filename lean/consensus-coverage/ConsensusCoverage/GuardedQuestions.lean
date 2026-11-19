module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! Compile normalized path formulas to finite Boolean searches. A successful
compilation emits both executable code and a kernel-checked equivalence; an
unsupported formula is not a negative answer. -/

namespace ConsensusCoverage.GuardedQuestions

open ActionProfile FullProfile GuardedDomain
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

private theorem guard_any {α : Type u} (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (bounded : ∀ x, p x → x ∈ xs)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.attach.any fun x => test x.1 x.2) = true ↔ ∃ x, p x := by
  constructor
  · intro yes
    obtain ⟨⟨x, mem⟩, _, pass⟩ := List.any_eq_true.mp yes
    exact ⟨x, (pointwise x mem).mp pass⟩
  · rintro ⟨x, hx⟩
    exact List.any_eq_true.mpr ⟨⟨x, bounded x hx⟩, List.mem_attach .., (pointwise x _).mpr hx⟩

private theorem and_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (a && b) = true ↔ p ∧ q := (LeaderEffect.and_true).trans (and_congr hp hq)

private theorem or_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (a || b) = true ↔ p ∨ q := by rw [Bool.or_eq_true, hp, hq]

private theorem not_cert {a : Bool} {p : Prop} (hp : a = true ↔ p) :
    (!a) = true ↔ ¬ p := by simp [← hp]

private def picked (value : Option Bool) (p : Prop) : Prop :=
  match value with
  | none => True
  | some yes => yes = true ↔ p

private theorem picked_some {o : Option Bool} {v : Bool} (h : o = some v)
    {p : Prop} (hp : picked o p) : v = true ↔ p := by
  cases h
  exact hp

private theorem exists_mem_iff {α : Type u} (l : List α) : (∃ x, x ∈ l) ↔ l ≠ [] :=
  ⟨fun ⟨_, h⟩ => List.ne_nil_of_mem h, List.exists_mem_of_ne_nil _⟩

meta section

open Lean Meta Elab Command

private abbrev Compiled := Expr × Expr -- Bool, and its equivalence certificate

private def normalized := `ConsensusCoverage.SolvedWitnesses

private def reach? (p : Expr) : Option Name := do
  let n ← p.constName?
  if n.getPrefix == normalized && n.getString!.startsWith "reach_" then some n else none

/-- Find a guard that the whole conjunction entails. Never use a guard from
just one disjunct, nor one whose list depends on the very witness it bounds. -/
private partial def findGuard (x p h : Expr) : MetaM (Option (Expr × Expr)) := do
  let args := p.getAppArgs
  if p.isAppOfArity ``Membership.mem 5 && args[4]! == x &&
      args[1]!.isAppOfArity ``List 1 && !args[3]!.containsFVar x.fvarId! then
    return some (args[3]!, h)
  if p.isAppOfArity ``And 2 then
    let l := p.getArg! 0
    let r := p.getArg! 1
    let args := #[some l, some r, some h]
    if let some hit ← findGuard x l (← mkAppOptM ``And.left args) then return some hit
    return ← findGuard x r (← mkAppOptM ``And.right args)
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `inner (p.getArg! 0) fun y => do
      let q := p.appArg!.beta #[y]
      withLocalDeclD `h q fun hq => do
        let some (list, mem) ← findGuard x q hq | return none
        if list.containsFVar y.fvarId! then return none
        let proof ← mkLambdaFVars #[y, hq] mem
        return some (list, ← mkAppM ``Exists.elim #[h, proof])
  return none

private def addRule (rules : SimpTheorems) (proof : Expr) (post := true) : MetaM SimpTheorems :=
  rules.add (.other ((`guardedRule).appendIndexAfter proof.hash.toNat)) #[] proof (post := post)

private def simplify (p : Expr) (rules : SimpTheorems) : MetaM Simp.Result := do
  let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
  return (← simp p ctx).1

private def recertify (r : Simp.Result) (proof : Expr) : MetaM Expr := do
  let some eq := r.proof? | return proof
  mkAppM ``Iff.trans #[proof, ← mkAppM ``Iff.symm #[← mkIffOfEq eq]]

private partial def reflect (p : Expr) (rules : SimpTheorems) : MetaM (Option Compiled) := do
  if p.isAppOfArity ``And 2 || p.isAppOfArity ``Or 2 then
    let some (l, pl) ← reflect (p.getArg! 0) rules | return none
    let some (r, pr) ← reflect (p.getArg! 1) rules | return none
    let isAnd := p.isAppOf ``And
    return some (mkApp2 (mkConst (if isAnd then ``Bool.and else ``Bool.or)) l r,
      ← mkAppM (if isAnd then ``and_cert else ``or_cert) #[pl, pr])
  if p.isAppOfArity ``Not 1 then
    let some (b, h) ← reflect p.appArg! rules | return none
    return some (mkApp (mkConst ``Bool.not) b, ← mkAppM ``not_cert #[h])
  if p.isAppOfArity ``Exists 2 then
    let pred := p.getArg! 1
    return ← withLocalDeclD `x (p.getArg! 0) fun x => do
      let inner := pred.beta #[x]
      let found ← withLocalDeclD `h inner fun h => do
        let some (list, mem) ← findGuard x inner h | return none
        return some (list, ← mkLambdaFVars #[x, h] mem)
      let some (list, bounded) := found | return none
      let mem ← mkAppM ``Membership.mem #[list, x]
      withLocalDeclD `mem mem fun hm => do
        let inner' ← simplify inner (← addRule rules hm)
        let some (b, proof) ← reflect inner'.expr rules | return none
        let test ← mkLambdaFVars #[x, hm] b
        let pointwise ← mkLambdaFVars #[x, hm] (← recertify inner' proof)
        let iff ← mkAppM ``guard_any #[list, pred, test, bounded, pointwise]
        let ty ← inferType iff
        return some (ty.getArg! 0 |>.getArg! 1, iff)
  let .some d ← trySynthInstance (mkApp (mkConst ``Decidable) p) | return none
  return some (mkApp2 (mkConst ``decide) p d, mkApp2 (mkConst ``decide_eq_true_iff) p d)

private def readerName := `ConsensusCoverage.GuardedQuestions.readView
private def coveredName := `ConsensusCoverage.GuardedQuestions.generatedColumns
private def correctName := `ConsensusCoverage.GuardedQuestions.readView_correct

private def compile : MetaM Unit := do
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  let branchTy := mkConst ``Classes.StepBranch
  let casesOn (level : Level) (motive b : Expr) (arms : Array Expr) :=
    mkAppN (mkConst ``Classes.StepBranch.casesOn [level]) (#[motive, b] ++ arms)
  lambdaTelescope ci.value! fun xs body => do
    let args := body.getAppArgs
    let params := xs.extract 0 4
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "unexpected normalized dispatcher"
    let armProps ← (args.extract 2 args.size).mapM fun arm => do
      let .const n us := arm.getAppFn | throwError "expected generated arm"
      unless n.getPrefix == normalized && n.getString!.startsWith "step_" && arm.getAppArgs == params do
        throwError "unexpected normalized arm {arm}"
      let ci ← getConstInfo n
      return (ci.value!.instantiateLevelParams ci.levelParams us).beta params

    -- This family has state, log-index and historical-observation guards.
    -- These are shared DAG nodes, not a list of supported columns.
    let roots := #[``SolvedWitnesses.reach_0, ``SolvedWitnesses.reach_1, ``SolvedWitnesses.reach_9,
      ``SolvedWitnesses.reach_10, ``SolvedWitnesses.reach_39]
    let mut basic : SimpTheorems := {}
    for r in #[``eq_self, ``and_true, ``true_and, ``or_false, ``false_or,
        ``exists_const, ``and_assoc, ``not_false_eq_true, ``not_true_eq_false] do
      basic ← basic.addConst r
    let mut unfoldRules := basic
    for n in roots do unfoldRules ← unfoldRules.addDeclToUnfold n

    let inst := xs[0]!
    let f := xs[1]!
    let t := xs[2]!
    let c := xs[3]!
    let b := xs[4]!
    withLocalDeclD `v (mkConst ``View) fun v =>
    withLocalDeclD `ok (mkAppN (mkConst ``View.Matches) #[inst, f, t, v, c]) fun ok => do
      let matchRule (n : Name) (post : Bool) (rs : SimpTheorems) :=
        addRule rs (mkAppN (mkConst n) #[inst, f, t, v, c, ok]) post
      let mut first := unfoldRules
      let now := mkAppN (mkConst ``any_fresh_now) #[inst, f, t, c]
      first ← addRule first now
      for r in #[``View.any_fresh_canon, ``View.other_log] do
        first ← matchRule r true first
      let mut second := basic
      for r in #[``View.old_post, ``View.led_before, ``View.led_after, ``View.canon_before,
          ``View.seen_before, ``View.seen_after] do
        second ← matchRule r false second
      for r in #[``View.pre_eq, ``View.post_eq, ``View.actor_eq, ``View.before_eq, ``View.after_eq] do
        second ← matchRule r true second
      for r in #[``Ctx.pre_now, ``Ctx.post_now, ``Ctx.term_le] do
        second ← addRule second (mkAppN (mkConst r) #[inst, f, t, c]) false
      second ← second.addConst ``exists_mem_iff
      second ← second.addConst ``sig_index
      second ← second.addDeclToUnfold ``Engaged

      let mut results := #[]
      for p in armProps do
        let some _ := p.find? (fun e => (reach? e).isSome) | do
          results := results.push none
          continue
        if (p.find? (fun e => (reach? e).any fun n => !roots.contains n)).isSome then
          results := results.push none
          continue
        let p₁ ← simplify p first
        let p₂ ← simplify p₁.expr second
        let some (value, proof) ← reflect p₂.expr basic | do
          results := results.push none
          continue
        if params.any (fun x => value.containsFVar x.fvarId!) then
          results := results.push none
          continue
        results := results.push (some (value, ← recertify p₁ (← recertify p₂ proof)))

      let ret := mkApp (mkConst ``Option [.zero]) (mkConst ``Bool)
      let values := results.map fun a => match a with
        | none => mkApp (mkConst ``Option.none [.zero]) (mkConst ``Bool)
        | some (value, _) => mkApp2 (mkConst ``Option.some [.zero]) (mkConst ``Bool) value
      addAndCompile <| .defnDecl {
        name := readerName, levelParams := [], type := ← mkForallFVars #[v, b] ret,
        value := ← mkLambdaFVars #[v, b] (casesOn (.succ .zero) (← mkLambdaFVars #[b] ret) b values),
        hints := .abbrev, safety := .safe }
      let covered := (branch.ctors.zip results.toList).filterMap fun (ctor, result) =>
        result.map fun _ => ctor
      let table ← mkListLit branchTy (covered.map mkConst)
      addAndCompile <| .defnDecl {
        name := coveredName, levelParams := [], type := ← inferType table,
        value := table, hints := .abbrev, safety := .safe }
      let goal := mkApp2 (mkConst ``picked) (mkApp2 (mkConst readerName) v b)
        (mkAppN (mkConst ci.name) xs)
      let proof := casesOn .zero (← mkLambdaFVars #[b] goal) b
        (results.map fun a => a.map Prod.snd |>.getD (mkConst ``True.intro))
      addDecl <| .thmDecl {
        name := correctName, levelParams := [],
        type := ← mkForallFVars (xs ++ #[v, ok]) goal,
        value := ← mkLambdaFVars (xs ++ #[v, ok]) proof }
      logInfo m!"guarded: {covered.length} exact columns: {covered}"

end

local elab "compile_guarded_questions" : command => Lean.Elab.Command.liftTermElabM compile
compile_guarded_questions

/-- The generated columns with a total reader on every initialized step. -/
public def covered : List Classes.StepBranch := generatedColumns

public theorem covered_count : covered.Nodup ∧ covered.length = 14 := by decide

/-- Evaluate several columns against one shared snapshot view. -/
public def answer (v : View) (b : Classes.StepBranch) : Option Bool := readView v b

/-- Read a generated coordinate of a recorded action. `none` is unsupported
(or a missing actor lookup), not a negative label. -/
public def read? (cfg : FullProfile.Configuration) (before after : Model.State) (past : List Model.State)
    (act : Model.Action) (b : Classes.StepBranch) : Option Bool := do
  let v ← ofAction cfg before after past act
  answer v b

private theorem supported (v : View) (b : Classes.StepBranch) :
    (readView v b).isSome = decide (b ∈ covered) := by
  cases b <;> rfl

public theorem read?_correct (s : Step) (b : Classes.StepBranch) {value : Bool}
    (known : read? s.cfg s.before s.after s.past s.act b = some value) :
    label s (.step b) = value := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := ofAction_matches s
  have h : readView v b = some value := by
    change (ofAction _ _ _ _ _ >>= fun v => readView v b) = some value at known
    rw [made] at known
    exact known
  have normalized : value = true ↔ SolvedWitnesses.sig s.context b :=
    picked_some h (@readView_correct (show Config.InitialConfiguration from inferInstance)
      s.frame s.after s.context b v ok)
  exact Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans
    ((SolvedWitnesses.sig_iff s.context b).trans normalized.symm))

public theorem read?_at (s : Step) {b : Classes.StepBranch} (h : b ∈ covered) :
    read? s.cfg s.before s.after s.past s.act b = some (label s (.step b)) := by
  obtain ⟨v, made, _⟩ := ofAction_matches s
  have yes : (readView v b).isSome := (supported v b).trans (decide_eq_true h)
  obtain ⟨out, eq⟩ := Option.isSome_iff_exists.mp yes
  have readEq : read? s.cfg s.before s.after s.past s.act b = some out := by
    change (ofAction _ _ _ _ _ >>= fun v => readView v b) = some out
    rw [made]
    exact eq
  rw [readEq, read?_correct s b readEq]

private def setup : FrontierRows.Run := ⟨{0, 1}, [0, 1, 2], []⟩

private def first (a : Model.Action)
    (ok : ((transitionSystem setup.cfg setup.nodes).step (FrontierRows.initial setup) a).isSome) :
    Step :=
  ⟨setup.cfg, setup.nodes, FrontierRows.initial setup, [], a, _,
    .initial (FrontierRows.initialized setup (by unfold FrontierRows.Run.valid; decide)),
    (Option.some_get ok).symm⟩

private def down := first (.local 0 (.timeout .checkQuorum)) (by decide +kernel)
private def backup := first (.local 2 (.initAsBackup [])) (by decide +kernel)

/-- In the same initialized deployment, the departing primary has a fresh
nonempty log state, but the newly initialized empty backup does not. -/
public theorem terms_sample :
    ∃ s t : Step, s.before = t.before ∧
      label s (.step .terms_now_after_inl) = true ∧
      label t (.step .terms_now_after_inl) = false :=
  ⟨down, backup, rfl,
    read?_correct down .terms_now_after_inl (by decide +kernel),
    read?_correct backup .terms_now_after_inl (by decide +kernel)⟩

end ConsensusCoverage.GuardedQuestions
