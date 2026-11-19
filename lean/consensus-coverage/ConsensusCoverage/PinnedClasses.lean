module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-!
# Generated step classes with a common context

Specialize the existing step formula DAG, without rewalking the proof. Add an equality
at each existential binding a witness of the root `Ctx f after` (or its transition
`LocalTransition f.current after`). Keep the original witnesses, their dependent
telescopes, all branch conditions, and all clause arguments. Every copy of a `reach_*`
call receives the same context, including calls inside other `reach_*` definitions.
When a transition is forwarded at dependent endpoints, its existing call-site
equations must already identify it with `c.tr`; the pass proves this, rather than
adding an equality between endpoint variables.

This concerns the recorded/generated classes only. It is not a reconstruction of
unrecorded splits or a converse to the proved weakening.

Use `sig c b` for the indexed question and `sig_imp c b` to weaken its answer.
Like `Classes`, this module keeps generated definition bodies behind `import all`
for proofs that need to unfold a named `step_*` predicate or its reach DAG.
-/

namespace ConsensusCoverage.PinnedClasses

open Consensus Consensus.Proofs Consensus.Proofs.Safety

private theorem forgetExists {α : Sort u} {P Q : α → Prop}
    (h : ∀ a, P a → Q a) : (∃ a, P a) → ∃ a, Q a :=
  fun ⟨a, p⟩ => ⟨a, h a p⟩

private theorem forgetPinned {α : Sort u} (chosen : α) {P Q : α → Prop}
    (h : ∀ a, P a → Q a) : (∃ a, a = chosen ∧ P a) → ∃ a, Q a :=
  fun ⟨a, _, p⟩ => ⟨a, h a p⟩

/-- The first argument certifies that a forwarded witness needs no extra conjunct. -/
private theorem forgetForwarded {α β : Sort u} (chosen : β) {P Q : α → Prop}
    (_ : ∀ a, P a → HEq a chosen) (h : ∀ a, P a → Q a) :
    (∃ a, P a) → ∃ a, Q a :=
  forgetExists h

meta section

open Lean Meta Elab Command

private def source := `ConsensusCoverage.Classes
private def target := `ConsensusCoverage.PinnedClasses

private def generated (n : Name) (stem : String) : Bool :=
  match n with
  | .str ns s => ns == source && s.startsWith stem
  | _ => false

private def copyName (n : Name) : Name := target ++ Name.mkSimple n.getString!
private def forgetName (n : Name) : Name := (copyName n).appendAfter "_imp"

private structure Stats where
  done : Std.HashSet Name := {}
  active : Std.HashSet Name := {}
  contexts : Nat := 0
  transitions : Nat := 0
  forwarded : Nat := 0

private abbrev Gen := StateRefT Stats MetaM

private structure Anchor where
  root : Array Expr
  ctx : Expr
  tr : Expr
  ctxType : Expr
  trType : Expr

private structure Change where
  pred : Expr
  forget : Expr

private def witnessHead (t : Expr) : Bool :=
  t.isAppOf ``Ctx || t.isAppOf ``LocalTransition

/-- Atomic conditions are copied literally. Reject hidden generated calls or witness binders,
rather than e.g. accidentally treating a reachability call under a negation as positive. -/
private def checkAtom (e : Expr) : MetaM Unit := do
  if let some bad := e.find? fun t => match t with
      | .const n _ => source.isPrefixOf n
      | .lam _ d _ _ | .forallE _ d _ _ | .letE _ d _ _ _ => witnessHead d
      | _ => (t.isAppOfArity ``Exists 2 || t.isAppOfArity ``Nonempty 1) &&
          witnessHead (t.getArg! 0) then
    throwError "unsupported occurrence {bad} in {e}"

private def orIdentity (e : Expr) (change : Option Change) : MetaM Change :=
  match change with
  | some ch => pure ch
  | none => return ⟨e, ← mkAppOptM ``id #[some e]⟩

private def addDefinition (name : Name) (levels : List Name) (value : Expr) : MetaM Unit := do
  addDecl <| .defnDecl {
    name, levelParams := levels, type := ← inferType value, value
    hints := .abbrev, safety := .safe }

private def addProof (name : Name) (levels : List Name) (type value : Expr) : MetaM Unit := do
  addDecl <| .thmDecl { name, levelParams := levels, type, value }

/-- The forwarded argument either has the desired equality literally, or is equated to
`tr`/`c.tr` for a witness that was itself pinned. Use its homogeneous pin to transport
the heterogeneous call-site equality. -/
private def forwardingEquality (x tr : Expr) (facts : List (Expr × Expr)) : MetaM Expr := do
  let goal ← mkHEq x tr
  for (p, h) in facts do
    if p == goal then return h
    unless p.isAppOfArity ``HEq 4 && p.getArg! 1 == x do continue
    for (q, pin) in facts do
      unless q.isAppOfArity ``Eq 3 do continue
      let old := q.getArg! 1
      unless old.isFVar do continue
      let rhs := p.getArg! 3
      unless ← isDefEq (rhs.replaceFVars #[old] #[q.getArg! 2]) tr do continue
      let motive ← withLocalDeclD `w (q.getArg! 0) fun w => do
        let body ← mkHEq x (rhs.replaceFVars #[old] #[w])
        mkLambdaFVars #[w] body
      return ← mkEqMP (← mkCongrArg motive pin) h
  throwError "call-site equations do not identify {x} with {tr}"

/-- Read the positive path conditions for `x`, in every disjunct. Only unfold pinned
reach calls that actually take `x` as an argument; other reach conditions are irrelevant
to this certificate. -/
private partial def certifyForwarding (x tr : Expr) (pending : List (Expr × Expr))
    (facts : List (Expr × Expr) := []) : MetaM Expr := do
  let (p, h) :: rest := pending | forwardingEquality x tr facts
  if p.isAppOfArity ``And 2 then
    let l ← mkAppOptM ``And.left #[some (p.getArg! 0), some (p.getArg! 1), some h]
    let r ← mkAppOptM ``And.right #[some (p.getArg! 0), some (p.getArg! 1), some h]
    return ← certifyForwarding x tr ((p.getArg! 0, l) :: (p.getArg! 1, r) :: rest) facts
  if p.isAppOfArity ``Or 2 then
    let branch (q : Expr) := withLocalDeclD `h q fun hq => do
      mkLambdaFVars #[hq] (← certifyForwarding x tr ((q, hq) :: rest) facts)
    return ← mkAppM ``Or.elim #[h, ← branch (p.getArg! 0), ← branch (p.getArg! 1)]
  if p.isAppOfArity ``Exists 2 then
    let k ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let body := (p.getArg! 1).beta #[w]
      withLocalDeclD `h body fun hw => do
        mkLambdaFVars #[w, hw] (← certifyForwarding x tr ((body, hw) :: rest) facts)
    return ← mkAppM ``Exists.elim #[h, k]
  if let .const (.str ns name) _ := p.getAppFn then
    if ns == target && name.startsWith "reach_" && p.getAppArgs.contains x then
      let some body ← unfoldDefinition? p | throwError "cannot unfold forwarding call {p}"
      return ← certifyForwarding x tr ((body, h) :: rest) facts
  let facts := if p.isAppOf ``Eq || p.isAppOf ``HEq then (p, h) :: facts else facts
  certifyForwarding x tr rest facts

mutual

/-- Rewrite only the positive closure constructors emitted by the shared generator.
Return `none` on a checked, unchanged subtree. -/
private partial def specialize (a : Anchor) (e : Expr) : Gen (Option Change) := do
  let args := e.getAppArgs
  if (e.isAppOf ``And || e.isAppOf ``Or) && args.size == 2 then
    let l ← specialize a args[0]!
    let r ← specialize a args[1]!
    if l.isNone && r.isNone then return none
    let l ← orIdentity args[0]! l
    let r ← orIdentity args[1]! r
    let mono := if e.isAppOf ``And then ``And.imp else ``Or.imp
    return some ⟨mkApp2 e.getAppFn l.pred r.pred, ← mkAppM mono #[l.forget, r.forget]⟩
  if e.isAppOfArity ``Exists 2 then
    let ty := args[0]!
    checkAtom ty
    unless args[1]!.isLambda do throwError "expected a generated Exists lambda in {e}"
    let head ← withReducible <| whnf ty
    let (chosen, forwarded) ←
      if head.isAppOf ``Ctx then do
        unless ← isDefEq ty a.ctxType do
          throwError "not the root Ctx type: {ty}, expected {a.ctxType}"
        modify fun st => { st with contexts := st.contexts + 1 }
        pure (some a.ctx, false)
      else if head.isAppOf ``LocalTransition then do
        if ← isDefEq ty a.trType then
          modify fun st => { st with transitions := st.transitions + 1 }
          pure (some a.tr, false)
        else
          modify fun st => { st with forwarded := st.forwarded + 1 }
          pure (none, true)
      else pure (none, false)
    return ← withLocalDecl args[1]!.bindingName! args[1]!.bindingInfo! ty fun x => do
      let body := args[1]!.bindingBody!.instantiate1 x
      let change ← specialize a body
      if chosen.isNone && !forwarded && change.isNone then return none
      let ch ← orIdentity body change
      let body' ← match chosen with
        | some c => pure <| mkAnd (← mkEq x c) ch.pred
        | none => pure ch.pred
      let pred := mkApp2 e.getAppFn ty (← mkLambdaFVars #[x] body')
      let oldBody ← mkLambdaFVars #[x] body
      let newBody ← mkLambdaFVars #[x] ch.pred
      let proof ← mkLambdaFVars #[x] ch.forget
      let forget ← match chosen with
        | some c => mkAppOptM ``forgetPinned #[some ty, some c, some newBody, some oldBody, some proof]
        | none =>
          if forwarded then
            let cert ← withLocalDeclD `h ch.pred fun h => do
              mkLambdaFVars #[x, h] (← certifyForwarding x a.tr [(ch.pred, h)])
            mkAppOptM ``forgetForwarded
              #[some ty, some a.trType, some a.tr, some newBody, some oldBody, some cert, some proof]
          else
            mkAppOptM ``forgetExists #[some ty, some newBody, some oldBody, some proof]
      return some ⟨pred, forget⟩
  if let .const n levels := e.getAppFn then
    if generated n "reach_" then
      unless args.extract 0 a.root.size == a.root do
        throwError "reach call changes the root arguments: {e}"
      for arg in args do checkAtom arg
      compilePredicate n
      let args := a.root ++ #[a.ctx] ++ args.extract a.root.size args.size
      return some ⟨mkAppN (mkConst (copyName n) levels) args,
        mkAppN (mkConst (forgetName n) levels) args⟩
  checkAtom e
  return none

/-- Memoize by declaration so shared call paths remain shared in the pinned DAG. -/
private partial def compilePredicate (n : Name) : Gen Unit := do
  if (← get).done.contains n then return
  if (← get).active.contains n then throwError "cycle at {n}"
  modify fun st => { st with active := st.active.insert n }
  try
    let .defnInfo ci ← getConstInfo n | throwError "expected a predicate definition"
    lambdaTelescope ci.value fun xs body => do
      let root := xs.extract 0 3
      unless root.size == 3 && (← isProp body) do throwError "expected a step predicate"
      for x in xs do checkAtom (← inferType x)
      let ctxType := mkAppN (mkConst ``Ctx) root
      withLocalDeclD `c ctxType fun ctx => do
        let tr := mkAppN (mkConst ``Ctx.tr) (root.push ctx)
        let trType ← inferType tr
        let change ← orIdentity body (← specialize ⟨root, ctx, tr, ctxType, trType⟩ body)
        let params := root ++ #[ctx] ++ xs.extract 3 xs.size
        addDefinition (copyName n) ci.levelParams (← mkLambdaFVars params change.pred)
        let ls := ci.levelParams.map mkLevelParam
        let lhs := mkAppN (mkConst (copyName n) ls) params
        let rhs := mkAppN (mkConst n ls) xs
        addProof (forgetName n) ci.levelParams
          (← mkForallFVars params (← mkArrow lhs rhs)) (← mkLambdaFVars params change.forget)
  catch ex =>
    throwError "while specializing {n}: {ex.toMessageData}"
  modify fun st => { st with done := st.done.insert n, active := st.active.erase n }

end

private def compile : MetaM Unit := do
  let sig ← getConstInfo ``Classes.sig
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope sig.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 4 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[3]! do
      throwError "unexpected generated Classes.sig dispatcher"
    let root := xs.extract 0 3
    let names ← (args.extract 2 args.size).mapM fun arm => do
      let some n := arm.getAppFn.constName? | throwError "unexpected dispatcher arm {arm}"
      unless generated n "step_" && arm.getAppArgs == root do
        throwError "unexpected dispatcher arm {arm}"
      return n
    let declared := (← getEnv).constants.toList.filterMap fun (n, ci) =>
      if generated n "step_" && (ci matches .defnInfo _) then some n else none
    unless names.toList.Nodup && declared.length == names.size &&
        declared.all names.contains do
      throwError "StepBranch, Classes.sig, and the step predicate declarations disagree"
    let (_, stats) ← (names.forM compilePredicate).run {}
    withLocalDeclD `c (mkAppN (mkConst ``Ctx) root) fun ctx => do
      let b := xs[3]!
      let params := root.push ctx
      let ls := sig.levelParams.map mkLevelParam
      let dispatch := target ++ `dispatch
      let pinnedArms := names.map fun n => mkAppN (mkConst (copyName n) ls) params
      let pinned := mkAppN body.getAppFn (#[args[0]!, b] ++ pinnedArms)
      addDefinition dispatch sig.levelParams (← mkLambdaFVars (params.push b) pinned)
      let ty ← mkArrow (mkAppN (mkConst dispatch ls) (params.push b))
        (mkAppN (mkConst ``Classes.sig ls) xs)
      let motive ← mkLambdaFVars #[b] ty
      let proofs := names.map fun n => mkAppN (mkConst (forgetName n) ls) params
      let proof := mkAppN (mkConst ``Classes.StepBranch.casesOn [Level.zero])
        (#[motive, b] ++ proofs)
      addProof (target ++ `dispatch_imp) sig.levelParams
        (← mkForallFVars (params.push b) ty) (← mkLambdaFVars (params.push b) proof)
    logInfo m!"pinned {names.size}/{declared.length} step predicates; \
      {stats.done.size - names.size} reachable reach definitions; \
      {stats.contexts} Ctx and {stats.transitions} LocalTransition binding sites pinned; \
      {stats.forwarded} dependent LocalTransition binding sites certified by call-site equations"

end

@[expose] public section

local elab "generate_pinned_classes" : command => Lean.Elab.Command.liftTermElabM compile
generate_pinned_classes

/-- Ask one generated step question using the actual common context `c`. -/
def sig [Config.InitialConfiguration] {f : Frame} {after : Model.State}
    (c : Ctx f after) (b : Classes.StepBranch) : Prop :=
  dispatch f after c b

/-- Forget all context equalities, recovering the original closed step question. -/
theorem sig_imp [Config.InitialConfiguration] {f : Frame} {after : Model.State}
    (c : Ctx f after) (b : Classes.StepBranch) :
    sig c b → Classes.sig f after b :=
  dispatch_imp f after c b

end
end ConsensusCoverage.PinnedClasses
