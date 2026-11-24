module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersPolar
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersShapes
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReadersCompiler
public meta import Lean

namespace ConsensusCoverage.ReadersPolarCompiler

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs
open ReadersAtoms ReadersPolar

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384

def picked (o : Option Bool) (p : Prop) : Prop :=
  match o with
  | none => True
  | some yes => yes = true ↔ p

theorem picked_some {o : Option Bool} {v : Bool} (h : o = some v)
    {p : Prop} (hp : picked o p) : v = true ↔ p := by
  cases h
  exact hp

theorem picked_answer {p : Prop} (a : Bool) (b : Unit → Bool)
    (yes : a = true → p) (no : b () = true → ¬ p) : picked (answer a b) p := by
  cases a
  · cases h : b () with
    | false => simp [answer, h, picked]
    | true => simpa [answer, h, picked] using no h
  · simpa [answer, picked] using yes rfl

theorem false_test {p : Prop} : false = true → p := by simp

meta section

open Lean Meta ReadersCompiler ReadersShapes

private structure PolarEnv where
  exact : Env
  pools : Expr
  memo : IO.Ref (Std.HashMap (Name × Bool) (Option (Name × Name)))

private def pole (yes : Bool) : String := if yes then "yes" else "no"

private def fromProof (h : Expr) : MetaM Compiled := do
  let .forallE _ eq _ _ ← inferType h | throwError "expected a soundness implication"
  unless eq.isAppOfArity ``Eq 3 do throwError "expected a Boolean premise"
  return (eq.getArg! 1, h)

private def fromExact (yes : Bool) (h : Expr) : MetaM Compiled := do
  fromProof (← mkAppM (if yes then ``exact_yes else ``exact_no) #[h])

private def transport (yes : Bool) (r : Simp.Result) (v : Compiled) : MetaM Compiled := do
  let some eq := r.proof? | return v
  return (v.1, ← mkAppM (if yes then ``recert_yes else ``recert_no) #[eq, v.2])

private def combine (l r : Option Compiled) : MetaM (Option Compiled) := do
  if let (some l, some r) := (l, r) then
    return some (← fromProof (← mkAppM ``either #[l.2, r.2]))
  return l.or r

private def poolFor (e : PolarEnv) (α : Expr) : MetaM (Option Expr) := do
  let attr := match α.getAppFn.constName? with
    | some ``Model.State => some ``Pools.states
    | some ``NodeID => some ``Pools.ids
    | some ``NodeState => some ``Pools.records
    | some ``Entry => some ``Pools.entries
    | some ``Model.Envelope => some ``Pools.envelopes
    | some ``Consensus.Model.Node.Message => some ``Pools.messages
    | some ``RequestVoteRequest => some ``Pools.requests
    | some ``RequestVoteResponse => some ``Pools.voteResponses
    | some ``AppendEntriesRequest => some ``Pools.appendRequests
    | some ``AppendEntriesResponse => some ``Pools.acknowledgements
    | some ``Configuration => some ``Pools.configurations
    | _ => none
  let attr ← if attr.isSome then pure attr
    else if ← isNatType α then pure (some ``Pools.naturals)
    else if α.isAppOf ``CCF.MultiNodeTransitionSystem.State &&
        (← withReducible (isDefEq α (mkConst ``Model.State))) then
      pure (some ``Pools.states)
    else if α.isAppOf ``CCF.Envelope &&
        (← withReducible (isDefEq α (mkConst ``Model.Envelope))) then
      pure (some ``Pools.envelopes)
    else if ← withReducible (isDefEq α (← mkAppM ``CCF.Finset #[mkConst ``NodeID])) then
      pure (some ``Pools.sets)
    else if ← withReducible (isDefEq α (mkApp (mkConst ``List [.zero]) (mkConst ``Entry))) then
      pure (some ``Pools.logs)
    else pure none
  if let some attr := attr then
    let field := mkApp (mkConst attr) e.pools
    if attr == ``Pools.states then return some field
    return some (← mkAppM ``Thunk.get #[field])
  if α.isConstOf ``Bool then
    return some (← mkListLit α [mkConst ``Bool.false, mkConst ``Bool.true])
  if α.isConstOf ``Role then
    return some (← mkListLit α ([``Role.none, ``Role.follower, ``Role.preVoteCandidate,
      ``Role.candidate, ``Role.primary].map mkConst))
  return none

private def exactCall (e : Env) (info : RInfo) (args : Array Expr) (yes : Bool) :
    CM (Option Compiled) := do
  let some (_, iff) := info.reader | return none
  let mut premises := #[]
  for cl in info.conds do
    let ty := cl.beta (#[e.inst, e.xv] ++ args)
    if let some h ← findLocal ty then
      premises := premises.push h
    else
      let r ← simplify e ty e.basic
      unless r.expr.isConstOf ``True do return none
      premises := premises.push (← mkEqMPR (← r.getProof) (mkConst ``True.intro))
  return some (← fromExact yes
    (mkAppN (mkConst iff) (#[e.inst, e.f, e.t, e.c, e.xv, e.ok] ++ args ++ premises)))

private def under (e : Env) (h p : Expr) : CM (Option SimpTheorems) := do
  let event := mkApp (mkConst ``XView.event) e.xv
  let mut rules := none
  let addRun (q proof : Expr) (rules : SimpTheorems) : MetaM SimpTheorems := do
    unless q.isAppOfArity ``Eq 3 && (q.getArg! 1 == event || q.appArg! == event) do
      return rules
    let eq ← if q.appArg! == event then pure proof else mkEqSymm proof
    addRule rules (← mkAppM ``X.run_for #[e.ok, eq]) (post := false)
  if p.isAppOfArity ``Eq 3 || p.isAppOfArity ``Membership.mem 5 then
    rules ← some <$> addRun p h (← addRule e.basic h)
  if let .const n _ := p.getAppFn then
    if isGenerated n then
      let info ← compileConst e n
      if let some args ← actualArgs e info p then
        for g in info.guards do
          let some (guard, proof) := g | continue
          let q := guard.beta (#[e.inst, e.xv] ++ args)
          if q.isAppOfArity ``Eq 3 && q.getArg! 1 != q.appArg! then
            let proof := mkAppN (mkConst proof)
              (#[e.inst, e.f, e.t, e.c, e.xv, e.ok] ++ args ++ #[h])
            rules ← some <$> addRun q proof (← addRule (rules.getD e.basic) proof)
  return rules

private def keyedPool (kind : GKind) (a : Expr) : MetaM (Option Expr) := do
  match kind with
  | .keyedSnd l k => return some (← mkAppM ``mem_sndPool #[l, k, a])
  | .keyedFst l k => return some (← mkAppM ``mem_fstPool #[l, k, a])
  | _ => return none

private def useKeyedPool (a : Expr) (g : Guard) : MetaM Guard := do
  let some iff ← keyedPool g.kind a | return g
  let mem ← mkAppM ``Iff.mpr #[iff, g.mem]
  return { g with list := (← inferType mem).getArg! 3, mem, how := .none }

private def existsGuard (e : Env) (α pred : Expr) : CM (Option (Guard × Expr × Expr)) := do
  withLocalDeclD `a α fun a => do
    let body := pred.beta #[a]
    withLocalDeclD `h body fun h => do
      let some g := pickGuard (← findGuards e a body h) | return none
      match g.kind with
      | .subst _ => return some (g, ← mkLambdaFVars #[a, h] g.mem, a)
      | _ =>
        if e.isFrame α then return none
        let g ← useKeyedPool a g
        return some (g, ← mkLambdaFVars #[a, h] g.mem, a)

private def forallGuard (e : Env) (α pred : Expr) : CM (Option (Guard × Expr × Expr)) := do
  withLocalDeclD `a α fun a =>
  forallTelescope (pred.beta #[a]) fun premises concl => do
    for h in premises do
      let typ ← inferType h
      unless ← isProp typ do continue
      let candidates ← findGuards e a typ h
      for g in candidates.qsort (·.rank < ·.rank) do
        let g ← useKeyedPool a g
        let value := match g.kind with | .subst a => a | _ => g.list
        if premises.any (fun h => value.containsFVar h.fvarId!) then continue
        if !(g.kind matches .subst ..) && e.isFrame α then continue
        let memTy ← inferType g.mem
        let bounded ← withLocalDeclD `no (mkApp (mkConst ``Not) memTy) fun no => do
          let impossible ← mkAppOptM ``absurd #[memTy, concl, g.mem, no]
          mkLambdaFVars #[a, no] (← mkLambdaFVars premises impossible)
        return some ({ g with how := .none }, bounded, a)
    return none

mutual

private partial def reflectS (e : PolarEnv) (n : Name) (yes : Bool)
    (p : Expr) (rules : SimpTheorems) : CM (Option Compiled) := do
  let r ← simplify e.exact p rules
  let some v ← reflectP e n yes r.expr | return none
  return some (← transport yes r v)

private partial def propositional (e : PolarEnv) (n : Name) (yes ex : Bool)
    (α pred : Expr) : CM (Option Compiled) := do
  let both := yes == ex
  let left ← reflectP e n both α
  if both && left.isNone then return none
  let right ← withLocalDeclD `h α fun h => do
    let rules ← under e.exact h α
    let rules ← if let some rules := rules then pure rules else addRule e.exact.basic h
    let some (b, pr) ← reflectS e n yes (pred.beta #[h]) rules | return none
    if b.containsFVar h.fvarId! then
      block n s!"{pole yes}:dependent_proof" ""
      return none
    return some (b, ← mkLambdaFVars #[h] pr)
  if both then
    let (some (a, ha), some (b, hb)) := (left, right) | return none
    let lemma := if ex then ``exists_prop_yes else ``forall_prop_no
    return some (← fromProof (← mkAppOptM lemma #[α, pred, a, b, ha, hb]))
  let left ← left.mapM fun (a, ha) => do
    let lemma := if ex then ``exists_prop_no_left else ``forall_prop_yes_left
    fromProof (← mkAppOptM lemma #[α, pred, a, ha])
  let right ← right.mapM fun (b, hb) => do
    let lemma := if ex then ``exists_prop_no_right else ``forall_prop_yes_right
    fromProof (← mkAppOptM lemma #[α, pred, b, hb])
  combine left right

private partial def guarded (e : PolarEnv) (n : Name) (yes ex : Bool)
    (α pred : Expr) (g : Guard) (bounded binder : Expr) : CM (Option Compiled) := do
  match g.kind with
  | .subst a =>
    let r ← simplify e.exact (pred.beta #[a]) e.exact.first
    let some v ← reflectS e n yes r.expr e.exact.second | return none
    let cert ← mkAppOptM (if ex then ``guard_subst else ``guard_forall_subst) #[α, pred, a, bounded]
    return some (← transport yes { expr := pred.beta #[a], proof? := some (← mkAppM ``propext #[cert]) }
      (← transport yes r v))
  | _ =>
    withLocalDeclD `a α fun a => do
    withLocalDeclD `mem (← mkAppM ``Membership.mem #[g.list, a]) fun mem => do
      let mut rules ← guardRules e.exact g a mem binder
      if let some iff ← keyedPool g.kind a then
        rules ← addRule rules (← mkAppM ``Iff.mp #[iff, mem])
      let some (b, cert) ← reflectS e n yes (pred.beta #[a]) rules | return none
      let test ← mkLambdaFVars #[a, mem] b
      let sound ← mkLambdaFVars #[a, mem] cert
      let proof ← match ex, yes with
        | true, true => mkAppOptM ``guarded_exists_yes #[α, pred, g.list, test, sound]
        | true, false => mkAppOptM ``exists_no #[α, pred, g.list, test, bounded, sound]
        | false, true => mkAppOptM ``forall_yes #[α, pred, g.list, test, bounded, sound]
        | false, false => mkAppOptM ``guarded_forall_no #[α, pred, g.list, test, sound]
      return some (← fromProof proof)

private partial def quantifier (e : PolarEnv) (n : Name) (yes ex : Bool) (p α pred : Expr) :
    CM (Option Compiled) := do
  if ← isProp α then return ← propositional e n yes ex α pred
  let bound ← if ex then existsGuard e.exact α pred else forallGuard e.exact α pred
  if let some (g, bounded, binder) := bound then
    if let some v ← guarded e n yes ex α pred g bounded binder then return some v
  if yes != ex then
    if ← isNatType α then
      if let some sat ← saturateNat ex pred then
        let rhs ← Core.betaReduce (← typeArg sat 1)
        if let some v ← reflectP e n yes rhs then
          return some (← transport yes { expr := rhs, proof? := some (← mkAppM ``propext #[sat]) } v)
    if α.isAppOf ``List && !ex then
      if let some (_, iff) ← applyIff ``backed_prefix_agreement p then
        let pr ← mkAppM ``Iff.mpr #[iff, mkConst ``True.intro]
        return some (← fromExact yes (← mkAppM ``ReadersShapes.proof_cert #[pr]))
    blockBinder n s!"{pole yes}:needs_bound" α pred
    return none
  if e.exact.isFrame α then
    blockBinder n s!"{pole yes}:binder_frame" α pred
    return none
  let some list ← poolFor e α | do
    blockBinder n s!"{pole yes}:no_pool" α pred
    return none
  withLocalDeclD `a α fun a => do
    let some (b, pr) ← reflectP e n yes (pred.beta #[a]) | return none
    let cert ← mkAppOptM (if yes then ``exists_yes else ``forall_no)
      #[α, pred, list, ← mkLambdaFVars #[a] b, ← mkLambdaFVars #[a] pr]
    return some (← fromProof cert)

private partial def reflectP (e : PolarEnv) (n : Name) (yes : Bool) (p : Expr) :
    CM (Option Compiled) := do
  let p := p.consumeMData
  let p ← if headName p == "other" then withReducible (whnf p) else pure p
  if p.isAppOfArity ``And 2 then
    let l := p.getArg! 0
    let r := p.appArg!
    let left ← reflectP e n yes l
    if yes && left.isNone then return none
    let right ← withLocalDeclD `left l fun h => do
      let out ← if let some rules ← under e.exact h l then reflectS e n yes r rules
        else reflectP e n yes r
      let some (b, pr) := out | return none
      if b.containsFVar h.fvarId! then return none
      return some (b, ← mkLambdaFVars #[h] pr)
    if yes then
      let (some (a, ha), some (b, hb)) := (left, right) | return none
      return some (← fromProof (← mkAppOptM ``and_yes #[l, r, a, b, ha, hb]))
    let left ← left.mapM fun (a, ha) => do
      fromProof (← mkAppOptM ``and_no_left #[l, r, a, ha])
    let right ← right.mapM fun (b, hb) => do
      fromProof (← mkAppOptM ``and_no_right #[l, r, b, hb])
    return ← combine left right
  if p.isAppOfArity ``Or 2 then
    let l := p.getArg! 0
    let r := p.appArg!
    let left ← reflectP e n yes l
    if !yes && left.isNone then return none
    let right ← reflectP e n yes r
    if !yes then
      let (some (a, ha), some (b, hb)) := (left, right) | return none
      return some (← fromProof (← mkAppOptM ``or_no #[l, r, a, b, ha, hb]))
    let left ← left.mapM fun (a, ha) => do
      fromProof (← mkAppOptM ``or_yes_left #[l, r, a, ha])
    let right ← right.mapM fun (b, hb) => do
      fromProof (← mkAppOptM ``or_yes_right #[l, r, b, hb])
    return ← combine left right
  if p.isAppOfArity ``Not 1 then
    let some (b, h) ← reflectP e n (!yes) p.appArg! | return none
    let h ← if yes then pure h else mkAppM ``not_no #[h]
    return some (b, h)
  if p.isAppOfArity ``Exists 2 then
    return ← quantifier e n yes true p (p.getArg! 0) p.appArg!
  if let .forallE arg α body bi := p then
    return ← quantifier e n yes false p α (.lam arg α body bi)
  if let .const callee _ := p.getAppFn then
    if isGenerated callee then
      let info ← compileConst e.exact callee
      let some args ← actualArgs e.exact info p | do
        block n s!"{pole yes}:call_shape" (shortName callee)
        return none
      if args.any e.exact.isFrame then
        block n s!"{pole yes}:call_frame" (shortName callee)
        return none
      if let some exact ← exactCall e.exact info args yes then return some exact
      let some (r, proof) ← compileP e callee info yes | do
        block n s!"{pole yes}:child" (shortName callee)
        return none
      return some (mkAppN (mkConst r) (#[e.exact.inst, e.exact.xv, e.pools] ++ args),
        mkAppN (mkConst proof) (#[e.exact.inst, e.exact.f, e.exact.t, e.exact.c,
          e.exact.xv, e.exact.ok, e.pools] ++ args))
  if let some h ← findLocal p then
    return some (← fromExact yes (← mkAppM ``ReadersShapes.proof_cert #[h]))
  if let some (_, pr) ← reflect e.exact n p then return some (← fromExact yes pr)
  blockAtom n s!"{pole yes}:atom" p
  return none

private partial def compileP (e : PolarEnv) (n : Name) (info : RInfo) (yes : Bool) :
    CM (Option (Name × Name)) := do
  let key := (n, yes)
  if let some v := (← e.memo.get)[key]? then return v
  e.memo.modify (·.insert key none)
  let result ← tryCatchRuntimeEx (emitP e n info yes) fun ex => do
    let text := (← ex.toMessageData.toString).take 350 |>.replace "\n" " " |>.replace "\t" " "
    block n s!"{pole yes}:exception" text
    return none
  e.memo.modify (·.insert key result)
  return result

private partial def emitP (e : PolarEnv) (n : Name) (info : RInfo) (yes : Bool) :
    CM (Option (Name × Name)) := do
  let env := e.exact
  let ci ← getConstInfo n
  unless ci.levelParams.isEmpty do return none
  let pre := #[env.inst, env.f, env.t, env.c] ++ (if info.hasC1 then #[env.c] else #[])
  forallTelescope (← instantiateForall ci.type pre) fun originals _ => do
    let mut args := #[]
    let mut params := #[]
    let tr ← env.transition
    for j in [:originals.size] do
      if let some (_, isTr) := info.pinned.find? (·.1 == j) then
        args := args.push (if isTr then tr else env.t)
      else
        let x := originals[j]!
        let ty ← inferType x
        if env.isFrame ty || info.pinned.any (fun (i, _) => ty.containsFVar originals[i]!.fvarId!) then
          block n s!"{pole yes}:param_frame" (headName ty)
          return none
        params := params.push x
        args := args.push x
    let p := ci.value!.beta (pre ++ args)
    let r ← if env.isFrame p then simplify env p env.first else pure { expr := p }
    let some (b, cert) ← reflectS e n yes r.expr env.second | return none
    let (_, cert) ← transport yes r (b, cert)
    if env.isFrame b then
      block n s!"{pole yes}:runtime_frame" ""
      return none
    let short := (pole yes ++ "_" ++ shortName n).toName
    let test := `ConsensusCoverage.ReadersPolarCompiler.R ++ short
    let sound := test.appendAfter "_sound"
    let rargs := #[env.inst, env.xv, e.pools] ++ params
    let pargs := #[env.inst, env.f, env.t, env.c, env.xv, env.ok, e.pools] ++ params
    let emit : MetaM Unit := commitIfNoEx do
      addReader <| .defnDecl {
        name := test, levelParams := [], type := ← mkForallFVars rargs (mkConst ``Bool),
        value := ← mkLambdaFVars rargs (← Core.betaReduce b), hints := .regular 0, safety := .safe }
      let lhs ← mkEq (mkAppN (mkConst test) rargs) (mkConst ``Bool.true)
      let call := mkAppN (mkConst n) (pre ++ args)
      let goal ← mkArrow lhs (if yes then call else mkApp (mkConst ``Not) call)
      addCertificate <| .thmDecl {
        name := sound, levelParams := [], type := ← mkForallFVars pargs goal,
        value := ← mkLambdaFVars pargs cert }
    emit
    return some (test, sound)

end

private def lookup (memo : Std.HashMap (Name × Bool) (Option (Name × Name)))
    (n : Name) (yes : Bool) : Option (Name × Name) := (memo[(n, yes)]?).join

public def readerName := `ConsensusCoverage.ReadersPolarCompiler.readView
public def correctName := `ConsensusCoverage.ReadersPolarCompiler.readView_correct

private def retained (env : Env) (n : Name) : MetaM RInfo := do
  let ci ← getConstInfo n
  unless ci.levelParams.isEmpty do return {}
  let short := shortName n
  let run := Name.mkStr `ConsensusCoverage.ReadersCompiler.R short
  let iff := Name.mkStr `ConsensusCoverage.ReadersCompiler.R (short ++ "_iff")
  let ty ← instantiateForall ci.type #[env.inst, env.f, env.t, env.c]
  let hasC1 := match ty with
    | .forallE _ d _ _ => d.isAppOf ``Consensus.Proofs.Safety.Ctx
    | _ => false
  let ty ← if hasC1 then instantiateForall ty #[env.c] else pure ty
  forallTelescope ty fun originals _ => do
    let tr ← env.transition
    let mut actuals := #[]
    let mut params := #[]
    let mut pinned := #[]
    for j in [:originals.size] do
      let x := originals[j]!
      let ty ← inferType x
      let specialized := ty.replaceFVars (originals.extract 0 j) actuals
      if specialized.isAppOf ``Consensus.Proofs.Safety.LocalTransition &&
          (← isDefEq specialized (← inferType tr)) then
        actuals := actuals.push tr
        pinned := pinned.push (j, true)
        continue
      if ty.isConstOf ``Model.State then
        if let some next := originals[j + 1]? then
          let nextTy ← inferType next
          if nextTy.isAppOfArity ``Consensus.Proofs.Safety.LocalTransition 2 && nextTy.appArg! == x then
            actuals := actuals.push env.t
            pinned := pinned.push (j, false)
            continue
      actuals := actuals.push x
      params := params.push x
    let build := ← getEnv
    let proofArgs := #[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ params
    let runtimeArgs := #[env.inst, env.xv] ++ params
    let guards ← params.mapIdxM fun j _ => do
      let name := Name.mkStr `ConsensusCoverage.ReadersCompiler.G s!"{short}_{j}"
      unless build.contains name do return none
      let type ← inferType (mkAppN (mkConst name) proofArgs)
      let .forallE _ _ body _ := type | throwError "expected retained guard: {name}"
      return some (← mkLambdaFVars runtimeArgs body, name)
    if !build.contains iff then return { hasC1, pinned, guards }
    let type ← inferType (mkAppN (mkConst iff) proofArgs)
    let conds ← forallTelescope type fun hyps _ =>
      hyps.mapM fun h => do mkLambdaFVars runtimeArgs (← inferType h)
    return { hasC1, pinned, guards, conds, reader := some (run, iff) }

def generate (env : Env) (armNames : Array Name) (xs : Array Expr)
    (selected : Name → Bool := fun _ => true) : MetaM Unit := do
  let start ← IO.monoMsNow
  let memo ← IO.mkRef {}
  let b := xs[4]!
  let mut exact : Std.HashMap Name RInfo := {}
  let mut pending := armNames
  repeat
    let some n := pending.back? | break
    pending := pending.pop
    if exact.contains n then continue
    exact := exact.insert n (← retained env n)
    if selected n || !armNames.contains n then
      let children := (← getConstInfo n).value!.foldConsts ({} : NameSet) fun child acc =>
        if isGenerated child then acc.insert child else acc
      pending := pending ++ children.toList.toArray
  withLocalDeclD `pools (mkConst ``Pools) fun pools => do
    let mut st : St := { memo := exact }
    let e : PolarEnv := { exact := env, pools, memo }
    let mut values := #[]
    let mut proofs := #[]
    let mut rows := #[]
    let rargs := #[env.inst, env.xv, pools]
    let pargs := #[env.inst, env.f, env.t, env.c, env.xv, env.ok, pools]
    let log ← env.reportDir.mapM fun dir => IO.FS.Handle.mk (dir / "polar-blockers.tsv") .write
    let progress ← env.reportDir.mapM fun dir => IO.FS.Handle.mk (dir / "polar-progress.tsv") .write
    for n in armNames do
      let info := exact[n]?.getD {}
      let fallback := info.reader.isNone && selected n
      let blocking := st.blockers.size
      let t0 ← IO.monoMsNow
      if fallback then
        for polarity in [true, false] do
          let (_, next) ← (compileP e n info polarity).run st
          st := next
      let out ← memo.get
      let pos := lookup out n true
      let neg := lookup out n false
      let result ← if pos.isNone && neg.isNone then
        pure (mkApp (mkConst ``Option.none [.zero]) (mkConst ``Bool), mkConst ``True.intro)
      else do
        let p := mkAppN (mkConst n) (xs.extract 0 4)
        let getTest (v : Option (Name × Name)) :=
          v.map (fun entry => mkAppN (mkConst entry.1) rargs) |>.getD (mkConst ``Bool.false)
        let a := getTest pos
        let z := getTest neg
        let negBody ← withLocalDeclD `u (mkConst ``Unit) fun u => mkLambdaFVars #[u] z
        let prove (v : Option (Name × Name)) (goal : Expr) : MetaM Expr := do
          if let some (_, proof) := v then return mkAppN (mkConst proof) pargs
          mkAppOptM ``false_test #[goal]
        let cert ← mkAppOptM ``picked_answer #[p, a, negBody, ← prove pos p,
          ← prove neg (mkApp (mkConst ``Not) p)]
        pure (mkApp2 (mkConst ``answer) a negBody, cert)
      values := values.push result.1
      proofs := proofs.push result.2
      let mark (ok : Bool) := if ok then "1" else "0"
      rows := rows.push s!"{shortName n}\t{mark info.reader.isSome}\t{mark pos.isSome}\t{mark neg.isSome}"
      if let some log := log then
        for (owner, kind, detail) in st.blockers.extract blocking st.blockers.size do
          log.putStrLn s!"{shortName n}\t{owner}\t{kind}\t{detail}"
        log.flush
      if let some progress := progress then
        progress.putStrLn s!"{shortName n}\t{(← IO.monoMsNow) - t0}\t{mark pos.isSome}\t{mark neg.isSome}"
        progress.flush
    let ret := mkApp (mkConst ``Option [.zero]) (mkConst ``Bool)
    let casesOn (level : Level) (motive : Expr) (arms : Array Expr) :=
      mkAppN (mkConst ``Classes.StepBranch.casesOn [level]) (#[motive, b] ++ arms)
    let callArgs := rargs.push b
    addReader <| .defnDecl {
      name := readerName, levelParams := [], type := ← mkForallFVars callArgs ret,
      value := ← mkLambdaFVars callArgs (casesOn (.succ .zero) (← mkLambdaFVars #[b] ret) values),
      hints := .abbrev, safety := .safe }
    let goal := mkApp2 (mkConst ``picked) (mkAppN (mkConst readerName) callArgs)
      (mkAppN (mkConst ``SolvedWitnesses.dispatch) xs)
    let proofArgs := xs ++ #[env.xv, env.ok, pools]
    addCertificate <| .thmDecl {
      name := correctName, levelParams := [], type := ← mkForallFVars proofArgs goal,
      value := ← mkLambdaFVars proofArgs (casesOn .zero (← mkLambdaFVars #[b] goal) proofs) }
    if let some dir := env.reportDir then
      IO.FS.writeFile (dir / "polar-status.tsv") ("predicate\texact\tyes\tno\n" ++
        String.intercalate "\n" rows.toList ++ "\n")
    let generated ← memo.get
    let successful p := (generated.toArray.filter fun ((_, polarity), v) => polarity == p && v.isSome).size
    logInfo m!"one-sided tests (all predicates): {successful true} yes, {successful false} no; {(← IO.monoMsNow) - start} ms"

end

end ConsensusCoverage.ReadersPolarCompiler
