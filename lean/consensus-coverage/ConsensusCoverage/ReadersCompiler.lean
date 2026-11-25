module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
public import ConsensusCoverage.ReadersIndex
public import ConsensusCoverage.ReadersMatchGuard
public import ConsensusCoverage.ReadersRequestCuts
public import ConsensusCoverage.ReadersVoteReply
public import ConsensusCoverage.CommitKeys
public import Consensus.Proofs.LogFacts
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersIndex
import all ConsensusCoverage.ReadersMatchGuard
import all ConsensusCoverage.ReadersRequestCuts
import all ConsensusCoverage.ReadersRequestTransport
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersVoteReply
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import Lean
public meta import ConsensusCoverage.ReadersRequestTransport

/-! Compile each shared normalized predicate once, including its reusable
witness bounds. The final dispatcher uses only readers with a certificate. -/

namespace ConsensusCoverage.ReadersCompiler

open CCF CCF.MultiNodeTransitionSystem
open ActionProfile FullProfile GuardedDomain ReadersAtoms ReadersShapes
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384

private def picked (value : Option Bool) (p : Prop) : Prop :=
  match value with
  | none => True
  | some yes => yes = true ↔ p

theorem picked_some {o : Option Bool} {v : Bool} (h : o = some v)
    {p : Prop} (hp : picked o p) : v = true ↔ p := by
  cases h
  exact hp

meta section

open Lean Meta Elab Command

abbrev Compiled := Expr × Expr

def normalized := `ConsensusCoverage.SolvedWitnesses

def isGenerated (n : Name) : Bool :=
  n.getPrefix == normalized && !n.getString!.endsWith "_iff" &&
    (n.getString!.startsWith "reach_" || n.getString!.startsWith "step_")

structure RInfo where
  reader : Option (Name × Name) := none
  /-- Per parameter: the exported guard proposition (a lambda over
  `inst, xv, params`) and the theorem deriving it from the predicate. -/
  guards : Array (Option (Expr × Name)) := #[]
  /-- Hypotheses (lambdas over `inst, xv, params`) the reader's equivalence assumes. -/
  conds : Array Expr := #[]
  hasC1 : Bool := false
  /-- Original parameters specialized to the recorded endpoint or transition. -/
  pinned : Array (Nat × Bool) := #[]

inductive GKind where
  | plain
  | keyedSnd (L a : Expr)
  | keyedFst (L b : Expr)
  | subst (e : Expr)

inductive AtomHow where
  | none | hint | someL | someR | input

structure Guard where
  kind : GKind
  list : Expr := .const ``True []
  mem : Expr
  rank : Nat
  tag : String
  atom : Expr := .const ``True []
  how : AtomHow := .none

structure Env where
  inst : Expr
  f : Expr
  t : Expr
  c : Expr
  xv : Expr
  ok : Expr
  first : SimpTheorems
  second : SimpTheorems
  basic : SimpTheorems
  simprocs : Simp.SimprocsArray
  reportDir : Option System.FilePath
  target : Name := `ConsensusCoverage.ReadersCompiler
  extraRules : Bool := false

structure St where
  memo : Std.HashMap Name RInfo := {}
  blockers : Array (String × String × String) := #[]
  guardTags : Array (String × String) := #[]

abbrev CM := StateRefT St MetaM

def shortName (n : Name) : String :=
  let n := (privateToUserName? n).getD n
  match n with
  | .str p s =>
    if s.startsWith "match_" || s.startsWith "proof_" || s == "mk" then
      match p with
      | .str _ q => s!"{q}.{s}"
      | _ => s
    else s
  | _ => n.toString

def headName (e : Expr) : String :=
  match e.getAppFn with
  | .const n _ => shortName n
  | .fvar _ => "fvar"
  | .forallE .. => "forall"
  | .lam .. => "lam"
  | .proj s _ _ => s!"proj:{shortName s}"
  | .sort _ => "sort"
  | _ => "other"

def atomKind (p : Expr) : String :=
  if p.isAppOfArity ``Eq 3 then s!"Eq[{headName (p.getArg! 0)}]"
  else if p.isAppOfArity ``Ne 3 then s!"Ne[{headName (p.getArg! 0)}]"
  else if p.isAppOfArity ``Membership.mem 5 then s!"Mem[{headName (p.getArg! 1)} {headName (p.getArg! 0)}]"
  else headName p

def Env.isFrame (env : Env) (e : Expr) : Bool :=
  e.containsFVar env.f.fvarId! || e.containsFVar env.t.fvarId! ||
    e.containsFVar env.c.fvarId! || e.containsFVar env.ok.fvarId!

def block (owner : Name) (kind detail : String) : CM Unit :=
  modify fun s => { s with blockers := s.blockers.push (shortName owner, kind, detail) }

def blockBinder (owner : Name) (kind : String) (α pred : Expr) : CM Unit := do
  let body ← withLocalDeclD `x α fun x => do
    let txt := toString (← ppExpr (pred.beta #[x])) |>.replace "\n" " " |>.replace "\t" " "
    return if txt.length > 400 then (txt.take 400).toString ++ "..." else txt
  block owner kind s!"{headName α}\t{body}"

def blockAtom (owner : Name) (kind : String) (p : Expr) : CM Unit := do
  let txt := toString (← ppExpr p) |>.replace "\n" " " |>.replace "\t" " "
  let txt := if txt.length > 240 then (txt.take 240).toString ++ "..." else txt
  block owner kind s!"{atomKind p}\t{txt}"

def addRule (rules : SimpTheorems) (proof : Expr) (post := true) : MetaM SimpTheorems :=
  rules.add (.other ((`totalRule).appendIndexAfter proof.hash.toNat)) #[] proof (post := post)

-- A rejected declaration must not leave behind Lean's recovery axiom.
def addCertificate (decl : Declaration) : MetaM Unit :=
  commitIfNoEx do addDecl decl

def addReader (decl : Declaration) : MetaM Unit :=
  commitIfNoEx do addAndCompile decl

def findLocal (ty : Expr) : MetaM (Option Expr) := do
  for d in ← getLCtx do
    if d.isImplementationDetail then continue
    if d.type == ty then return some d.toExpr
    if d.type.getAppFn == ty.getAppFn then
      if ← withReducible (isDefEq d.type ty) then return some d.toExpr
  return none

partial def conjunctProof (target proof ty : Expr) : MetaM (Option Expr) := do
  if ty.isAppOfArity ``And 2 then
    let l ← mkAppM ``And.left #[proof]
    if let some h ← conjunctProof target l (ty.getArg! 0) then return some h
    let r ← mkAppM ``And.right #[proof]
    return ← conjunctProof target r ty.appArg!
  if ty.getAppFn == target.getAppFn && (← withReducible (isDefEq ty target)) then
    return some proof
  return none

def recordedIndexEq (env : Env) (p : Expr) : MetaM (Option Expr) := do
  unless p.isAppOfArity ``Eq 3 && (p.getArg! 0).isForall do return none
  let l := p.getArg! 1
  let r := p.appArg!
  let base := mkApp (mkConst ``XView.base) env.xv
  let pre := mkApp (mkConst ``View.pre) base
  let post := mkApp (mkConst ``View.post) base
  let same a b := withReducible (isDefEq a b)
  for (field, rule, patchRule) in
      [(``NodeState.sentIndex, ``ReadersIndex.sameSent_iff, ``ReadersIndex.patchedSent_iff),
       (``NodeState.matchIndex, ``ReadersIndex.sameMatch_iff, ``ReadersIndex.patchedMatch_iff)] do
    let preField := mkApp (mkConst field) pre
    let postField := mkApp (mkConst field) post
    let forward ← same l postField
    let e := if forward then r else l
    unless forward || (← same r postField) do continue
    let bare ← same e preField
    unless bare do
      unless e.isAppOfArity ``CCF.Function.update 6 do continue
      unless ← same (e.getArg! 3) preField do continue
    let primary ← mkEq (mkApp (mkConst ``NodeState.role) pre) (mkConst ``Role.primary)
    for d in ← getLCtx do
      if d.isImplementationDetail then continue
      if let some proof ← conjunctProof primary d.toExpr d.type then
        let cert ← if bare then mkAppM rule #[env.ok, proof]
          else mkAppM patchRule #[env.ok, proof, e.getArg! 4, e.getArg! 5]
        return some (← if forward then pure cert else mkAppM ``ReadersIndex.eq_symm_cert #[cert])
  return none

def discharge (env : Env) (p : Expr) : MetaM (Option Expr) := do
  if let some h ← findLocal p then return some h
  let sent := mkApp (mkConst ``XView.sent) env.xv
  if p.isAppOfArity ``Membership.mem 5 && p.getArg! 3 == sent then
    let x := mkApp (mkConst ``XView.base) env.xv
    let memAt (side : Name) : MetaM Expr := do
      let network ← mkAppM ``CCF.MultiNodeTransitionSystem.State.network #[mkApp (mkConst side) x]
      mkAppM ``Membership.mem #[network, p.appArg!]
    let some yes ← findLocal (← memAt ``View.after) | return none
    let some no ← findLocal (mkApp (mkConst ``Not) (← memAt ``View.before)) | return none
    return some (← mkAppM ``X.sent_of_new #[env.ok, yes, no])
  return none

def simplify (env : Env) (p : Expr) (rules : SimpTheorems) : MetaM Simp.Result := do
  let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
    (config := { autoUnfold := false })
  return (← withReducible (simp p ctx env.simprocs (some fun hyp => discharge env hyp))).1

def sendPayload? (p : Expr) : Option Expr := do
  let name ← p.getAppFn.constName?
  let surface (n : Name) := (privateToUserName? n).getD n
  if (surface name).getPrefix == surface ``SendOK && p.getAppNumArgs ≥ 2 then
    some (p.getArg! 1)
  else none

def sendMatcher (env : Env) (p : Expr) : MetaM (Option Expr) := do
  let some payload := sendPayload? p | return none
  let e ← match payload with
    | .proj ``CCF.Envelope 2 e => pure e
    | .app _ e =>
      unless payload.isAppOf ``CCF.Envelope.payload do return none
      pure e
    | _ => return none
  let sent := mkApp (mkConst ``XView.sent) env.xv
  let some mem ← discharge env (← mkAppM ``Membership.mem #[sent, e]) | return none
  let h ← mkAppM ``X.send_ok #[env.ok, e, mem]
  let h ← mkAppM ``And.right #[h]
  let normalize (h : Expr) (rules : SimpTheorems) : MetaM Expr := do
    let r ← simplify env (← inferType h) rules
    if let some eq := r.proof? then mkEqMP eq h else pure h
  let h ← normalize (← normalize h env.first) env.second
  unless ← isDefEq (← inferType h) p do return none
  return some (← mkAppM ``proof_cert #[h])

def reflectMessageCases (p payload : Expr) (branch : Expr → CM (Option Compiled)) :
    CM (Option Compiled) := do
  let message := ``Consensus.Model.Node.Message
  let ci ← getConstInfoInduct message
  let predicate (msg : Expr) := p.replace fun e => if e == payload then some msg else none
  let dispatch (level : Level) (motive msg : Expr) (arms : Array Expr) :=
    mkAppN (mkConst ``Consensus.Model.Node.Message.casesOn [level]) (#[motive, msg] ++ arms)
  let mut readers := #[]
  let mut proofs := #[]
  for ctor in ci.ctors do
    let some (reader, proof) ← forallTelescope (← getConstInfoCtor ctor).type fun args _ => do
      let some (b, h) ← branch (predicate (mkAppN (mkConst ctor) args)) | return none
      return some (← mkLambdaFVars args b, ← mkLambdaFVars args h)
      | return none
    readers := readers.push reader
    proofs := proofs.push proof
  let (readMotive, propMotive) ← withLocalDeclD `msg (mkConst message) fun msg => do
    let readMotive ← mkLambdaFVars #[msg] (mkConst ``Bool)
    let yes ← mkEq (dispatch (.succ .zero) readMotive msg readers) (mkConst ``Bool.true)
    let propMotive ← mkLambdaFVars #[msg] (mkApp2 (mkConst ``Iff) yes (predicate msg))
    return (readMotive, propMotive)
  return some (dispatch (.succ .zero) readMotive payload readers,
    dispatch .zero propMotive payload proofs)

partial def conjuncts (p : Expr) : List Expr :=
  if p.isAppOfArity ``And 2 then conjuncts (p.getArg! 0) ++ conjuncts p.appArg!
  else [p]

def sameFormula (p q : Expr) : Bool :=
  p.cleanupAnnotations.eqv q.cleanupAnnotations

partial def proveConjunct (p h goal : Expr) : MetaM Expr := do
  if p.isAppOfArity ``And 2 then
    if (conjuncts (p.getArg! 0)).any (sameFormula · goal) then
      proveConjunct (p.getArg! 0) (← mkAppM ``And.left #[h]) goal
    else proveConjunct p.appArg! (← mkAppM ``And.right #[h]) goal
  else if sameFormula p goal then mkExpectedTypeHint h goal
  else throwError "conjunction does not contain target"

partial def proveConjunction (p h goal : Expr) : MetaM Expr := do
  if goal.isAppOfArity ``And 2 then
    mkAppM ``And.intro #[← proveConjunction p h (goal.getArg! 0), ← proveConjunction p h goal.appArg!]
  else if goal.isConstOf ``True then pure (mkConst ``True.intro)
  else proveConjunct p h goal

def sameConjuncts (p q : Expr) : MetaM Expr := do
  let pq ← withLocalDeclD `h p fun h => do
    mkLambdaFVars #[h] (← proveConjunction p h q)
  let qp ← withLocalDeclD `h q fun h => do
    mkLambdaFVars #[h] (← proveConjunction q h p)
  mkAppM ``Iff.intro #[pq, qp]

def envelopeGuard (env : Env) (x p h : Expr) : MetaM (Option Guard) := do
  unless ← withReducible (isDefEq (← inferType x) (mkConst ``Model.Envelope)) do return none
  let xid := x.fvarId!
  let eqs := (conjuncts p).filter (·.isAppOfArity ``Eq 3)
  let mut facts := #[]
  for field in [``Envelope.source, ``Envelope.target, ``Envelope.payload] do
    let projection ← mkAppM field #[x]
    let eq? ← eqs.findSomeM? fun q => do
      for (lhs, rhs, reverse) in [(q.getArg! 1, q.appArg!, false), (q.appArg!, q.getArg! 1, true)] do
        if lhs.containsFVar xid && !rhs.containsFVar xid && !env.isFrame rhs then
          if ← withReducible (isDefEq lhs projection) then
            let proof ← proveConjunct p h q
            return some (← if reverse then mkEqSymm proof else pure proof)
      return none
    let some eq := eq? | return none
    facts := facts.push eq
  let mem ← mkAppM ``envelope_value facts
  return some { kind := .subst (← inferType mem).appArg!, mem, rank := 0, tag := "envelopeFields" }

def recertify (r : Simp.Result) (proof : Expr) : MetaM Expr := do
  let some eq := r.proof? | return proof
  mkAppM ``Iff.trans #[proof, ← mkAppM ``Iff.symm #[← mkIffOfEq eq]]

def typeArg (proof : Expr) (i : Nat) : MetaM Expr := do
  let ty ← instantiateMVars (← inferType proof)
  let some arg := ty.getAppArgs[i]? |
    throwError "expected argument {i} of the proposition headed by {headName ty}"
  return arg

def boolOf (cert : Expr) : MetaM Expr := do
  let lhs ← typeArg cert 0
  let some bit := lhs.getAppArgs[1]? | throwError "expected a Bool equality certificate"
  return bit

def applyIff (lemma : Name) (p : Expr) : MetaM (Option (Expr × Expr)) := withNewMCtxDepth do
  let thm ← mkConstWithFreshMVarLevels lemma
  let (args, _, ty) ← forallMetaTelescope (← inferType thm)
  unless ty.isAppOfArity ``Iff 2 do return none
  unless ← isDefEq (ty.getArg! 0) p do return none
  let proof ← instantiateMVars (mkAppN thm args)
  if proof.hasExprMVar then return none
  return some (← instantiateMVars (ty.getArg! 1), proof)

def isNatType (ty : Expr) : MetaM Bool :=
  return (← withReducible (whnf ty)).isConstOf ``Nat

/-- Keep arity checking outside the monadic type test: a `←` in a
short-circuit condition is brought forward by do elaboration. -/
def isNatApp (e : Expr) (head : Name) (arity : Nat) : MetaM Bool :=
  if arity > 0 && e.isAppOfArity head arity then isNatType (e.getArg! 0) else pure false

/-- The list of values of field `i` of constructor `ctorName` in `e` (empty for
other constructors), built with `casesOn`. -/
def ctorProj (ctorName : Name) (i : Nat) (e : Expr) : MetaM (Option Expr) := do
  let .ctorInfo ctor ← getConstInfo ctorName | return none
  let ind ← getConstInfoInduct ctor.induct
  unless ind.numIndices == 0 do return none
  let eTy ← whnf (← inferType e)
  let .const _ us := eTy.getAppFn | return none
  let params := eTy.getAppArgs
  unless params.size == ind.numParams do return none
  let ctorTy ← instantiateForall (ctor.type.instantiateLevelParams ctor.levelParams us) params
  let some τ ← forallTelescope ctorTy fun fs _ => do
      if i ≥ fs.size then return none
      let ty ← inferType fs[i]!
      if (fs.extract 0 i).any (fun y => ty.containsFVar y.fvarId!) then return none
      return some ty
    | return none
  let lvl ← getLevel τ
  let lvl ← instantiateLevelMVars lvl
  let some u := lvl.dec | return none
  let listTy := mkApp (mkConst ``List [u]) τ
  let motive := Expr.lam `x eTy listTy .default
  let minors ← ind.ctors.toArray.mapM fun cn => do
    let cinfo ← getConstInfoCtor cn
    let cty ← instantiateForall (cinfo.type.instantiateLevelParams cinfo.levelParams us) params
    forallTelescope cty fun fs _ => do
      let val ← if cn == ctorName then mkListLit τ [fs[i]!] else pure (mkApp (mkConst ``List.nil [u]) τ)
      mkLambdaFVars fs val
  return some (mkAppN (mkConst (mkCasesOnName ind.name) (lvl :: us)) (params ++ #[motive, e] ++ minors))

def isCtorApp (e : Expr) : MetaM (Option (Name × Nat)) := do
  let .const n _ := e.getAppFn | return none
  let .ctorInfo ci ← getConstInfo n | return none
  if e.getAppNumArgs != ci.numParams + ci.numFields then return none
  return some (n, ci.numParams)

/-- Descend from `mem : C args ∈ L` to a list containing `x`, through constructor fields. -/
partial def ctorDescend (x : Expr) (term L mem : Expr) : MetaM (Option (Expr × Expr)) := do
  if term == x then return some (L, mem)
  let some (cn, np) ← isCtorApp term | return none
  let args := term.getAppArgs
  for j in [np:args.size] do
    let a := args[j]!
    unless a.containsFVar x.fvarId! do continue
    let elemTy ← inferType term
    let some projSelf ← ctorProj cn (j - np) term | continue
    let f ← withLocalDeclD `m elemTy fun m => do
      let some p ← ctorProj cn (j - np) m | return none
      return some (← mkLambdaFVars #[m] p)
    let some f := f | continue
    let memSelf ← mkExpectedTypeHint (← mkAppM ``List.mem_singleton_self #[a])
      (← mkAppM ``Membership.mem #[projSelf, a])
    let L' ← mkAppM ``List.flatMap #[f, L]
    let mem' ← mkAppOptM ``mem_flatMap_of #[none, none, L, f, term, a, mem, memSelf]
    if let some r ← ctorDescend x a L' mem' then return some r
  return none

/-- Start from `h : E = C args` with `E` free of `x`. -/
def ctorPin (x E term h : Expr) : MetaM (Option (Expr × Expr)) := do
  let some (cn, np) ← isCtorApp term | return none
  let args := term.getAppArgs
  for j in [np:args.size] do
    let a := args[j]!
    unless a.containsFVar x.fvarId! do continue
    let some projE ← ctorProj cn (j - np) E | continue
    let some projSelf ← ctorProj cn (j - np) term | continue
    let eTy ← inferType E
    let motive ← withLocalDeclD `m eTy fun m => do
      let some p ← ctorProj cn (j - np) m | return none
      return some (← mkLambdaFVars #[m] (← mkAppM ``Membership.mem #[p, a]))
    let some motive := motive | continue
    let memSelf ← mkExpectedTypeHint (← mkAppM ``List.mem_singleton_self #[a])
      (← mkAppM ``Membership.mem #[projSelf, a])
    let eqProp ← mkCongrArg motive h
    let mem ← mkExpectedTypeHint (← mkEqMPR eqProp memSelf) (← mkAppM ``Membership.mem #[projE, a])
    if let some r ← ctorDescend x a projE mem then return some r
  return none

def Env.transition (env : Env) : MetaM Expr :=
  mkAppM ``Ctx.tr #[env.c]

def actualArgs (env : Env) (info : RInfo) (p : Expr) : MetaM (Option (Array Expr)) := do
  let args := p.getAppArgs
  let pre := if info.hasC1 then 5 else 4
  unless args.size ≥ pre && args[0]! == env.inst && args[1]! == env.f && args[2]! == env.t &&
      args[3]! == env.c && (!info.hasC1 || args[4]! == env.c) do return none
  let mut others := #[]
  for j in [pre:args.size] do
    if let some (_, transition) := info.pinned.find? (·.1 == j - pre) then
      let pinned ← if transition then env.transition else pure env.t
      unless ← isDefEq args[j]! pinned do return none
    else
      others := others.push args[j]!
  return some others

/-- Occurrences of `x : Nat` in `e`, each in an atom that is constant above a
threshold: (rule lemma, threshold, extra explicit argument). `none` if `x`
occurs anywhere else. -/
partial def satAtoms (x e : Expr) (acc : Array (Name × Expr × Array Expr)) :
    MetaM (Option (Array (Name × Expr × Array Expr))) := do
  let xid := x.fvarId!
  if !e.containsFVar xid then return some acc
  if e == x then return none
  let closed (c : Expr) := !c.hasLooseBVars && !c.containsFVar xid
  let succ (c : Expr) : MetaM Expr := mkAppM ``HAdd.hAdd #[c, mkNatLit 1]
  if (← isNatApp e ``LE.le 4) || (← isNatApp e ``LT.lt 4) then
    let le := e.isAppOfArity ``LE.le 4
    let a := e.getArg! 2
    let b := e.getArg! 3
    if b == x && closed a then
      return some (acc.push (if le then ``sat_ge else ``sat_gt, ← if le then pure a else succ a, #[]))
    if a == x && closed b then
      return some (acc.push (if le then ``sat_le else ``sat_lt, ← if le then succ b else pure b, #[]))
  if ← isNatApp e ``Eq 3 then
    let a := e.getArg! 1
    let b := e.getArg! 2
    if a == x && closed b then return some (acc.push (``sat_eq, ← succ b, #[]))
    if b == x && closed a then return some (acc.push (``sat_eq', ← succ a, #[]))
  if (e.isAppOfArity ``List.take 3 || e.isAppOfArity ``List.drop 3) &&
      closed (e.getArg! 2) then
    let L := e.getArg! 2
    let i := e.getArg! 1
    let len ← mkAppM ``List.length #[L]
    let take := e.isAppOf ``List.take
    if i == x then
      return some (acc.push (if take then ``sat_take else ``sat_drop, len, #[L]))
    if i.isAppOfArity ``HSub.hSub 6 && i.getArg! 4 == x && closed (i.getArg! 5) then
      let k := i.getArg! 5
      return some (acc.push (if take then ``sat_take_sub else ``sat_drop_sub,
        ← mkAppM ``HAdd.hAdd #[k, len], #[L, k]))
  match e with
  | .app f a =>
    let some acc ← satAtoms x f acc | return none
    satAtoms x a acc
  | .lam _ t b _ | .forallE _ t b _ =>
    let some acc ← satAtoms x t acc | return none
    satAtoms x b acc
  | .mdata _ b => satAtoms x b acc
  | _ => return none

/-- `(∃ x, P x) ↔ ∃ x, x < B + 1 ∧ P x` (or the `∀` form) when `P` saturates. -/
def saturateNat (ex : Bool) (pred : Expr) : MetaM (Option Expr) := do
  withLocalDeclD `x (mkConst ``Nat) fun x => do
    let body := pred.beta #[x]
    let some atoms ← satAtoms x body #[] | return none
    if atoms.isEmpty then return none
    let bounds := atoms.map (·.2.1)
    let mut tails : Array Expr := #[mkNatLit 0]
    for b in bounds.reverse do
      tails := tails.push (← mkAppM ``Max.max #[b, tails.back!])
    let rev := tails.reverse
    let B := rev[0]!
    withLocalDeclD `w (mkConst ``Nat) fun w => do
    withLocalDeclD `hw (← mkEq w (← mkAppM ``Min.min #[x, B])) fun hw => do
      let mut rules : SimpTheorems := {}
      for i in [0:atoms.size] do
        let (lem, b, extra) := atoms[i]!
        let mut hb ← mkAppM ``sat_head #[b, rev[i+1]!]
        for j' in [0:i] do
          let j := i - 1 - j'
          hb ← mkAppM ``sat_tail #[bounds[j]!, hb]
        rules ← addRule rules (← mkAppM lem (extra ++ #[hb, hw]))
      let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
      let (r, _) ← simp body ctx #[]
      if r.expr.containsFVar x.fvarId! then return none
      let P' ← mkLambdaFVars #[w] r.expr
      let iff ← match r.proof? with
        | some eq => mkIffOfEq eq
        | none => mkAppM ``Iff.refl #[body]
      let H ← mkLambdaFVars #[x, w, hw] iff
      return some (← mkAppOptM (if ex then ``nat_saturate else ``nat_saturate_all)
        #[pred, P', B, H])

/-- Eliminating an exactly pinned inner witness can preserve exact equality
of the outer witness, even if the inner value itself depends on the frame. -/
def substDependentGuard (env : Env) (x y : Expr) (g gy : Guard) : MetaM (Option Guard) := do
  let .subst e := g.kind | return none
  let .subst v := gy.kind | return none
  if v.containsFVar x.fvarId! || v.containsFVar y.fvarId! then return none
  let projection ← mkLambdaFVars #[y] e
  let value := projection.beta #[v]
  let normal ← if env.isFrame value then simplify env value env.second else pure { expr := value }
  if env.isFrame normal.expr || normal.expr.containsFVar x.fvarId! then return none
  let projected ← mkCongrArg projection gy.mem
  let mem ← mkEqTrans g.mem projected
  let mem ← if let some rw := normal.proof? then mkEqTrans mem rw else pure mem
  return some { kind := .subst normal.expr, mem, rank := 0, tag := "depEq" }

/-- Boolean ghost readers whose `= true` bounds an argument by a history list:
function, arity, argument position, guard lemma. -/
def atomGuards : List (Name × Nat × Nat × Name) :=
  [(``electedExact, 5, 0, ``electedExact_node), (``electedExact, 5, 1, ``electedExact_term),
   (``electedExact, 5, 2, ``electedExact_log), (``electedExact, 5, 3, ``electedExact_idx),
   (``canonAt, 4, 1, ``canonAt_term), (``canonAt, 4, 2, ``canonAt_log),
   (``grantedIn, 5, 1, ``grant_voter_bound), (``grantedIn, 5, 2, ``grant_candidate_bound),
   (``grantedIn, 5, 3, ``grant_term_bound)]

private def postMatchGuard (env : Env) (peer p h : Expr) : MetaM (Option Guard) := do
  unless (p.find? (·.isConstOf ``Role.primary)).isSome do return none
  unless ← withReducible (isDefEq (← inferType peer) (mkConst ``NodeID)) do return none
  try
    let rule ← mkAppOptM ``ReadersMatchGuard.positiveAfter
      #[none, none, none, none, none, some env.ok, some peer]
    forallTelescope (← inferType rule) fun premises _ => do
      let hs ← premises.mapM fun pr => do conjunctProof (← inferType pr) h p
      let #[some primary, some other, some positive] := hs | return none
      let mem := mkAppN rule #[primary, other, positive]
      return some {kind := .plain, list := ← typeArg mem 3, mem, rank := 2, tag := "matchPeers"}
  catch _ => pure none

mutual

partial def findGuards (env : Env) (x p h : Expr) : CM (Array Guard) := do
  let p := p.consumeMData
  let xid := x.fvarId!
  unless p.containsFVar xid do return #[]
  let free (e : Expr) := !e.containsFVar xid && !env.isFrame e
  let mut out : Array Guard := #[]
  if p.isAppOfArity ``Membership.mem 5 then
    let ct := p.getArg! 1
    let coll := p.getArg! 3
    let elem := p.getArg! 4
    if free coll then
      if elem == x then
        if ct.isAppOfArity ``List 1 then
          let rank := if coll.isAppOf ``XView.sent then 0 else 1
          out := out.push { kind := .plain, list := coll, mem := h, rank, tag := "mem", atom := p, how := .hint }
        else if ct.isAppOf ``CCF.Finset then
          let list ← mkAppM ``CCF.Finset.val #[coll]
          out := out.push { kind := .plain, list, rank := 1, tag := "finset", mem := ← mkExpectedTypeHint h (← mkAppM ``Membership.mem #[list, x]), atom := p, how := .hint }
      else if ct.isAppOfArity ``List 1 && elem.isAppOfArity ``Prod.mk 4 &&
          (elem.getArg! 2 == x || elem.getArg! 3 == x) then
        let a := elem.getArg! 2
        let b := elem.getArg! 3
        if b == x then
          if free a then
            out := out.push { kind := .keyedSnd coll a, mem := h, rank := 1, tag := "keyedSnd" }
          let mem ← mkAppM ``guard_snd #[h]
          out := out.push { kind := .plain, list := ← typeArg mem 3, mem, rank := 2, tag := "pairSnd" }
        else
          if free b then
            out := out.push { kind := .keyedFst coll b, mem := h, rank := 1, tag := "keyedFst" }
          let mem ← mkAppM ``guard_fst #[h]
          out := out.push { kind := .plain, list := ← typeArg mem 3, mem, rank := 2, tag := "pairFst" }
      else if ct.isAppOfArity ``List 1 && elem.containsFVar xid then
        if let some (L, mem) ← ctorDescend x elem coll h then
          if free L then
            out := out.push { kind := .plain, list := L, mem, rank := 2, tag := "ctorMem" }
  else if p.isAppOfArity ``Eq 3 then
    let a := p.getArg! 1
    let b := p.getArg! 2
    if b.isConstOf ``Bool.true then
      for (fn, arity, pos, lem) in atomGuards do
        if a.isAppOfArity fn arity && a.getArg! pos == x then
          let mem ← mkAppM lem #[h]
          let list ← typeArg mem 3
          if free list then
            out := out.push { kind := .plain, list, mem, rank := 3, tag := s!"atom:{shortName fn}:{pos}" }
    if a == x && !b.containsFVar xid then
      out := out.push { kind := .subst b, mem := h, rank := 0, tag := "eq" }
    else if b == x && !a.containsFVar xid then
      out := out.push { kind := .subst a, mem := ← mkEqSymm h, rank := 0, tag := "eq" }
    else if b.isAppOfArity ``Option.some 2 && b.getArg! 1 == x && free a then
      out := out.push { kind := .plain, list := ← mkAppM ``Option.toList #[a], mem := ← mkAppM ``guard_some_left #[h], rank := 1, tag := "some", atom := p, how := .someL }
    else if a.isAppOfArity ``Option.some 2 && a.getArg! 1 == x && free b then
      out := out.push { kind := .plain, list := ← mkAppM ``Option.toList #[b], mem := ← mkAppM ``guard_some_right #[h], rank := 1, tag := "some", atom := p, how := .someR }
    else if b.isAppOfArity ``Event.internal 1 && b.appArg! == x && free a then
      out := out.push {
        kind := .plain, list := mkApp (mkConst ``inputs) a, mem := ← mkAppM ``guard_input #[h],
        rank := 1, tag := "input", atom := p, how := .input }
    else if a.isAppOfArity ``Event.internal 1 && a.appArg! == x && free b then
      out := out.push {
        kind := .plain, list := mkApp (mkConst ``inputs) b, mem := ← mkAppM ``guard_input #[← mkEqSymm h],
        rank := 1, tag := "input", atom := p, how := .input }
    else if free a && b.containsFVar xid then
      if let some (L, mem) ← ctorPin x a b h then
        if free L then out := out.push { kind := .plain, list := L, mem, rank := 2, tag := "ctorPin" }
    else if free b && a.containsFVar xid then
      if let some (L, mem) ← ctorPin x b a (← mkEqSymm h) then
        if free L then out := out.push { kind := .plain, list := L, mem, rank := 2, tag := "ctorPin" }
    for (whole, expr, eq) in #[(a, b, h), (b, a, ← mkEqSymm h)] do
      if env.extraRules && whole == x && expr.isAppOfArity ``List.take 3 && free expr.appArg! &&
          (expr.getArg! 1).isAppOfArity ``List.length 2 && (expr.getArg! 1).appArg! == x then
        let iff ← mkAppOptM ``List.prefix_iff_eq_take #[none, some x, some expr.appArg!]
        let pref ← mkAppM ``Iff.mpr #[iff, eq]
        let mem ← mkAppM ``guard_prefix #[pref]
        out := out.push { kind := .plain, list := ← typeArg mem 3, mem, rank := 4, tag := "prefixEq" }
      if free whole then
        if let some (ctor, np) ← isCtorApp expr then
          let ci ← getConstInfoCtor ctor
          if (getStructureInfo? (← getEnv) ci.induct).isSome then
            for j in [np:expr.getAppNumArgs] do
              let field := expr.getArg! j
              unless field.containsFVar xid do continue
              let proj ← withLocalDeclD `s (← inferType whole) fun s =>
                mkLambdaFVars #[s] (.proj ci.induct (j - np) s)
              let eq' ← mkCongrArg proj eq
              let atom ← mkEq (.proj ci.induct (j - np) whole) field
              if ← withReducible (isDefEq (← inferType eq') atom) then
                out := out ++ (← findGuards env x atom (← mkExpectedTypeHint eq' atom))
      if free whole && (expr.isAppOfArity ``List.append 3 || expr.isAppOfArity ``HAppend.hAppend 6) then
        let pref := expr.getArg! (expr.getAppNumArgs - 2)
        let tail := expr.appArg!
        if pref == x && free tail || tail == x && free pref then
          let mem ← mkAppM (if pref == x then ``append_left_value else ``append_right_value) #[eq]
          let value := (← instantiateMVars (← inferType mem)).appArg!
          out := out.push { kind := .subst value, mem, rank := 0, tag := "append" }
  else if p.isAppOfArity ``HEq 4 then
    let a := p.getArg! 1
    let b := p.appArg!
    if (a == x && !b.containsFVar xid || b == x && !a.containsFVar xid) &&
        (← isDefEq (p.getArg! 0) (p.getArg! 2)) then
      let eq ← mkAppM ``eq_of_heq #[h]
      let (value, mem) ← if a == x then pure (b, eq) else pure (a, ← mkEqSymm eq)
      out := out.push { kind := .subst value, mem, rank := 0, tag := "heq" }
  else if (← isNatApp p ``LT.lt 4) && p.getArg! 2 == x &&
      free (p.getArg! 3) then
    out := out.push { kind := .plain, list := ← mkAppM ``List.range #[p.getArg! 3], mem := ← mkAppM ``guard_lt #[h], rank := 3, tag := "lt" }
  else if (← isNatApp p ``LE.le 4) && p.getArg! 2 == x &&
      free (p.getArg! 3) then
    out := out.push { kind := .plain, list := ← mkAppM ``List.range #[← mkAppM ``HAdd.hAdd #[p.getArg! 3, mkNatLit 1]], mem := ← mkAppM ``guard_le #[h], rank := 3, tag := "le" }
  else if p.isAppOfArity ``List.IsPrefix 3 && p.getArg! 1 == x && free (p.getArg! 2) then
    out := out.push { kind := .plain, list := ← mkAppM ``prefixes #[p.getArg! 2], mem := ← mkAppM ``guard_prefix #[h], rank := 4, tag := "prefix" }
  else if p.isAppOfArity ``List.IsPrefix 3 && (p.getArg! 1).isAppOfArity ``List.cons 3 &&
      (p.getArg! 1).appArg! == x && free (p.getArg! 2) then
    let mem ← mkAppM ``cons_prefix_bound #[h]
    let list ← typeArg mem 3
    out := out.push { kind := .plain, list, mem, rank := 4, tag := "consPrefix" }
  else if p.isForall && p.bindingDomain!.isConstOf ``Nat &&
      (p.find? (·.isConstOf ``canonAt)).isSome then
    let some mem ← (try
      let mem ← instantiateMVars (← mkAppOptM ``anchored_prefix_bound #[none, none, some x, some h])
      pure (if mem.hasMVar then none else some mem)
    catch _ => pure none) | return out
    let list ← typeArg mem 3
    if free list then
      out := out.push { kind := .plain, list, mem, rank := 4, tag := "anchoredPrefix" }
  else if p.isAppOfArity ``And 2 then
    let l := p.getArg! 0
    let r := p.getArg! 1
    out := out ++ (← findGuards env x l (← mkAppOptM ``And.left #[l, r, h]))
    let terminal ← if out.any (·.rank == 0) then pure true
      else if out.any (·.rank == 1) then
        pure !(← withReducible (isDefEq (← inferType x) (mkConst ``Model.Envelope)))
      else pure false
    unless terminal do
      out := out ++ (← findGuards env x r (← mkAppOptM ``And.right #[l, r, h]))
    if out.isEmpty then
      let matchGuard ← if env.extraRules then postMatchGuard env x p h else pure none
      if let some g := matchGuard then
        out := out.push g
      else if let some g ← envelopeGuard env x p h then
        out := out.push g
  else if p.isAppOfArity ``Exists 2 then
    let inner ← withLocalDeclD `inner (p.getArg! 0) fun y => do
      let q := (p.getArg! 1).beta #[y]
      withLocalDeclD `h q fun hq => do
        let mut gs ← findGuards env x q hq
        let ty := p.getArg! 0
        if env.extraRules && ty.containsFVar xid && (← isProp ty) then
          gs := (← findGuards env x ty y) ++ gs
        let mut res := #[]
        let mut yGuards : Option (Array Guard) := none
        let yid := y.fvarId!
        for g in gs do
          let bad := match g.kind with
            | .plain => g.list.containsFVar yid
            | .keyedSnd L a => L.containsFVar yid || a.containsFVar yid
            | .keyedFst L b => L.containsFVar yid || b.containsFVar yid
            | .subst e => e.containsFVar yid
          let mut g := g
          if bad then
            if yGuards.isNone then
              yGuards := some (← findGuards env y q hq)
            let mut found := none
            for gy in (yGuards.getD #[]).qsort (·.rank < ·.rank) do
              if let some pin ← substDependentGuard env x y g gy then
                found := some pin
                break
              -- Dependent membership uses the finite union of the inner lists.
              let some (Lx, memx) ← asList g | continue
              let some (Ly, memy) ← asList gy | continue
              if Ly.containsFVar xid || Ly.containsFVar yid || env.isFrame Ly then continue
              let F ← mkLambdaFVars #[y] Lx
              let L' ← mkAppM ``List.flatMap #[F, Ly]
              let mem' ← mkAppOptM ``mem_flatMap_of #[none, none, Ly, F, y, x, memy, memx]
              found := some { kind := .plain, list := L', mem := mem', rank := max g.rank gy.rank + 1, tag := s!"dep:{gy.tag}>{g.tag}" : Guard }
              break
            let some g' := found | continue
            g := g'
          else if g.atom.containsFVar yid then continue
          let proof ← mkLambdaFVars #[y, hq] g.mem
          let memTy ← inferType g.mem
          if memTy.containsFVar yid then continue
          let mem ← mkAppOptM ``Exists.elim #[none, (p.getArg! 1), memTy, h, proof]
          res := res.push { g with mem, how := if g.how matches .hint then .none else g.how, atom := if g.how matches .hint then .const ``True [] else g.atom }
        -- Normalize the index before extracting guards on projections of a
        -- heterogeneously equal transition.
        if res.isEmpty && (p.getArg! 0).isConstOf ``Model.State &&
            q.isAppOfArity ``Exists 2 && (q.getArg! 0).isAppOf ``LocalTransition &&
            (q.getArg! 0).containsFVar yid then
          let ys ← if let some ys := yGuards then pure ys else findGuards env y q hq
          for gy in ys do
            let .subst v := gy.kind | continue
            if v.containsFVar yid || v.containsFVar xid then continue
            let bounded ← mkLambdaFVars #[y, hq] gy.mem
            let iff ← mkAppOptM ``guard_subst #[p.getArg! 0, p.appArg!, v, bounded]
            let hv ← mkAppM ``Iff.mp #[iff, h]
            let r ← simplify env (p.appArg!.beta #[v]) env.second
            let hv ← if let some eq := r.proof? then mkEqMP eq hv else pure hv
            let guards ← findGuards env x r.expr hv
            if !guards.isEmpty then return guards
        return res
    out := out ++ inner
  else if p.isAppOfArity ``Or 2 then
    let l := p.getArg! 0
    let r := p.getArg! 1
    let lift (branch : Expr) := withLocalDeclD `hb branch fun hb => do
      (← findGuards env x branch hb).mapM fun g => do
        return { g with mem := ← mkLambdaFVars #[hb] g.mem }
    let gl ← lift l
    if gl.isEmpty then return #[]
    let gr ← lift r
    if gr.isEmpty then return #[]
    for a in gl do
      let .subst ea := a.kind | continue
      for b in gr do
        let .subst eb := b.kind | continue
        unless ← isDefEq ea eb do continue
        let eq ← mkEq x ea
        let mem ← mkAppOptM ``Or.elim #[l, r, eq, h, a.mem, b.mem]
        return #[{ kind := .subst ea, mem, rank := 0, tag := "orEq" }]
    return ← withLocalDeclD `hl l fun hl =>
      withLocalDeclD `hr r fun hr => do
        for a in gl do
          let some (L, ml) ← asList { a with mem := a.mem.beta #[hl] } | continue
          for b in gr do
            let some (R, mr) ← asList { b with mem := b.mem.beta #[hr] } | continue
            let list ← mkAppM ``HAppend.hAppend #[L, R]
            let mem ← mkAppOptM ``guard_or #[none, l, r, x, L, R, h,
              ← mkLambdaFVars #[hl] ml, ← mkLambdaFVars #[hr] mr]
            return #[{ kind := .plain, list, mem, rank := 5, tag := "or" }]
        return #[]
  else if let .const n _ := p.getAppFn then
    if isGenerated n then
      let info ← compileConst env n
      if let some others ← actualArgs env info p then
        for j in [0:info.guards.size] do
          let some (L, g) := info.guards[j]! | continue
          unless others[j]! == x do continue
          let memTy := L.beta (#[env.inst, env.xv] ++ others)
          let mem := mkAppN (mkConst g) (#[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ others ++ #[h])
          for g' in ← findGuards env x memTy mem do
            out := out.push { g' with rank := g'.rank + 1, tag := s!"reach:{g'.tag}", how := .none, atom := .const ``True [] }
      if out.isEmpty && p.getAppArgs.contains x then
        let ty ← inferType x
        let aliased := ty.isConstOf ``NodeState && (p.getAppArgs.filter (· == x)).size > 1
        if aliased || ty.isAppOf ``Model.State || ty.isAppOf ``LocalTransition || ty.isAppOf ``Ctx then
          -- A dependent endpoint may not have a runnable reader of its own.
          -- Its definition can still prove the endpoint is the recorded one.
          let ci ← getConstInfo n
          let .const _ levels := p.getAppFn | return out
          let body := (ci.value!.instantiateLevelParams ci.levelParams levels).beta p.getAppArgs
          let proof ← mkExpectedTypeHint h body
          out := ← findGuards env x body proof
  return out

partial def asList (g : Guard) : CM (Option (Expr × Expr)) := do
  match g.kind with
  | .plain => return some (g.list, g.mem)
  | .subst e => return some (← mkListLit (← inferType e) [e], ← mkAppM ``guard_eq_right #[← mkEqSymm g.mem])
  | .keyedSnd _ _ =>
      let mem ← mkAppM ``guard_snd #[g.mem]
      return some (← typeArg mem 3, mem)
  | .keyedFst _ _ =>
      let mem ← mkAppM ``guard_fst #[g.mem]
      return some (← typeArg mem 3, mem)

partial def pickGuard (gs : Array Guard) : Option Guard :=
  gs.foldl (fun best g => match best with
    | none => some g
    | some b => if g.rank < b.rank then some g else some b) none

/-- Rules usable once `hm` asserts the guard's membership for `x`. -/
partial def guardRules (env : Env) (g : Guard) (x hm : Expr) (binder : Expr) : CM SimpTheorems := do
  let mut rules ← addRule env.basic hm
  match g.how with
  | .hint =>
    let atom := g.atom.replaceFVar binder x
    rules ← addRule rules (← mkExpectedTypeHint hm atom)
  | .someL => rules ← addRule rules (← mkAppM ``option_some_mem #[hm])
  | .someR => rules ← addRule rules (← mkAppM ``option_some_mem' #[hm])
  | .input =>
    let eq ← mkAppM ``input_mem #[hm]
    rules ← addRule rules eq
    let event ← typeArg eq 1
    if event == mkApp (mkConst ``XView.event) env.xv then
      rules ← addRule rules (← mkAppM ``X.run_for #[env.ok, ← mkEqSymm eq]) (post := false)
  | .none => pure ()
  return rules

partial def reflectSimp (env : Env) (owner : Name) (p : Expr) (rules : SimpTheorems) :
    CM (Option Compiled) := do
  let r ← simplify env p rules
  let some (b, cert) ← reflect env owner r.expr | return none
  return some (b, ← recertify r cert)

/-- Reflect a quantifier over `α` with predicate `pred`, given a guard found on a
local `x`. `ex` selects `∃` (else `∀`). `bounded` is a closed proof. -/
partial def quantify (env : Env) (owner : Name) (ex : Bool) (α pred : Expr) (g : Guard) (binder : Expr)
    (bounded : Expr) : CM (Option Compiled) := do
  match g.kind with
  | .subst e =>
    let p := pred.beta #[e]
    let r ← if env.isFrame e then simplify env p env.first else pure { expr := p }
    let rules := if env.isFrame e then env.second else env.basic
    let some (b, cert) ← reflectSimp env owner r.expr rules | return none
    let cert ← recertify r cert
    let iff ← mkAppOptM (if ex then ``guard_subst else ``guard_forall_subst) #[α, pred, e, bounded]
    let cert ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]]
    return some (b, cert)
  | .plain =>
    withLocalDeclD `x α fun x => do
    withLocalDeclD `hm (← mkAppM ``Membership.mem #[g.list, x]) fun hm => do
      let rules ← guardRules env g x hm binder
      let some (b, cert) ← reflectSimp env owner (pred.beta #[x]) rules | return none
      let test ← mkLambdaFVars #[x, hm] b
      let pw ← mkLambdaFVars #[x, hm] cert
      let useUnique ← if [``List.map, ``List.flatMap, ``List.append, ``HAppend.hAppend,
          ``historicalPrefixes].any g.list.isAppOf then
          if ← isNatType α then pure true
          else withReducible <| isDefEq α (mkApp (mkConst ``List [.zero]) (mkConst ``Entry))
        else pure false
      let cert ← if useUnique then
          mkAppM (if ex then ``guard_any_unique else ``guard_forall_unique)
            #[g.list, pred, test, bounded, pw]
        else mkAppOptM (if ex then ``guard_any else ``guard_forall) #[α, g.list, pred, test, bounded, pw]
      return some (← boolOf cert, cert)
  | .keyedSnd L a | .keyedFst L a =>
    let snd := g.kind matches .keyedSnd ..
    let pairTy := (← inferType L).appArg!
    withLocalDeclD `q pairTy fun q => do
      let xq ← mkAppM (if snd then ``Prod.snd else ``Prod.fst) #[q]
      let pair ← if snd then mkAppM ``Prod.mk #[a, xq] else mkAppM ``Prod.mk #[xq, a]
      withLocalDeclD `hm (← mkAppM ``Membership.mem #[L, pair]) fun hm => do
        let rules ← addRule env.basic hm
        let some (b, cert) ← reflectSimp env owner (pred.beta #[xq]) rules | return none
        let test ← mkLambdaFVars #[q, hm] b
        let pw ← mkLambdaFVars #[q, hm] cert
        let lemma := match ex, snd with
          | true, true => ``guard_keyed_snd
          | true, false => ``guard_keyed_fst
          | false, true => ``guard_forall_keyed_snd
          | false, false => ``guard_forall_keyed_fst
        let cert ← mkAppM lemma #[L, a, pred, test, bounded, pw]
        return some (← boolOf cert, cert)

partial def reflectExists (env : Env) (owner : Name) (p : Expr) (swapped := false) :
    CM (Option Compiled) := do
  let α := p.getArg! 0
  let pred := p.getArg! 1
  if ← isProp α then
    let ra ← reflect env owner α
    return ← withLocalDeclD `h α fun hx => do
      let rq ← reflect env owner (pred.beta #[hx])
      let some (_, ha) := ra | return none
      let some (bq, hq) := rq | return none
      if !env.extraRules && bq.containsFVar hx.fvarId! then
        block owner "depProp" ""
        return none
      let cert ← mkAppOptM ``dite_cert #[α, pred, none, ha, ← mkLambdaFVars #[hx] bq,
        ← mkLambdaFVars #[hx] hq]
      return some (← boolOf cert, cert)
  if pred.isLambda && !pred.bindingBody!.hasLooseBVars then
    let body := pred.bindingBody!
    if body.isConstOf ``False then
      let iff ← mkAppOptM ``exists_false_iff #[some α]
      let some (b, cert) ← reflect env owner body | return none
      return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]])
    let base := mkApp (mkConst ``XView.base) env.xv
    for name in [``View.pre, ``View.before, ``XView.event] do
      let witness := mkApp (mkConst name) (if name == ``XView.event then env.xv else base)
      if ← withReducible (isDefEq (← inferType witness) α) then
        let iff ← mkAppM ``exists_vacuous #[witness, body]
        let some (b, cert) ← reflect env owner body | return none
        return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]])
  -- quorum: ∃ voters, hasQuorum cs voters ∧ ∀ v ∈ voters, P v
  let quorum? ← withLocalDeclD `vs α fun vs => do
    unless α.isAppOf ``CCF.Finset do return none
    let inner := pred.beta #[vs]
    let (dependent, separate) := ((conjuncts inner).eraseDupsBy sameFormula).partition
      (·.containsFVar vs.fvarId!)
    let isQuorum (q : Expr) := q.isAppOfArity ``hasQuorum 2 ||
      (q.isAppOfArity ``Eq 3 && (q.getArg! 1).isAppOfArity ``List.all 3 &&
        q.appArg!.isConstOf ``Bool.true)
    let [hq] := dependent.filter isQuorum | return none
    let [rest] := dependent.filter Expr.isForall | return none
    let extras := dependent.filter (fun q => !isQuorum q && !q.isForall)
    unless extras.all (fun q => q.isAppOfArity ``Membership.mem 5 && q.getArg! 3 == vs &&
        !q.appArg!.containsFVar vs.fvarId!) do return none
    let allShape := hq.isAppOfArity ``Eq 3 && (hq.getArg! 1).isAppOfArity ``List.all 3 &&
      (hq.getArg! 2).isConstOf ``Bool.true
    unless hq.isAppOfArity ``hasQuorum 2 && hq.getArg! 1 == vs || allShape do return none
    let cs := if allShape then (hq.getArg! 1).getArg! 1 else hq.getArg! 0
    if cs.containsFVar vs.fvarId! then return none
    if allShape then
      let expected ← mkAppM ``Eq #[← mkAppM ``List.all #[cs, ← withLocalDeclD `c (mkConst ``Node.Configuration)
        fun cc => do mkLambdaFVars #[cc] (← mkDecide (← mkAppM ``hasConfigurationMajority #[vs, cc]))],
        mkConst ``Bool.true]
      unless ← isDefEq expected hq do return none
    let .forallE _ nodeTy body _ := rest | return none
    withLocalDeclD `v nodeTy fun v => do
      let body := body.instantiate1 v
      let .forallE _ memTy concl _ := body | return none
      unless memTy.isAppOfArity ``Membership.mem 5 && memTy.getArg! 3 == vs && memTy.getArg! 4 == v &&
        !concl.hasLooseBVars && !concl.containsFVar vs.fvarId! do return none
      let some (b, cert) ← reflect env owner concl | return some none
      let test ← mkLambdaFVars #[v] b
      let pw ← mkLambdaFVars #[v] cert
      let and p q := mkApp2 (mkConst ``And) p q
      let core := and hq rest
      let corePred ← mkLambdaFVars #[vs] (extras.foldr and core)
      let coreEx := mkApp2 p.getAppFn α corePred
      let cert ← if extras.isEmpty then
          mkAppM (if allShape then ``quorum_all_cert else ``quorum_cert) #[cs, test, pw]
        else do
          let required ← mkListLit nodeTy (extras.map (·.appArg!))
          let cert ← mkAppM (if allShape then ``quorum_all_required else ``quorum_required) #[cs, required, test, pw]
          let mut rules : SimpTheorems := {}
          for n in [``List.forall_mem_cons, ``List.not_mem_nil, ``false_implies, ``forall_const, ``and_true] do
            rules ← rules.addConst n
          let vars ← simplify env (← typeArg cert 1) rules
          let cert ← mkAppM ``Iff.trans #[cert, ← mkIffOfEq (← vars.getProof)]
          let expanded ← Core.betaReduce ((← typeArg cert 1).appArg!.beta #[vs])
          let bridge ← mkLambdaFVars #[vs] (← sameConjuncts expanded (corePred.beta #[vs]))
          mkAppM ``Iff.trans #[cert, ← mkAppOptM ``exists_congr #[α, none, corePred, bridge]]
      let lhs ← mkEq (← boolOf cert) (mkConst ``Bool.true)
      let cert ← mkExpectedTypeHint cert (← mkAppM ``Iff #[lhs, coreEx])
      let independent := separate.foldr and (mkConst ``True)
      let some (_, independentCert) ← reflect env owner independent | return some none
      let cert ← mkAppM ``and_cert #[cert, independentCert]
      let canon := and (corePred.beta #[vs]) independent
      let canonPred ← mkLambdaFVars #[vs] canon
      let canonEx := mkApp2 p.getAppFn α canonPred
      let pull ← mkAppOptM ``exists_and_right #[α, corePred, independent]
      let cert ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[pull]]
      let cert ← mkExpectedTypeHint cert (← mkAppM ``Iff #[← mkEq (← boolOf cert) (mkConst ``Bool.true), canonEx])
      let pointwise ← mkLambdaFVars #[vs] (← sameConjuncts canon inner)
      let congr ← mkAppOptM ``exists_congr #[α, canonPred, pred, pointwise]
      let cert ← mkAppM ``Iff.trans #[cert, congr]
      return some (some (← boolOf cert, cert))
  if let some r := quorum? then
    return r
  let found ← withLocalDeclD `x α fun x => do
    let inner := pred.beta #[x]
    withLocalDeclD `h inner fun h => do
      let gs ← findGuards env x inner h
      let some g := pickGuard gs | return none
      return some (g, ← mkLambdaFVars #[x, h] g.mem, x)
  match found with
  | some (g, bounded, binder) =>
    if env.isFrame α && !(g.kind matches .subst ..) then
      block owner "binderFrame" (headName α)
      return none
    modify fun s => { s with guardTags := s.guardTags.push (shortName owner,
      s!"{g.tag}:{headName g.list}") }
    quantify env owner true α pred g binder bounded
  | none =>
    if env.isFrame α then
      block owner "binderFrame" (headName α)
      return none
    if α.isConstOf ``Bool || α.isConstOf ``Role then
      let list ← if α.isConstOf ``Bool then
          mkListLit α [mkConst ``Bool.false, mkConst ``Bool.true]
        else mkListLit α ([``Role.none, ``Role.follower, ``Role.preVoteCandidate, ``Role.candidate,
          ``Role.primary].map mkConst)
      let lem := if α.isConstOf ``Bool then ``bool_mem else ``role_mem
      let bounded ← withLocalDeclD `x α fun x => withLocalDeclD `h (pred.beta #[x]) fun h => do
        mkLambdaFVars #[x, h] (mkApp (mkConst lem) x)
      let dummy ← withLocalDeclD `x α fun x => pure x
      return ← quantify env owner true α pred { kind := .plain, list, mem := mkConst ``True.intro, rank := 9, tag := "enum" } dummy bounded
    if ← isNatType α then
      if env.extraRules then
        let erased := pred.beta #[mkNatLit 0]
        let vacuous? ← withLocalDeclD `n α fun n => do
          let body := pred.beta #[n]
          unless ← withNewMCtxDepth (withTransparency .default (isDefEq body erased)) do
            return none
          let refl := mkApp (mkConst ``Iff.rfl) erased
          let eq ← mkExpectedTypeHint refl (← mkAppM ``Iff #[body, erased])
          let eq ← mkLambdaFVars #[n] eq
          return some (← mkAppM ``exists_congr #[eq])
        if let some eq := vacuous? then
          let some (b, cert) ← reflect env owner erased | return none
          let vacuous ← mkAppM ``exists_vacuous #[mkNatLit 0, erased]
          let back ← mkAppM ``Iff.trans #[← mkAppM ``Iff.symm #[vacuous], ← mkAppM ``Iff.symm #[eq]]
          modify fun s => { s with guardTags := s.guardTags.push (shortName owner, "irrelevantNat") }
          return some (b, ← mkAppM ``Iff.trans #[cert, back])
      if let some sat ← saturateNat true pred then
        let rhs ← Core.betaReduce (← typeArg sat 1)
        if let some (b, cert) ← reflect env owner rhs then
          modify fun s => { s with guardTags := s.guardTags.push (shortName owner, "saturate") }
          return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[sat]])
        return none
    let disj ← withLocalDeclD `x α fun x => do
      let body := pred.beta #[x]
      unless body.isAppOfArity ``Or 2 do return none
      let l ← mkLambdaFVars #[x] (body.getArg! 0)
      let r ← mkLambdaFVars #[x] (body.appArg!)
      let iff ← mkAppOptM ``exist_or #[some α, some l, some r]
      return some (l, r, iff)
    if let some (l, r, iff) := disj then
      let wrap q := mkApp2 p.getAppFn α q
      let other := mkApp2 (mkConst ``Or) (wrap l) (wrap r)
      let some (b, cert) ← reflectSimp env owner other env.basic | return none
      return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]])
    -- `∃ x y, P x y`: try `∃ y x, P x y`, whose outer binder may have a guard
    if !swapped then
      let p2? ← withLocalDeclD `x α fun x => do
        let inner := pred.beta #[x]
        unless inner.isAppOfArity ``Exists 2 do return none
        let β := inner.getArg! 0
        if β.containsFVar x.fvarId! then return none
        return some (← mkLambdaFVars #[x] (inner.getArg! 1))
      if let some p2 := p2? then
        let comm ← mkAppOptM ``exists_comm #[none, none, some p2]
        let rhs ← Core.betaReduce (← typeArg comm 1)
        let saved := (← get).blockers.size
        if let some (b, cert) ← reflectExists env owner rhs (swapped := true) then
          let cert ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[comm]]
          return some (b, cert)
        modify fun s => { s with blockers := s.blockers.shrink saved }
    blockBinder owner "noguard" α pred
    return none

/-- Premises of a `∀`, each possibly guarding the bound variable. -/
partial def reflectForall (env : Env) (owner : Name) (p : Expr) : CM (Option Compiled) := do
  let .forallE n α body bi := p | return none
  if α.isAppOf ``List then
    if let some (_, iff) ← applyIff ``backed_prefix_agreement p then
      let pr ← mkAppM ``Iff.mpr #[iff, mkConst ``True.intro]
      let cert ← mkAppM ``proof_cert #[pr]
      return some (← boolOf cert, cert)
  if ← isProp α then
    if !body.hasLooseBVars then
      let ra ← reflect env owner α
      let rb ← reflect env owner body
      let some (_, ha) := ra | return none
      let some (_, hb) := rb | return none
      let cert ← mkAppM ``imp_cert #[ha, hb]
      return some (← boolOf cert, cert)
    let pred := Expr.lam n α body bi
    let ra ← reflect env owner α
    return ← withLocalDeclD `h α fun hx => do
      let rq ← reflect env owner (body.instantiate1 hx)
      let some (_, ha) := ra | return none
      let some (bq, hq) := rq | return none
      if !env.extraRules && bq.containsFVar hx.fvarId! then
        block owner "depProp" ""
        return none
      let cert ← mkAppOptM ``forall_prop_cert #[α, pred, none, ha, ← mkLambdaFVars #[hx] bq,
        ← mkLambdaFVars #[hx] hq]
      return some (← boolOf cert, cert)
  let pred := Expr.lam n α body bi
  let hits? ← withLocalDeclD `xs α fun xs => do
    let .forallE _ q body _ := body.instantiate1 xs | return none
    unless q.isAppOfArity ``hasQuorum 2 && q.appArg! == xs && !body.hasLooseBVars &&
        body.isAppOfArity ``Exists 2 do return none
    let cs := q.getArg! 0
    if cs.containsFVar xs.fvarId! then return none
    withLocalDeclD `v (body.getArg! 0) fun v => do
      let p := body.appArg!.beta #[v]
      unless p.isAppOfArity ``And 2 do return none
      let mem := p.getArg! 0
      let rest := p.appArg!
      unless mem.isAppOfArity ``Membership.mem 5 && mem.getArg! 3 == xs && mem.appArg! == v &&
          !rest.containsFVar xs.fvarId! do return none
      let some (b, cert) ← reflect env owner rest | return some none
      let test ← mkLambdaFVars #[v] b
      let pw ← mkLambdaFVars #[v] cert
      let cert ← mkAppM ``quorum_hits #[cs, test, pw]
      return some (some (← boolOf cert, cert))
  if let some r := hits? then return r
  let found ← withLocalDeclD `x α fun x => do
    let inner := body.instantiate1 x
    forallTelescope inner fun hyps concl => do
      for hi in hyps do
        let hty ← inferType hi
        unless ← isProp hty do continue
        let gs ← findGuards env x hty hi
        -- A projected guard may be independent even when a cheaper keyed
        -- guard still contains a later telescope local.
        let locals := hyps.map (·.fvarId!)
        let mentions (e : Expr) := locals.any e.containsFVar
        let some g := pickGuard (gs.filter fun g =>
          match g.kind with
          | .plain => !env.isFrame α && !mentions g.list
          | .keyedSnd L a => !env.isFrame α && !mentions L && !mentions a
          | .keyedFst L b => !env.isFrame α && !mentions L && !mentions b
          | .subst e => !mentions e) | continue
        let memTy ← inferType g.mem
        let notMem ← mkAppM ``Not #[memTy]
        let bounded ← withLocalDeclD `hn notMem fun hn => do
          let absurd ← mkAppOptM ``absurd #[memTy, concl, g.mem, hn]
          let inner ← mkLambdaFVars hyps absurd
          match g.kind with
          | .keyedSnd .. | .keyedFst .. | .plain | .subst _ => mkLambdaFVars #[x, hn] inner
        return some (g, bounded, x)
      return none
  match found with
  | some (g, bounded, binder) =>
    let g := { g with how := .none }
    modify fun s => { s with guardTags := s.guardTags.push (shortName owner, s!"all:{g.tag}") }
    quantify env owner false α pred g binder bounded
  | none =>
    if env.isFrame α then
      block owner "binderFrame" (headName α)
      return none
    if ← isNatType α then
      if let some sat ← saturateNat false (.lam n α body bi) then
        let rhs ← Core.betaReduce (← typeArg sat 1)
        if let some (b, cert) ← reflect env owner rhs then
          modify fun s => { s with guardTags := s.guardTags.push (shortName owner, "saturate") }
          return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[sat]])
        return none
    if α.isConstOf ``Bool || α.isConstOf ``Role then
      block owner "forallEnum" (headName α)
    else
      blockBinder owner "forall" α (.lam n α body bi)
    return none

partial def reflect (env : Env) (owner : Name) (p : Expr) : CM (Option Compiled) := do
  let p := p.consumeMData
  let p ← if headName p == "other" then withReducible (whnf p) else pure p
  if p.isAppOfArity ``And 2 then
    let l := p.getArg! 0
    let r := p.appArg!
    let some (_, pl) ← reflect env owner l | return none
    return ← withLocalDeclD `left l fun h => do
      let event := mkApp (mkConst ``XView.event) env.xv
      let mut rules := env.basic
      let mut changed := false
      if l.isAppOfArity ``Eq 3 &&
          (l.getArg! 1 == event || l.appArg! == event) then do
        let eq ← if l.appArg! == event then pure h else mkEqSymm h
        let run ← mkAppM ``X.run_for #[env.ok, eq]
        rules ← addRule rules run (post := false)
        changed := true
      else if l.isAppOfArity ``Eq 3 && ((l.getArg! 1).isFVar || l.appArg!.isFVar) &&
          (!env.extraRules ||
            ((l.getArg! 1).isFVar && !l.appArg!.containsFVar (l.getArg! 1).fvarId!) ||
            (l.appArg!.isFVar && !(l.getArg! 1).containsFVar l.appArg!.fvarId!)) then
        rules ← addRule rules h
        changed := true
      else if l.isAppOfArity ``Membership.mem 5 && (l.getArg! 3).isAppOf ``XView.sent then
        rules ← addRule rules h
        changed := true
      if let .const n _ := l.getAppFn then
        if isGenerated n then
          let info ← compileConst env n
          if let some args ← actualArgs env info l then
            for g in info.guards do
              let some (guard, proof) := g | continue
              let q := guard.beta (#[env.inst, env.xv] ++ args)
              if q.isAppOfArity ``Eq 3 && q.getArg! 1 != q.appArg! then
                let proof := mkAppN (mkConst proof)
                  (#[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ args ++ #[h])
                rules ← addRule rules proof
                if q.getArg! 1 == event || q.appArg! == event then
                  let eq ← if q.appArg! == event then pure proof else mkEqSymm proof
                  rules ← addRule rules (← mkAppM ``X.run_for #[env.ok, eq]) (post := false)
                changed := true
      let some (b, pr) ← (if changed then reflectSimp env owner r rules else reflect env owner r) |
        return none
      if b.containsFVar h.fvarId! then
        block owner "depProp" ""
        return none
      let cert ← mkAppM ``and_under_cert #[pl, ← mkLambdaFVars #[h] pr]
      return some (← boolOf cert, cert)
  if p.isAppOfArity ``Or 2 || p.isAppOfArity ``Iff 2 then
    let some (_, pl) ← reflect env owner (p.getArg! 0) | return none
    let some (_, pr) ← reflect env owner (p.getArg! 1) | return none
    let lemma := if p.isAppOf ``Or then ``or_cert else ``iff_cert
    let cert ← mkAppM lemma #[pl, pr]
    return some (← boolOf cert, cert)
  if p.isAppOfArity ``Not 1 then
    let some (_, h) ← reflect env owner p.appArg! | return none
    let cert ← mkAppM ``not_cert #[h]
    return some (← boolOf cert, cert)
  if p.isAppOfArity ``Exists 2 then
    return ← reflectExists env owner p
  if p.isForall then
    return ← reflectForall env owner p
  if let .const n _ := p.getAppFn then
    if isGenerated n then
      let info ← compileConst env n
      let some others ← actualArgs env info p | do
        block owner "callShape" (shortName n)
        return none
      if others.any env.isFrame then
        block owner "argFrame" (shortName n)
        return none
      let some (r, riff) := info.reader | do
        block owner "child" (shortName n)
        return none
      let mut hs := #[]
      for cl in info.conds do
        let ty := cl.beta (#[env.inst, env.xv] ++ others)
        let hc ← if let some h ← findLocal ty then pure (some h) else do
          let r ← simplify env ty env.basic
          if r.expr.isConstOf ``True then
            pure (some (← mkEqMPR (← r.getProof) (mkConst ``True.intro)))
          else pure none
        let some hc := hc | do
          let text := (toString (← ppExpr ty)).replace "\n" " " |>.replace "\t" " "
          block owner "cond" s!"{shortName n}\t{text}"
          return none
        hs := hs.push hc
      return some (mkAppN (mkConst r) (#[env.inst, env.xv] ++ others),
        mkAppN (mkConst riff) (#[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ others ++ hs))
  if let some cert ← sendMatcher env p then
    return some (← boolOf cert, cert)
  if let some payload := sendPayload? p then
    if let some compiled ← reflectMessageCases p payload fun arm => do
      let atom ← withTransparency .all (whnf arm)
      if (sendPayload? atom).isSome then return none
      reflectSimp env owner atom env.second
    then return some compiled
  if p.isAppOf ``MessageOK then
    if let some cert ← withNewMCtxDepth do
      for name in [``ReadersVoteReply.before_response, ``ReadersVoteReply.after_response] do
        let rule ← mkAppM name #[env.ok]
        let (xs, _, ty) ← forallMetaTelescope (← inferType rule)
        if ← withReducible (isDefEq (ty.getArg! 0) p) then
          let iff ← instantiateMVars (mkAppN rule xs)
          unless iff.hasExprMVar do return some (← mkAppM ``Iff.symm #[iff])
      return none
    then return some (← boolOf cert, cert)
    let payload ← withTransparency .all (whnf (← mkAppM ``Envelope.payload #[p.appArg!]))
    if let some head := payload.getAppFn.constName? then
      if let .ctorInfo ci ← getConstInfo head then
        if ci.induct == ``Consensus.Model.Node.Message then
          let atom ← withTransparency .all (whnf p)
          unless atom.isAppOf ``MessageOK do
            let r ← simplify env atom env.first
            let some (b, cert) ← reflectSimp env owner r.expr env.second | return none
            return some (b, ← recertify r cert)
  if p.isAppOfArity ``Wins 4 then
    let iff ← mkAppM ``wins_view #[env.ok]
    if ← withReducible (isDefEq (← typeArg iff 0) p) then
      let some (b, cert) ← reflect env owner (← typeArg iff 1) | return none
      return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]])
    let rules ← env.first.addDeclToUnfold ``Wins
    let r ← simplify env p rules
    let some (b, cert) ← reflectSimp env owner r.expr env.second | return none
    return some (b, ← recertify r cert)
  if p.isAppOfArity ``HEq 4 then
    let a := p.getArg! 1
    if ← isDefEq (p.getArg! 0) (p.getArg! 2) then
      if ← isDefEq a p.appArg! then
        let proof ← mkAppM ``HEq.refl #[a]
        let proof ← mkExpectedTypeHint proof p
        let cert ← mkAppM ``proof_cert #[proof]
        return some (← boolOf cert, cert)
  if let some cert ← recordedIndexEq env p then
    return some (← boolOf cert, cert)
  if env.isFrame p then
    let rule := ([(``CampaignFacts, ``campaignFacts_iff), (``CommitFacts, ``commitFacts_iff),
      (``ElectionCert, ``electionCert_iff), (``CopyLog, ``copyLog_iff),
      (``AppendEvidence, ``appendEvidence_iff)].find? (·.1 == p.getAppFn.constName?.getD .anonymous)).map Prod.snd
    if let some rule := rule then
      if let some (q, iff) ← applyIff rule p then
        let r ← simplify env q env.first
        let some (b, cert) ← reflectSimp env owner r.expr env.second | return none
        return some (b, ← mkAppM ``Iff.trans #[← recertify r cert, ← mkAppM ``Iff.symm #[iff]])
    blockAtom owner "frame" p
    return none
  match ← trySynthInstance (mkApp (mkConst ``Decidable) p) with
  | .some d =>
    let d ← instantiateMVars d
    if (d.find? fun e => e.isConstOf ``Classical.propDecidable || e.isConstOf ``Classical.choice).isSome then
      blockAtom owner "classical" p
      return none
    return some (mkApp2 (mkConst ``decide) p d, mkApp2 (mkConst ``decide_eq_true_iff) p d)
  | _ =>
    if p.isAppOfArity ``Eq 3 && (p.getArg! 0).isConstOf ``NodeState then
      let iff ← mkAppM ``node_eq_iff #[p.getArg! 1, p.getArg! 2]
      let body := (← inferType iff).appArg!
      let rules ← env.basic.addConst ``update_eq_iff
      let rules ← rules.addConst ``update_eq_self
      let rules ← rules.addConst ``eq_update_self
      let some (b, cert) ← reflectSimp env owner body rules | return none
      return some (b, ← mkAppM ``Iff.trans #[cert, ← mkAppM ``Iff.symm #[iff]])
    blockAtom owner "undecidable" p
    return none

/-- A disjunction does not need to normalize every arm before finding out
whether its first arm has a reader. No failed branch is treated as false. -/
partial def reflectDisjunction (env : Env) (owner : Name) (p : Expr) : CM (Option Compiled) := do
  if p.isAppOfArity ``Or 2 then
    let some (_, pl) ← reflectDisjunction env owner (p.getArg! 0) | return none
    let some (_, pr) ← reflectDisjunction env owner p.appArg! | return none
    let cert ← mkAppM ``or_cert #[pl, pr]
    return some (← boolOf cert, cert)
  let r ← simplify env p env.first
  let some (b, cert) ← reflectSimp env owner r.expr env.second | return none
  return some (b, ← recertify r cert)

partial def compileConst (env : Env) (n : Name) : CM RInfo := do
  if let some i := (← get).memo[n]? then return i
  if let some dir := env.reportDir then
    IO.FS.withFile (dir / "attempts.log") .append fun h => h.putStrLn (shortName n)
  let t0 ← IO.monoMsNow
  let b0 := (← get).blockers.size
  let info ← tryCatchRuntimeEx (compileUncached env n)
    fun ex => do
      block n "exception" ((← ex.toMessageData.toString).take 200 |>.replace "\n" " " |>.replace "\t" " ")
      pure {}
  modify fun s => { s with memo := s.memo.insert n info }
  let dt := (← IO.monoMsNow) - t0
  let all := (← get).blockers
  let mine := (all.extract b0 all.size).filter (·.1 == shortName n)
  let kinds : Array String := mine.map fun (_, k, d) => s!"{k}:{(d.splitOn "\t").headD ""}"
  let kinds := kinds.foldl (fun (acc : Array String) k => if acc.contains k then acc else acc.push k) #[]
  if let some dir := env.reportDir then
    IO.FS.withFile (dir / "progress.log") .append fun h =>
      h.putStrLn s!"{shortName n}\t{dt}\t{if info.reader.isSome then 1 else 0}\t{String.intercalate "," kinds.toList}"
  return info

partial def compileUncached (env : Env) (n : Name) : CM RInfo := do
  let ci ← getConstInfo n
  unless ci.levelParams.isEmpty do
    block n "levels" ""
    return {}
  let ty0 ← instantiateForall ci.type #[env.inst, env.f, env.t, env.c]
  let hasC1 := match ty0 with
    | .forallE _ d _ _ => d.isAppOf ``Ctx
    | _ => false
  let pre := if hasC1 then #[env.inst, env.f, env.t, env.c, env.c] else #[env.inst, env.f, env.t, env.c]
  let ty ← instantiateForall ci.type pre
  forallTelescope ty fun originals _ => do
    let tr ← env.transition
    let mut actuals := #[]
    let mut params := #[]
    let mut pinned := #[]
    for j in [:originals.size] do
      let x := originals[j]!
      let ty ← inferType x
      let ty' := ty.replaceFVars (originals.extract 0 j) actuals
      if ty'.isAppOf ``LocalTransition && (← isDefEq ty' (← inferType tr)) then
        actuals := actuals.push tr
        pinned := pinned.push (j, true)
        continue
      if ty.isConstOf ``Model.State then
        if let some next := originals[j + 1]? then
          let nextTy ← inferType next
          if nextTy.isAppOfArity ``LocalTransition 2 && nextTy.appArg! == x then
            actuals := actuals.push env.t
            pinned := pinned.push (j, false)
            continue
      actuals := actuals.push x
      params := params.push x
    let mut frameParam := false
    let mut dependent := #[]
    for x in params do
      let ty ← inferType x
      if env.isFrame ty || pinned.any (fun (i, _) => ty.containsFVar originals[i]!.fvarId!) then
        frameParam := true
        dependent := dependent.push (headName ty)
    if frameParam then
      block n "paramFrame" (String.intercalate "," dependent.toList)
      return { hasC1, pinned, guards := params.map fun _ => none }
    let p := ci.value!.beta (pre ++ actuals)
    let call := mkAppN (mkConst n) (pre ++ actuals)
    let split := params.isEmpty && p.isAppOfArity ``Or 2
    let cuts ← RequestTransport.normalize isGenerated env.ok env.xv env.f p
    let r1 ← if !split && env.isFrame p then
      cuts.mkEqTrans (← simplify env cuts.expr env.first)
    else pure cuts
    let r2 ← if !split then simplify env r1.expr env.second else pure { expr := r1.expr }
    let short := shortName n
    let mut guards := #[]
    let mut conds := #[]
    for j in [0:params.size] do
      let x := params[j]!
      let g? ← withLocalDeclD `h call fun h => do
        let h1 := match r1.proof? with
          | some pr => mkApp4 (mkConst ``Eq.mp [.zero]) p r1.expr pr h
          | none => h
        let h2 := match r2.proof? with
          | some pr => mkApp4 (mkConst ``Eq.mp [.zero]) r1.expr r2.expr pr h1
          | none => h1
        let gs ← findGuards env x r2.expr h2
        let gs := gs.qsort (·.rank < ·.rank)
        for g in gs do
          let memTy ← instantiateMVars (← inferType g.mem)
          if env.isFrame memTy then continue
          if (match g.kind with | .subst e => e.containsFVar x.fvarId! | _ => false) then continue
          let gname := Name.mkStr (env.target ++ `G) s!"{short}_{j}"
          let allArgs := #[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ params ++ #[h]
          let thmTy ← mkForallFVars allArgs memTy
          let thmVal ← mkLambdaFVars allArgs g.mem
          addCertificate <| .thmDecl { name := gname, levelParams := [], type := thmTy, value := thmVal }
          return some (← mkLambdaFVars (#[env.inst, env.xv] ++ params) memTy, gname)
        return none
      guards := guards.push g?
      if let some (lam, _) := g? then
        let xTy ← inferType x
        let decEq ← withReducible (trySynthInstance (← mkAppM ``DecidableEq #[xTy]))
        unless decEq matches .some _ do
          conds := conds.push lam
    let condTys := conds.map (·.beta (#[env.inst, env.xv] ++ params))
    let mut reader := none
    let decls := condTys.mapIdx fun i ty => ((`hc).appendIndexAfter i, fun _ => pure ty)
    reader ← withLocalDeclsD decls fun hs => do
      let r3 ← if hs.isEmpty then pure { expr := r2.expr : Simp.Result } else do
        let mut rules := env.second
        for hc in hs do rules ← addRule rules hc
        simplify env r2.expr rules
      let out ← if split then reflectDisjunction env n r3.expr else reflect env n r3.expr
      let some (b, cert) := out | return none
      if env.isFrame b || hs.any (fun hc => b.containsFVar hc.fvarId!) then
        block n "leak" ""
        return none
      let cert ← recertify r3 cert
      let cert ← recertify r2 cert
      let cert ← recertify r1 cert
      let b ← Core.betaReduce b
      let rname := Name.mkStr (env.target ++ `R) short
      let iname := Name.mkStr (env.target ++ `R) s!"{short}_iff"
      let rargs := #[env.inst, env.xv] ++ params
      addReader <| .defnDecl {
        name := rname, levelParams := [],
        type := ← mkForallFVars rargs (mkConst ``Bool), value := ← mkLambdaFVars rargs b,
        hints := .regular 0, safety := .safe }
      let lhs := mkAppN (mkConst rname) rargs
      let stmt ← mkAppM ``Iff #[← mkEq lhs (mkConst ``Bool.true), call]
      let iargs := #[env.inst, env.f, env.t, env.c, env.xv, env.ok] ++ params ++ hs
      addCertificate <| .thmDecl {
        name := iname, levelParams := [],
        type := ← mkForallFVars iargs stmt, value := ← mkLambdaFVars iargs cert }
      return some (rname, iname)
    return { reader, guards, conds, hasC1, pinned }

end

def tryAddConst (rules : SimpTheorems) (n : Name) (missing : IO.Ref (Array Name)) : MetaM SimpTheorems := do
  try rules.addConst n catch _ => do missing.modify (·.push n); pure rules

def tryUnfold (rules : SimpTheorems) (n : Name) (missing : IO.Ref (Array Name)) : MetaM SimpTheorems := do
  if (← getEnv).contains n then rules.addDeclToUnfold n else do missing.modify (·.push n); pure rules

structure ExactTarget where
  namespaceName : Name := `ConsensusCoverage.ReadersCompiler
  columns : Option NameSet := none
  /-- Additional guards not included in the audited factored dispatch. -/
  extraRules : Bool := false

public def driverWith (run? : Option (Env → Array Name → Array Expr → MetaM Unit))
    (target : ExactTarget := {}) : MetaM Unit := do
  let start ← IO.monoMsNow
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  let branchTy := mkConst ``Classes.StepBranch
  let casesOn (level : Level) (motive b : Expr) (arms : Array Expr) :=
    mkAppN (mkConst ``Classes.StepBranch.casesOn [level]) (#[motive, b] ++ arms)
  let missing ← IO.mkRef (#[] : Array Name)
  lambdaTelescope ci.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "unexpected normalized dispatcher"
    let armNames : Array Name ← (args.extract 2 args.size).mapM fun arm => do
      let .const n _ := arm.getAppFn | throwError "expected generated arm"
      return n
    let inst := xs[0]!
    let f := xs[1]!
    let t := xs[2]!
    let c := xs[3]!
    let b := xs[4]!
    withLocalDeclD `x (mkConst ``XView) fun xv =>
    withLocalDeclD `ok (mkAppN (mkConst ``XView.Matches) #[inst, f, t, xv, c]) fun ok => do
      let base := mkApp (mkConst ``XView.base) xv
      let okb := mkAppN (mkConst ``XView.Matches.base_ok) #[inst, f, t, xv, c, ok]
      let mut basic : SimpTheorems := {}
      for r in [``eq_self, ``and_true, ``true_and, ``or_false, ``false_or, ``or_true, ``true_or,
          ``and_false, ``false_and, ``and_self, ``or_self, ``exists_const, ``not_false_eq_true,
          ``not_true_eq_false, ``exists_prop, ``exists_eq_left, ``exists_eq_right,
          ``exists_eq_left', ``exists_eq_right', ``exists_eq, ``exists_eq', ``heq_eq_eq, ``ne_eq,
          ``forall_eq, ``forall_eq', ``true_implies, ``implies_true, ``false_implies, ``Prod.eta,
          ``exists_and_left, ``exists_and_right, ``gt_iff_lt, ``ge_iff_le, ``iff_self,
          ``Prod.mk.injEq, ``exists_eq_right_right, ``Bool.false_eq_true, ``Bool.true_eq_false,
          ``Classical.not_not, ``obs_eta, ``Option.some.injEq, ``forall_const, ``imp_self] do
        basic ← tryAddConst basic r missing
      for ind in [``Event, ``Consensus.Model.Node.Message, ``Input, ``CCF.Envelope, ``Safety.Observation] do
        let info ← getConstInfoInduct ind
        for ctor in info.ctors do
          let inj := ctor ++ `injEq
          if (← getEnv).contains inj then basic ← basic.addConst inj
      for r in [``X.before_of_after, ``X.after_of_before, ``X.pre_mem, ``X.post_mem, ``X.run_eq,
          ``view_same, ``view_same'] do
        basic ← addRule basic (mkAppN (mkConst r) #[inst, f, t, xv, c, ok])
      for r in [``message_before, ``message_after] do
        basic ← addRule basic (mkAppN (mkConst r) #[inst, f, t, xv, c, ok])
      for r in [``ReadersIndex.observe_match, ``ReadersIndex.observe_sent] do
        basic ← basic.addConst r
      basic ← basic.addConst ``exists_false_iff
      let simprocs ← Simp.getSimprocs
      let mut first := basic
      first ← addRule first (mkAppN (mkConst ``X.elect_now) #[inst, f, t, xv, c, ok])
        (post := false)
      for n in [``Committed, ``Canon, ``Elected, ``Granted, ``Seen, ``CanonNow, ``CommitStep,
          ``ElectStep, ``Led, ``Engaged, ``Backed, ``Acked, ``Rooted, ``LogFacts.ElectionAt,
          ``LogFacts.GrantAt, ``LogFacts.Ghost.canonNow, ``LogFacts.Ghost.commitAt, ``LogFacts.Ghost.led, ``Advance,
          ``Campaign, ``Accepted, ``VoterRank, ``RankOrLoss, ``VoteRank, ``Blocked, ``Bad,
          ``AEOk, ``Direct.CommitFrontier, ``Direct.Extends, ``vals] do
        first ← tryUnfold first n missing
      for n in [``commitFacts_iff, ``campaignFacts_iff, ``electionCert_iff, ``appendEvidence_iff, ``copyLog_iff,
          ``prefix_witness_iff, ``common_extension_iff] do
        first ← first.addConst n
      for r in [``Inv.canon_mono, ``Inv.rankedElections, ``Inv.election_safety,
          ``Inv.electionCerts, ``Inv.copyLogs, ``Inv.ballots, ``Inv.commitChains] do
        first ← addRule first (← mkAppM r #[← mkAppM ``Ctx.inv #[c]]) (post := false)
        first ← addRule first (← mkAppM r #[← mkAppM ``Ctx.inv_step #[c]]) (post := false)
      first ← addRule first (← mkAppM ``wins_recorded #[c]) (post := false)
      first ← addRule first (mkAppN (mkConst ``any_fresh_now) #[inst, f, t, c])
      for r in [``View.any_fresh_canon, ``View.other_log] do
        first ← addRule first (mkAppN (mkConst r) #[inst, f, t, base, c, okb])
      first ← addRule first (mkAppN (mkConst ``X.unchanged_iff) #[inst, f, t, xv, c, ok])
      first ← addRule first (mkAppN (mkConst ``View.old_post) #[inst, f, t, base, c, okb]) (post := false)
      for r in [``Ctx.pre_now, ``Ctx.post_now, ``Ctx.term_le] do
        first ← addRule first (mkAppN (mkConst r) #[inst, f, t, c]) (post := false)
      let mut second := basic
      let endpoint := mkAppN (mkConst ``X.after_eq) #[inst, f, t, xv, c, ok]
      let endpointRules ← addRule {} endpoint
      let endpointSimp ← Simp.mkContext (simpTheorems := #[endpointRules])
        (congrTheorems := ← getSimpCongrTheorems)
      for r in [``X.now_before, ``X.now_after, ``X.pending_before, ``X.pending_after,
          ``X.seen_before, ``X.seen_after, ``X.led_before, ``X.led_after, ``X.canon_before,
          ``X.canon_after, ``X.committed_before, ``X.committed_after, ``X.grant_before,
          ``X.grant_after, ``X.elected_before, ``X.elected_after, ``X.current_after,
          ``X.votes_after, ``X.pending_eq] do
        let proof := mkAppN (mkConst r) #[inst, f, t, xv, c, ok]
        second ← addRule second proof (post := false)
        let (alias, _) ← simp (← inferType proof) endpointSimp #[]
        if let some rewrite := alias.proof? then
          second ← addRule second (← mkEqMP rewrite proof) (post := false)
      for r in [``X.elected_advanced, ``X.canon_advanced, ``X.committed_advanced] do
        second ← addRule second (mkAppN (mkConst r) #[inst, f, t, xv, c, ok])
      for r in [``X.tr_actor_eq, ``X.tr_pre_eq, ``X.tr_post_eq, ``X.tr_event_eq, ``X.tr_sent_eq,
          ``X.event_eq, ``X.sent_eq, ``X.outputs_eq, ``X.before_eq, ``X.after_eq, ``X.votes_before] do
        second ← addRule second (mkAppN (mkConst r) #[inst, f, t, xv, c, ok])
      for r in [``View.pre_eq, ``View.post_eq, ``View.actor_eq] do
        second ← addRule second (mkAppN (mkConst r) #[inst, f, t, base, c, okb])
      second ← addRule second (← mkAppM ``wins_view #[ok]) (post := false)
      second ← second.addConst ``exists_mem_iff
      second ← second.addConst ``sig_index
      second ← second.addConst ``update_eq_iff
      let send := mkAppN (mkConst ``X.send_ok) #[inst, f, t, xv, c, ok]
      let sendRules ← forallTelescope (← inferType send) fun args _ => do
        let send := mkAppN send args
        let p ← whnf (← inferType send)
        #[``And.left, ``And.right].mapM fun field => do
          let proof ← mkAppOptM field #[p.getArg! 0, p.appArg!, send]
          let normalize (proof : Expr) (rules : SimpTheorems) := do
            let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
            let (simp, _) ← withReducible (simp (← inferType proof) ctx #[simprocs])
            if let some eq := simp.proof? then mkEqMP eq proof else pure proof
          let normalized ← normalize (← normalize proof first) second
          mkLambdaFVars args normalized
      for proof in sendRules do
        basic ← addRule basic proof
      let reportDir := (← IO.getEnv "CCF_READERS_REPORT").map fun path =>
        let parent := System.FilePath.mk path
        if target.columns.isSome then parent / target.namespaceName.getString! else parent
      if let some dir := reportDir then
        IO.FS.createDirAll dir
        IO.FS.writeFile (dir / "progress.log") ""
        IO.FS.writeFile (dir / "attempts.log") ""
      let env : Env := {
        inst, f, t, c, xv, ok, first, second, basic, simprocs := #[simprocs], reportDir,
        target := target.namespaceName, extraRules := target.extraRules }
      let miss ← missing.get
      unless miss.isEmpty do logInfo m!"missing simp names: {miss}"
      if let some run := run? then return ← run env armNames xs
      let st ← IO.mkRef ({} : St)
      -- Try shallow formulas first. The order changes only when work is
      -- attempted; the dispatcher is emitted in constructor order.
      let chosen := match target.columns with
        | none => armNames
        | some columns =>
          (Array.zip armNames branch.ctors.toArray).filterMap fun (entry : Name × Name) =>
            if columns.contains entry.2 then some entry.1 else none
      let byDepth ← chosen.mapM fun n => do
        return (n, (← getConstInfo n).value!.approxDepth)
      for (n, _) in byDepth.qsort (·.2 < ·.2) do
        let (_, s') ← (compileConst env n).run (← st.get)
        st.set s'
      let s ← st.get
      let results := armNames.map fun n =>
        let reader := s.memo[n]?.bind (·.reader)
        (reader.map Prod.fst, reader.map Prod.snd)
      -- reports
      let mut lines := #[]
      for (o, k, d) in s.blockers do lines := lines.push s!"{o}\t{k}\t{d}"
      let mut status := #[]
      let visited := (s.memo.toArray.map (·.1) |>.filter fun n => (shortName n).startsWith "reach_").qsort
        fun a b => (((shortName a).splitOn "_").getLast!.toNat?.getD 0) <
          (((shortName b).splitOn "_").getLast!.toNat?.getD 0)
      let reachCompiled := visited.filter fun n => (s.memo[n]?.bind (·.reader)).isSome
      let reachGuarded := visited.filter fun n => (s.memo[n]?.map (·.guards.any Option.isSome)).getD false
      for n in visited ++ armNames do
        let info := s.memo[n]?.getD {}
        let gs := info.guards.map fun g => if g.isSome then "1" else "0"
        status := status.push s!"{shortName n}\t{if info.reader.isSome then 1 else 0}\t{String.join gs.toList}"
      let mut tags := #[]
      for (o, g) in s.guardTags do tags := tags.push s!"{o}\t{g}"
      if let some dir := reportDir then
        IO.FS.writeFile (dir / "blockers.tsv") (String.intercalate "\n" lines.toList ++ "\n")
        IO.FS.writeFile (dir / "status.tsv") (String.intercalate "\n" status.toList ++ "\n")
        IO.FS.writeFile (dir / "guards.tsv") (String.intercalate "\n" tags.toList ++ "\n")
        let h ← IO.FS.Handle.mk (dir / "dag.tsv") .write
        let mut pending := armNames
        let mut seen : Std.HashSet Name := {}
        repeat
          let some n := pending.back? | break
          pending := pending.pop
          if seen.contains n then continue
          seen := seen.insert n
          let callees := (← getConstInfo n).value!.foldConsts ({} : NameSet) fun child acc =>
            if isGenerated child then acc.insert child else acc
          h.putStrLn s!"{n.getString!}\t{String.intercalate "," (callees.toList.map (·.getString!))}"
          pending := pending ++ callees.toList.toArray
        h.flush
      -- assemble
      let readerName := env.target ++ `readView
      let coveredName := env.target ++ `generatedColumns
      let correctName := env.target ++ `readView_correct
      let supportedName := env.target ++ `readView_supported
      let ret := mkApp (mkConst ``Option [.zero]) (mkConst ``Bool)
      let values := results.map fun (r, _) => match r with
        | none => mkApp (mkConst ``Option.none [.zero]) (mkConst ``Bool)
        | some r => mkApp2 (mkConst ``Option.some [.zero]) (mkConst ``Bool) (mkApp2 (mkConst r) inst xv)
      addReader <| .defnDecl {
        name := readerName, levelParams := [], type := ← mkForallFVars #[inst, xv, b] ret,
        value := ← mkLambdaFVars #[inst, xv, b] (casesOn (.succ .zero) (← mkLambdaFVars #[b] ret) b values),
        hints := .abbrev, safety := .safe }
      let covered := (branch.ctors.zip results.toList).filterMap fun (ctor, (r, _)) => r.map fun _ => ctor
      let table ← mkListLit branchTy (covered.map mkConst)
      addReader <| .defnDecl {
        name := coveredName, levelParams := [], type := ← inferType table,
        value := table, hints := .abbrev, safety := .safe }
      let goal := mkApp2 (mkConst ``picked) (mkAppN (mkConst readerName) #[inst, xv, b])
        (mkAppN (mkConst ci.name) xs)
      let proof := casesOn .zero (← mkLambdaFVars #[b] goal) b
        (results.map fun (_, i) => match i with
          | some i => mkAppN (mkConst i) #[inst, f, t, c, xv, ok]
          | none => mkConst ``True.intro)
      addCertificate <| .thmDecl {
        name := correctName, levelParams := [],
        type := ← mkForallFVars (xs ++ #[xv, ok]) goal,
        value := ← mkLambdaFVars (xs ++ #[xv, ok]) proof }
      let known ← mkAppM ``Option.isSome #[mkAppN (mkConst readerName) #[inst, xv, b]]
      let mem ← mkAppM ``Membership.mem #[mkConst coveredName, b]
      let support ← mkEq known (← mkDecide mem)
      let supportProof := casesOn .zero (← mkLambdaFVars #[b] support) b
        (← results.mapM fun (r, _) => mkEqRefl (toExpr r.isSome))
      addCertificate <| .thmDecl {
        name := supportedName, levelParams := [],
        type := ← mkForallFVars #[inst, xv, b] support,
        value := ← mkLambdaFVars #[inst, xv, b] supportProof }
      let msg := s!"reach predicates visited: {visited.size}, with reader: {reachCompiled.size}, with some guard: {reachGuarded.size}; arms with reader: {covered.length}; blockers: {s.blockers.size}; {(← IO.monoMsNow) - start} ms"
      if let some dir := reportDir then
        IO.FS.writeFile (dir / "summary.txt") (msg ++ "\n" ++ toString (covered.map fun n => n.getString!) ++ "\n")
      logInfo msg

public def driver : MetaM Unit := driverWith none

end

end ConsensusCoverage.ReadersCompiler
