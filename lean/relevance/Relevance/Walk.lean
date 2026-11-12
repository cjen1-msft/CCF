module

public meta import Lean
public import Relevance.Split

/-!
# Walking proof terms for recorded splits

Nothing here mentions a particular model. The walker reads the elaborated proof of a root
theorem, inlines every theorem in scope (a name prefix), and collects:

- every recorded split (`Relevance.splitMark`) and branch (`Relevance.branchMark`), with the
  branch's path condition lifted through the inlined lemmas to the root and closed into a
  predicate over the root's state or step;
- every eliminator that splits a proof into two or more cases outside a recorded split,
  classified as internal to automation or not.

## Rules as implemented

Inlining. An application `c a₁ … aₖ` of a theorem `c` in scope is walked as `c`'s proof with its
parameters bound by `let` to the arguments. Data arguments are walked once, at the call site;
proof arguments (and proofs bound by `let`/`have`) are walked where they are used. A theorem used
twice is walked twice, once per call path. Projections of a structure constructor that a theorem
in scope builds are reduced to the field.

Splits found in the term. An application of an eliminator whose result is a proof and that has
two or more alternatives: `I.casesOn`, `I.rec`, `I.recOn`, `I.brecOn` for an inductive `I` with
at least two constructors, a `match` auxiliary or its `splitter` with at least two alternatives,
`dite`, `ite`, `Decidable.byCases`, `Classical.byCases`, `Or.elim`, `Or.by_cases`. Eliminators
between a split marker and its branch markers belong to that split (the splitter's term), except
inside inlined theorems. Every other one is unrecorded.

Internal to automation. An unrecorded split is internal when the proposition it splits on (the
type of the major premise, the condition, or the discriminants' types) mentions no constant whose
name is in the analysed package (a list of name roots), and no free variable of the proof other
than ones introduced inside the same automation term; it is a protocol split otherwise. Only the
first part is checked mechanically: the proposition mentions no package constant.

Clause obligations. In a step-level root, the constructor of the state pattern's structure (the
invariant) at the post-state is split into one obligation per field (clause): for an instance `x`
of the clause, its premises `P(t, x)` and the same premises at the pre-state `P(s, x)`.

Roles and predicates. At a branch marker, the path condition is the conjunction of the conditions
of the enclosing branch markers and of this one. A step-level branch under a clause obligation is
`frame` when every premise at the pre-state is a local hypothesis (the instance already existed),
and `effect` otherwise; its predicate adds the clause premises at the post-state and the negation
of their conjunction at the pre-state (the instance is new). A step-level branch outside an
obligation is `step-own`, unless it lies under a data binder introduced outside a splitter
(`unattributed`). The predicate closes the condition existentially over every variable that is
not a parameter or one of the root's step (state) variables, and conjoins every hypothesis that
mentions a closed variable, to a fixpoint, except a `let`-bound proof whose value contains the
branch (a branch does not assume the proof it is part of). `let` variables (inlined arguments,
`have`) are unfolded.

## Tie-back

When the configuration names a namespace `Ns`, the walk also returns the walked term rebuilt, and
for every branch of a step-level or state-level root adds two kinds of theorem, each checked by the
kernel when it is added:

- `Ns.branch_<i>` (branch `i`, numbered in walk order): for all the root's binders, the closed
  variables of the branch's predicate and its hypotheses (the conjuncts of the predicate before
  closing; for an `effect` branch without the negated pre-state premises), the branch's goal. Its
  proof is the branch's own sub-term of the proof, rebuilt (nested branches replaced by calls of
  their lemmas), with the variables and hypotheses abstracted; the original sub-term is used if the
  rebuilt one does not close over the telescope.
- `Ns.frame_<i>`, for a `frame` branch: under the same telescope, the clause premises at the
  pre-state, proved by the local hypotheses that witness them.

In the rebuilt term every branch with a lemma is replaced by a call of it, theorems in scope are
`let`-bound applications of their proofs, and a `let`-bound proof walked at a use takes the value
rebuilt at its first use (abstracted over the local arguments it is applied to) when that value
mentions only variables declared before the `let`.
-/
public meta section

open Lean Meta

namespace Relevance

inductive Level where
  | step | state | other
  deriving BEq, Inhabited, Repr

def Level.str : Level → String
  | .step => "step" | .state => "state" | .other => "other"

structure BranchRec where
  root : Name
  level : Level
  path : Array String
  decl : Name
  split : String
  tag : String
  dead : Bool
  splitId : Nat
  parent : Option Nat
  conds : Array String
  /-- The predicate as a lambda over the pattern's binders (step-level and state-level roots). -/
  pred : Option Expr := none
  predStr : String := "-"
  /-- The clause whose obligation the branch lies under, or `-`. -/
  clause : String := "-"
  /-- `step-own`, `effect`, `frame`, `unattributed`, `state` or `other`. -/
  role : String := "-"
  /-- The tie-back lemmas generated for this occurrence (see `TieRec`). -/
  tie : Option Nat := none
  deriving Inhabited

/-- What a branch lemma is about: its name, the numbers of its binders (root binders, closed
variables that are not root binders, hypotheses), the positions among them of the closed
variables (in the order the predicate closes them) and of the kept root binders, and the extra
conjuncts of the predicate (the newness condition) abstracted over the root binders and closed
variables. -/
structure TieRec where
  branch : Nat
  /-- `branch`: the branch lemma; `frame`: the frame lemma. -/
  kind : String
  name : Option Name := none
  error : String := ""
  nRoots : Nat := 0
  nRest : Nat := 0
  nHyps : Nat := 0
  closedPos : Array Nat := #[]
  keptPos : Array Nat := #[]
  extra : Array Expr := #[]
  /-- The lemma's proof uses the rebuilt body (nested branches are calls of their lemmas). -/
  factored : Bool := false
  /-- Why the rebuilt body was not used, if it was not. -/
  fallback : String := ""
  deriving Inhabited

structure SplitRec where
  root : Name
  level : Level
  path : Array String
  decl : Name
  name : String
  /-- The live branch whose script closes every other live branch (replay test), or `""`. -/
  coveredBy : String := ""
  /-- The goal of the split is `False`: it reasons about a hypothetical item. -/
  refutation : Bool := false
  branches : Array Nat := #[]
  deriving Inhabited

structure Unrecorded where
  root : Name
  path : Array String
  decl : Name
  head : Name
  major : String
  cond : String
  internal : Bool
  deriving Inhabited

structure Config where
  scope : Name
  package : Array Name
  stepPat : Expr
  statePat : Expr
  /-- The constructor of the structure named by the state pattern, if it is one. -/
  stateCtor : Option Name := none
  /-- Namespace of the generated tie-back lemmas; none are generated when anonymous. -/
  ns : Name := .anonymous

/-- One clause obligation of the state pattern's structure at a step: the clause premises (local
hypotheses, at the post-state) and the same premises at the pre-state. -/
structure Clause where
  name : Name
  prems : Array Expr
  premS : Array Expr

structure Ctx where
  cfg : Config
  root : Name
  level : Level
  /-- Root binders that become binders of the generated predicate, with the pattern binders. -/
  keep : Array Expr := #[]
  pattern : Array Expr := #[]
  /-- All of the root's binders. -/
  rootBinders : Array Expr := #[]
  /-- Theorems not to inline (walked as roots of their own). -/
  stop : Array Name := #[]
  /-- The root's pre-state (first explicit binder of the step pattern). -/
  pre : Option Expr := none
  /-- The clause obligation being walked. -/
  clause : Option Clause := none
  /-- Data variables introduced by a binder outside a splitter on the path. -/
  bound : Array FVarId := #[]
  /-- Binders of a transport's minor premise that stand for a `let`-bound proof. -/
  alias : Array (FVarId × FVarId) := #[]
  /-- `let`-bound proofs whose values are being walked at a use: a branch inside such a value
  does not take the proof itself as a hypothesis. -/
  walking : Array FVarId := #[]

structure St where
  region : Bool := false
  curSplit : Nat := 0
  stack : Array Nat := #[]
  condStack : Array Expr := #[]
  path : Array String := #[]
  calls : Std.HashMap String Nat := {}
  inProgress : Array Name := #[]
  branches : Array BranchRec := #[]
  splits : Array SplitRec := #[]
  unrecorded : Array Unrecorded := #[]
  noValue : Array Name := #[]
  inlined : Array Name := #[]
  /-- `let`-bound proofs that were walked at a use. -/
  used : Std.HashSet FVarId := {}
  /-- `have`s whose value is a theorem in scope and that are never used. -/
  unusedHaves : Array (Name × String) := #[]
  ties : Array TieRec := #[]
  /-- Rebuilt values of `let`-bound proofs, from their uses. -/
  rebuiltLets : Std.HashMap FVarId Expr := {}

abbrev M := ReaderT Ctx (StateRefT St MetaM)

def oneLine (e : Expr) : MetaM String := do
  let f ← withOptions (fun o => o.set `format.width (100000 : Nat)) (ppExpr e)
  return (toString f).replace "\n" " "

def strLit? : Expr → Option String
  | .lit (.strVal s) => some s
  | .mdata _ e => strLit? e
  | _ => none

def inScope (c : Name) : M Bool := do
  let c := (privateToUserName? c).getD c
  return (← read).cfg.scope.isPrefixOf c

def inPackage (pkg : Array Name) (c : Name) : Bool :=
  let c := (privateToUserName? c).getD c
  pkg.any (·.isPrefixOf c)

def curDecl : M Name := do
  let st ← get
  return st.inProgress.back?.getD (← read).root

/-- The two-way eliminators given as functions, with the index of the condition argument. -/
def twoWay : List (Name × Nat) :=
  [(``dite, 1), (``ite, 1), (``Decidable.byCases, 0), (``Classical.byCases, 0),
   (``Or.elim, 3), (``Or.by_cases, 3)]

/-- If `c args` is a split (two or more alternatives), the proposition it splits on and the major
premise. -/
def splitOn? (c : Name) (args : Array Expr) : MetaM (Option (Expr × Expr)) := do
  let env ← getEnv
  if let some (_, i) := twoWay.find? (·.1 == c) then
    let some a := args[i]? | return none
    let p ← if c == ``Or.elim || c == ``Or.by_cases then inferType a else pure a
    return some (p, a)
  let matcher ← match ← getMatcherInfo? c with
    | some info => pure (some info)
    | none =>
      if c.isStr && c.getString! == "splitter" then getMatcherInfo? c.getPrefix else pure none
  if let some info := matcher then
    if info.numAlts < 2 || args.size < info.getFirstDiscrPos + info.numDiscrs then return none
    let ds := args.extract info.getFirstDiscrPos (info.getFirstDiscrPos + info.numDiscrs)
    let tys ← ds.mapM inferType
    return some (mkAppN (mkConst ``Unit) tys, mkAppN (mkConst ``Unit) ds)
  let isElim := isCasesOnRecursor env c || isRecOnRecursor env c || isBRecOnRecursor env c
  let isRec := match env.find? c with | some (.recInfo _) => true | _ => false
  unless isElim || isRec do return none
  let ind := c.getPrefix
  let some (.inductInfo iv) := env.find? ind | return none
  if iv.ctors.length < 2 then return none
  let majorIdx ← if isRec then
      match env.find? c with
      | some (.recInfo rv) => pure rv.getMajorIdx
      | _ => return none
    else if isCasesOnRecursor env c then
      pure (iv.numParams + 1 + iv.numIndices)
    else
      -- recOn and brecOn: params, motive, indices, major
      pure (iv.numParams + 1 + iv.numIndices)
  let some m := args[majorIdx]? | return none
  return some (← inferType m, m)

/-- The telescope of the current branch: the closed variables (in context order) and the
hypotheses (their types, and the terms that prove them here: `let`-bound facts, then the
conditions that are not closed variables). -/
structure Tele where
  closed : Array FVarId := #[]
  hypArgs : Array Expr := #[]
  hypTys : Array Expr := #[]

def zetaAll (e : Expr) : MetaM Expr := do zetaReduce (← instantiateMVars e)

/-- Close the path conditions `conds` (and the variables of `extra`) over every variable that is
not kept, with every hypothesis that mentions a closed variable, to a fixpoint. -/
def teleOf (conds : Array Expr) (extra : Array Expr := #[]) : M Tele := do
  let ctx ← read
  let keep : Std.HashSet FVarId := ctx.keep.foldl (fun s x => s.insert x.fvarId!) {}
  let lctx ← getLCtx
  let zeta := zetaAll
  -- facts: Prop expressions to conjoin, with the fvars they mention (after unfolding lets)
  let mut closed : Std.HashSet FVarId := {}
  let mut facts : Array Expr := #[]
  let mut factArgs : Array Expr := #[]
  let mut factSet : Std.HashSet FVarId := {}
  let mut work : Array FVarId := #[]
  let mut condFacts : Array Expr := #[]
  let mut condArgs : Array Expr := #[]
  for c in conds do
    let ty ← zeta (← inferType c)
    match c with
    | .fvar id =>
      if let some d := lctx.find? id then
        if !d.isLet (allowNondep := true) then
          closed := closed.insert id
          work := work.push id
          continue
    | _ => pure ()
    condFacts := condFacts.push ty
    condArgs := condArgs.push c
    for f in (collectFVars {} ty).fvarIds do
      if !keep.contains f then work := work.push f
  for e in extra do
    let ty ← zeta e
    for f in (collectFVars {} ty).fvarIds do
      if !keep.contains f then work := work.push f
  let mut changed := true
  while changed do
    changed := false
    while !work.isEmpty do
      let f := work.back!
      work := work.pop
      let some d := lctx.find? f | continue
      if d.isLet (allowNondep := true) then continue
      unless closed.contains f do
        closed := closed.insert f
      let ty ← zeta d.type
      for g in (collectFVars {} ty).fvarIds do
        if !keep.contains g && !closed.contains g then
          if let some dg := lctx.find? g then
            if !dg.isLet (allowNondep := true) then
              closed := closed.insert g
              work := work.push g
    for d in lctx do
      if d.isImplementationDetail || closed.contains d.fvarId || factSet.contains d.fvarId then continue
      if keep.contains d.fvarId || ctx.walking.contains d.fvarId then continue
      unless ← isProp d.type do continue
      let ty ← zeta d.type
      if (collectFVars {} ty).fvarIds.any closed.contains then
        if d.isLet (allowNondep := true) then
          factSet := factSet.insert d.fvarId
          facts := facts.push ty
          factArgs := factArgs.push d.toExpr
        else
          closed := closed.insert d.fvarId
          work := work.push d.fvarId
        changed := true
        for g in (collectFVars {} ty).fvarIds do
          if !keep.contains g && !closed.contains g then
            if let some dg := lctx.find? g then
              if !dg.isLet (allowNondep := true) then
                closed := closed.insert g
                work := work.push g
    unless work.isEmpty do changed := true
  let order := lctx.foldl (init := #[]) fun acc d =>
    if closed.contains d.fvarId then acc.push d.fvarId else acc
  return { closed := order, hypArgs := factArgs ++ condArgs, hypTys := facts ++ condFacts }

/-- `∃ closed, hyps`, innermost first: a closed proposition that the rest does not mention is a
conjunct rather than a binder. -/
def closeBody (closed : Array Expr) (hyps : Array Expr) : MetaM Expr := do
  let mkAnd' (a b : Expr) : Expr := if b.isConstOf ``True then a else mkAnd a b
  let mut body : Expr := mkConst ``True
  for p in hyps.reverse do
    body := mkAnd' p body
  for x in closed.reverse do
    let ty ← zetaAll (← inferType x)
    if (← isProp ty) && !body.containsFVar x.fvarId! then
      body := mkAnd' ty body
    else
      let lam ← mkLambdaFVars #[x] body
      let lam := lam.updateLambdaE! ty lam.bindingBody!
      body := mkApp2 (mkConst ``Exists [← getLevel ty]) ty lam
  zetaAll body

/-- The predicate of the current branch over the pattern's binders: the closure of its
telescope, with `extra` conjoined. -/
def closePred (conds : Array Expr) (extra : Array Expr := #[]) : M (Option (Expr × Tele)) := do
  let ctx ← read
  if ctx.level == .other then return none
  let tele ← teleOf conds extra
  let closedBody ← closeBody (tele.closed.map mkFVar) (tele.hypTys ++ (← extra.mapM fun x => zetaAll x))
  -- abstract the kept root binders, then rename them to the pattern's binders
  let lam ← mkLambdaFVars ctx.keep closedBody
  let pred := lam.beta ctx.pattern
  let pred ← mkLambdaFVars ctx.pattern pred
  check pred
  return some (pred, tele)

def mkAndN (ps : Array Expr) : Expr :=
  if ps.isEmpty then mkConst ``True else ps.pop.foldr mkAnd ps.back!

def mkOrN (ps : Array Expr) : Expr :=
  if ps.isEmpty then mkConst ``False else ps.pop.foldr mkOr ps.back!

/-- Rule F3, the frame test: every premise at the pre-state is the type of a local hypothesis up
to definitional unfolding at default transparency (`and_intros <;> assumption`). Returns those
hypotheses. -/
def frameWitness? (premS : Array Expr) : MetaM (Option (Array Expr)) := do
  let lctx ← getLCtx
  let mut out := #[]
  for p in premS do
    let mut found := none
    for d in lctx do
      if d.isImplementationDetail then continue
      if ← (try withNewMCtxDepth (isDefEq d.type p) catch _ => pure false) then
        found := some d.toExpr
        break
    let some h := found | return none
    out := out.push h
  return some out

def isFrame (premS : Array Expr) : MetaM Bool := return (← frameWitness? premS).isSome

/-- `⟨h₁, …, hₖ⟩ : p₁ ∧ … ∧ pₖ` (the shape of `mkAndN`). -/
def mkAndIntroN (ps hs : Array Expr) : Expr := Id.run do
  if ps.isEmpty then return mkConst ``True.intro
  let mut ty := ps.back!
  let mut prf := hs.back!
  for i in (List.range (ps.size - 1)).reverse do
    prf := mkApp4 (mkConst ``And.intro) ps[i]! ty hs[i]! prf
    ty := mkAnd ps[i]! ty
  return prf

def withFreshHyps (tys : List Expr) (k : Array Expr → MetaM α) (acc : Array Expr := #[]) :
    MetaM α :=
  match tys with
  | [] => k acc
  | ty :: rest => withLocalDeclD `h ty fun h => withFreshHyps rest k (acc.push h)

/-- Abstract the proof `body` of `goal` over the root binders and the telescope: the closed
variables that are not root binders, then one hypothesis per telescope hypothesis (a `let`-bound
fact or condition becomes that hypothesis; any other `let` is kept as a `let`). Returns the
statement, the proof and the arguments that instantiate it here; fails if the proof or the
statement mentions a variable outside the telescope. -/
def abstractTele (tele : Tele) (goal body : Expr) :
    M (Except String (Expr × Expr × Array Expr × Nat)) := do
  let ctx ← read
  let lctx ← getLCtx
  let roots := ctx.rootBinders
  let rootIds := roots.map (·.fvarId!)
  let rest := (tele.closed.filter (!rootIds.contains ·)).map mkFVar
  let goalZ ← zetaAll goal
  let mut lctx' := lctx
  for x in roots ++ rest do
    let ty ← zetaAll (← inferType x)
    lctx' := lctx'.modifyLocalDecl x.fvarId! (·.setType ty)
  let mut conv : Array (Option FVarId) := #[]
  for (a, ty) in tele.hypArgs.zip tele.hypTys do
    if let .fvar id := a then
      if let some d := lctx.find? id then
        if d.isLet (allowNondep := true) && !conv.contains (some id) then
          lctx' := lctx'.modifyLocalDecl id fun _ =>
            .cdecl d.index id d.userName ty .default .default
          conv := conv.push (some id)
          continue
    conv := conv.push none
  let convIds := conv.filterMap id
  let lets := lctx.foldl (init := #[]) fun acc d =>
    if d.isLet (allowNondep := true) && !convIds.contains d.fvarId then acc.push d.toExpr else acc
  let freshTys := (tele.hypTys.zip conv).filterMap fun (ty, c) => if c.isNone then some ty else none
  withLCtx lctx' (← getLocalInstances) do
    withFreshHyps freshTys.toList fun fresh => do
      let mut hyps := #[]
      let mut k := 0
      for c in conv do
        match c with
        | some id => hyps := hyps.push (mkFVar id)
        | none => hyps := hyps.push fresh[k]!; k := k + 1
      let binders := roots ++ rest ++ hyps
      let value ← mkLambdaFVars (binders ++ lets) body (usedLetOnly := true)
      let type ← mkForallFVars binders goalZ
      let free := (collectFVars (collectFVars {} value) type).fvarIds
      unless free.isEmpty do
        let names := free.map fun f => ((lctx.find? f).map (·.userName.toString)).getD "?"
        return .error s!"uses variables outside the telescope: {names.toList}"
      return .ok (type, value, roots ++ rest ++ tele.hypArgs, rest.size)

/-- Add a theorem, checked by the kernel now (not in a background task), so that a failure is
reported here and leaves no declaration behind. -/
def addTheorem (name : Name) (type value : Expr) : MetaM (Except String Unit) := do
  let lps := (collectLevelParams (collectLevelParams {} type) value).params.toList
  let env ← getEnv
  try
    withOptions (Elab.async.set · false) do
      addDecl <| .thmDecl { name, levelParams := lps, type, value }
    return .ok ()
  catch ex =>
    setEnv env
    return .error (← ex.toMessageData.toString)

/-- Strip `mdata` and `let`s (instantiating their values) at the head, and beta-reduce. -/
partial def zetaHead (e : Expr) : Expr :=
  match e with
  | .mdata _ b => zetaHead b
  | .letE _ _ v b _ => zetaHead (b.instantiate1 v)
  | _ => if e.getAppFn.isLambda then zetaHead e.headBeta else e

/-- Read a clause statement as `∀ x, P → Q`: the number of leading data binders and of the
leading proposition binders that follow them. -/
def clauseShape (ty : Expr) : MetaM (Nat × Nat) := forallTelescope ty fun bs _ => do
  let mut nd := 0
  let mut np := 0
  for b in bs do
    let p ← isProp (← inferType b)
    if np == 0 && !p then nd := nd + 1
    else if p then np := np + 1
    else break
  return (nd, np)

/-- The state pattern's body at the state `st` (its last explicit binder); the other binders are
found by unification and instance synthesis. -/
def stateAt (statePat st : Expr) : MetaM Expr := do
  let (ms, bis, body) ← lambdaMetaTelescope statePat
  let some k := (List.range ms.size).reverse.find? (bis[·]! == .default) |
    throwError "relevance: the state pattern has no explicit binder"
  unless ← isDefEq ms[k]! st do throwError "relevance: state pattern does not apply to {st}"
  for (m, bi) in ms.zip bis do
    if bi.isInstImplicit && !(← m.mvarId!.isAssigned) then
      m.mvarId!.assign (← synthInstance (← inferType m))
  let body ← instantiateMVars body
  if body.hasExprMVar then throwError "relevance: state pattern not determined at {st}"
  return body

/-- The premises of a clause statement `fieldS` (at some state) for the instance `xs`. -/
def premisesAt (fieldS : Expr) (xs prems : Array Expr) : MetaM (Array Expr) := do
  let mut e ← instantiateForall fieldS xs
  let mut out := #[]
  for h in prems do
    let e' ← whnfCore e
    let .forallE _ d b _ := e' | throwError "relevance: clause premise missing"
    out := out.push d
    e := b.instantiate1 h
  return out

def resolveAlias (id : FVarId) : M FVarId := do
  match (← read).alias.find? (·.1 == id) with
  | some (_, t) => return t
  | none => return id

def isAlias (id : FVarId) : M Bool := return (← read).alias.any (·.1 == id)

def deferredValue? (id : FVarId) : M (Option Expr) := do
  let id ← resolveAlias id
  let some d := (← getLCtx).find? id | return none
  unless d.isLet (allowNondep := true) do return none
  unless ← isProp d.type do return none
  return d.value? (allowNondep := true)

def markUsed (id : FVarId) : M Unit := do
  let id ← resolveAlias id
  modify fun s => { s with used := s.used.insert id }

/-- Run `k` as the body of a call of theorem `c` (call path, recursion guard). -/
def withCall (c : Name) (k : M α) : M α := do
  let st ← get
  let key := s!"{st.path}/{c}"
  let n := st.calls.getD key 0
  let label := if n == 0 then c.toString else s!"{c}#{n+1}"
  set { st with calls := st.calls.insert key (n + 1), region := false,
                path := st.path.push label, inProgress := st.inProgress.push c,
                inlined := if st.inlined.contains c then st.inlined else st.inlined.push c }
  try k finally
    modify fun s => { s with region := st.region, path := st.path, inProgress := st.inProgress }

def withCalls : List Name → M α → M α
  | [], k => k
  | c :: cs, k => withCall c (withCalls cs k)

/-- The theorem in scope that `c` names, with its proof, if it may be inlined here. -/
def inlinable? (c : Name) (us : List Lean.Level) : M (Option Expr) := do
  unless ← inScope c do return none
  if (← read).stop.contains c || (← get).inProgress.contains c then return none
  let some ci := (← getEnv).find? c | return none
  unless ci matches .thmInfo _ do return none
  let some v := ci.value? (allowOpaque := true) | return none
  return some (v.instantiateLevelParams ci.levelParams us)

/-- Reduce `e` to an application of constructor `ctor`, unfolding `let`-bound
proofs and theorems in scope (whose names are returned, outermost first). The flag is set when
the reduction went through an alias. -/
partial def resolveCtor (ctor : Name) (arity : Nat) (e : Expr) (labels : Array Name)
    (viaAlias : Bool := false) : M (Option (Array Name × Expr × Bool)) := do
  let e := zetaHead e
  let args := e.getAppArgs
  match e.getAppFn.consumeMData with
  | .const c us =>
    if c == ctor then
      return if args.size == arity then some (labels, e, viaAlias) else none
    let some v ← inlinable? c us | return none
    if labels.contains c then return none
    resolveCtor ctor arity (v.beta args) (labels.push c) viaAlias
  | .fvar id =>
    let some v ← deferredValue? id | return none
    markUsed id
    resolveCtor ctor arity (mkAppN v args) labels (viaAlias || (← isAlias id))
  | _ => return none

/-- Record `v` as the rebuilt value of the `let`-bound proof `id` if it is well-scoped there. -/
def noteRebuilt (id : FVarId) (v : Expr) : M Unit := do
  if (← get).rebuiltLets.contains id then return
  let lctx ← getLCtx
  let some d := lctx.find? id | return
  if (collectFVars {} v).fvarIds.all fun f => (lctx.find? f).any (·.index < d.index) then
    modify fun s => { s with rebuiltLets := s.rebuiltLets.insert id v }

/-- `let x := v; r` with `v` replaced by its recorded rebuilt value, if any; dropped if `r` does
not use `x`. -/
def mkLetRebuilt (x : Expr) (r : Expr) : M Expr := do
  let some v := (← get).rebuiltLets.get? x.fvarId! | mkLetFVars #[x] r (usedLetOnly := true)
  unless r.containsFVar x.fvarId! do return r
  let d ← x.fvarId!.getDecl
  return .letE d.userName d.type v (r.abstract #[x]) false

/-- Walk the value of the `let`-bound proof `id` at a use. -/
def withWalking (id : FVarId) (k : M α) : M α := do
  let id ← resolveAlias id
  withReader (fun c => { c with walking := c.walking.push id }) k

mutual

/-- Walk `e`, recording splits and branches, and return it rebuilt: every branch whose lemma was
generated is replaced by a call of the lemma, inlined theorems are `let`-bound applications of
their proofs, and proofs bound by `let` are replaced by their rebuilt values at their uses. The
rebuilt term has the type of `e` up to definitional unfolding. -/
partial def walk (e : Expr) : M Expr := do
  match e with
  | .mdata _ b => walk b
  | .proj S i b =>
    if isStructure (← getEnv) S then
      return ← reduceProj (getStructureCtor (← getEnv) S).name i b #[]
        fun b' extra' => mkAppN (.proj S i b') extra'
    return .proj S i (← walk b)
  | .lam n t b bi => withLocalDecl n bi t fun x => do
    let r ← if !(← get).region && !(← isProp t) then
        withReader (fun c => { c with bound := c.bound.push x.fvarId! }) (walk (b.instantiate1 x))
      else walk (b.instantiate1 x)
    mkLambdaFVars #[x] r
  | .letE n t v b _ =>
    if ← isProp t then
      return ← withLetDecl n t v fun x => do
        let r ← walk (b.instantiate1 x)
        unless (← get).used.contains x.fvarId! do
          if let .const c _ := (zetaHead v).getAppFn then
            if ← inScope c then
              modify fun s => { s with unusedHaves := s.unusedHaves.push (c, n.toString) }
        mkLetRebuilt x r
    discard <| walk v
    withLetDecl n t v fun x => do mkLetFVars #[x] (← walk (b.instantiate1 x)) (usedLetOnly := true)
  | .fvar id =>
    if let some v ← deferredValue? id then
      markUsed id
      let v' ← withWalking id (walk v)
      noteRebuilt (← resolveAlias id) v'
      return if ← isAlias id then e else v'
    return e
  | .app .. | .const .. => walkApp e
  | _ => return e

/-- Walk a transport's minor premise; a binder whose argument is a `let`-bound proof becomes an
alias of it, so the proof is walked where the minor premise uses it (the binder's type differs
from the proof's by the transport, so the two are not substituted). -/
partial def walkMinor (m : Expr) : List (Option FVarId) → M Expr
  | [] => walk m
  | a :: rest => match m, a with
    | .mdata _ b, _ => walkMinor b (a :: rest)
    | .lam n t b bi, some id => withLocalDecl n bi t fun x => do
      let r ← withReader (fun c => { c with alias := c.alias.push (x.fvarId!, id) })
        (walkMinor (b.instantiate1 x) rest)
      mkLambdaFVars #[x] r
    | .lam n t b bi, none => withLocalDecl n bi t fun x => do
      let r ← if !(← get).region && !(← isProp t) then
          withReader (fun c => { c with bound := c.bound.push x.fvarId! })
            (walkMinor (b.instantiate1 x) rest)
        else walkMinor (b.instantiate1 x) rest
      mkLambdaFVars #[x] r
    | _, _ => do
      let r ← walk m
      for o in a :: rest do
        if let some id := o then discard <| walk (mkFVar id)
      return r

partial def walkArgs (args : Array Expr) : M (Array Expr) := args.mapM walk

/-- Walk field `i` of the constructor application that `b` reduces to, applied to
`extra`; otherwise walk `b` and `extra` and rebuild with `rebuild`. -/
partial def reduceProj (ctor : Name) (i : Nat) (b : Expr) (extra : Array Expr)
    (rebuild : Expr → Array Expr → Expr) : M Expr := do
  let cv ← getConstInfoCtor ctor
  match ← resolveCtor ctor (cv.numParams + cv.numFields) b #[] with
  | some (labels, app, viaAlias) =>
    let field := app.getAppArgs[cv.numParams + i]!
    if viaAlias then
      discard <| (withCalls labels.toList (walk (mkAppN field extra).headBeta))
      return rebuild b extra
    withCalls labels.toList (walk (mkAppN field extra).headBeta)
  | none => return rebuild (← walk b) (← walkArgs extra)

/-- The clause obligations of the state pattern's constructor at a step. -/
partial def walkObligations (c : Name) (us : List Lean.Level) (args : Array Expr) : M Expr := do
  let ctx ← read
  let cv ← getConstInfoCtor c
  let np := cv.numParams
  let some pre := ctx.pre | return mkAppN (mkConst c us) (← walkArgs args)
  let params := args.extract 0 np
  let paramsS := (← stateAt ctx.cfg.statePat pre).getAppArgs
  let ty := cv.type.instantiateLevelParams cv.levelParams us
  let mut tT ← instantiateForall ty params
  let mut tS ← instantiateForall ty paramsS
  let names := (getStructureInfo? (← getEnv) cv.induct).map (·.fieldNames) |>.getD #[]
  let mut fields := #[]
  for k in [0:cv.numFields] do
    let field := args[np + k]!
    let fT := tT.bindingDomain!
    let fS := tS.bindingDomain!
    let name := names[k]?.getD (Name.mkSimple s!"field{k}")
    let (nd, npr) ← clauseShape fT
    let field' ← forallBoundedTelescope fT (some (nd + npr)) fun ys _ => do
      if ys.size != nd + npr then
        return ← walk field
      let xs := ys.extract 0 nd
      let prems := ys.extract nd ys.size
      let premS ← premisesAt fS xs prems
      let r ← withReader (fun c => { c with clause := some { name, prems, premS } })
        (walk (mkAppN field ys).headBeta)
      mkLambdaFVars ys r
    fields := fields.push field'
    tT := tT.bindingBody!.instantiate1 field
    tS := tS.bindingBody!.instantiate1 field
  return mkAppN (mkConst c us) (params ++ fields ++ args.extract (np + cv.numFields) args.size)

partial def walkApp (e : Expr) : M Expr := do
  let f := e.getAppFn
  let args := e.getAppArgs
  match f with
  | .mdata _ b => walkApp (mkAppN b args)
  | .lam .. => walk (e.headBeta)
  | .fvar id =>
    if let some v ← deferredValue? id then
      markUsed id
      let r ← withWalking id (walk (mkAppN v args).headBeta)
      -- applied to local variables: the rebuilt value is `r` abstracted over them
      let args := args.map (·.consumeMData)
      if args.all (·.isFVar) then
        if ← args.allM fun a => return !(← a.fvarId!.getDecl).isLet (allowNondep := true) then
          noteRebuilt (← resolveAlias id) (← mkLambdaFVars args r)
      return if ← isAlias id then e else r
    else return mkAppN f (← walkArgs args)
  | .proj S i b =>
    if isStructure (← getEnv) S then
      return ← reduceProj (getStructureCtor (← getEnv) S).name i b args
        fun b' extra' => mkAppN (.proj S i b') extra'
    return mkAppN (← walk f) (← walkArgs args)
  | .const c us =>
    if c == ``splitMark && args.size ≥ 4 then
      let p' ← walkSplit args[1]! args[2]! args[3]!
      return mkAppN f ((args.extract 0 3).push p' ++ (← walkArgs (args.extract 4 args.size)))
    if c == ``branchMark && args.size ≥ 4 then
      let r ← walkBranch f args[0]! args[1]! args[2]! args[3]!
      return mkAppN r (← walkArgs (args.extract 4 args.size))
    -- transports (from `subst`, `simp at`, `▸`): the minor premise applied to the remaining
    -- arguments is walked by beta, so values passed through it reach their uses
    let transport : Option (Nat × Nat × Nat) := match c with
      | ``Eq.ndrec | ``Eq.rec => some (6, 3, 5)
      | ``Eq.mp | ``Eq.mpr | ``cast => some (4, 3, 2)
      | _ => none
    if let some (arity, minor, eqn) := transport then
      if args.size ≥ arity then
        let eqn' ← walk args[eqn]!
        let mut as := #[]
        let mut rest := #[]
        for x in args.extract arity args.size do
          match x.consumeMData with
          | .fvar id =>
            if (← deferredValue? id).isSome then
              as := as.push (some id); rest := rest.push x; continue
            as := as.push none; rest := rest.push x
          | _ =>
            rest := rest.push (← walk x)
            as := as.push none
        let minor' ← walkMinor args[minor]! as.toList
        let head := ((args.extract 0 arity).set! eqn eqn').set! minor minor'
        return mkAppN f (head ++ rest)
    if let some pinfo := (← getEnv).getProjectionFnInfo? c then
      if args.size > pinfo.numParams then
        return ← reduceProj pinfo.ctorName pinfo.i args[pinfo.numParams]!
          (args.extract (pinfo.numParams + 1) args.size)
          fun b' extra' => mkAppN f ((args.extract 0 pinfo.numParams).push b' ++ extra')
    let ctx ← read
    if ctx.level == .step && ctx.clause.isNone && ctx.cfg.stateCtor == some c then
      let cv ← getConstInfoCtor c
      if args.size == cv.numParams + cv.numFields then
        return ← walkObligations c us args
    if (← inScope c) && !(← read).stop.contains c then
      if let some ci := (← getEnv).find? c then
        if ci matches .thmInfo _ then
          if (← get).inProgress.contains c then
            return mkAppN f (← walkArgs args)
          match ci.value? (allowOpaque := true) with
          | none =>
            modify fun st => { st with noValue := st.noValue.push c }
            return mkAppN f (← walkArgs args)
          | some v =>
            let v := v.instantiateLevelParams ci.levelParams us
            -- proof arguments are walked where the callee uses them
            for a in args do
              unless ← (try isProof a catch _ => pure false) do discard <| walk a
            return ← inline c v args
    if let some (p, major) ← (try splitOn? c args catch _ => pure none) then
      let isPrf ← try isProof e catch _ => pure false
      if isPrf && !(← get).region then
        let pkg := (← read).cfg.package
        let internal := !p.getUsedConstants.any (inPackage pkg)
        let rec_ : Unrecorded := {
          root := (← read).root, path := (← get).path, decl := ← curDecl, head := c,
          major := ← oneLine major, cond := ← oneLine p, internal }
        modify fun st => { st with unrecorded := st.unrecorded.push rec_ }
    return mkAppN f (← walkArgs args)
  | _ => return mkAppN (← walk f) (← walkArgs args)

/-- Walk `v` (the proof of theorem `c`) applied to `args`, binding parameters by `let`. -/
partial def inline (c : Name) (v : Expr) (args : Array Expr) : M Expr :=
  withCall c (bindParams v args.toList)
where
  bindParams (v : Expr) : List Expr → M Expr
    | [] => walk v
    | a :: rest => match v with
      | .lam n t b _ => withLetDecl n t a fun x => do
        mkLetRebuilt x (← bindParams (b.instantiate1 x) rest)
      | .mdata _ b => bindParams b (a :: rest)
      | _ => do return mkAppN (← walk v) (a :: rest).toArray

partial def walkSplit (name coveredBy p : Expr) : M Expr := do
  let st ← get
  let some name := strLit? name | walk p
  let refutation ← try
      pure ((← whnfR (← instantiateMVars (← inferType p))).isConstOf ``False)
    catch _ => pure false
  let id := st.splits.size
  let rec_ : SplitRec := {
    root := (← read).root, level := (← read).level, path := st.path, decl := ← curDecl, name,
    coveredBy := (strLit? coveredBy).getD "", refutation }
  set { st with region := true, curSplit := id, splits := st.splits.push rec_ }
  try walk p finally modify fun s => { s with region := st.region, curSplit := st.curSplit }

/-- Generate a lemma `∀ root binders, ∀ telescope, goal` proved by `body`; record it. -/
partial def tieLemma (branch : Nat) (kind : String) (name : Name) (tele : Tele)
    (goal : Expr) (bodies : Array (Expr × Bool)) (extra : Array Expr) :
    M (Option (Name × Array Expr)) := do
  let ctx ← read
  let mut err := ""
  let mut fallback := ""
  for (body, factored) in bodies do
    if !factored && bodies.size > 1 then fallback := err
    match ← abstractTele tele goal body with
    | .error e => err := e
    | .ok (type, value, args, nRest) =>
      match ← addTheorem name type value with
      | .error e => err := s!"kernel: {e}"
      | .ok () =>
        let roots := ctx.rootBinders
        let pos (x : FVarId) : Option Nat :=
          (roots.map (·.fvarId!)).idxOf? x |>.orElse fun _ =>
            ((tele.closed.filter fun y => !(roots.map (·.fvarId!)).contains y).idxOf? x).map
              (roots.size + ·)
        let binders := roots ++ (tele.closed.filter fun y =>
          !(roots.map (·.fvarId!)).contains y).map mkFVar
        let extraAbs ← extra.mapM fun x => do mkLambdaFVars binders (← zetaAll x)
        let r : TieRec := {
          branch, kind, name := some name, nRoots := roots.size, nRest,
          nHyps := tele.hypArgs.size, closedPos := tele.closed.filterMap pos,
          keptPos := ctx.keep.filterMap fun k => (roots.map (·.fvarId!)).idxOf? k.fvarId!,
          extra := extraAbs, factored, fallback }
        modify fun s => { s with ties := s.ties.push r }
        return some (name, args)
  modify fun s => { s with ties := s.ties.push { branch, kind, error := err } }
  return none

partial def walkBranch (f α tag dead p : Expr) : M Expr := do
  let st ← get
  let tag := (strLit? tag).getD "?"
  let deadE := dead
  let dead := dead.isConstOf ``Bool.true
  let splitId := st.curSplit
  -- collect conditions
  let mut conds := #[]
  let mut condApps := #[]
  let mut body := p
  while body.isAppOfArity ``condMark 4 do
    conds := conds.push body.getAppArgs[2]!
    condApps := condApps.push (mkAppN body.getAppFn (body.getAppArgs.extract 0 3))
    body := body.getAppArgs[3]!
  let condStrs ← conds.mapM fun c => do oneLine (← inferType c)
  let id := st.branches.size
  let ctx ← read
  let rec_ : BranchRec := {
    root := ctx.root, level := ctx.level, path := st.path, decl := ← curDecl,
    split := st.splits[splitId]!.name, tag, dead, splitId,
    parent := st.stack.back?, conds := condStrs,
    clause := (ctx.clause.map (·.name.toString)).getD "-" }
  set { st with branches := st.branches.push rec_ }
  modify fun s => { s with splits := s.splits.modify splitId fun r =>
    { r with branches := r.branches.push id } }
  -- predicate: conditions of all enclosing branches (still in scope) and this one
  let outer := (← get).condStack
  let compute (cs extra : Array Expr) : M (Option (Expr × Tele)) := do
    try closePred cs extra catch ex => do
      logWarning m!"relevance: predicate of {tag} ill-typed: {ex.toMessageData}"
      pure none
  -- the telescope of the branch lemma, with the extra conjuncts of the predicate
  let mut lemmaConds : Option (Array Expr × Array Expr) := none
  let mut frame : Option (Array Expr × Array Expr) := none
  let (role, pred) ← match ctx.level, ctx.clause with
      | .step, some cl =>
        let extra := #[mkNot (mkAndN cl.premS)]
        lemmaConds := some (outer ++ conds ++ cl.prems, extra)
        if let some ws ← frameWitness? cl.premS then
          frame := some (cl.premS, ws)
          pure ("frame", none)
        else if dead then pure ("effect", none)
        else pure ("effect", ← compute (outer ++ conds ++ cl.prems) extra)
      | .step, none =>
        lemmaConds := some (outer ++ conds, #[])
        if ctx.bound.isEmpty then
          pure ("step-own", ← if dead then pure none else compute (outer ++ conds) #[])
        else pure ("unattributed", none)
      | .state, _ =>
        lemmaConds := some (outer ++ conds, #[])
        pure ("state", ← if dead then pure none else compute (outer ++ conds) #[])
      | _, _ => pure ("other", none)
  let predStr ← match pred with
    | some (e, _) => oneLine e
    | none => pure "-"
  modify fun s => { s with
    branches := s.branches.modify id fun b => { b with pred := pred.map (·.1), predStr, role },
    region := false, stack := s.stack.push id, condStack := s.condStack ++ conds }
  let body' ← try walk body finally
    modify fun s => { s with region := st.region, stack := st.stack, condStack := outer }
  let rebuiltMark := mkApp4 f α (mkStrLit tag) deadE (condApps.foldr (·.app ·) body')
  let ns := ctx.cfg.ns
  if ns.isAnonymous then return rebuiltMark
  let some (cs, extra) := lemmaConds | return rebuiltMark
  let tele ← match pred with
    | some (_, t) => pure t
    | none => try teleOf cs extra catch _ => pure {}
  -- frame lemma: the clause instance held before the step
  if let some (premS, ws) := frame then
    discard <| tieLemma id "frame" (ns ++ Name.mkSimple s!"frame_{id}") tele
      (mkAndN premS) #[(mkAndIntroN premS ws, false)] #[]
  -- branch lemma: proved by the rebuilt body if it closes over the telescope, else by the
  -- original body
  let bodies := if body' == body then #[(body, false)] else #[(body', true), (body, false)]
  let extraL := if pred.isSome && role == "effect" then extra else #[]
  match ← tieLemma id "branch" (ns ++ Name.mkSimple s!"branch_{id}") tele α bodies
      extraL with
  | some (name, args) =>
    let k := (← get).ties.size - 1
    modify fun s => { s with branches := s.branches.modify id fun b => { b with tie := some k } }
    let ci ← getConstInfo name
    return mkAppN (mkConst name (ci.levelParams.map mkLevelParam)) args
  | none => return rebuiltMark

end


end Relevance

end
