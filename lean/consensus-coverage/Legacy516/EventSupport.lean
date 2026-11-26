module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public meta import ConsensusCoverage.ProofWalk
public import ConsensusCoverage.ActionContext
public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

/-!
# Event support for recorded step questions

`allowed` gives the constructor tags not excluded for each pinned question.
`sig_support` certifies the exclusions for the action of the actual pinned
context; it does not assert that any remaining tag or answer vector is reachable.
-/

namespace ConsensusCoverage.EventSupport

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Only the input or message constructor is recorded; actors, payloads and
timeout kinds are deliberately erased. -/
public inductive Tag where
  | append | sendEntries | timeout | nominateSuccessor | initAsBackup
  | appendEntriesRequest | appendEntriesResponse
  | requestVoteRequest | requestVoteResponse | requestPreVoteRequest | requestPreVoteResponse
  | proposeRequestVoteRequest
  deriving DecidableEq, Repr

private def inputTag : Input → Tag
  | .append _ => .append
  | .sendEntries .. => .sendEntries
  | .timeout _ => .timeout
  | .nominateSuccessor => .nominateSuccessor
  | .initAsBackup _ => .initAsBackup

private def messageTag : Message → Tag
  | .appendEntriesRequest _ => .appendEntriesRequest
  | .appendEntriesResponse _ => .appendEntriesResponse
  | .requestVoteRequest _ => .requestVoteRequest
  | .requestVoteResponse _ => .requestVoteResponse
  | .requestPreVoteRequest _ => .requestPreVoteRequest
  | .requestPreVoteResponse _ => .requestPreVoteResponse
  | .proposeRequestVoteRequest _ => .proposeRequestVoteRequest

/-- The classification can be read from the recorded action itself. -/
@[expose] public def actionTag : Model.Action → Tag
  | .local _ i => inputTag i
  | .deliver e => messageTag e.payload

private def eventTag : Event → Tag
  | .internal i => inputTag i
  | .receive _ m => messageTag m

private theorem tag_of_pin {s u t : Model.State} {l : LocalTransition s u} {r : LocalTransition s t}
    (pin : u = t ∧ HEq l r) : eventTag l.event = eventTag r.event := by
  obtain ⟨rfl, h⟩ := pin
  cases eq_of_heq h
  rfl

private theorem actionTag_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : actionTag (ActionContext.action c) = eventTag c.tr.event := by
  unfold ActionContext.action ActionContext.encode
  cases c.tr.event <;> rfl

private def inputs : List Tag := [.append, .sendEntries, .timeout, .nominateSuccessor, .initAsBackup]
private def messages : List Tag :=
  [.appendEntriesRequest, .appendEntriesResponse, .requestVoteRequest, .requestVoteResponse,
   .requestPreVoteRequest, .requestPreVoteResponse, .proposeRequestVoteRequest]

private theorem allInputTags (i : Input) : inputTag i ∈ inputs := by
  cases i <;> simp [inputTag, inputs]
private theorem allMessageTags (m : Message) : messageTag m ∈ messages := by
  cases m <;> simp [messageTag, messages]

private theorem included {small big : List Tag}
    (h : small.all (fun t => decide (t ∈ big)) = true) {t : Tag} (mem : t ∈ small) :
    t ∈ big :=
  of_decide_eq_true (List.all_eq_true.mp h t mem)

private theorem mem_of_eq {x y : Tag} {ts : List Tag} (eq : x = y)
    (mem : y ∈ ts) : x ∈ ts := eq ▸ mem

private theorem mem_inter {x : Tag} {l r : List Tag} (left : x ∈ l) (right : x ∈ r) :
    x ∈ l.filter (fun t => decide (t ∈ r)) := List.mem_filter.mpr ⟨left, decide_eq_true right⟩

private theorem allTag (t : Tag) : t ∈ inputs ++ messages := by cases t <;> decide

/-!
For positive formulas, compute guaranteed equalities between constructor tags and
guaranteed tag memberships. Conjunctions link aliases and intersect memberships; disjunctions keep only
common consequences (taking the union for membership); existentials forget
consequences still mentioning the witness. Reach calls reuse kernel-checked
summaries over their parameters. In particular, membership of an arbitrary
existential's tag never constrains the actual step without a proved link.
The endpoint and transition pins identify the event of the actual transition.
Unrecognized conditions do not restrict its tag.
-/

set_option maxHeartbeats 0
set_option maxRecDepth 8192

meta section

open Lean Meta Elab Command

private inductive Condition where
  | eq (x y : Expr)
  | mem (x : Expr) (tags : List Name)

private structure Fact where
  cond : Condition
  proof : Expr

private structure SummaryFact where
  cond : Condition
  lemmaName : Name

private abbrev Gen := StateRefT (Std.HashMap Name (Array SummaryFact)) MetaM

private def isReach (n : Name) : Bool :=
  n.getPrefix == `ConsensusCoverage.PinnedClasses && n.getString!.startsWith "reach_"

private def inputNames : List Name :=
  [``Tag.append, ``Tag.sendEntries, ``Tag.timeout, ``Tag.nominateSuccessor, ``Tag.initAsBackup]

private def messageNames : List Name :=
  [``Tag.appendEntriesRequest, ``Tag.appendEntriesResponse, ``Tag.requestVoteRequest,
   ``Tag.requestVoteResponse, ``Tag.requestPreVoteRequest, ``Tag.requestPreVoteResponse,
   ``Tag.proposeRequestVoteRequest]

private def tagList (ns : List Name) : MetaM Expr := mkListLit (mkConst ``Tag) (ns.map mkConst)

private def tagTy := mkConst ``Tag
private def tagTypeLevel := Level.succ .zero

private def Condition.prop : Condition → MetaM Expr
  | .eq x y => pure (mkApp3 (mkConst ``Eq [tagTypeLevel]) tagTy x y)
  | .mem x tags => return mkApp3 (mkConst ``List.Mem [.zero]) tagTy x (← tagList tags)

private def Condition.mapM (f : Expr → MetaM Expr) : Condition → MetaM Condition
  | .eq x y => return .eq (← f x) (← f y)
  | .mem x tags => return .mem (← f x) tags

private def Condition.mentions (p : Condition) (x : Expr) : Bool :=
  let contains := fun (e : Expr) => e.containsFVar x.fvarId!
  match p with
  | .eq a b => contains a || contains b
  | .mem a _ => contains a

/-- Normalize only the projections/constructors we model. In particular, never
unfold network or protocol functions while comparing observed terms. -/
private def observation (ty x : Expr) : MetaM (Option Expr) := do
  let mut e := x
  if ty.isAppOf ``Ctx then
    let tr := mkAppN (mkConst ``Ctx.tr) (ty.getAppArgs.push x)
    e := mkApp3 (mkConst ``LocalTransition.event)
      (mkApp (mkConst ``Frame.current) (ty.getArg! 1)) (ty.getArg! 2) tr
  else if ty.isAppOf ``LocalTransition then
    e := mkAppN (mkConst ``LocalTransition.event) (ty.getAppArgs.push x)
  else unless ty.isConstOf ``Event || ty.isConstOf ``Input || ty.isConstOf ``Consensus.Model.Node.Message do
    return none
  if e.isAppOf ``Ctx.event then
    if let some raw ← unfoldDefinition? e then e := raw
  -- The same transition projection can be indexed by `t` or `(f.advance t).current`.
  e := e.replace fun x =>
    if x.isAppOfArity ``Frame.current 1 && x.appArg!.isAppOf ``Frame.advance then
      some x.appArg!.appArg! else none
  let (fn, v) :=
    if ty.isConstOf ``Input then (``inputTag, e)
    else if ty.isConstOf ``Consensus.Model.Node.Message then (``messageTag, e)
    else if e.isAppOf ``Event.internal then (``inputTag, e.appArg!)
    else if e.isAppOf ``Event.receive then (``messageTag, e.appArg!)
    else (``eventTag, e)
  if let .const (.str ns ctor) _ := v.getAppFn then
    let tag := ``Tag ++ Name.mkSimple ctor
    if (fn == ``inputTag && ns == ``Input && inputNames.contains tag) ||
        (fn == ``messageTag && ns == ``Consensus.Model.Node.Message && messageNames.contains tag) then
      return some (mkConst tag)
  return some (mkApp (mkConst fn) v)

private def fromEq (ty x y h : Expr) : MetaM (Array Fact) := do
  let some a ← observation ty x | return #[]
  let some b ← observation ty y | return #[]
  if a == b then return #[]
  let obs ← withLocalDeclD `v ty fun v => do
    let some r ← observation ty v | throwError "expected observation at {ty}"
    mkLambdaFVars #[v] r
  let proof := mkAppN (mkConst ``congrArg [tagTypeLevel, tagTypeLevel]) #[ty, tagTy, x, y, obs, h]
  return #[⟨.eq a b, proof⟩]

private def widen (f : Fact) (tags : List Name) : MetaM Expr := do
  let .mem x small := f.cond | throwError "expected membership"
  if small == tags then return f.proof
  return mkAppN (mkConst ``included) #[← tagList small, ← tagList tags,
    ← mkEqRefl (mkConst ``Bool.true), x, f.proof]

private def addFact (fs : Array Fact) (f : Fact) : MetaM (Array Fact) := do
  match f.cond with
  | .mem x tags =>
    if let some i := fs.findIdx? fun g => match g.cond with
      | .mem y _ => x == y
      | _ => false then
      match fs[i]? with
      | some ⟨.mem _ old, oldProof⟩ =>
        if old.all tags.contains then return fs
        if tags.all old.contains then return fs.set! i f
        let proof := mkAppN (mkConst ``mem_inter) #[x, ← tagList old, ← tagList tags, oldProof, f.proof]
        return fs.set! i ⟨.mem x (old.filter tags.contains), proof⟩
      | _ => return fs
    else return fs.push f
  | .eq x y =>
    if x == y || fs.any (fun g => match g.cond with
        | .eq a b => (a == x && b == y) || (a == y && b == x)
        | _ => false) then return fs
    else return fs.push f

private def symm (x y h : Expr) : Expr :=
  mkAppN (mkConst ``Eq.symm [tagTypeLevel]) #[tagTy, x, y, h]

private def trans (x y z xy yz : Expr) : Expr :=
  mkAppN (mkConst ``Eq.trans [tagTypeLevel]) #[tagTy, x, y, z, xy, yz]

private def links (fs : Array Fact) (x : Expr) : Array (Expr × Expr) := Id.run do
  let mut out := #[]
  for f in fs do
    if let .eq a b := f.cond then
      if a == x then out := out.push (b, f.proof)
      else if b == x then out := out.push (a, symm a b f.proof)
  return out

private def seed (x : Expr) : MetaM (Option Fact) := do
  if let .const n _ := x then
    if inputNames.contains n || messageNames.contains n then
      return some ⟨.mem x [n], mkApp3 (mkConst ``List.Mem.head [.zero]) tagTy x (← tagList [])⟩
  if x.isAppOf ``inputTag then
    return some ⟨.mem x inputNames, mkApp (mkConst ``allInputTags) x.appArg!⟩
  if x.isAppOf ``messageTag then
    return some ⟨.mem x messageNames, mkApp (mkConst ``allMessageTags) x.appArg!⟩
  return none

/-- Close the small equality graph before forgetting any existential witnesses. -/
private def close (facts : Array Fact) : MetaM (Array Fact) := do
  let keys := facts.foldl (init := #[]) fun ks f =>
    let add (xs : Array Expr) (x : Expr) := if xs.contains x then xs else xs.push x
    match f.cond with
    | .eq x y => add (add ks x) y
    | .mem x _ => add ks x
  let mut fs ← facts.foldlM addFact #[]
  for x in keys do
    if let some f ← seed x then fs ← addFact fs f
    let neighbors := links fs x
    for (a, ha) in neighbors do
      for (b, hb) in neighbors do
        if a != b && !(fs.any fun f => match f.cond with
            | .eq y z => (a == y && b == z) || (a == z && b == y)
            | _ => false) then
          fs ← addFact fs ⟨.eq a b, trans a x b (symm x a ha) hb⟩
  for f in fs do
    if let .mem x tags := f.cond then
      for (y, hy) in links fs x do
        let proof := mkAppN (mkConst ``mem_of_eq) #[y, x, ← tagList tags, symm x y hy, f.proof]
        fs ← addFact fs ⟨.mem y tags, proof⟩
  -- Constants already have their singleton fact wherever they occur. Keep the
  -- resulting memberships, not edges through constants or tautological facts.
  return fs.filter fun f => match f.cond with
    | .eq x y => !x.isConst && !y.isConst
    | .mem x _ => !x.isConst

private def join (l r : Array Fact) (p h : Expr) : MetaM (Array Fact) := do
  let mut out := #[]
  for f in l do
    for g in r do
      let matched ← match f.cond, g.cond with
        | .eq a b, .eq c d =>
          if a == c && b == d then pure (some (f.cond, f.proof, g.proof))
          else if a == d && b == c then pure (some (f.cond, f.proof, symm c d g.proof))
          else pure none
        | .mem a xs, .mem b ys =>
          if a == b then do
            let ts := (inputNames ++ messageNames).filter fun n => xs.contains n || ys.contains n
            if ts.length == inputNames.length + messageNames.length then pure none
            else pure (some (.mem a ts, ← widen f ts, ← widen g ts))
          else pure none
        | _, _ => pure none
      if let some (cond, lp, rp) := matched then
        out := out.push ⟨cond, ProofWalk.casesOr p h (← cond.prop)
          (Lean.mkLambda `hl .default (p.getArg! 0) lp)
          (Lean.mkLambda `hr .default (p.getArg! 1) rp)⟩
  return out

mutual

/-- Branch proofs use bound index zero for their hypothesis. Building binders
directly avoids re-abstracting the long right-hand certificate at every join. -/
private partial def summarize (p h : Expr) : Gen (Array Fact) := do
  let args := p.getAppArgs
  if p.isAppOfArity ``And 2 then
    if args[0]!.isAppOfArity ``Eq 3 && args[1]!.isAppOfArity ``HEq 4 &&
        (args[1]!.getArg! 0).isAppOf ``LocalTransition then
      let a := args[1]!.getAppArgs
      let some l ← observation a[0]! a[1]! | throwError "expected left transition"
      let some r ← observation a[2]! a[3]! | throwError "expected right transition"
      let proof := mkAppN (mkConst ``tag_of_pin)
        #[a[0]!.getArg! 0, a[0]!.getArg! 1, a[2]!.getArg! 1, a[1]!, a[3]!, h]
      return #[⟨.eq l r, proof⟩]
    let ((lp, lh), (rp, rh)) := ProofWalk.conjuncts p h
    let l ← summarize lp lh
    let r ← summarize rp rh
    if l.isEmpty then return r
    if r.isEmpty then return l
    close (l ++ r)
  else if p.isAppOfArity ``Or 2 then
    let l ← summarize args[0]! (mkBVar 0)
    if l.isEmpty then return #[]
    join l (← summarize args[1]! (mkBVar 0)) p h
  else if p.isAppOfArity ``Exists 2 && args[1]!.isLambda then
    withLocalDeclD `w args[0]! fun w => do
      let body := args[1]!.beta #[w]
      let fs ← summarize body (mkBVar 0)
      (fs.filter fun f => !f.cond.mentions w).mapM fun f => do
        let scope := Lean.mkLambda `hw .default body f.proof
        let branch := Lean.mkLambda `w .default args[0]! (scope.abstract #[w])
        return ⟨f.cond, ProofWalk.casesExists p h (← f.cond.prop) branch⟩
  else if p.isAppOfArity ``Eq 3 then
    close (← fromEq args[0]! args[1]! args[2]! h)
  else if let .const n ls := p.getAppFn then
    if isReach n then
      let fs ← compileReach n
      return ← fs.mapM fun f => do
        return ⟨← f.cond.mapM (fun e => pure (e.beta args)),
          mkAppN (mkConst f.lemmaName ls) (args.push h)⟩
    else return #[]
  else return #[]

private partial def compileReach (n : Name) : Gen (Array SummaryFact) := do
  if let some fs := (← get)[n]? then return fs
  let ci ← getConstInfo n
  let fs ← lambdaTelescope ci.value! fun xs p =>
    withLocalDeclD `h p fun h => do
      for dep in p.getUsedConstants do
        if isReach dep then discard (compileReach dep)
      let facts ← close (← summarize p h)
      facts.mapIdxM fun i f => do
        let name := `ConsensusCoverage.EventSupport ++ Name.mkSimple (n.getString!) |>.appendIndexAfter i
        let call := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
        let ty ← mkForallFVars xs (← mkArrow call (← f.cond.prop))
        let value ← mkLambdaFVars (xs.push h) f.proof
        addDecl (.thmDecl {name, levelParams := ci.levelParams, type := ty, value})
        return ⟨← f.cond.mapM (mkLambdaFVars xs), name⟩
  modify fun m => m.insert n fs
  return fs

end

private def compile : MetaM Unit := do
  let ci ← getConstInfo ``PinnedClasses.dispatch
  let tags ← getConstInfoInduct ``Tag
  unless tags.ctors == inputNames ++ messageNames do
    throwError "tag enumeration does not match the constructor partition"
  let branch ← getConstInfoInduct ``Classes.StepBranch
  let ls := ci.levelParams.map mkLevelParam
  lambdaTelescope ci.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "unexpected PinnedClasses.dispatch"
    let b := xs[4]!
    let params := xs.extract 0 4
    let ctx := params[3]!
    let some key ← observation (← inferType ctx) ctx | throwError "expected pinned context"
    let arms := args.extract 2 args.size
    let (results, cache) ← (arms.mapM (fun arm => do
      unless arm.getAppArgs == params do throwError "unexpected pinned arm: {arm}"
      let some p ← unfoldDefinition? arm | throwError "cannot unfold {arm}"
      withLocalDeclD `h p fun h => do
        for dep in p.getUsedConstants do
          if isReach dep then discard (compileReach dep)
        let facts ← close (← summarize p h)
        let some f := facts.find? (fun f => match f.cond with
            | .mem x _ => x == key
            | _ => false) | return (tags.ctors, ← mkLambdaFVars #[h] (mkApp (mkConst ``allTag) key))
        let .mem _ ts := f.cond | throwError "expected membership"
        return (ts, ← mkLambdaFVars #[h] f.proof)) : Gen _).run {}
    let listType := mkApp (mkConst ``List [.zero]) (mkConst ``Tag)
    let lists ← results.mapM (fun (ts, _) => tagList ts)
    let allowed := `ConsensusCoverage.EventSupport.allowed
    let value := mkAppN (mkConst ``Classes.StepBranch.casesOn [.succ .zero])
      (#[← mkLambdaFVars #[b] listType, b] ++ lists)
    let allowedDecl := Declaration.defnDecl {
      name := allowed
      levelParams := []
      type := ← mkForallFVars #[b] listType
      value := ← mkLambdaFVars #[b] value
      hints := .abbrev
      safety := .safe }
    addDecl allowedDecl (forceExpose := true)
    compileDecl allowedDecl
    let ds := mkAppN (mkConst ``PinnedClasses.dispatch ls) xs
    let result ← mkAppM ``List.Mem #[key, mkApp (mkConst allowed) b]
    let ty ← mkArrow ds result
    let motive ← mkLambdaFVars #[b] ty
    let proof := mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero])
      (#[motive, b] ++ results.map Prod.snd)
    addDecl <| .thmDecl {
      name := `ConsensusCoverage.EventSupport.dispatch_support
      levelParams := ci.levelParams
      type := ← mkForallFVars xs ty
      value := ← mkLambdaFVars xs proof }
    let restricted := results.filter (fun (ts, _) => ts.length < tags.ctors.length)
    let pairs : Nat := results.foldl (fun acc (ts, _) => acc + ts.length) 0
    let histogram := (List.range (tags.ctors.length + 1)).filterMap fun k =>
      let n := results.countP (fun (ts, _) => ts.length == k)
      if n == 0 then none else some (k, n)
    logInfo m!"event support: {restricted.size}/{arms.size} restricted columns; \
      {arms.size * tags.ctors.length - pairs} excluded tag-column pairs; \
      analyzed {cache.size} reach definitions; \
      column counts by allowed-list size: {histogram}"

end

@[expose] public section

local elab "generate_event_support" : command => Lean.Elab.Command.liftTermElabM compile
generate_event_support

/-- Conservative constructor support lists for the pinned step questions. -/
add_decl_doc allowed

/-- A true answer can only be supported by a tag in the computed list for that
question. This is a necessary condition, not a realizability claim. -/
theorem sig_support [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (b : Classes.StepBranch) :
    PinnedClasses.sig c b → actionTag (ActionContext.action c) ∈ allowed b := by
  rw [actionTag_eq]
  exact dispatch_support _ _ _ _

/-- On replay, the action tag alone forces every excluded coordinate to false. -/
theorem label_false (s : ActionProfile.Step) (b : Classes.StepBranch)
    (excluded : actionTag s.act ∉ allowed b) : ActionProfile.label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_false_iff.mpr
  intro yes
  have support := sig_support s.context b ((ActionProfile.label_true s _).mp yes)
  have recorded := (s.context_eq s.context).mpr rfl
  exact excluded (recorded ▸ support)

/-- Count exclusions by testing the matrix, not by assuming anything about
duplicate entries or the syntax of an `allowed` list. -/
theorem exclusion_counts :
    let columns := FullProfile.stepBranches
    let misses := fun b => (inputs ++ messages).countP (fun t => decide (t ∉ allowed b))
    columns.size = 516 ∧ (columns.filter fun b => misses b > 0).size = 228 ∧
      columns.foldl (fun n b => n + misses b) 0 = 2176 := by decide +kernel

/-- A local timeout cannot satisfy the commit-backing branch for the maximum
of the old commit index and the newly committable index. -/
theorem timeout_not_commitBackedMax [Config.InitialConfiguration]
    {f : Frame} {t : Model.State} (c : Ctx f t) {actor : NodeID} {kind : TimeoutKind}
    (recorded : ActionContext.action c = .local actor (.timeout kind)) :
    ¬ PinnedClasses.sig c .commit_backed_max_eq_or_inl := by
  intro yes
  have support := sig_support c _ yes
  rw [recorded] at support
  exact (by decide : Tag.timeout ∉ allowed .commit_backed_max_eq_or_inl) support

/-- Even another delivery cannot satisfy the vote-request question unless its
message has the appropriate constructor. -/
theorem appendEntriesResponse_not_requestVoteRequest [Config.InitialConfiguration]
    {f : Frame} {t : Model.State} (c : Ctx f t) {src dst : NodeID}
    {response : AppendEntriesResponse}
    (recorded : ActionContext.action c = .deliver ⟨src, dst, .appendEntriesResponse response⟩) :
    ¬ PinnedClasses.sig c .receive_message_requestVoteRequest := by
  intro yes
  have support := sig_support c _ yes
  rw [recorded] at support
  exact (by decide : Tag.appendEntriesResponse ∉ allowed .receive_message_requestVoteRequest) support

end

end ConsensusCoverage.EventSupport
