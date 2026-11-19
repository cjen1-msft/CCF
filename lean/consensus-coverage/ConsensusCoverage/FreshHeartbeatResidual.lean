module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
meta import all ConsensusCoverage.FreshHeartbeatPaths
public import ConsensusCoverage.FreshHeartbeatPaths
import all ConsensusCoverage.FreshHeartbeatPaths
import all ConsensusCoverage.FreshHeartbeat
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! The complete generated proof label for the first successful heartbeat.
The compiler closes the remaining reach paths of `FreshHeartbeatPaths` using
the single queued packet, the recorded send, and the unchanged node/log facts. -/

namespace ConsensusCoverage.FreshHeartbeatResidual

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open FullProfile ActionProfile FreshHeartbeat

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

attribute [local instance] FreshHeartbeat.instInitialConfiguration_consensusCoverage

private abbrev f := witness.frame
private abbrev t := witness.after
private abbrev send : Event := .internal (.sendEntries 1 0)

private theorem entered_summary : SolvedWitnesses.reach_399 f t concrete concrete := by
  have root := (FreshHeartbeatPaths.queue26 concrete heartbeat).2 ⟨rfl, rfl⟩
  exact .inr (.inr (.inr ⟨heartbeat, root, (outgoing heartbeat).2 rfl, rfl⟩))

-- The dependent transition pair carries the actual recorded event, not an
-- arbitrary event with the same before and after snapshots.
private theorem pin_transition {P : (u : Model.State) → LocalTransition f.current u → Prop} :
    (∃ u tr, SolvedWitnesses.reach_434 f t concrete u tr ∧ P u tr) ↔ P t concrete.tr := by
  constructor
  · rintro ⟨u, tr, ⟨_, rfl, heq⟩, h⟩
    cases eq_of_heq heq
    exact h
  · exact fun h => ⟨t, concrete.tr, ⟨entered_summary, rfl, HEq.rfl⟩, h⟩

private theorem event463 (n : NodeID) (st : NodeState) (e : Event) :
    SolvedWitnesses.reach_463 f t concrete n st e ↔ n = 0 ∧ st = primary ∧ e = send :=
  pin_transition

private theorem event1307 (e : Event) :
    SolvedWitnesses.reach_1307 f t concrete e ↔ e = send :=
  pin_transition

private theorem event1457 (st : NodeState) (e : Event) :
    SolvedWitnesses.reach_1457 f t concrete st e ↔ st = primary ∧ e = send :=
  pin_transition

private def FixedTransition (u : Model.State) (tr : LocalTransition f.current u) : Prop :=
  u = t ∧ tr ≍ concrete.tr

private theorem fixed_fields {u : Model.State} {tr : LocalTransition f.current u}
    (h : FixedTransition u tr) : tr.actor = 0 ∧ tr.pre = primary ∧ tr.event = send := by
  obtain ⟨rfl, h⟩ := h
  cases eq_of_heq h
  exact ⟨rfl, rfl, rfl⟩

private theorem pin_pair {R : (u : Model.State) → LocalTransition f.current u → Prop}
    (fixed : ∀ u tr, R u tr → FixedTransition u tr)
    {P : (u : Model.State) → LocalTransition f.current u → Prop} :
    (∃ u tr, R u tr ∧ P u tr) ↔ R t concrete.tr ∧ P t concrete.tr := by
  constructor
  · rintro ⟨u, tr, h, p⟩
    obtain ⟨rfl, eq⟩ := fixed u tr h
    cases eq_of_heq eq
    exact ⟨h, p⟩
  · exact fun ⟨h, p⟩ => ⟨t, concrete.tr, h, p⟩

private theorem pins425 (u : Model.State) (tr : LocalTransition f.current u)
    (h : SolvedWitnesses.reach_425 f t concrete u tr) : FixedTransition u tr := by
  rcases h with ⟨_, _, _, _, eq, heq⟩ | ⟨_, _, _, _, _, eq, heq⟩ | ⟨_, eq, heq⟩
  all_goals exact ⟨eq, heq⟩

private theorem pins446 (u : Model.State) (tr : LocalTransition f.current u)
    (h : SolvedWitnesses.reach_446 f t concrete u tr) : FixedTransition u tr :=
  ⟨h.2.1, h.2.2⟩

private theorem event454 (n : NodeID) (st : NodeState) (e : Event) :
    SolvedWitnesses.reach_454 f t concrete n st e ↔
      SolvedWitnesses.reach_425 f t concrete t concrete.tr ∧ n = 0 ∧ st = primary ∧ e = send :=
  pin_pair pins425

private theorem event475 (n : NodeID) (st : NodeState) (e : Event) :
    SolvedWitnesses.reach_475 f t concrete n st e ↔
      SolvedWitnesses.reach_446 f t concrete t concrete.tr ∧ n = 0 ∧ st = primary ∧ e = send :=
  pin_pair pins446

private theorem after_mem (n : NodeID) (st : NodeState) :
    (n, st) ∈ t.nodes ↔ (n = 0 ∧ st = primary) ∨ (n = 1 ∧ st = FreshHeartbeatPaths.backup) :=
  (show Now (f.advance t) n st ↔ _ from Iff.rfl).symm.trans <|
    (Iff.of_eq (congrFun (congrFun FreshHeartbeatPaths.no_new_now n) st)).trans
      (FreshHeartbeatPaths.old_now n st)

private theorem before_mem (n : NodeID) (st : NodeState) :
    (n, st) ∈ f.current.nodes ↔ (n = 0 ∧ st = primary) ∨ (n = 1 ∧ st = FreshHeartbeatPaths.backup) :=
  FreshHeartbeatPaths.old_now n st

private theorem frame_current : (f.advance t).current = t := rfl

private theorem zero_term (l : List Entry) : termAt l 0 = 0 := rfl

private theorem zero_match (n : NodeID) : primary.matchIndex n = 0 := rfl

private theorem new_commit (k : Nat) (l : List Entry) : ¬ (f.advance t).logs.committed k l := by
  rw [FreshHeartbeatPaths.log_ghost_eq]
  exact FreshHeartbeatPaths.no_old_commit k l

private theorem no_grant_at (v c : NodeID) (k : Nat) (r : RequestVoteRequest) :
    ¬ LogFacts.GrantAt f.current t v c k r := by
  rintro ⟨_, y, _, mem, _, _, vote, _⟩
  rw [FreshHeartbeat.sameNodes] at mem
  rw [(FreshHeartbeatPaths.quiet v y mem).1] at vote
  contradiction

private theorem empty_append :
    ∃ entries : List Entry, (∀ a ∈ entries, a.term = BOOTSTRAP_TERM) ∧
      ∃ sentIndex : NodeID → Nat,
        {primary with
          role := .primary
          currentTerm := BOOTSTRAP_TERM
          log := Config.GENESIS :: entries
          commitIndex := 0
          sentIndex := sentIndex
          votedFor := none} = primary :=
  ⟨[], by simp, primary.sentIndex, rfl⟩

private theorem append_state (l : List Entry) :
    (∃ sentIndex : NodeID → Nat,
      {primary with
        role := .primary
        currentTerm := BOOTSTRAP_TERM
        log := Config.GENESIS :: l
        commitIndex := 0
        sentIndex := sentIndex
        votedFor := none} = primary) ↔ l = [] := by
  constructor
  · intro ⟨_, eq⟩
    exact (List.cons.inj (congrArg NodeState.log eq)).2
  · rintro rfl
    exact ⟨primary.sentIndex, rfl⟩

private abbrev rebuilt (l : List Entry) (sentIndex : NodeID → Nat) : NodeState :=
  {primary with
    role := .primary
    currentTerm := BOOTSTRAP_TERM
    log := Config.GENESIS :: l
    commitIndex := 0
    sentIndex := sentIndex
    votedFor := none}

private theorem append_middle (middle : NodeState) (p : Prop) :
    (∃ l s, middle = rebuilt l s ∧ rebuilt l s = primary ∧
      (∀ a ∈ l, a.term = BOOTSTRAP_TERM) ∧ p) ↔ middle = primary ∧ p := by
  constructor
  · rintro ⟨_, _, h, h', _, hp⟩
    exact ⟨h.trans h', hp⟩
  · rintro ⟨rfl, hp⟩
    exact ⟨[], primary.sentIndex, rfl, rfl, by simp, hp⟩

private theorem append_middle_nil (middle : NodeState) (p : Prop) :
    (∃ s, middle = rebuilt [] s ∧ rebuilt [] s = primary ∧ p) ↔ middle = primary ∧ p := by
  constructor
  · rintro ⟨_, h, h', hp⟩
    exact ⟨h.trans h', hp⟩
  · rintro ⟨rfl, hp⟩
    exact ⟨primary.sentIndex, rfl, rfl, hp⟩

private theorem append_middle_rev (middle : NodeState) :
    (∃ s, rebuilt [] s = primary ∧ middle = rebuilt [] s) ↔ middle = primary := by
  constructor
  · rintro ⟨_, h, h'⟩
    exact h'.trans h
  · rintro rfl
    exact ⟨primary.sentIndex, rfl, rfl⟩

private theorem replace_pin (node member : NodeID) (value st : NodeState) :
    SolvedWitnesses.reach_1244 f t concrete node member value st ↔
      SolvedWitnesses.reach_1185 f t concrete concrete member st ∧
        Now (f.advance t) member st ∧ (member, st) ∈ t.nodes ∧ node = 0 ∧ value = primary := by
  constructor
  · rintro ⟨u, tr, ⟨h, now, rfl, eq⟩, mem, hn, hv⟩
    cases eq_of_heq eq
    exact ⟨h, now, mem, hn, hv⟩
  · exact fun ⟨h, now, mem, hn, hv⟩ =>
    ⟨t, concrete.tr, ⟨h, now, rfl, HEq.rfl⟩, mem, hn, hv⟩

private theorem replace_here :
    (0, primary) ∈ Consensus.Proofs.Concrete.replaceNode f.current.nodes 0 primary := by
  have mem := (before_mem 0 primary).2 (.inl ⟨rfl, rfl⟩)
  exact List.mem_map.mpr ⟨(0, primary), mem, rfl⟩

private theorem no_peer_replace (n : NodeID) (st : NodeState) (p : Prop) :
    ¬ ((n ≠ 0 → n = 0 ∧ st = primary) ∧ p ∧ (n ≠ 0 → n = 0 ∧ st = primary) ∧ n ≠ 0) :=
  fun ⟨h, _, _, hn⟩ => hn (h hn).1

private theorem owner_replace :
    ∃ n st, (n = 0 ∧ st = primary ∨ n = 1 ∧ st = FreshHeartbeatPaths.backup) ∧
      (n ≠ 0 → n = 0 ∧ st = primary) :=
  ⟨0, primary, .inl ⟨rfl, rfl⟩, fun h => (h rfl).elim⟩

private theorem heartbeat_peer : 1 ∈ eligiblePeers primary 0 := by decide +kernel

private theorem heartbeat_retirement :
    (primary.retirement 0).phase ≠ MembershipState.retiredCommitted := by decide +kernel

private theorem sent_zero : primary.sentIndex 1 = 0 := rfl

private theorem message_empty : messageEntries primary.log (primary.sentIndex 1) 0 = [] := rfl

private theorem heartbeat_request : makeAppendEntriesRequest primary 1 0 = request := rfl

private theorem heartbeat_sent_update :
    {primary with sentIndex := CCF.Function.update primary.sentIndex 1 0} = primary := by
  have h : CCF.Function.update primary.sentIndex 1 0 = primary.sentIndex :=
    CCF.Function.update_eq_self _ _
  exact congrArg (fun s => {primary with sentIndex := s}) h

private theorem heartbeat_send_ok : SendOK 0 primary send primary heartbeat :=
  ⟨rfl, FreshHeartbeatPaths.coherent, by decide +kernel, .inl ⟨rfl, rfl⟩⟩

private theorem backed_at (k i : Nat) (l : List Entry) :
    Backed (f.advance t) l i k ↔ i = 0 := by
  unfold Backed Committed
  simp [FreshHeartbeatPaths.log_ghost_eq, FreshHeartbeatPaths.no_old_commit]

private theorem old_canon (k : Nat) (l : List Entry) :
    f.logs.canon k l ↔ k = BOOTSTRAP_TERM ∧ l = [Config.GENESIS] := by
  change (False ∨ ∃ n st, CanonNow f n st k ∧ st.log = l) ↔ _
  rw [false_or]
  constructor
  · rintro ⟨n, st, canon, rfl⟩
    have hn := (FreshHeartbeatPaths.old_led n k).mp canon.2.2.2
    have mem := (FreshHeartbeatPaths.old_now n st).mp canon.1
    rcases mem with ⟨_, rfl⟩ | ⟨eq, _⟩
    · exact ⟨hn.1, rfl⟩
    · exact (Nat.zero_ne_one (hn.2.symm.trans eq)).elim
  · rintro ⟨rfl, rfl⟩
    exact ⟨0, primary, ⟨(FreshHeartbeatPaths.old_now _ _).mpr (.inl ⟨rfl, rfl⟩),
      rfl, by decide +kernel, (FreshHeartbeatPaths.old_led _ _).mpr ⟨rfl, rfl⟩⟩, rfl⟩

meta section
open Lean Meta Elab Command

private def makeRules : MetaM SimpTheorems := do
  let mut rules ← FreshHeartbeatPaths.baseRules
  for n in #[``pin_transition, ``event454, ``event463, ``event475, ``event1307, ``event1457, ``backed_at, ``old_canon,
      ``before_mem, ``after_mem, ``frame_current, ``no_grant_at, ``empty_append, ``append_state,
      ``zero_term, ``zero_match, ``new_commit, ``append_middle, ``append_middle_nil,
      ``append_middle_rev, ``replace_pin, ``replace_here, ``no_peer_replace, ``owner_replace,
      ``heartbeat_peer, ``heartbeat_retirement, ``sent_zero, ``message_empty, ``heartbeat_request,
      ``heartbeat_sent_update, ``heartbeat_send_ok] do
    rules ← rules.addConst n (post := false)
  return rules

private structure Compiler where
  seen : Std.HashSet Name := {}
  rules : SimpTheorems

private abbrev Reduce := StateRefT Compiler MetaM

private theorem and_left_false {p q : Prop} (hp : p = False) : (p ∧ q) = False := by simp [hp]
private theorem or_left_true {p q : Prop} (hp : p = True) : (p ∨ q) = True := by simp [hp]
private theorem and_subst {α : Type} (x y : α) (P : α → Prop) :
    (x = y ∧ P x) ↔ x = y ∧ P y := by
  constructor <;> rintro ⟨rfl, h⟩ <;> exact ⟨rfl, h⟩

private def combine (pf : Expr) (r : Simp.Result) : MetaM Simp.Result := do
  let pf ← mkPropExt pf
  let proof ← match r.proof? with
    | none => pure pf
    | some pr => mkEqTrans pf pr
  return { r with proof? := some proof }

-- Cut a dead arm before reducing its payload. The payload can contain a
-- large protocol fold, even when its first reach conjunct is impossible.
private partial def reduce (atom : Expr → MetaM Simp.Result) (p : Expr) : MetaM Simp.Result := do
  let and := p.isAppOfArity ``And 2
  if and || p.isAppOfArity ``Or 2 then
    let a ← reduce atom (p.getArg! 0)
    if a.expr.isConstOf (if and then ``False else ``True) then
      let pr ← mkAppOptM (if and then ``and_left_false else ``or_left_true)
        #[some (p.getArg! 0), some (p.getArg! 1), some (← a.getProof)]
      return { expr := a.expr, proof? := some pr }
    let b := p.getArg! 1
    if and && a.expr.isAppOfArity ``Eq 3 then
      let x := a.expr.getArg! 1
      let y := a.expr.getArg! 2
      if x.isFVar && !y.hasFVar && b.containsFVar x.fvarId! then
        let ty := a.expr.getArg! 0
        if (← withTransparency .reducible (isDefEq ty (mkConst ``NodeState))) ||
            (← withTransparency .reducible (isDefEq ty (mkConst ``NodeID))) then
          let pred ← mkLambdaFVars #[x] b
          if let some pin ← observing? (mkAppM ``and_subst #[x, y, pred]) then
            let congr ← mkAppM ``and_congr
              #[← mkIffOfEq (← a.getProof), ← mkAppM ``Iff.refl #[b]]
            let pf ← mkAppM ``Iff.trans #[congr, pin]
            let new := mkApp2 p.getAppFn a.expr (pred.beta #[y])
            return ← combine pf (← reduce atom new)
    let b ← reduce atom b
    let e := mkApp2 p.getAppFn a.expr b.expr
    let pf ← mkAppM (if and then ``and_congr else ``or_congr)
      #[← mkIffOfEq (← a.getProof), ← mkIffOfEq (← b.getProof)]
    return ← combine pf
      (← if a.expr.isConstOf ``True || a.expr.isConstOf ``False ||
          b.expr.isConstOf ``True || b.expr.isConstOf ``False then atom e else pure { expr := e })
  if p.isAppOfArity ``Exists 2 && p.appArg!.isLambda then
    let pred := p.appArg!
    return ← withLocalDeclD pred.bindingName! pred.bindingDomain! fun x => do
      let r ← reduce atom (pred.beta #[x])
      let e := mkApp2 p.getAppFn (p.getArg! 0) (← mkLambdaFVars #[x] r.expr)
      let pf ← mkAppM ``exists_congr #[← mkLambdaFVars #[x] (← mkIffOfEq (← r.getProof))]
      return ← combine pf (← atom e)
  atom p

private def compiled (ns : Name) (suffix : String) (n : Name) : Name :=
  ns ++ Name.mkSimple (n.getString! ++ suffix)

-- A reach application already supplies the exact arguments of its cached
-- rewrite. Bypass simp's syntactic indexing for dependent binder types.
private def cached (p : Expr) : MetaM (Option Simp.Result) := do
  let some n := p.getAppFn.constName? | return none
  if !FreshHeartbeatPaths.inReach n || p.getAppNumArgs < 4 then return none
  let args := p.getAppArgs.extract 4 p.getAppNumArgs
  for hn in #[compiled `ConsensusCoverage.FreshHeartbeatResidual "_fixed" n,
      compiled `ConsensusCoverage.FreshHeartbeatPaths "_at_send" n] do
    if let some ci := (← getEnv).find? hn then
      let eq := args.foldl (fun ty arg => ty.bindingBody!.instantiate1 arg) ci.type
      if eq.isAppOfArity ``Eq 3 then
        let lhs := eq.getArg! 1
        if lhs.getAppFn == p.getAppFn && lhs.getAppNumArgs == p.getAppNumArgs &&
            (← withTransparency .reducible (isDefEq lhs p)) then
          return some { expr := eq.getArg! 2, proof? := some (mkAppN (mkConst hn) args) }
  return none

private def simplify (rules : SimpTheorems) (body : Expr) : MetaM Simp.Result := do
  let config : Simp.Config := { maxSteps := 2400, failIfUnchanged := false }
  let ctx ← Simp.mkContext config #[rules] (← getSimpCongrTheorems)
  let procs := #[← Simp.getSimprocs]
  let atom := fun e => do
    if e.isAppOfArity ``Exists 2 && !e.hasFVar then
      let proof := mkConst ``empty_append
      if ← withTransparency .reducible (isDefEq e (← inferType proof)) then
        return { expr := mkConst ``True, proof? := some (← mkEqTrue proof) }
    if let some r ← cached e then
      if r.expr.isConstOf ``False || r.expr.isConstOf ``True then return r
      let r' : Option Simp.Result ← observing? (Prod.fst <$> simp r.expr ctx procs)
      if let some pr := r'.bind (·.proof?) then
        return { expr := r'.get!.expr, proof? := some (← mkEqTrans (← r.getProof) pr) }
      return r
    let r : Option Simp.Result ← observing? (Prod.fst <$> simp e ctx procs)
    return r.getD { expr := e }
  let r ← reduce atom body
  if r.expr == body || r.expr.isConstOf ``True || r.expr.isConstOf ``False then return r
  let r' ← reduce atom r.expr
  return { expr := r'.expr, proof? := some (← mkEqTrans (← r.getProof) (← r'.getProof)) }

-- A transition wrapper may carry arbitrary other path conditions. We only
-- extract the two equations identifying its dependent arguments, checking
-- every disjunct and never guessing the other witnesses.
private partial def project (goal : Expr) (facts : List (Expr × Expr)) : MetaM (Option Expr) := do
  let (p, h) :: rest := facts | return none
  if p == goal then return some h
  if p.isAppOfArity ``And 2 then
    let a := p.getArg! 0
    let b := p.getArg! 1
    let left := mkApp3 (mkConst ``And.left) a b h
    let right := mkApp3 (mkConst ``And.right) a b h
    return ← project goal ((a, left) :: (b, right) :: rest)
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `hq q fun hq => do
      let some pf ← project goal ((q, hq) :: rest) | return none
      return some (← mkLambdaFVars #[hq] pf)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (mkAppN (mkConst ``Or.elim) #[p.getArg! 0, p.getArg! 1, goal, h, l, r])
  if p.isAppOfArity ``Eq 3 || p.isAppOfArity ``HEq 4 then
    if ← withTransparency .reducible (isDefEq p goal) then return some h
  project goal rest

private def transitionRule (ps : Array Expr) (n : Name) (body : Expr)
    (rules : SimpTheorems) : MetaM SimpTheorems :=
  lambdaTelescope body fun xs p => do
    if xs.size != 2 then return rules
    unless (← inferType xs[1]!).isAppOf ``LocalTransition do return rules
    let fixed := mkApp2 (mkConst ``FixedTransition) xs[0]! xs[1]!
    let want ← unfoldDefinition fixed
    let proof ← withLocalDeclD `h p fun h => do
      let some l ← project (want.getArg! 0) [(p,h)] | return none
      let some r ← project (want.getArg! 1) [(p,h)] | return none
      return some (← mkLambdaFVars (xs.push h)
        (mkAppN (mkConst ``And.intro) (want.getAppArgs ++ #[l,r])))
    let some proof := proof | return rules
    let rel := mkAppN (mkConst n) ps
    let ty ← mkForallFVars xs (← mkArrow (mkAppN rel xs) fixed)
    let projection := `ConsensusCoverage.FreshHeartbeatResidual ++ Name.mkSimple (n.getString! ++ "_pins")
    addDecl (.thmDecl { name := projection, levelParams := [], type := ty, value := proof })
    let rule ← mkAppOptM ``pin_pair #[some rel, some (mkConst projection)]
    let type ← inferType rule
    let name := projection.appendAfter "_pair"
    addDecl (.thmDecl { name, levelParams := [], type, value := rule })
    rules.addConst name (post := false)

private partial def specialize (ps : Array Expr) (n : Name) : Reduce Unit := do
  if (← get).seen.contains n then return
  let old := `ConsensusCoverage.FreshHeartbeatPaths ++ Name.mkSimple (n.getString! ++ "_at_send")
  if let some prev := (← getEnv).find? old then
    let rules ← (← get).rules.addConst old (post := false)
    if prev.type.getForallBody.getAppArgs.back? == some (mkConst ``False) then
      modify fun s => { seen := s.seen.insert n, rules }
      return
    modify fun s => { s with rules }
  let ci ← getConstInfo n
  let body := ci.value!.beta ps
  (FreshHeartbeatPaths.dependencies body).forM (specialize ps)
  let rules ← transitionRule ps n body (← get).rules
  let rules ← lambdaTelescope body fun xs p => do
    let simplified : MetaM (Option Simp.Result) := observing? (simplify rules p)
    let some r ← simplified | return rules
    -- Memoize only small eliminators. Inlining long disjunctions would
    -- duplicate proofs on each incoming edge of the reach DAG.
    if r.expr == p || !FreshHeartbeatPaths.small 14 r.expr then return rules
    let name := `ConsensusCoverage.FreshHeartbeatResidual ++ Name.mkSimple (n.getString! ++ "_fixed")
    let c := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) (ps ++ xs)
    let type ← mkForallFVars xs (← mkEq c r.expr)
    let value ← mkLambdaFVars xs (← r.getProof)
    addDecl (.thmDecl { name, levelParams := ci.levelParams, type, value })
    rules.addConst name (post := false)
  modify fun s => { seen := s.seen.insert n, rules }

private def table := `ConsensusCoverage.FreshHeartbeatResidual.residualRead
private def sound := `ConsensusCoverage.FreshHeartbeatResidual.residualCertified

private def compile : MetaM Unit := do
  let ps ← FreshHeartbeatPaths.fixedParams
  let slots ← FreshHeartbeatPaths.slots (mkConst ``FreshHeartbeatPaths.residual)
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branches ← getConstInfoInduct ``Classes.StepBranch
  let arms := (ci.value!.beta ps).bindingBody!.getAppArgs.extract 2 (branches.ctors.length + 2)
  unless arms.size == branches.ctors.length do throwError "unexpected dispatcher layout"
  let mut state : Compiler := { rules := ← makeRules }
  let mut answers : Array (Option Bool × Expr) := #[]
  let mut positives : Array Nat := #[]
  let mut negatives : Array Nat := #[]
  for i in [:arms.size] do
    if !slots.contains i then
      answers := answers.push (none, mkConst ``True.intro)
      continue
    let n := arms[i]!.getAppFn.constName!
    let p := (← getConstInfo n).value!.beta ps
    let (_, st) ← ((FreshHeartbeatPaths.dependencies p).forM (specialize ps)).run state
    state := st
    if let some r ← observing? (simplify st.rules p) then
      if r.expr.isConstOf ``True || r.expr.isConstOf ``False then
        let b := r.expr.isConstOf ``True
        let pf := mkApp2 (mkConst (if b then ``FreshHeartbeatPaths.certified_yes else
          ``FreshHeartbeatPaths.certified_no)) arms[i]! (← r.getProof)
        if b then positives := positives.push i else negatives := negatives.push i
        answers := answers.push (some b, pf)
        continue
    answers := answers.push (none, mkConst ``True.intro)
  logInfo m!"fresh heartbeat residual: {positives.size} new positives, {negatives.size} new negatives"
  withLocalDeclD `branch (mkConst ``Classes.StepBranch) fun b => do
    let answer := mkApp (mkConst ``Option [.zero]) (mkConst ``Bool)
    let motive ← mkLambdaFVars #[b] answer
    let type ← mkForallFVars #[b] answer
    let value ← mkLambdaFVars #[b] (mkAppN (FreshHeartbeatPaths.casesFn (.succ .zero))
      (#[motive, b] ++ answers.map (FreshHeartbeatPaths.boolOption ∘ Prod.fst)))
    let decl := Declaration.defnDecl {
      name := table, levelParams := [], type, value
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let p := mkAppN (mkConst ``SolvedWitnesses.dispatch) (ps.push b)
    let ty := mkApp2 (mkConst ``FreshHeartbeatPaths.Certified) p (mkApp (mkConst table) b)
    let motive ← mkLambdaFVars #[b] ty
    let type ← mkForallFVars #[b] ty
    let value ← mkLambdaFVars #[b]
      (mkAppN (FreshHeartbeatPaths.casesFn .zero) (#[motive, b] ++ answers.map Prod.snd))
    addDecl (.thmDecl { name := sound, levelParams := [], type, value })

end

local elab "compile_heartbeat_residual" : command => Lean.Elab.Command.liftTermElabM compile
set_option maxHeartbeats 0 in
compile_heartbeat_residual

/-- Combined answers on the original initialized first send. -/
public def read? (q : Question) : Option Bool :=
  match q with
  | .step b => (residualRead b).orElse fun _ => FreshHeartbeatPaths.read? q
  | _ => FreshHeartbeatPaths.read? q

private theorem new_sound (b : Classes.StepBranch) {v : Bool}
    (h : residualRead b = some v) : label witness (.step b) = v := by
  have proof := residualCertified b
  rw [h] at proof
  have equiv : holds witness (.step b) ↔ SolvedWitnesses.sig concrete b := by
    change PinnedClasses.sig witness.context b ↔ SolvedWitnesses.sig concrete b
    rw [← concrete_context]
    exact SolvedWitnesses.sig_iff _ _
  cases v
  · exact Bool.eq_false_iff.mpr fun yes => proof (equiv.mp ((label_true _ _).mp yes))
  · exact (label_true _ _).mpr (equiv.mpr proof)

public theorem read_sound (q : Question) {v : Bool} (h : read? q = some v) :
    label witness q = v := by
  cases q with
  | pre b => exact FreshHeartbeatPaths.read_sound _ h
  | post b => exact FreshHeartbeatPaths.read_sound _ h
  | step b =>
    change (residualRead b).orElse (fun _ => FreshHeartbeatPaths.read? (.step b)) = some v at h
    cases hs : residualRead b with
    | none => exact FreshHeartbeatPaths.read_sound _ (by simpa only [hs, Option.orElse_none] using h)
    | some ans => exact new_sound b (hs.trans (by simpa only [hs, Option.orElse_some] using h))

@[expose] public def residual : List Classes.StepBranch :=
  FreshHeartbeatPaths.residual.filter fun b => (residualRead b).isNone

@[expose] public def positives : List Classes.StepBranch :=
  stepBranches.toList.filter fun b => read? (.step b) == some true

public theorem residual_iff (b : Classes.StepBranch) : b ∈ residual ↔ read? (.step b) = none := by
  cases h : residualRead b <;> simp [residual, read?, h, FreshHeartbeatPaths.residual_iff b]

public theorem positive (b : Classes.StepBranch) (h : b ∈ positives) :
    label witness (.step b) = true :=
  read_sound _ (beq_iff_eq.mp (List.mem_filter.mp h).2)

public theorem negative (b : Classes.StepBranch) (resolved : b ∉ residual)
    (notPositive : b ∉ positives) : label witness (.step b) = false := by
  cases h : read? (.step b) with
  | none => exact (resolved ((residual_iff b).2 h)).elim
  | some v =>
    cases v
    · exact read_sound _ h
    · exact (notPositive (List.mem_filter.mpr ⟨FreshHeartbeat.mem_universe b, beq_iff_eq.mpr h⟩)).elim

/-- Exact zero-based step slots, in the generated dispatcher order. -/
public theorem positive_slots : positives.map (·.ctorIdx) =
    [48, 49, 50, 71, 72, 73, 104, 105, 114, 146, 148, 150, 166, 174, 186, 187,
     232, 248, 250, 272, 274, 362, 363] :=
  by decide +kernel

public theorem residual_empty : residual = [] := by decide +kernel

public theorem counts :
    stateBranches.size = 12 ∧ stepBranches.size = 433 ∧
      positives.length = 23 ∧
      (stepBranches.toList.filter fun b => read? (.step b) == some false).length = 410 :=
  by decide +kernel

/-- The complete executable label: both endpoints and all 433 step bits. -/
@[expose] public def read : Profile
  | .pre b | .post b => ProofContexts.answers (true, false) b
  | .step b => read? (.step b) == some true

public theorem exact_profile : read = label witness := by
  funext q
  cases q with
  | pre b => exact (congrFun FreshHeartbeat.endpoints.1 b).symm
  | post b => exact (congrFun FreshHeartbeat.endpoints.2 b).symm
  | step b =>
    cases hb : read? (.step b) with
    | none =>
      have h := (residual_iff b).2 hb
      rw [residual_empty] at h
      exact (List.not_mem_nil h).elim
    | some v =>
      have h := read_sound _ hb
      change (read? (.step b) == some true) = _
      rw [hb]
      cases v <;> exact h.symm

end ConsensusCoverage.FreshHeartbeatResidual
