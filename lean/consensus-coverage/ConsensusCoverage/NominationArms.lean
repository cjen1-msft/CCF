module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! The summary and successor coordinates of a fresh recorded nomination. -/

namespace ConsensusCoverage.NominationArms

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192
set_option maxHeartbeats 0

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

public def IsNomination (c : Ctx f t) : Prop :=
  c.event = .internal .nominateSuccessor

public def FreshOutgoing (c : Ctx f t) (e : Model.Envelope) : Prop :=
  e ∈ c.sent ∧ ¬ Pending f e

private theorem actual (event : IsNomination c)
    {e : Model.Envelope} (sent : e ∈ c.sent) :
    c.pre = c.post ∧ c.pre.role = .primary ∧
      (∀ p : Model.Envelope, p ∈ c.sent →
        p.source = c.actor ∧ p.payload = .proposeRequestVoteRequest c.pre.currentTerm) ∧
      ∃ target, findSuccessor c.pre c.actor = some target := by
  have ran := c.tr.ran
  change (Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {} =
    some (c.post, c.tr.outputs) at ran
  change c.event = .internal .nominateSuccessor at event
  rw [event] at ran
  obtain ⟨new, eq, same, role, nominated⟩ :=
    nominate_sends c.actor c.pre {} _ _ ran
  refine ⟨same.symm, role, ?_, ?_⟩
  · rw [← List.nil_append new, ← eq] at nominated
    exact nominated
  cases h : findSuccessor c.pre c.actor with
  | some target => exact ⟨target, rfl⟩
  | none =>
    have empty : (Node.step (Capabilities.record c.actor) c.actor c.pre
        (.internal .nominateSuccessor)).run {} = some (c.pre, {}) := by
      simp [Node.step, act, nominateSuccessor, role, h, StateT.run]
      rfl
    rw [empty, Option.some.injEq, Prod.mk.injEq] at ran
    simp [Ctx.sent, ← ran.2] at sent

private theorem reach434 {e : Model.Envelope} (sent : e ∈ c.sent) (fresh : ¬ Pending f e) :
    SolvedWitnesses.reach_434 f t c t c.tr := by
  have pending : Pending (f.advance t) e := by
    change e ∈ t.network
    rw [c.tr.networkEq]
    exact List.mem_append_right _ sent
  have h26 : SolvedWitnesses.reach_26 f t c c e :=
    ⟨⟨pending, fresh, rfl⟩, sent, pending, rfl⟩
  exact ⟨Or.inr (Or.inr (Or.inr ⟨e, h26, sent, rfl⟩)), rfl, HEq.rfl⟩

private theorem reach2296 (h : SolvedWitnesses.reach_434 f t c t c.tr)
    (event : c.event = .internal .nominateSuccessor) :
    SolvedWitnesses.reach_2296 f t c c.actor c.pre :=
  ⟨c.event, ⟨t, c.tr, h, rfl, rfl, rfl⟩, event⟩

meta section
open Lean Meta Elab Tactic

private partial def startsWithReach (name : Name) (p : Expr) : Bool :=
  if p.isAppOfArity ``Exists 2 then
    startsWithReach name p.appArg!.bindingBody!
  else
    p.isAppOfArity ``And 2 && (p.getArg! 0).isAppOf name

private partial def selectArm (name : Name) : TacticM Unit := do
  let p ← whnf (← getMainTarget)
  if p.isAppOfArity ``Or 2 then
    if startsWithReach name (p.getArg! 0) then
      evalTactic (← `(tactic| left))
    else
      evalTactic (← `(tactic| right))
      selectArm name
  else
    unless startsWithReach name p do throwError "could not find arm for {name}"

/-- Select an arm by its first reach conjunct, rather than its position in the generated Or. -/
elab "reach_arm " reach:ident : tactic => withMainContext do
  selectArm (← realizeGlobalConstNoOverloadWithInfo reach)

end

public theorem summary_event_internal (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    SolvedWitnesses.sig c .summary_event_internal := by
  reach_arm SolvedWitnesses.reach_1307
  exact ⟨c.event, ⟨t, c.tr, reach434 fresh.1 fresh.2, rfl⟩, .nominateSuccessor, event⟩

public theorem summary_input_nominateSuccessor (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    SolvedWitnesses.sig c .summary_input_nominateSuccessor := by
  reach_arm SolvedWitnesses.reach_1307
  exact ⟨c.event, ⟨t, c.tr, reach434 fresh.1 fresh.2, rfl⟩, event⟩

public theorem quiet_summary_either_inl (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    SolvedWitnesses.sig c .quiet_summary_either_inl := by
  obtain ⟨same, role, nominated, _⟩ := actual event fresh.1
  have engaged : Engaged c.pre := by simp [Engaged, role]
  reach_arm SolvedWitnesses.reach_2345
  have path : SolvedWitnesses.reach_2345 f t c c.actor c.pre c.pre c.event c.sent := by
    reach_arm SolvedWitnesses.reach_2296
    exact ⟨c.pre, reach2296 (reach434 fresh.1 fresh.2) event,
      ⟨role, nominated⟩, role, nominated, ⟨role, nominated⟩, role, nominated, rfl, rfl, event⟩
  refine ⟨c.actor, c.pre, c.pre, c.event, c.sent, path, Or.inl engaged, engaged,
    rfl, rfl, rfl, rfl, rfl, rfl, rfl, fun _ => Or.inl engaged, ?_⟩
  simpa only [← same] using (Summary.sends c.sum)

public theorem nominate_sends_successor_some (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    SolvedWitnesses.sig c .nominate_sends_successor_some := by
  obtain ⟨_, role, _, successor⟩ := actual event fresh.1
  reach_arm SolvedWitnesses.reach_2451
  exact ⟨c.actor, c.pre, Or.inl (reach2296 (reach434 fresh.1 fresh.2) event),
    role, role, role, successor⟩

private def Arguments (c : Ctx f t) (self : NodeID) (state : NodeState) : Prop :=
  self = c.actor ∧ state = c.pre

private def Ports (c : Ctx f t) (self : NodeID) (state : NodeState) (event : Event) : Prop :=
  Arguments c self state ∧ event = c.event

private theorem pinnedPorts {u : Model.State} {tr : LocalTransition f.current u}
    {self state event} (pin : u = t ∧ HEq tr c.tr) (actor : self = tr.actor)
    (pre : state = tr.pre) (ev : event = tr.event) : Ports c self state event := by
  obtain ⟨rfl, heq⟩ := pin
  cases eq_of_heq heq
  exact ⟨⟨actor, pre⟩, ev⟩

private def BumpingSend (sent : List Model.Envelope) : Prop :=
  ∃ e, e ∈ sent ∧ Bumping e.payload

omit [Config.InitialConfiguration] in
private theorem proposal_not_bumping {sent : List Model.Envelope} {self : NodeID} {term : Nat}
    (proposal : ∀ e : Model.Envelope, e ∈ sent →
      e.source = self ∧ e.payload = .proposeRequestVoteRequest term) :
    ¬ BumpingSend sent := by
  rintro ⟨e, mem, bump⟩
  simp only [(proposal e mem).2, Bumping] at bump

private abbrev HasSuccessor (c : Ctx f t) : Prop :=
  ∃ target, findSuccessor c.pre c.actor = some target

private theorem successor_conflict {self state} (args : Arguments c self state)
    (actual : HasSuccessor c)
    (no : ∀ target, findSuccessor state self = some target → False) : False := by
  obtain ⟨rfl, rfl⟩ := args
  obtain ⟨target, eq⟩ := actual
  exact no target eq

meta section
open Lean Meta Elab Command

private def solved := `ConsensusCoverage.SolvedWitnesses
private def certName (n : Name) := `ConsensusCoverage.NominationArms ++
  Name.mkSimple (n.getString! ++ "_on_nomination")

private def splitOr (p h : Expr) (k : Expr → Expr → MetaM Expr) : MetaM Expr := do
  let arm (q : Expr) := withLocalDeclD `arm q fun hq => do mkLambdaFVars #[hq] (← k q hq)
  mkAppM ``Or.elim #[h, ← arm (p.getArg! 0), ← arm (p.getArg! 1)]

private def openExist (p h : Expr) (k : Expr → Expr → MetaM Expr) : MetaM Expr := do
  withLocalDeclD p.appArg!.bindingName! (p.getArg! 0) fun w => do
    let b := p.appArg!.beta #[w]
    withLocalDeclD `witness b fun hq => do
      mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hq] (← k b hq)]

/-- In the summary portals, the rightmost conjunction records the two pins. -/
private partial def fromPins (args : Array Expr) (p h : Expr) : MetaM Expr := do
  if p.isAppOfArity ``Or 2 then
    return ← splitOr p h (fromPins args)
  if p.isAppOfArity ``And 2 then
    if p.appArg!.isAppOf ``HEq then
      return ← mkAppM ``pinnedPorts (#[h] ++ args)
    return ← fromPins args p.appArg! (← mkAppM ``And.right #[h])
  throwError "expected the endpoint and transition pins, got {p}"

private def portal (p h : Expr) : MetaM Expr :=
  openExist p h fun p h => openExist p h fun p h => do
    let pin := p.getArg! 0
    let some body ← unfoldDefinition? pin | throwError "cannot unfold portal pin {pin}"
    let r ← mkAppM ``And.right #[h]
    let rr ← mkAppM ``And.right #[r]
    fromPins #[← mkAppM ``And.left #[r], ← mkAppM ``And.left #[rr], ← mkAppM ``And.right #[rr]]
      body (← mkAppM ``And.left #[h])

private inductive Shape where
  | portal | arguments | quiet | closed
  deriving BEq

/-- These two generated proof cones only need the summary portals, the
    argument pins of nomination/advance-commit, and the sends of quiet summary. -/
private def shape (n : Name) : Shape :=
  let i := ((n.getString!.drop 6).toString.toNat?).getD 0
  if 447 ≤ i && i ≤ 475 then .portal
  else if (2280 ≤ i && i ≤ 2308) || (2435 ≤ i && i ≤ 2463) then .arguments
  else if 2338 ≤ i && i ≤ 2373 then .quiet
  else .closed

private def reach? (p : Expr) : Option Name := do
  let n ← p.getAppFn.constName?
  if n.getPrefix == solved && n.getString!.startsWith "reach_" then some n else none

private def closeGuard (ports nom condition : Expr) : MetaM Expr := do
  let eq ← mkAppM ``Eq.trans #[← mkAppM ``And.right #[ports], nom]
  let rules ← (← getSimpTheorems).add (.other `actualNomination) #[] eq
  let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
  let (r, _) ← simp (← inferType condition) ctx
  let proof ← mkEqMP (← r.getProof) condition
  if r.expr.isConstOf ``False then return proof
  if r.expr.isAppOfArity ``Eq 3 then return ← mkNoConfusion (mkConst ``False) proof
  throwError "live non-nomination guard: {r.expr}"

private abbrev Fact := Expr × Expr

mutual

private partial def certify (n : Name) : MetaM Unit := do
  if (← getEnv).contains (certName n) then return
  let ci ← getConstInfo n
  let levels := ci.levelParams.map mkLevelParam
  lambdaTelescope ci.value! fun xs p => do
    let c := xs[3]!
    let kind := shape n
    let result ← match kind with
      | .portal => mkAppM ``Ports #[c, xs[4]!, xs[5]!, xs[6]!]
      | .arguments => mkAppM ``Arguments #[c, xs[4]!, xs[5]!]
      | .quiet => mkNot <$> mkAppM ``BumpingSend #[xs[8]!]
      | .closed => pure (mkConst ``False)
    let pred := mkAppN (mkConst n levels) xs
    let add (extra : Array Expr) (proof : Expr) : MetaM Unit := do
      let all := xs ++ extra
      addDecl <| .thmDecl {
        name := certName n, levelParams := ci.levelParams
        type := ← mkForallFVars all result, value := ← mkLambdaFVars all proof }
    try
      if kind == .portal then
        withLocalDeclD `h pred fun h => do add #[h] (← portal p h)
      else
        withLocalDeclD `nom (← mkAppM ``IsNomination #[c]) fun nom =>
          withLocalDeclD `h pred fun h => do
            let proof ← follow result nom none [(p, h)] []
            add #[nom, h] proof
    catch e => throwError "certifying {n}: {e.toMessageData}"

/-- Traverse the positive logical skeleton; a subeffect proved impossible
    immediately discharges its enclosing conjunction. -/
private partial def follow (result nom : Expr) (succ : Option Expr)
    (todo seen : List Fact) : MetaM Expr := do
  let (p, h) :: rest := todo | throwError "unresolved leaf for {result}"
  if let some n := reach? p then
    certify n
    let .const _ ls := p.getAppFn | throwError "expected generated reach"
    let kind := shape n
    let proof := mkAppN (mkConst (certName n) ls)
      (p.getAppArgs ++ if kind == .portal then #[h] else #[nom, h])
    let p' ← inferType proof
    if p'.isConstOf ``False then return ← mkFalseElim result proof
    if ← isDefEq p' result then return proof
    if kind == .portal then
      if result.isConstOf ``False then
        -- The other conjunct of an entry guard is the exact event test.
        let [(_, test)] := rest | throwError "unexpected portal continuation"
        return ← closeGuard proof nom test
      let hargs ← mkAppM ``And.left #[proof]
      if ← isDefEq (← inferType hargs) result then return hargs
    return ← follow result nom succ rest ((p', proof) :: seen)
  if p.isAppOfArity ``And 2 then
    return ← follow result nom succ
      ((p.getArg! 0, ← mkAppM ``And.left #[h]) :: (p.appArg!, ← mkAppM ``And.right #[h]) :: rest) seen
  if p.isAppOfArity ``Or 2 then
    return ← splitOr p h fun q hq => follow result nom succ ((q, hq) :: rest) seen
  if let some (_, no) := seen.find? (fun (q, _) => q.isAppOfArity ``Not 1 &&
      q.appArg!.isAppOf ``BumpingSend) then
    if result.isConstOf ``False && (← isDefEq p (← inferType no).appArg!) then
      return mkApp no h
  if p.isAppOfArity ``Exists 2 then
    return ← openExist p h fun q hq => follow result nom succ ((q, hq) :: rest) seen
  if p.isForall then
    if result.isAppOfArity ``Not 1 && result.appArg!.isAppOf ``BumpingSend then
      if let some proof ← observing? (mkAppM ``proposal_not_bumping #[h]) then
        if ← isDefEq (← inferType proof) result then return proof
    if let some s := succ then
      if let some (_, args) := seen.find? (fun (q, _) => q.isAppOf ``Arguments) then
        if let some proof ← observing? (mkAppM ``successor_conflict #[args, s, h]) then
          return proof
  follow result nom succ rest seen

end

private def compileNegatives : MetaM Unit := do
  for (n, needsSuccessor) in [(``SolvedWitnesses.step_quiet_summary_either_inr, false),
      (``SolvedWitnesses.step_nominate_sends_successor_none, true)] do
    let ci ← getConstInfo n
    let ls := ci.levelParams.map mkLevelParam
    lambdaTelescope ci.value! fun xs p => do
      let c := xs[3]!
      let pred := mkAppN (mkConst n ls) xs
      withLocalDeclD `nom (← mkAppM ``IsNomination #[c]) fun nom => do
        let close (succ : Option Expr) := withLocalDeclD `h pred fun h => do
          let proof ← follow (mkConst ``False) nom succ [(p, h)] []
          let args := xs ++ #[nom] ++ succ.toArray ++ #[h]
          addDecl <| .thmDecl {
            name := certName n, levelParams := ci.levelParams
            type := ← mkForallFVars args (mkConst ``False), value := ← mkLambdaFVars args proof }
        if needsSuccessor then
          withLocalDeclD `succ (← mkAppM ``HasSuccessor #[c]) fun s => close (some s)
        else close none

local elab "compile_nomination_negatives" : command => Lean.Elab.Command.liftTermElabM compileNegatives
compile_nomination_negatives

end

public theorem quiet_summary_either_inr (event : IsNomination c) :
    ¬ SolvedWitnesses.sig c .quiet_summary_either_inr :=
  @step_quiet_summary_either_inr_on_nomination _ f t c event

public theorem nominate_sends_successor_none (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    ¬ SolvedWitnesses.sig c .nominate_sends_successor_none :=
  @step_nominate_sends_successor_none_on_nomination _ f t c event (actual event fresh.1).2.2.2

/-- In the order of the summary and successor questions, the pinned bits are
    `true, true, true, false, true, false`. No separate pre/post equality
    hypothesis is needed: the recorded local run supplies it. -/
public theorem pinned_answers (event : IsNomination c)
    {e : Model.Envelope} (fresh : FreshOutgoing c e) :
    PinnedClasses.sig c .summary_event_internal ∧
      PinnedClasses.sig c .summary_input_nominateSuccessor ∧
      PinnedClasses.sig c .quiet_summary_either_inl ∧
      ¬ PinnedClasses.sig c .quiet_summary_either_inr ∧
      PinnedClasses.sig c .nominate_sends_successor_some ∧
      ¬ PinnedClasses.sig c .nominate_sends_successor_none :=
  ⟨(SolvedWitnesses.sig_iff c _).mpr (summary_event_internal event fresh),
    (SolvedWitnesses.sig_iff c _).mpr (summary_input_nominateSuccessor event fresh),
    (SolvedWitnesses.sig_iff c _).mpr (quiet_summary_either_inl event fresh),
    fun h => quiet_summary_either_inr event ((SolvedWitnesses.sig_iff c _).mp h),
    (SolvedWitnesses.sig_iff c _).mpr (nominate_sends_successor_some event fresh),
    fun h => nominate_sends_successor_none event fresh ((SolvedWitnesses.sig_iff c _).mp h)⟩

end ConsensusCoverage.NominationArms
