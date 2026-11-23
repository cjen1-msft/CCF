module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DelayedNomination

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

structure Stable [Config.InitialConfiguration] (f : Frame) (t : Model.State) (c : Ctx f t) : Prop where
  nodes : t.nodes = f.current.nodes
  seen : (f.advance t).logs.seen = f.logs.seen
  grant : (f.advance t).logs.grant = f.logs.grant
  elected : (f.advance t).logs.elected = f.logs.elected
  canon : (f.advance t).logs.canon = f.logs.canon
  event : c.event = .internal .nominateSuccessor
  noElection : ∀ n k l i, ¬ (f.advance t).logs.elected n k l i
  post : c.post = c.pre
  proposal : ∀ e ∈ c.sent, NominationRows.proposal e.payload = true

private theorem stable (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    @Stable ⟨s.cfg⟩ s.frame s.after s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨tag, _, grants, elect⟩ := (test_iff s).mp h
  obtain ⟨event, post, nodes, proposal⟩ := NominationRows.run_nomination s tag
  have fold := StutterProfile.advance_logs_nodes nodes
  exact ⟨nodes, (congrArg LogFacts.Ghost.seen fold).trans (StutterProfile.frozenSeen s.context.inv),
    grants, (congrArg LogFacts.Ghost.elected fold).trans (StutterProfile.frozenElection s.context.inv),
    (congrArg LogFacts.Ghost.canon fold).trans (StutterProfile.frozenCanon s.folded), event, elect,
    post, proposal⟩

variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private theorem stNow (s : Stable f t c) : Now (f.advance t) = Now f := by
  funext n st
  change ((n, st) ∈ t.nodes) = ((n, st) ∈ f.current.nodes)
  rw [s.nodes]

private theorem stSeen (s : Stable f t c) : Seen (f.advance t) = Seen f := by
  unfold Seen
  rw [s.seen]

private theorem stLed (s : Stable f t c) : Led (f.advance t) = Led f := by
  unfold Led LogFacts.Ghost.led
  rw [s.elected]

private theorem stGhostLed (s : Stable f t c) : (f.advance t).logs.led = f.logs.led := by
  unfold LogFacts.Ghost.led
  rw [s.elected]

private theorem stCanonNow (s : Stable f t c) : CanonNow (f.advance t) = CanonNow f := by
  funext n st k
  unfold CanonNow LogFacts.Ghost.canonNow
  change ((n, st) ∈ t.nodes ∧ _) = ((n, st) ∈ f.current.nodes ∧ _)
  rw [s.nodes, stGhostLed s]

private theorem stCommit (s : Stable f t c) : CommitStep (f.advance t) = CommitStep f := by
  funext n st k base i
  unfold CommitStep LogFacts.Ghost.commitAt
  have h := stCanonNow s
  unfold CanonNow at h
  rw [h, s.seen]

private theorem stRole (s : Stable f t c) : c.pre.role = .primary := by
  have ran := c.tr.ran
  change (Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {} =
    some (c.post, c.tr.outputs) at ran
  rw [s.event] at ran
  obtain ⟨_, _, _, role, _⟩ := nominate_sends c.actor c.pre {} _ _ ran
  exact role

private theorem stNoWins (s : Stable f t c) : ¬ Wins c.actor c.pre c.event c.post := by
  rintro ⟨cand, ⟨_, _, _, camp⟩, _, adv⟩
  have term : c.post.currentTerm = cand.currentTerm := by
    rcases adv with h | h
    · rw [h]; rfl
    · exact h.2.1
  have post := s.post
  rcases camp with ⟨_, up, _⟩ | ⟨cr, _⟩
  · rw [post] at term
    omega
  · rw [stRole s] at cr
    cases cr

private theorem stNoElection (s : Stable f t c) (n k l i) : ¬ f.logs.elected n k l i := by
  rw [← s.elected]
  exact s.noElection n k l i

private theorem stNo13 (s : Stable f t c) {term part node later log commit}
    (h : SolvedWitnesses.reach_13 f t c term part node later log commit) : False :=
  s.noElection _ _ _ _ h.2.1

private theorem stNo2 (s : Stable f t c) {c₁ term part node later log commit}
    (h : SolvedWitnesses.reach_2 f t c c₁ term part node later log commit) : False :=
  stNo13 s ⟨h.1, h.2.1, h.2.2.1, h.2.2.2.1⟩

private theorem stProposal (s : Stable f t c) (e : Model.Envelope)
    (fresh : Pending (f.advance t) e) (notOld : ¬ Pending f e) :
    NominationRows.proposal e.payload = true := by
  rcases c.tr.mem_network fresh with old | sent
  · exact (notOld old).elim
  · exact s.proposal e sent

private theorem stPayload (s : Stable f t c) {e : Model.Envelope} {m : Message}
    (new : SolvedWitnesses.reach_25 f t c c e) (eq : e.payload = m)
    (no : NominationRows.proposal m = false) : False := by
  have yes := stProposal s e new.1 new.2.1
  rw [eq, no] at yes
  contradiction

private theorem stNo43 (s : Stable f t c) {c₁ e}
    (h : SolvedWitnesses.reach_43 f t c c₁ e) : False := by
  have proposal := stProposal s e h.1 (fun old => h.2.2.1 ⟨old, h.2.1⟩)
  have bump := h.2.1
  cases eq : e.payload <;> simp [eq, NominationRows.proposal, Bumping] at proposal bump

private theorem stPin {u : Model.State} {tr : LocalTransition f.current u}
    (pin : u = t ∧ HEq tr c.tr) : tr.event = c.event := by
  obtain ⟨rfl, heq⟩ := pin
  cases eq_of_heq heq
  rfl

private theorem stPinIntro {u : Model.State} {tr : LocalTransition f.current u}
    (hu : u = t) (h : HEq tr c.tr) : u = t ∧ HEq tr c.tr := ⟨hu, h⟩

private theorem stEvent (s : Stable f t c) {e : Event}
    (h : e = c.event) : e = .internal .nominateSuccessor := h.trans s.event

private theorem stEventTrans {e : Event} {u : Model.State} {tr : LocalTransition f.current u}
    (h : e = tr.event) (pin : u = t ∧ HEq tr c.tr) : e = c.event := h.trans (stPin pin)

private def possible : Classes.StepBranch → Bool
  | .sorted_now_after_inl | .sorted_post_log_inl | .sorted_post_log_inr_inl
  | .sorted_post_log_inr_inr | .sorted_now_after_inr
  | .rooted_now_after_inl | .rooted_post_log_inl | .rooted_post_log_inr_inl
  | .rooted_post_log_inr_inr | .rooted_now_after_inr
  | .commitChains_step_committed_inr | .commitChains_step_backing_inl | .commitChains_step_backing_inr
  | .post_log_kind_same | .post_log_kind_append | .facts_advance_inl
  | .messages_mem_network_inr | .mem_network_mem_append_inl | .mem_network_mem_append_inr
  | .new_message_h_proposeRequestVoteRequest
  | .prefix_small_inl | .prefix_small_inr | .mem_replaceNode_here_pos | .mem_replaceNode_here_neg
  | .summary_event_internal | .summary_input_nominateSuccessor
  | .quiet_summary_either_inl | .quiet_summary_either_inr
  | .nominate_sends_successor_some | .nominate_sends_successor_none => true
  | _ => false

meta section
open Lean Meta Elab Command

private abbrev Fact := Expr × Expr
private abbrev Compile := StateRefT (Std.HashMap Name Bool) MetaM
private def certName (n : Name) (kind : String) : Name :=
  `ConsensusCoverage.DelayedNomination ++ Name.mkSimple (n.getString! ++ "_" ++ kind)
private def isReach (n : Name) : Bool :=
  n.getPrefix == `ConsensusCoverage.SolvedWitnesses && n.getString!.startsWith "reach_"
private def tryApp (n : Name) (args : Array Expr) : MetaM (Option Expr) :=
  observing? (mkAppM n args)

private def isCtor (p : Expr) : MetaM Bool := do
  let .const n _ := p.getAppFn | return false
  return (← getEnv).isConstructor n

private def contradict (ctx : Simp.Context) (facts : List Fact) : MetaM (Option Expr) := do
  let mut rules : SimpTheorems := {}
  let mut k := 0
  for (p, h) in facts do
    unless p.isAppOfArity ``Eq 3 do continue
    let l := p.getArg! 1
    let r := p.getArg! 2
    let rule ←
      if l.isFVar && !r.isFVar && !r.containsFVar l.fvarId! then pure (some h)
      else if r.isFVar && !l.isFVar && !l.containsFVar r.fvarId! then some <$> mkEqSymm h
      else if l.hasFVar && !(← isCtor l) && (← isCtor r) then pure (some h)
      else pure none
    if let some rule := rule then
      rules ← rules.add (.other ((`substRule).appendIndexAfter k)) #[] rule
      k := k + 1
  let ctx := ctx.setSimpTheorems (ctx.simpTheorems.push rules)
  let mut simple := []
  for (p, h) in facts do
    let (r, _) ← simp p ctx (simprocs := #[← Simp.getSimprocs])
    let pf ← if let some eq := r.proof? then mkEqMP eq h else pure h
    if r.expr.isConstOf ``False then return some pf
    simple := (r.expr, pf) :: simple
  for (p, h) in simple do
    if p.isAppOfArity ``Not 1 then
      if let some yes ← StutterProfile.rebuild simple p.appArg! then return some (mkApp h yes)
  return none

private def eventIndex (n : Name) : MetaM (Option Nat) := do
  forallTelescope (← getConstInfo n).type fun xs _ => do
    let mut found := none
    for i in [4:xs.size] do
      if (← inferType xs[i]!).isConstOf ``Event then
        if found.isSome then return none
        found := some i
    return found

private def hasTransition (n : Name) : MetaM Bool := do
  forallTelescope (← getConstInfo n).type fun xs _ => do
    let some last := xs.back? | return false
    return (← inferType last).isAppOf ``LocalTransition

private inductive Goal where
  | excluded
  | pinned (u tr : Expr)
  | event (e : Expr)

private def pinType (s u tr : Expr) : MetaM Expr := do
  let args := (← inferType s).getAppArgs
  let original ← mkAppM ``Ctx.tr #[args[3]!]
  return mkAnd (← mkEq u args[2]!) (← mkHEq tr original)

private def payloadConflict (s : Expr) (atoms : List Fact) : MetaM (Option Expr) := do
  for (p, h) in atoms do
    unless p.isAppOf ``SolvedWitnesses.reach_25 do continue
    let payload ← mkAppM ``CCF.Envelope.payload #[p.appArg!]
    for (q, eq) in atoms do
      unless q.isAppOfArity ``Eq 3 && q.getArg! 1 == payload do continue
      let .const (.str ns name) _ := q.appArg!.getAppFn | continue
      if ns == ``Consensus.Model.Node.Message && name != "proposeRequestVoteRequest" then
        if let some proof ← tryApp ``stPayload #[s, h, eq, ← mkEqRefl (mkConst ``Bool.false)] then
          return some proof
  return none

-- Port of the scratch certifier: split only propositional connectives, share
-- reach certificates, and use pinned transition/event facts to reject alien cases.
mutual

private partial def pinOf (s : Expr) (atoms : List Fact) (tr : Expr) : Compile (Option Expr) := do
  let u := (← whnf (← inferType tr)).appArg!
  for (p, h) in atoms do
    if p.isAppOfArity ``HEq 4 && p.getArg! 1 == tr then
      for (q, hq) in atoms do
        if q.isAppOfArity ``Eq 3 && q.getArg! 1 == u then
          if let some proof ← tryApp ``stPinIntro #[hq, h] then
            if ← isDefEq (← inferType proof) (← pinType s u tr) then return some proof
    if let .const n us := p.getAppFn then
      if isReach n && p.appArg! == tr && (← hasTransition n) then
        if ← certify n "pinned" then
          return some (mkAppN (mkConst (certName n "pinned") us) (p.getAppArgs ++ #[s, h]))
  return none

private partial def eventOf (s : Expr) (atoms : List Fact) (e : Expr) : Compile (Option Expr) := do
  let c := (← inferType s).getAppArgs[3]!
  let event ← mkAppM ``Ctx.event #[c]
  for (p, h) in atoms do
    if p.isAppOfArity ``Eq 3 && p.getArg! 1 == e then
      let rhs := p.appArg!
      if rhs == event then return some h
      if rhs.isAppOf ``LocalTransition.event then
        if let some pin ← pinOf s atoms rhs.appArg! then
          return some (← mkAppM ``stEventTrans #[h, pin])
    if let .const n us := p.getAppFn then
      if isReach n then
        if let some i ← eventIndex n then
          if p.getAppArgs[i]! == e && (← certify n "event") then
            return some (mkAppN (mkConst (certName n "event") us) (p.getAppArgs ++ #[s, h]))
  return none

private partial def eventConflict (s : Expr) (atoms : List Fact) : Compile (Option Expr) := do
  for (q, eq) in atoms do
    unless q.isAppOfArity ``Eq 3 && (q.getArg! 0).isConstOf ``Event do continue
    let rhs := q.appArg!
    unless rhs.isAppOf ``Event.receive || rhs.isAppOf ``Event.internal do continue
    let some same ← eventOf s atoms (q.getArg! 1) | continue
    let nom ← mkAppM ``stEvent #[s, same]
    if rhs.isAppOf ``Event.receive then return some (← mkAppM ``NominationRows.notReceive #[nom, eq])
    for (r, hi) in atoms do
      unless r.isAppOfArity ``Eq 3 && r.getArg! 1 == rhs.appArg! do continue
      let .const (.str ns name) _ := r.appArg!.getAppFn | continue
      if ns == ``Input && name != "nominateSuccessor" then
        return some (← mkAppM ``NominationRows.notInput #[nom, eq, hi, ← mkEqRefl (mkConst ``Bool.false)])
  return none

private partial def solve (ctx : Simp.Context) (s : Expr) (goal : Goal) (ty : Expr)
    (todo : List Fact) (atoms : List Fact := []) (unfolds : Nat := 2) : Compile (Option Expr) := do
  let (p, h) :: rest := todo |
    match goal with
    | .pinned _ tr => if let some pf ← pinOf s atoms tr then return some pf
    | .event e => if let some pf ← eventOf s atoms e then return some pf
    | .excluded => pure ()
    let contradiction ← eventConflict s atoms
    let contradiction ← if contradiction.isSome then pure contradiction else payloadConflict s atoms
    let contradiction ← if contradiction.isSome then pure contradiction
      else liftM (contradict ctx atoms)
    contradiction.mapM fun pf => liftM (mkFalseElim ty pf)
  if p.isAppOfArity ``Wins 4 then
    if let some pf ← tryApp ``stNoWins #[s] then
      if ← isDefEq (← inferType pf).appArg! p then return some (← mkFalseElim ty (mkApp pf h))
  if p.isAppOfArity ``LogFacts.Ghost.elected 5 then
    let args := p.getAppArgs
    for lemma in [``Stable.noElection, ``stNoElection] do
      let pf ← mkAppM lemma #[s, args[1]!, args[2]!, args[3]!, args[4]!]
      if ← isDefEq (← inferType pf).appArg! p then return some (← mkFalseElim ty (mkApp pf h))
  if p.isAppOfArity ``SolvedWitnesses.reach_2 11 then
    return some (← mkFalseElim ty (← mkAppM ``stNo2 #[s, h]))
  if p.isAppOfArity ``SolvedWitnesses.reach_13 10 then
    return some (← mkFalseElim ty (← mkAppM ``stNo13 #[s, h]))
  if p.isAppOf ``SolvedWitnesses.reach_43 then
    return some (← mkFalseElim ty (← mkAppM ``stNo43 #[s, h]))
  if let .const n us := p.getAppFn then
    if isReach n then
      if ← certify n "excluded" then
        let pf := mkAppN (mkConst (certName n "excluded") us) (p.getAppArgs ++ #[s, h])
        return some (← mkFalseElim ty pf)
      if unfolds > 0 then
        let body := ((← getConstInfo n).instantiateValueLevelParams! us).beta p.getAppArgs
        return ← solve ctx s goal ty ((body, ← mkExpectedTypeHint h body) :: rest) ((p, h) :: atoms) (unfolds - 1)
  if p.isAppOfArity ``And 2 then
    return ← solve ctx s goal ty
      ((p.getArg! 0, ← mkAppM ``And.left #[h]) :: (p.getArg! 1, ← mkAppM ``And.right #[h]) :: rest) atoms unfolds
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `h q fun hq => do
      let some result ← solve ctx s goal ty ((q, hq) :: rest) atoms unfolds | return none
      return some (← mkLambdaFVars #[hq] result)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (← mkAppOptM ``Or.elim #[p.getArg! 0, p.getArg! 1, ty, h, l, r])
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := p.appArg!.beta #[w]
      withLocalDeclD `h q fun hq => do
        let rest := if ← isProp (p.getArg! 0) then (p.getArg! 0, w) :: rest else rest
        let some result ← solve ctx s goal ty ((q, hq) :: rest) atoms unfolds | return none
        return some (← mkAppOptM ``Exists.elim #[p.getArg! 0, p.getArg! 1, ty, h,
          ← mkLambdaFVars #[w, hq] result])
  solve ctx s goal ty rest ((p, h) :: atoms) unfolds

private partial def certify (n : Name) (kind : String) : Compile Bool := do
  let key := certName n kind
  if let some done := (← get)[key]? then return done
  modify (·.insert key false)
  let ci ← getConstInfo n
  let result ← lambdaTelescope ci.value! fun xs p => do
    let ps := xs.extract 0 4
    withLocalDeclD `stable (mkAppN (mkConst ``Stable) ps) fun s => do
      let info : Option (Goal × Expr) ← match kind with
        | "excluded" => pure (some (.excluded, mkConst ``False))
        | "pinned" =>
          if xs.size < 6 then pure none else
          let u := xs[xs.size - 2]!
          let tr := xs.back!
          pure (some (.pinned u tr, ← pinType s u tr))
        | _ => do
          let some i ← eventIndex n | pure none
          pure (some (.event xs[i]!, ← mkEq xs[i]! (← mkAppM ``Ctx.event #[ps[3]!])))
      let some (goal, ty) := info | return false
      let mut rules : SimpTheorems := {}
      rules ← rules.addConst ``Nat.lt_irrefl
      for name in #[``Committed, ``Canon, ``Elected, ``Granted, ``Bumping] do
        rules ← rules.addDeclToUnfold name
      let mut eqs := #[]
      for lem in #[``Stable.seen, ``Stable.grant, ``Stable.elected, ``Stable.canon, ``Stable.event,
          ``Stable.post, ``stNow, ``stSeen, ``stLed, ``stGhostLed, ``stCanonNow, ``stCommit, ``stRole] do
        eqs := eqs.push (← mkAppOptM lem (ps.map some |>.push (some s)))
      for i in [:eqs.size] do
        rules ← rules.add (.other ((`stableRewrite).appendIndexAfter i)) #[] eqs[i]!
      let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
      let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
      withLocalDeclD `h pred fun h => do
        let some proof ← solve ctx s goal ty [(p, ← mkExpectedTypeHint h p)] | return false
        addDecl (.thmDecl {
          name := key, levelParams := ci.levelParams,
          type := ← mkForallFVars (xs.push s) (← mkArrow pred ty),
          value := ← mkLambdaFVars (xs ++ #[s, h]) (← instantiateMVars proof) })
        return true
  modify (·.insert key result)
  return result

end

private def buildPruner : MetaM Unit := do
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope ci.value! fun xs body => do
    let bs := body.getAppArgs.extract 2 body.getAppNumArgs
    let ps := xs.extract 0 4
    unless bs.size == branch.ctors.length && body.isAppOf ``Classes.StepBranch.casesOn &&
        bs.all (fun a => a.getAppArgs == ps) do throwError "unexpected normalized dispatcher"
    let b := xs[4]!
    withLocalDeclD `stable (mkAppN (mkConst ``Stable) ps) fun s => do
      let motive ← withLocalDeclD `b (mkConst ``Classes.StepBranch) fun q => do
        let out ← mkEq (mkApp (mkConst ``possible) q) (mkConst ``Bool.true)
        mkLambdaFVars #[q] (← mkArrow (mkAppN (mkConst ci.name) (ps.push q)) out)
      let one (arm : Expr) (name : Name) : Compile Expr :=
        withLocalDeclD `h arm fun h => do
          let selected := mkApp (mkConst ``possible) (mkConst name)
          let out ← mkEq selected (mkConst ``Bool.true)
          let pf ← if ← withTransparency .all (isDefEq selected (mkConst ``Bool.true)) then
            mkEqRefl (mkConst ``Bool.true)
          else
            let n := arm.getAppFn.constName!
            unless ← certify n "excluded" do throwError "unproved delayed nomination exclusion: {name}"
            mkFalseElim out (mkAppN (mkConst (certName n "excluded")) (ps ++ #[s, h]))
          mkLambdaFVars #[h] pf
      let (arms, _) ← (bs.zipWithM one branch.ctors.toArray).run {}
      addDecl (.thmDecl {
        name := `ConsensusCoverage.DelayedNomination.possible_of_sig, levelParams := [],
        type := ← mkForallFVars (xs.push s) (motive.beta #[b]),
        value := ← mkLambdaFVars (xs.push s)
          (mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero]) (#[motive, b] ++ arms)) })

run_cmd liftTermElabM buildPruner

end

end ConsensusCoverage.DelayedNomination

#print axioms ConsensusCoverage.DelayedNomination.possible_of_sig
