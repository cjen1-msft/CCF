module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public meta import ConsensusCoverage.EventSupport
public import ConsensusCoverage.ReducedQuestions
public import ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.NominationRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open FullProfile ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192
set_option maxHeartbeats 0

private def proposal : Message → Bool
  | .proposeRequestVoteRequest _ => true
  | _ => false

private structure Stable [Config.InitialConfiguration] (f : Frame) (t : Model.State) (c : Ctx f t) : Prop where
  nodes : t.nodes = f.current.nodes
  logs : (f.advance t).logs = f.logs
  only : ∀ e, Pending (f.advance t) e → ¬ Pending f e → proposal e.payload = true
  event : c.event = .internal .nominateSuccessor

private theorem oldNow [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c : Ctx f t} (stable : Stable f t c) : Now (f.advance t) = Now f := by
  funext n st
  change ((n, st) ∈ t.nodes) = ((n, st) ∈ f.current.nodes)
  rw [stable.nodes]

private theorem payload26 [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c w : Ctx f t} {e : Model.Envelope} (stable : Stable f t c)
    (reach : SolvedWitnesses.reach_26 f t c w e) {m : Message}
    (eq : e.payload = m) (no : proposal m = false) : False := by
  have yes := stable.only e reach.1.1 reach.1.2.1
  simp_all

private theorem no43 [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c w : Ctx f t} {e : Model.Envelope} (stable : Stable f t c)
    (h : SolvedWitnesses.reach_43 f t c w e) : False := by
  obtain ⟨pending, bumps, notOld, _⟩ := h
  have yes := stable.only e pending (fun old => notOld ⟨old, bumps⟩)
  cases eq : e.payload <;> simp_all [proposal, Bumping]

private theorem event434 [Config.InitialConfiguration] {f : Frame} {t u : Model.State}
    {c : Ctx f t} {tr : LocalTransition f.current u} (stable : Stable f t c)
    (h : SolvedWitnesses.reach_434 f t c u tr) : tr.event = .internal .nominateSuccessor := by
  obtain ⟨_, rfl, heq⟩ := h
  cases eq_of_heq heq
  exact stable.event

private theorem event463 [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {n st e} (s : Stable f t c) (h : SolvedWitnesses.reach_463 f t c n st e) :
    e = .internal .nominateSuccessor := by
  obtain ⟨_, _, h, _, _, rfl⟩ := h
  exact event434 s h

private theorem event1307 [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {e} (s : Stable f t c) (h : SolvedWitnesses.reach_1307 f t c e) :
    e = .internal .nominateSuccessor := by
  obtain ⟨_, _, h, rfl⟩ := h
  exact event434 s h

private theorem event1457 [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {st e} (s : Stable f t c) (h : SolvedWitnesses.reach_1457 f t c st e) :
    e = .internal .nominateSuccessor := by
  obtain ⟨_, _, h, _, rfl⟩ := h
  exact event434 s h

private def isNom : Input → Bool | .nominateSuccessor => true | _ => false

private theorem notReceive {e : Event} {src m} (h : e = .internal .nominateSuccessor)
    (receive : e = .receive src m) : False := by simp_all

private theorem notInput {e : Event} {i j : Input} (h : e = .internal .nominateSuccessor)
    (input : e = .internal i) (eq : i = j) (no : isNom j = false) : False := by
  subst e j
  cases input
  contradiction

private def possible : Classes.StepBranch → Bool
  | .messages_mem_network_inr | .mem_network_mem_append_inl | .mem_network_mem_append_inr
  | .new_message_h_proposeRequestVoteRequest | .summary_event_internal | .summary_input_nominateSuccessor
  | .quiet_summary_either_inl | .quiet_summary_either_inr
  | .nominate_sends_successor_some | .nominate_sends_successor_none => true
  | _ => false

meta section
open Lean Meta Elab Command

private abbrev Gen := StateRefT (Std.HashMap Name Bool) MetaM
private abbrev Fact := Expr × Expr
private def cert (n : Name) := `ConsensusCoverage.NominationRows ++ Name.mkSimple (n.getString! ++ "_excluded")

private def eventConflict (stable : Expr) (atoms : List Fact) : MetaM (Option Expr) := do
  for (p, h) in atoms do
    let some n := p.getAppFn.constName? | continue
    let some lem := [( ``SolvedWitnesses.reach_463, ``event463),
        (``SolvedWitnesses.reach_1307, ``event1307), (``SolvedWitnesses.reach_1457, ``event1457)].lookup n | continue
    let nom ← mkAppM lem #[stable, h]
    for (q, eq) in atoms do
      unless q.isAppOfArity ``Eq 3 && q.getArg! 1 == p.appArg! do continue
      let rhs := q.appArg!
      if rhs.isAppOf ``Event.receive then return some (← mkAppM ``notReceive #[nom, eq])
      unless rhs.isAppOf ``Event.internal do continue
      let i := rhs.appArg!
      for (r, hi) in atoms do
        unless r.isAppOfArity ``Eq 3 && r.getArg! 1 == i do continue
        let .const (.str ns name) _ := r.appArg!.getAppFn | continue
        if ns == ``Input && name != "nominateSuccessor" then
          return some (← mkAppM ``notInput #[nom, eq, hi, ← mkEqRefl (mkConst ``Bool.false)])
  return none

mutual

private partial def deny (ctx : Simp.Context) (stable : Expr) (todo : List Fact)
    (packets shapes atoms : List Fact := []) :
    Gen (Option Expr) := do
  let (p, h) :: rest := todo |
    for (e, reach) in packets do
      for (lhs, eq) in shapes do
        let payload ← mkAppM ``CCF.Envelope.payload #[e]
        if lhs == payload then
          return some (← mkAppM ``payload26 #[stable, reach, eq, ← mkEqRefl (mkConst ``Bool.false)])
    if let some proof ← eventConflict stable atoms then return some proof
    StutterProfile.contradictionFrom ctx atoms
  if let .const n us := p.getAppFn then
    if n.getPrefix == `ConsensusCoverage.SolvedWitnesses && n.getString!.startsWith "reach_" then
      if n == ``SolvedWitnesses.reach_43 then return some (← mkAppM ``no43 #[stable, h])
      if n == ``SolvedWitnesses.reach_26 then return ← deny ctx stable rest ((p.appArg!, h) :: packets) shapes atoms
      if ← certify n then return some (mkAppN (mkConst (cert n) us) (p.getAppArgs ++ #[stable, h]))
  if p.isAppOfArity ``Eq 3 then
    let rhs := p.getArg! 2
    if let .const (.str ns name) _ := rhs.getAppFn then
      if ns == ``Consensus.Model.Node.Message && name != "proposeRequestVoteRequest" then
        return ← deny ctx stable rest packets ((p.getArg! 1, h) :: shapes) ((p, h) :: atoms)
  if p.isAppOfArity ``And 2 then
    return ← deny ctx stable ((p.getArg! 0, ← mkAppM ``And.left #[h]) ::
      (p.getArg! 1, ← mkAppM ``And.right #[h]) :: rest) packets shapes atoms
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `arm q fun hq => do
      let some result ← deny ctx stable ((q, hq) :: rest) packets shapes atoms | return none
      return some (← mkLambdaFVars #[hq] result)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (← mkAppM ``Or.elim #[h, l, r])
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `x (p.getArg! 0) fun x => do
      let q := p.appArg!.beta #[x]
      withLocalDeclD `hx q fun hx => do
        let some r ← deny ctx stable ((q, hx) :: rest) packets shapes atoms | return none
        return some (← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[x, hx] r])
  deny ctx stable rest packets shapes ((p, h) :: atoms)

private partial def certify (n : Name) : Gen Bool := do
  if let some ok := (← get)[n]? then return ok
  let ci ← getConstInfo n
  let ok ← lambdaTelescope ci.value! fun xs p => do
    let params := xs.extract 0 3
    let ls := ci.levelParams.map mkLevelParam
    let pred := mkAppN (mkConst n ls) xs
    withLocalDeclD `stable (mkAppN (mkConst ``Stable) (xs.extract 0 4)) fun stable => do
      withLocalDeclD `h pred fun h => do
        let mut rules : SimpTheorems := {}
        for name in #[``Committed, ``Canon, ``Elected, ``Granted] do
          rules ← rules.addDeclToUnfold name
        let logs := mkProj ``Stable 1 stable
        let eqs := #[← mkAppM ``oldNow #[stable], mkAppN (mkConst ``StutterProfile.seen_eq) (params.push logs),
          mkAppN (mkConst ``StutterProfile.led_eq) (params.push logs), logs]
        for i in [:eqs.size] do
          rules ← rules.add (.other ((`stableRewrite).appendIndexAfter i)) #[] eqs[i]!
        let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
        let result ← deny ctx stable [(p, h)]
        let some proof := result | return false
        addDecl (.thmDecl {
          name := cert n, levelParams := ci.levelParams,
          type := ← mkForallFVars (xs.push stable) (← mkArrow pred (mkConst ``False)),
          value := ← mkLambdaFVars (xs ++ #[stable, h]) proof})
        return true
  modify (·.insert n ok)
  return ok

end

private def compile : MetaM Unit := do
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope ci.value! fun xs body => do
    let bs := body.getAppArgs.extract 2 body.getAppNumArgs
    let ps := xs.extract 0 4
    let b := xs[4]!
    unless bs.size == branch.ctors.length && body.isAppOf ``Classes.StepBranch.casesOn &&
        bs.all (fun a => a.getAppArgs == ps) do throwError "unexpected normalized dispatcher"
    withLocalDeclD `stable (mkAppN (mkConst ``Stable) ps) fun stable => do
      let motive ← withLocalDeclD `b (mkConst ``Classes.StepBranch) fun q => do
        let out ← mkEq (mkApp (mkConst ``possible) q) (mkConst ``Bool.true)
        mkLambdaFVars #[q] (← mkArrow (mkAppN (mkConst ci.name) (ps.push q)) out)
      let one (arm : Expr) (name : Name) : Gen Expr := do
        let n := arm.getAppFn.constName!
        withLocalDeclD `h arm fun h => do
          let out ← mkEq (mkApp (mkConst ``possible) (mkConst name)) (mkConst ``Bool.true)
          let pf ← if ← certify n then mkFalseElim out (mkAppN (mkConst (cert n)) (ps ++ #[stable, h]))
            else mkEqRefl (mkConst ``Bool.true)
          mkLambdaFVars #[h] pf
      let (arms, _) ← (bs.zipWithM one branch.ctors.toArray).run {}
      addDecl (.thmDecl {
        name := `ConsensusCoverage.NominationRows.possible_of_sig, levelParams := [],
        type := ← mkForallFVars (xs.push stable) (motive.beta #[b]),
        value := ← mkLambdaFVars (xs.push stable)
          (mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero]) (#[motive, b] ++ arms)) })

end

local elab "prune_nomination" : command => Lean.Elab.Command.liftTermElabM compile
prune_nomination

/-- Observable sufficient conditions for a nomination sending a new proposal:
the node records do not change by the protocol rule; the log evidence must
separately be shown stable. A repeated queued proposal fails the message test. -/
@[expose] public def test (cfg : FullProfile.Configuration) (s : Model.State) (a : Model.Action) (t : Model.State)
    (past : List Model.State) : Bool :=
  decide (EventSupport.actionTag a = .nominateSuccessor) && SignedQuiet.evidence cfg s t past &&
    ReducedQuestions.answer s t .message

private theorem from_test (s : Step) (passes : test s.cfg s.before s.act s.after s.past = true) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Stable s.frame s.after s.context ∧ s.context.post = s.context.pre ∧
      ∃ e ∈ s.context.sent, ¬ Pending s.frame e := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  obtain ⟨⟨tag, evidence⟩, message⟩ := show
      (EventSupport.actionTag s.act = .nominateSuccessor ∧ SignedQuiet.evidence s.cfg s.before s.after s.past = true)
      ∧ ReducedQuestions.answer s.before s.after .message = true by simpa [test] using passes
  have action : ActionContext.action c = s.act := (s.context_eq c).mpr rfl
  rw [← action, EventSupport.actionTag_eq] at tag
  have event : c.event = .internal .nominateSuccessor := by
    cases h : c.event with
    | internal i => cases i <;> first | rfl | simp [show c.tr.event = _ from h, EventSupport.eventTag, EventSupport.inputTag] at tag
    | receive src m => cases m <;> simp [show c.tr.event = _ from h, EventSupport.eventTag, EventSupport.messageTag] at tag
  have ran := c.tr.ran
  change ((Model.Node.step _ _ _ c.event).run {}) = _ at ran
  rw [event] at ran
  obtain ⟨sentList, outgoing, same, _, allSent⟩ := nominate_sends c.actor c.pre _ _ _ ran
  change c.tr.outputs.outgoing = [] ++ sentList at outgoing
  have nodes : s.after.nodes = (current s.frame).nodes := by
    rw [c.tr.nodesEq, same]
    exact InertProfile.replace_eq c.inv.distinct c.tr.found
  have logs := SignedQuiet.stable s (nodes.trans (congrArg (fun x : Model.State => x.nodes) s.current_eq)) evidence
  have sig := (ReducedQuestions.answer_iff s .message).mp message
  obtain ⟨e, sent, fresh, _⟩ := (ReducedQuestions.freshSend_iff ..).mp ((ReducedQuestions.messages_iff c).mp sig)
  refine ⟨⟨nodes, logs, ?_, event⟩, same, e, sent, fresh⟩
  intro e pending new
  rcases c.tr.mem_network pending with old | sent
  · exact (new old).elim
  · rw [(allSent e (outgoing ▸ sent : e ∈ [] ++ sentList)).2]
    rfl

public theorem excluded (s : Step) (passes : test s.cfg s.before s.act s.after s.past = true)
    (b : Classes.StepBranch) (out : possible b = false) : label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_false_iff.mpr
  intro yes
  have h := (SolvedWitnesses.sig_iff s.context b).mp ((label_true s _).mp yes)
  exact Bool.noConfusion (out.symm.trans (possible_of_sig _ _ _ _ (from_test s passes).1 h))

end ConsensusCoverage.NominationRows
