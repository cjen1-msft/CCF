module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.DeltaSupport
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.FrontierRows
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! Specialize the generated proof questions for the first empty AppendEntries
send between the two initial voters. Use the same initialized run as the
predecessor of `InertProfile.duplicate_heartbeat_witness`. -/

namespace ConsensusCoverage.FreshHeartbeat

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open FullProfile ActionProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- The first real send, before there is an envelope to duplicate. -/
public def witness : Step :=
  ⟨InertProfile.cfg, InertProfile.nodes, InertProfile.initial, [], InertProfile.send, InertProfile.queued,
    .initial InertProfile.initialized, (Option.some_get _).symm⟩

private theorem sameNodes : witness.after.nodes = witness.before.nodes :=
  (InertProfile.send_shape witness.run witness.ran rfl rfl).1

private theorem stableLogs : @StutterProfile.StableLogs ⟨witness.cfg⟩ witness.frame witness.after :=
  StutterProfile.step_stable_of_nodes witness sameNodes (StutterProfile.unsigned_check (by decide +kernel))

local instance : Config.InitialConfiguration := ⟨InertProfile.cfg⟩

private abbrev primary := initialNodeState InertProfile.cfg 0
private abbrev request : AppendEntriesRequest := ⟨BOOTSTRAP_TERM, 0, 0, [], 0⟩
private abbrev heartbeat : Model.Envelope := ⟨0, 1, .appendEntriesRequest request⟩
private def outputs : Outputs NodeID Message Notification := { outgoing := [heartbeat] }

private theorem send_result :
    (Model.Node.step (Capabilities.record 0) 0 primary (.internal (.sendEntries 1 0))).run {} =
      some (primary, outputs) := by
  have update : CCF.Function.update primary.sentIndex 1 0 = primary.sentIndex :=
    CCF.Function.update_eq_self _ _
  exact (show _ = some ({primary with sentIndex := CCF.Function.update primary.sentIndex 1 0}, outputs)
    from rfl).trans (congrArg (fun sentIndex => some ({primary with sentIndex}, outputs)) update)

private def concrete : Ctx witness.frame witness.after where
  tr := ⟨0, primary, primary, .internal (.sendEntries 1 0), outputs, [], rfl, send_result,
    sameNodes.trans (InertProfile.replace_eq (by decide +kernel) rfl).symm,
    rfl, by simp, .inl ⟨_, rfl, rfl⟩, by intro _ h; cases h⟩
  inv := witness.folded.invariant

private theorem concrete_context : concrete = witness.context :=
  (witness.context_eq concrete).mp rfl

private theorem now_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : t.nodes = f.current.nodes) : Now (f.advance t) = Now f := by
  funext n st
  change ((n, st) ∈ t.nodes) = ((n, st) ∈ f.current.nodes)
  rw [h]

private theorem old_pending (e : Model.Envelope) : ¬ Pending witness.frame e := by
  change e ∉ ([] : List Model.Envelope)
  simp

private theorem new_pending (e : Model.Envelope) :
    Pending (witness.frame.advance witness.after) e ↔ e = heartbeat := by
  change e ∈ [heartbeat] ↔ _
  simp

private theorem outgoing (e : Model.Envelope) : e ∈ concrete.tr.outputs.outgoing ↔ e = heartbeat := by
  change e ∈ [heartbeat] ↔ _
  simp

private theorem guard_false {P : Prop} : false = true → ¬P := by simp

meta section

open Lean Meta Elab Command

private abbrev Gen := StateRefT (Std.HashMap Name Bool) MetaM
private abbrev Fact := Expr × Expr

private def certName (n : Name) : Name :=
  `ConsensusCoverage.FreshHeartbeat ++ Name.mkSimple (n.getString! ++ "_stable_core")

mutual

/-- Eliminate conjunctions, disjunctions and existentials without unfolding
arbitrary atoms. In contrast to the stutter compiler, leave queued-envelope
newness untouched. Reuse its newness contradiction check at the leaves. -/
private partial def refute (ctx : Simp.Context) (nodes logs : Expr)
    (todo : List Fact) (atoms : List Fact := []) : Gen (Option Expr) := do
  let (p, h) :: rest := todo | StutterProfile.contradictionFrom ctx atoms
  if let some n := StutterProfile.reachName? p then
    if ← certify n then
      let .const _ us := p.getAppFn | throwError "expected constant"
      return some (mkAppN (mkConst (certName n) us) (p.getAppArgs ++ #[nodes, logs, h]))
  if p.isAppOfArity ``And 2 then
    return ← refute ctx nodes logs
      ((p.getArg! 0, ← mkAppM ``And.left #[h]) :: (p.getArg! 1, ← mkAppM ``And.right #[h]) :: rest) atoms
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `h q fun hq => do
      let some result ← refute ctx nodes logs ((q, hq) :: rest) atoms | return none
      return some (← mkLambdaFVars #[hq] result)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (← mkAppM ``Or.elim #[h, l, r])
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := (p.getArg! 1).beta #[w]
      withLocalDeclD `h q fun hq => do
        let some result ← refute ctx nodes logs ((q, hq) :: rest) atoms | return none
        return some (← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hq] result])
  refute ctx nodes logs rest ((p, h) :: atoms)

private partial def certify (n : Name) : Gen Bool := do
  if let some done := (← get)[n]? then return done
  let .defnInfo ci ← getConstInfo n | throwError "expected predicate {n}"
  let result ← lambdaTelescope ci.value fun xs p => do
    let inst := xs[0]!
    let f := xs[1]!
    let t := xs[2]!
    let current := mkApp (mkConst ``Frame.current) f
    let next := mkAppN (mkConst ``Frame.advance) #[inst, f, t]
    let nodesOf (s : Expr) := mkProj ``CCF.MultiNodeTransitionSystem.State 0 s
    withLocalDeclD `nodes (← mkEq (nodesOf t) (nodesOf current)) fun nodes => do
      let project (x : Expr) := mkApp (mkConst ``Frame.logs) x
      withLocalDeclD `logs (← mkEq (project next) (project f)) fun logs => do
        let mut rules : SimpTheorems := {}
        for name in #[``Committed, ``Canon, ``Elected, ``Granted] do
          rules ← rules.addDeclToUnfold name
        let rewrites := #[
          mkAppN (mkConst ``now_eq) #[inst, f, t, nodes],
          mkAppN (mkConst ``StutterProfile.seen_eq) #[inst, f, t, logs],
          mkAppN (mkConst ``StutterProfile.led_eq) #[inst, f, t, logs], logs]
        for i in [:rewrites.size] do
          rules ← rules.add (.other ((`heartbeatRewrite).appendIndexAfter i)) #[] rewrites[i]!
        let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
        withLocalDeclD `h p fun h => do
          let some proof ← refute ctx nodes logs [(p, h)] | return false
          let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
          let type ← mkForallFVars (xs ++ #[nodes, logs]) (← mkArrow pred (mkConst ``False))
          let value ← mkLambdaFVars (xs ++ #[nodes, logs, h]) proof
          addDecl (.thmDecl { name := certName n, levelParams := ci.levelParams, type, value })
          return true
  modify fun m => m.insert n result
  return result

end

private def compile : MetaM Unit := do
  let .defnInfo ci ← getConstInfo ``PinnedClasses.dispatch | throwError "expected pinned dispatcher"
  let branch ← getConstInfoInduct ``Classes.StepBranch
  lambdaTelescope ci.value fun xs body => do
    let params := xs.extract 0 4
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "unexpected pinned dispatcher"
    let arms := args.extract 2 args.size
    let (results, _) ← (arms.mapM fun arm => do
      let .const n us := arm.getAppFn | throwError "unexpected dispatcher arm {arm}"
      unless n.getPrefix == `ConsensusCoverage.PinnedClasses && n.getString!.startsWith "step_" &&
          arm.getAppArgs == params do
        throwError "unexpected dispatcher arm {arm}"
      return (← certify n, mkAppN (mkConst (certName n) us) params) : Gen _).run {}
    let b := xs[4]!
    let caseFn u := mkConst ``Classes.StepBranch.casesOn [u]
    let table := `ConsensusCoverage.FreshHeartbeat.coreExcluded
    let decl := Declaration.defnDecl {
      name := table, levelParams := [], type := ← mkForallFVars #[b] (mkConst ``Bool)
      value := ← mkLambdaFVars #[b] (mkAppN (caseFn (.succ .zero))
        (#[← mkLambdaFVars #[b] (mkConst ``Bool), b] ++
          results.map fun (ok, _) => mkConst (if ok then ``Bool.true else ``Bool.false)))
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let f := params[1]!
    let t := params[2]!
    let current := mkApp (mkConst ``Frame.current) f
    let next := mkAppN (mkConst ``Frame.advance) (params.extract 0 3)
    let nodes (s : Expr) := mkProj ``CCF.MultiNodeTransitionSystem.State 0 s
    let logs (x : Expr) := mkApp (mkConst ``Frame.logs) x
    withLocalDeclD `nodes (← mkEq (nodes t) (nodes current)) fun same => do
      withLocalDeclD `logs (← mkEq (logs next) (logs f)) fun stable => do
        let typeAt (b : Expr) := do
          let pred := mkAppN (mkConst ``PinnedClasses.dispatch) (params.push b)
          let excluded ← mkEq (mkApp (mkConst table) b) (mkConst ``Bool.true)
          mkArrow excluded (← mkArrow pred (mkConst ``False))
        let types ← mkForallFVars (xs ++ #[same, stable]) (← typeAt b)
        let motive ← withLocalDeclD `b (mkConst ``Classes.StepBranch) fun q => do
          mkLambdaFVars #[q] (← typeAt q)
        let proofs ← results.zipWithM (fun (ok, cert) arm => do
          if ok then
            withLocalDeclD `excluded (← mkEq (mkConst ``Bool.true) (mkConst ``Bool.true)) fun h =>
              mkLambdaFVars #[h] (mkApp2 cert same stable)
          else
            mkAppOptM ``guard_false #[some arm]) arms
        let value ← mkLambdaFVars (xs ++ #[same, stable])
          (mkAppN (caseFn .zero) (#[motive, b] ++ proofs))
        addDecl (.thmDecl {
          name := `ConsensusCoverage.FreshHeartbeat.dispatch_excluded
          levelParams := ci.levelParams, type := types, value })
    let live := (branch.ctors.zip results.toList).filterMap fun (ctor, (ok, _)) =>
      if ok then none else some ctor.getString!
    logInfo m!"heartbeat: {arms.size - live.length}/{arms.size} excluded by unchanged nodes/log evidence"

end

local elab "specialize_heartbeat" : command => Lean.Elab.Command.liftTermElabM compile
specialize_heartbeat

set_option maxHeartbeats 1500000

private theorem core_negative (b : Classes.StepBranch) (h : coreExcluded b = true) :
    label witness (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨witness.cfg⟩
  apply Bool.eq_false_iff.mpr
  intro yes
  have known : @PinnedClasses.sig ⟨witness.cfg⟩ witness.frame witness.after witness.context b :=
    (label_true witness (.step b)).mp yes
  have nodes : witness.after.nodes = (FullProfile.current witness.frame).nodes :=
    sameNodes.trans (congrArg (fun t : Model.State => t.nodes) witness.current_eq).symm
  exact @dispatch_excluded ⟨witness.cfg⟩ witness.frame witness.after witness.context b nodes stableLogs h known

/-- The first request also enters the incumbent-leader arm of `post_led`;
the positive profile is not exhausted by the queue reader's answers. -/
public theorem incumbent_send :
    label witness (.step .post_led_origin_inl) = true := by
  apply (label_true _ _).mpr
  change PinnedClasses.sig witness.context .post_led_origin_inl
  rw [← concrete_context]
  apply (SolvedWitnesses.sig_iff _ _).mpr
  change SolvedWitnesses.step_post_led_origin_inl witness.frame witness.after concrete
  have stay : concrete.pre.role = .primary ∧ concrete.post.currentTerm = concrete.pre.currentTerm :=
    ⟨rfl, rfl⟩
  have candidate : concrete.post.role ≠ .candidate := by decide +kernel
  have ok : AEOk concrete.actor heartbeat.target concrete.post request :=
    ⟨by decide +kernel, rfl, by decide +kernel, rfl, List.nil_prefix, by decide +kernel⟩
  have mem := (new_pending heartbeat).mpr rfl
  have sent := (outgoing heartbeat).mpr rfl
  have root : SolvedWitnesses.reach_26 witness.frame witness.after concrete concrete heartbeat :=
    ⟨⟨mem, old_pending heartbeat, rfl⟩, sent, mem, rfl⟩
  refine ⟨?_, stay, stay.1, stay.2, .inl stay⟩
  exact ⟨heartbeat, root, rfl, ⟨ok, candidate, .inl stay⟩,
    request, rfl, rfl, ok, ⟨candidate, .inl stay⟩, candidate, .inl stay, ok.1,
    ok.2, ok.2.1, ok.2.2, ok.2.2.1, ok.2.2.2, ok.2.2.2.1, ok.2.2.2.2,
    ok.2.2.2.2.1, ok.2.2.2.2.2, sent, rfl⟩

private def evidence : ReplayAnswers.Evidence :=
  ReplayAnswers.read witness.cfg witness.before witness.act witness.after witness.past

/-- Read the certified columns, including both endpoints. A residual bit is
`none`, not a negative answer. -/
public def read? (q : Question) : Option Bool :=
  match q with
  | .step b => if b = .post_led_origin_inl then some true
    else if coreExcluded b then some false else ReplayAnswers.answer evidence q
  | _ => ReplayAnswers.answer evidence q

public theorem read_sound (q : Question) {v : Bool} (h : read? q = some v) :
    label witness q = v := by
  cases q with
  | pre b => exact ReplayAnswers.sound witness _ h
  | post b => exact ReplayAnswers.sound witness _ h
  | step b =>
    change (if b = .post_led_origin_inl then some true else
      if coreExcluded b then some false else ReplayAnswers.answer evidence (.step b)) = some v at h
    split at h
    · subst b
      exact incumbent_send.trans (Option.some.inj h)
    · split at h
      · exact (core_negative b (by assumption)).trans (Option.some.inj h)
      · exact ReplayAnswers.sound witness _ h

private theorem mem_universe (b : Classes.StepBranch) : b ∈ stepBranches.toList := by
  rw [← step_get b]
  exact Array.getElem_mem_toList ..

/-- Exhaustive residual list, in the generated dispatcher order. -/
@[expose] public def residual : List Classes.StepBranch :=
  stepBranches.toList.filter fun b => (read? (.step b)).isNone

/-- All positively certified columns, in the same order. -/
@[expose] public def positives : List Classes.StepBranch :=
  stepBranches.toList.filter fun b => read? (.step b) == some true

public theorem positives_eq : positives =
    [.messages_mem_network_inr, .message_terms_mem_network_inr, .message_terms_h_appendEntriesRequest,
      .mem_network_mem_append_inr, .new_message_h_appendEntriesRequest, .post_led_origin_inl] :=
  by decide +kernel

public theorem counts :
    stepBranches.size = 433 ∧ residual.length = 118 ∧ positives.length = 6 ∧
      (stepBranches.toList.filter fun b => read? (.step b) == some false).length = 309 :=
  by decide +kernel

public theorem residual_iff (b : Classes.StepBranch) :
    b ∈ residual ↔ read? (.step b) = none := by
  simp [residual, mem_universe b]

public theorem positive (b : Classes.StepBranch) (h : b ∈ positives) :
    label witness (.step b) = true :=
  read_sound _ (beq_iff_eq.mp (List.mem_filter.mp h).2)

/-- All other columns are certified negative. This theorem does not assign
any truth value to a member of `residual`. -/
public theorem negative (b : Classes.StepBranch) (unknown : b ∉ residual)
    (notPositive : b ∉ positives) : label witness (.step b) = false := by
  cases h : read? (.step b) with
  | none => exact (unknown ((residual_iff b).2 h)).elim
  | some v =>
    cases v
    · exact read_sound _ h
    · exact (notPositive (List.mem_filter.mpr ⟨mem_universe b, beq_iff_eq.mpr h⟩)).elim

private theorem pre_key : StateCoverage.read witness.cfg witness.before witness.past = (true, false) :=
  by decide +kernel

private theorem post_key : StateCoverage.read witness.cfg witness.after (witness.before :: witness.past) =
    (true, false) := by decide +kernel

/-- Both complete endpoint answers, computed on the real histories. -/
public theorem endpoints :
    (label witness).pre = ProofContexts.answers (true, false) ∧
    (label witness).post = ProofContexts.answers (true, false) := by
  exact ⟨(pre_answers witness).trans (congrArg ProofContexts.answers pre_key),
    (post_answers witness).trans (congrArg ProofContexts.answers post_key)⟩

/-- The first send is an enabled 0-to-1 heartbeat, not a pure stutter. -/
public theorem witness_packet :
    witness.cfg = {0, 1} ∧ witness.nodes = [0, 1] ∧ witness.past = [] ∧
    witness.act = .local 0 (.sendEntries 1 0) ∧ witness.after.nodes = witness.before.nodes ∧
    witness.before.network = [] ∧
    witness.after.network = [⟨0, 1, .appendEntriesRequest ⟨BOOTSTRAP_TERM, 0, 0, [], 0⟩⟩] :=
  ⟨rfl, rfl, rfl, rfl, sameNodes, rfl, rfl⟩

/- An example of a remaining quantified path is slot 432. Even after
equation-pinned witnesses are substituted and the send context fixed, its
26 arms quantify entry lists `left`, `right` and require both
`maxCommittableIndex left ≠ 0` and `left <+: right`. In its first arm,
`reach_888` obtains these lists as `take frontier` of other entry lists
satisfying `reach_862`. A finite packet or node lookup does not by itself
discharge those reach obligations. -/
private theorem prefix_residual :
    label witness (.step .maxCommittableIndex_le_of_prefix_zero_neg) = true ↔
      SolvedWitnesses.step_maxCommittableIndex_le_of_prefix_zero_neg witness.frame witness.after concrete := by
  rw [label_true]
  change PinnedClasses.sig witness.context .maxCommittableIndex_le_of_prefix_zero_neg ↔ _
  rw [← concrete_context]
  exact SolvedWitnesses.sig_iff _ _

end ConsensusCoverage.FreshHeartbeat
