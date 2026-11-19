module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.StateBasis
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-! The complete pinned step profile when a recorded action preserves node
states, queued-envelope membership, and log evidence. This includes literal
stutters, but does not require the two proof frames to be equal. -/

namespace ConsensusCoverage.StutterProfile

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- Equality of the node table and of the support of the network queue, not
its order or multiplicities. -/
public def SameSupport (s t : Model.State) : Prop :=
  t.nodes = s.nodes ∧ ∀ e : Model.Envelope, e ∈ t.network ↔ e ∈ s.network

public theorem SameSupport.of_eq {s t : Model.State} (h : t = s) : SameSupport s t := by
  cases h
  exact ⟨rfl, fun _ => Iff.rfl⟩

private theorem now_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : SameSupport f.current t) : Now (f.advance t) = Now f := by
  have nodes := h.1
  change t.nodes = f.current.nodes at nodes
  funext n st
  change ((n, st) ∈ t.nodes) = ((n, st) ∈ f.current.nodes)
  rw [nodes]

private theorem pending_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : SameSupport f.current t) : Pending (f.advance t) = Pending f :=
  funext fun e => propext (h.2 e)

private theorem seen_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : (f.advance t).logs = f.logs) : Seen (f.advance t) = Seen f := by
  unfold Seen
  rw [h]

private theorem led_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : (f.advance t).logs = f.logs) : Led (f.advance t) = Led f := by
  unfold Led
  rw [h]

meta section

open Lean Meta Elab Command

private def pinned := `ConsensusCoverage.PinnedClasses
private def certName (n : Name) : Name :=
  `ConsensusCoverage.StutterProfile ++ Name.mkSimple (n.getString! ++ "_no_stutter")

private def reachName? (p : Expr) : Option Name := do
  let n ← p.getAppFn.constName?
  if n.getPrefix == pinned && n.getString!.startsWith "reach_" then some n else none

private abbrev Fact := Expr × Expr
private abbrev Gen := StateRefT (Std.HashMap Name Bool) MetaM

/-- After rebasing the postconditions, rebuild the positive part of a newness
test from the positive path conditions. No witnesses are invented. -/
private partial def rebuild (facts : List Fact) (p : Expr) : MetaM (Option Expr) := do
  if let some (_, h) := facts.find? (fun (q, _) => q == p) then return some h
  if p.isAppOfArity ``And 2 then
    let some l ← rebuild facts (p.getArg! 0) | return none
    let some r ← rebuild facts (p.getArg! 1) | return none
    return some (← mkAppM ``And.intro #[l, r])
  return none

private def contradictionFrom (ctx : Simp.Context) (facts : List Fact) : MetaM (Option Expr) := do
  unless facts.any (fun (p, _) => p.isAppOfArity ``Not 1) do return none
  let facts ← facts.mapM fun (p, h) => do
    let (r, _) ← simp p ctx
    let h ← if let some eq := r.proof? then mkEqMP eq h else pure h
    return (r.expr, h)
  for (p, h) in facts do
    if p.isAppOfArity ``Not 1 then
      if let some yes ← rebuild facts (p.getArg! 0) then return some (mkApp h yes)
  return none

mutual

/-- Refute a positive path formula. Conjunctions may contain more than one reach
call: one refuted conjunct suffices. Disjunctions require proofs for both
arms. A cached certificate is a kernel-checked lemma, not a boolean oracle. -/
private partial def refute (ctx : Simp.Context) (eq logs : Expr)
    (todo : List Fact) (atoms : List Fact := []) : Gen (Option Expr) := do
  let (p, h) :: rest := todo | contradictionFrom ctx atoms
  if let some n := reachName? p then
    if ← certify n then
      let .const _ us := p.getAppFn | throwError "expected constant"
      return some (mkAppN (mkConst (certName n) us) (p.getAppArgs ++ #[eq, logs, h]))
  if p.isAppOfArity ``And 2 then
    return ← refute ctx eq logs
      ((p.getArg! 0, ← mkAppM ``And.left #[h]) :: (p.getArg! 1, ← mkAppM ``And.right #[h]) :: rest) atoms
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `h q fun hq => do
      let some result ← refute ctx eq logs ((q, hq) :: rest) atoms | return none
      return some (← mkLambdaFVars #[hq] result)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (← mkAppM ``Or.elim #[h, l, r])
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := (p.getArg! 1).beta #[w]
      withLocalDeclD `h q fun hq => do
        let some result ← refute ctx eq logs ((q, hq) :: rest) atoms | return none
        return some (← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hq] result])
  refute ctx eq logs rest ((p, h) :: atoms)

private partial def certify (n : Name) : Gen Bool := do
  if let some done := (← get)[n]? then return done
  let .defnInfo ci ← getConstInfo n | throwError "expected predicate {n}"
  let result ← lambdaTelescope ci.value fun xs p => do
    let inst := xs[0]!
    let f := xs[1]!
    let t := xs[2]!
    let current := mkApp (mkConst ``Frame.current) f
    let next := mkAppN (mkConst ``Frame.advance) #[inst, f, t]
    withLocalDeclD `support (mkApp2 (mkConst ``SameSupport) current t) fun eq => do
      let project (x : Expr) := mkApp (mkConst ``Frame.logs) x
      withLocalDeclD `logs (← mkEq (project next) (project f)) fun logs => do
        let mut rules : SimpTheorems := {}
        for name in #[``Committed, ``Canon, ``Elected, ``Granted] do
          rules ← rules.addDeclToUnfold name
        let rewrites := #[
          mkAppN (mkConst ``now_eq) #[inst, f, t, eq],
          mkAppN (mkConst ``pending_eq) #[inst, f, t, eq],
          mkAppN (mkConst ``seen_eq) #[inst, f, t, logs],
          mkAppN (mkConst ``led_eq) #[inst, f, t, logs], logs]
        for i in [:rewrites.size] do
          rules ← rules.add (.other ((`stutterRewrite).appendIndexAfter i)) #[] rewrites[i]!
        let ctx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
        withLocalDeclD `h p fun h => do
          let some proof ← refute ctx eq logs [(p, h)] | return false
          let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
          let type ← mkForallFVars (xs ++ #[eq, logs]) (← mkArrow pred (mkConst ``False))
          let value ← mkLambdaFVars (xs ++ #[eq, logs, h]) proof
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
    let (proofs, cache) ← (arms.mapM fun arm => do
      let .const n us := arm.getAppFn | throwError "unexpected dispatcher arm {arm}"
      unless n.getPrefix == pinned && n.getString!.startsWith "step_" && arm.getAppArgs == params do
        throwError "unexpected dispatcher arm {arm}"
      unless ← certify n do throwError "no stutter certificate for {n}"
      return mkAppN (mkConst (certName n) us) params : Gen _).run {}
    let b := xs[4]!
    let typeAt := fun b => do
      let ty ← inferType proofs[0]!
      forallTelescope ty fun ys _ => do
        let pred := mkAppN (mkConst ``PinnedClasses.dispatch) (params.push b)
        mkForallFVars (ys.extract 0 2) (← mkArrow pred (mkConst ``False))
    let type ← mkForallFVars xs (← typeAt b)
    let motive ← withLocalDeclD `b (mkConst ``Classes.StepBranch) fun b => do
      mkLambdaFVars #[b] (← typeAt b)
    let value ← mkLambdaFVars xs (mkAppN (mkConst ``Classes.StepBranch.casesOn [.zero])
      (#[motive, b] ++ proofs))
    addDecl <| .thmDecl {
      name := `ConsensusCoverage.StutterProfile.dispatch_false, levelParams := ci.levelParams,
      type, value }
    logInfo m!"stutter: {arms.size} dispatcher arms; {cache.size - arms.size} shared reach certificates"

end

local elab "certify_stutter" : command => Lean.Elab.Command.liftTermElabM compile
certify_stutter

/-- Whether folding the next snapshot adds log evidence, independently of
how the vote observations are stored. -/
public def StableLogs [Config.InitialConfiguration] (f : FullProfile.ProofFrame) (t : Model.State) : Prop :=
  (f.advance t).logs = f.logs

/-- Unchanged support and unchanged log evidence refute every question for
the same actual context. Vote-list equality is not required. -/
public theorem sig_false_of_support [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (support : SameSupport (FullProfile.current f) t) (logs : StableLogs f t)
    (b : Classes.StepBranch) : ¬ PinnedClasses.sig c b :=
  dispatch_false _ _ c b support logs

/-- In particular, literal stuttering suffices if the log evidence is stable. -/
public theorem sig_false [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (eq : t = FullProfile.current f) (logs : StableLogs f t)
    (b : Classes.StepBranch) : ¬ PinnedClasses.sig c b :=
  sig_false_of_support c (.of_eq eq) logs b

private theorem noElection [Config.InitialConfiguration] {f : Frame} (inv : Inv f)
    {grants n k l i} : ¬ LogFacts.ElectionAt f.current f.current grants n k l i := by
  rintro ⟨x, y, old, new, _, _, _, term, eq, role, _⟩
  have same := state_unique inv.distinct old new
  subst y
  rcases term with lt | ⟨_, cand⟩
  · omega
  · simp [cand] at role

private theorem frozenElection [Config.InitialConfiguration] {f : Frame} (inv : Inv f) :
    (f.advance f.current).logs.elected = f.logs.elected := by
  funext n k l i
  apply propext
  exact ⟨fun h => h.elim id fun ⟨_, eq, new⟩ => by
    cases eq
    exact (noElection inv new).elim, Or.inl⟩

private theorem frozenSeen [Config.InitialConfiguration] {f : Frame} (inv : Inv f) :
    (f.advance f.current).logs.seen = f.logs.seen := by
  funext n k l
  apply propext
  exact ⟨fun h => h.elim id fun ⟨st, now, term, log⟩ => by
    cases term; cases log
    exact inv.observed n st now, Or.inl⟩

/-- Every current canonical log is already included by the fold that installed
the current snapshot, including the initial fold. -/
private theorem currentCanon {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∀ {n st k}, CanonNow f n st k → f.logs.canon k st.log := by
  cases folded <;> exact fun h => Or.inr ⟨_, _, h, rfl⟩

private theorem frozenCanon {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    (f.advance f.current).logs.canon = f.logs.canon := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  have elections := frozenElection folded.invariant
  funext k l
  apply propext
  constructor
  · rintro (old | ⟨n, st, canon, rfl⟩)
    · exact old
    · apply currentCanon folded (n := n)
      refine ⟨canon.1, canon.2.1, canon.2.2.1, ?_⟩
      have led := canon.2.2.2
      change (f.advance f.current).logs.led Config.INITIAL_PRIMARY n k at led
      change f.logs.led Config.INITIAL_PRIMARY n k
      unfold LogFacts.Ghost.led at led ⊢
      rwa [elections] at led
  · exact Or.inl

/-- A structural sufficient condition, not an assertion that the frame always
stays fixed: the deployment currently has neither votes nor signed entries.
The history and the current node list are otherwise unrestricted. -/
public def UnsignedUnvoted (s : Model.State) : Prop :=
  ∀ n st, (n, st) ∈ s.nodes → st.votedFor = none ∧ ∀ i, isSignatureAt st.log i = false

private theorem logs_ext {a b : LogFacts.Ghost}
    (seen : a.seen = b.seen) (grant : a.grant = b.grant) (elected : a.elected = b.elected)
    (canon : a.canon = b.canon) (committed : a.committed = b.committed) : a = b := by
  cases a; cases b
  grind

private theorem stableLogs {cfg nodes f} (folded : FullProfile.Folded cfg nodes f)
    (quiet : UnsignedUnvoted (FullProfile.current f)) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    StableLogs f f.current := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  have seen := frozenSeen folded.invariant
  have elect := frozenElection folded.invariant
  have canon := frozenCanon folded
  have grant : (f.advance f.current).logs.grant = f.logs.grant := by
    funext v n k r
    apply propext
    refine ⟨?_, Or.inl⟩
    rintro (old | ⟨_, eq, atStep, _⟩)
    · exact old
    · cases eq
      obtain ⟨_, y, _, mem, _, _, vote, _⟩ := atStep
      rw [(quiet v y mem).1] at vote
      contradiction
  have committed : (f.advance f.current).logs.committed = f.logs.committed := by
    funext k l
    apply propext
    refine ⟨?_, Or.inl⟩
    rintro (old | ⟨n, st, _, i, step, _, _⟩)
    · exact old
    · have h := step.2.2.2.1
      rw [(quiet n st step.1.1).2 i] at h
      contradiction
  exact logs_ext seen grant elect canon committed

private theorem advance_logs_nodes [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (nodes : t.nodes = f.current.nodes) :
    (f.advance t).logs = (f.advance f.current).logs := by
  cases f with
  | mk s logs votes =>
    cases s
    cases t
    cases nodes
    rfl

/-- Only the next snapshot's node table enters the log fold. -/
public theorem step_stable_of_nodes (s : ActionProfile.Step) (nodes : s.after.nodes = s.before.nodes)
    (quiet : UnsignedUnvoted s.before) :
    @StableLogs ⟨s.cfg⟩ s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have same : s.after.nodes = s.frame.current.nodes :=
    nodes.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  exact (advance_logs_nodes same).trans (stableLogs s.folded (s.current_eq.symm ▸ quiet))

/-- In the initialized unsigned/unvoted class, repeating the snapshot adds no
log evidence. This does not equate frames or assume idempotence of the fold. -/
public theorem step_stable (s : ActionProfile.Step) (stutter : s.after = s.before)
    (quiet : UnsignedUnvoted s.before) :
    @StableLogs ⟨s.cfg⟩ s.frame s.after :=
  step_stable_of_nodes s (congrArg (fun t : Model.State => t.nodes) stutter) quiet

/-- The diagonal label for the two equal state profiles. -/
public def diagonal (pre : ProofContexts.Answers) : FullProfile.Profile
  | .pre b => pre b
  | .step _ => false
  | .post b => pre b

/-- All 433 coordinates share the context of the recorded action. -/
public theorem step_profile_of_support (s : ActionProfile.Step) (support : SameSupport s.before s.after)
    (logs : @StableLogs ⟨s.cfg⟩ s.frame s.after) :
    (ActionProfile.label s).step = fun _ => false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have support' : SameSupport (FullProfile.current s.frame) s.after := s.current_eq.symm ▸ support
  funext b
  apply Bool.eq_false_iff.mpr
  intro yes
  exact sig_false_of_support s.context support' logs b
    ((ActionProfile.label_true s (.step b)).mp yes)

public theorem step_profile_of_stable (s : ActionProfile.Step) (stutter : s.after = s.before)
    (logs : @StableLogs ⟨s.cfg⟩ s.frame s.after) :
    (ActionProfile.label s).step = fun _ => false :=
  step_profile_of_support s (.of_eq stutter) logs

/-- All 433 action-specific coordinates on initialized stutters with no
current votes or signed entries. -/
public theorem step_profile (s : ActionProfile.Step) (stutter : s.after = s.before)
    (quiet : UnsignedUnvoted s.before) :
    (ActionProfile.label s).step = fun _ => false :=
  step_profile_of_stable s stutter (step_stable s stutter quiet)

/-- The full 457-coordinate label, with unchanged pre/post proof-state answers. -/
public theorem label_eq_of_support (s : ActionProfile.Step) (support : SameSupport s.before s.after)
    (logs : @StableLogs ⟨s.cfg⟩ s.frame s.after) :
    ActionProfile.label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have eq : (s.frame.advance s.after).current.nodes = s.frame.current.nodes :=
    support.1.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  have logsEq : (s.frame.advance s.after).logs = s.frame.logs := logs
  have same := (StateBasis.ctx_equiv_iff ‹_› ‹_› (s.frame.advance s.after) s.frame).2
    ⟨by simp only [StateBasis.Zero, eq], by simp only [StateBasis.Backing, Committed, eq, logsEq]⟩
  funext q
  cases q with
  | pre b => exact congrFun (ActionProfile.pre_answers s) b
  | step b => exact congrFun (step_profile_of_support s support logs) b
  | post b =>
    have h := (ActionProfile.label_true s (.post b)).trans
      ((same b).trans (ActionProfile.label_true s (.pre b)).symm)
    exact (Bool.eq_iff_iff.mpr h).trans (congrFun (ActionProfile.pre_answers s) b)

public theorem label_eq_of_stable (s : ActionProfile.Step) (stutter : s.after = s.before)
    (logs : @StableLogs ⟨s.cfg⟩ s.frame s.after) :
    ActionProfile.label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  label_eq_of_support s (.of_eq stutter) logs

public theorem label_eq (s : ActionProfile.Step) (stutter : s.after = s.before)
    (quiet : UnsignedUnvoted s.before) :
    ActionProfile.label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  label_eq_of_stable s stutter (step_stable s stutter quiet)

private theorem unsigned_check {s : Model.State}
    (h : s.nodes.all (fun (_, st) => st.votedFor.isNone && st.log.all (! ·.content.isSignature)) = true) :
    UnsignedUnvoted s := by
  intro n st mem
  have check := List.all_eq_true.mp h (n, st) mem
  simp only [Bool.and_eq_true] at check
  obtain ⟨vote, unsigned⟩ := check
  refine ⟨Option.isNone_iff_eq_none.mp vote, fun i => ?_⟩
  cases atEntry : entryAt? st.log i with
  | none => simp [isSignatureAt, atEntry]
  | some e =>
    have index : i ≠ 0 := by intro z; simp [entryAt?, z] at atEntry
    have yes : st.log[i - 1]? = some e := by simpa [entryAt?, index] using atEntry
    simpa [isSignatureAt, atEntry] using List.all_eq_true.mp unsigned e (List.mem_of_getElem? yes)

private def beforeAppend : Model.State := StateCoverage.initial [0, 1]

private def appendUnsigned : Model.Action := .local 0 (.append [{content := .transaction 42 {}}])

private def appendResult : Option Model.State :=
  (transitionSystem {0} [0, 1]).step beforeAppend appendUnsigned

private theorem appendEnabled : appendResult.isSome := by decide +kernel

private def afterAppend : Model.State := appendResult.get appendEnabled

private theorem appendChanges : beforeAppend ≠ afterAppend := by
  intro same
  have lengths := congrArg (fun s : Model.State => s.nodes.map fun p => p.2.log.length) same
  exact (by decide : [1, 0] ≠ [2, 0]) lengths

private theorem nominateStutters :
    (transitionSystem {0} [0, 1]).step afterAppend (.local 0 .nominateSuccessor) = some afterAppend := by
  rfl

private def witnessStep : ActionProfile.Step :=
  ⟨{0}, [0, 1], afterAppend, [beforeAppend], .local 0 .nominateSuccessor, afterAppend,
    .step (.initial (StateCoverage.init _ (by decide))) (Option.some_get _).symm, nominateStutters⟩

/-- A word of length two: first append an unsigned transaction, then record
the successful stuttering nomination. The voter set is smaller than the node
list, and the witness does not use a disabled action. -/
public theorem noninitial_witness :
    ∃ s : ActionProfile.Step, s.cfg = {0} ∧ s.nodes = [0, 1] ∧
      (∃ earlier, s.past = [earlier] ∧ earlier ≠ s.before) ∧
      s.after = s.before ∧ UnsignedUnvoted s.before ∧ (ActionProfile.label s).step = fun _ => false := by
  have quiet : UnsignedUnvoted afterAppend := unsigned_check (by decide +kernel)
  exact ⟨witnessStep, rfl, rfl, ⟨beforeAppend, rfl, appendChanges⟩, rfl, quiet,
    step_profile witnessStep rfl quiet⟩

end ConsensusCoverage.StutterProfile
