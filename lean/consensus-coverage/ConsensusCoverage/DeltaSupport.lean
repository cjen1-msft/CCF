module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.ActionProfile
import ConsensusCoverage.EventSupport
import ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-!
# Fresh evidence required by recorded step questions

Each generated exclusion is a sufficient condition for a *negative* answer.
Absence of a guard never asserts that a question is true. In particular a
queue may lose messages and still satisfy its guard; duplicate occurrences
are not fresh values.
-/

namespace ConsensusCoverage.DeltaSupport

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- Families of proof evidence that can be ruled out independently. -/
public inductive Family
  | pending | now | election | commit
  deriving Repr, DecidableEq

/-- One-way inclusion is enough: a post-step atom supplies the corresponding
pre-step fact, or no election can take place. -/
private def Stable [Config.InitialConfiguration] (f : Frame) (t : Model.State) : Family → Prop
  | .pending => ∀ e, Pending (f.advance t) e → Pending f e
  | .now => ∀ n st, Now (f.advance t) n st → Now f n st
  | .election => ∀ n k l i, ¬ ElectStep f t n k l i
  | .commit => ∀ n st k base i, ¬ CommitStep (f.advance t) n st k base i

private theorem oldElected [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : Stable f t .election) {n k l i} :
    Elected (f.advance t) n k l i → Elected f n k l i := by
  rintro (old | ⟨_, eq, step⟩)
  · exact old
  · cases eq
    exact (h n k l i step).elim

private theorem oldLed [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : Stable f t .election) {n k} : Led (f.advance t) n k → Led f n k :=
  fun led => led.imp_right fun ⟨l, i, elect⟩ => ⟨l, i, oldElected h elect⟩

private theorem oldCommitted [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : Stable f t .commit) {k l} : Committed (f.advance t) k l → Committed f k l := by
  rintro (old | ⟨n, st, base, i, step, _, _⟩)
  · exact old
  · exact (h n st k base i step).elim

private def subset [BEq α] (before after : List α) : Bool := after.all before.contains

private theorem subset_sound [BEq α] [LawfulBEq α] {before after : List α}
    (h : subset before after = true) : ∀ a ∈ after, a ∈ before :=
  fun a mem => List.contains_iff_mem.mp (List.all_eq_true.mp h a mem)

/-- There is no fresh node record exactly when the acting node's whole record
is unchanged, including its function-valued fields. -/
private theorem stableNow_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : Stable f t .now ↔ c.post = c.pre := by
  constructor
  · intro h
    exact c.now_pre (h _ _ c.post_now)
  · intro same n st mem
    rcases c.now_after mem with ⟨rfl, rfl⟩ | ⟨_, old⟩
    · exact same ▸ c.pre_now
    · exact old

private def actor : Model.Action → NodeID
  | .local n _ => n
  | .deliver e => e.target

private theorem action_actor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : actor (ActionContext.action c) = c.actor := by
  unfold ActionContext.action ActionContext.encode
  cases c.tr.event <;> rfl

private def actorTest (s : Model.State) (a : Model.Action) (t : Model.State)
    (p : NodeState → NodeState → Bool) : Bool :=
  match nodeState s (actor a), nodeState t (actor a) with
  | some pre, some post => p pre post
  | _, _ => false

private theorem actorTest_sound [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (p : NodeState → NodeState → Bool)
    (h : actorTest f.current (ActionContext.action c) t p = true) : p c.pre c.post = true := by
  have found := Direct.nodeState_of_mem c.keys_after c.post_now
  simpa only [actorTest, action_actor, c.tr.found, found] using h

private def samePrimary (s t : Model.State) (pre post : NodeState) : Bool :=
  post.role == .primary && LeaderEffect.sameNode (LeaderEffect.probes s t) pre post

private def sameRoleTerm (pre post : NodeState) : Bool :=
  pre.role == post.role && pre.currentTerm == post.currentTerm

private theorem stableElection [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (test : sameRoleTerm c.pre c.post = true) : Stable f t .election := by
  intro n k l i step
  obtain ⟨role, term⟩ : c.pre.role = c.post.role ∧ c.pre.currentTerm = c.post.currentTerm := by
    simpa [sameRoleTerm] using test
  obtain ⟨_, _, _, lt | ⟨_, cand⟩, atTerm, primary | none, _⟩ := c.electStep step
  · omega
  · omega
  · rw [role, primary] at cand
    contradiction
  · rw [role, none] at cand
    contradiction

private def unsigned (t : Model.State) : Bool :=
  t.nodes.all fun (_, st) => st.log.all (! ·.content.isSignature)

private theorem stableCommit [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (test : unsigned t = true) : Stable f t .commit := by
  intro n st k base i step
  have check := List.all_eq_true.mp test (n, st) step.1.1
  have sig := step.2.2.2.1
  change isSignatureAt st.log i = true at sig
  cases atEntry : entryAt? st.log i with
  | none => simp [isSignatureAt, atEntry] at sig
  | some e =>
    have index : i ≠ 0 := by intro z; simp [entryAt?, z] at atEntry
    have found : st.log[i - 1]? = some e := by simpa [entryAt?, index] using atEntry
    have no := List.all_eq_true.mp check e (List.mem_of_getElem? found)
    simp only [isSignatureAt, atEntry] at sig
    simp [sig] at no

/-- Snapshot and exact-action checks shared across all columns. -/
public structure Evidence where
  pending : Bool
  now : Bool
  election : Bool
  commit : Bool

private def Evidence.stable (e : Evidence) : Family → Bool
  | .pending => e.pending
  | .now => e.now
  | .election => e.election
  | .commit => e.commit

/-- Compute once per replayed action. The `now` guard recognizes unchanged
primaries; other actors are conservatively left unknown. -/
@[expose] public def read (s : Model.State) (a : Model.Action) (t : Model.State) : Evidence :=
  ⟨subset s.network t.network, actorTest s a t (samePrimary s t), actorTest s a t sameRoleTerm,
    unsigned t⟩

private theorem read_sound [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : Family)
    (test : (read f.current (ActionContext.action c) t).stable k = true) :
    Stable f t k := by
  cases k with
  | pending => exact subset_sound test
  | now =>
    have h := actorTest_sound c _ test
    obtain ⟨role, fields⟩ := Bool.and_eq_true_iff.mp h
    exact (stableNow_iff c).mpr
      (((LeaderEffect.sameNode_actor_iff c (beq_iff_eq.mp role)).mp fields).symm)
  | election => exact stableElection c (actorTest_sound c _ test)
  | commit => exact stableCommit test

meta section

open Lean Meta Elab Command

private def pinned := `ConsensusCoverage.PinnedClasses

private def reachName? (p : Expr) : Option Name := do
  let n ← p.getAppFn.constName?
  if n.getPrefix == pinned && n.getString!.startsWith "reach_" then some n else none

private def families : Array Name :=
  #[``Family.pending, ``Family.now, ``Family.election, ``Family.commit]
private def certName (n k : Name) : Name :=
  `ConsensusCoverage.DeltaSupport ++ Name.mkSimple (n.getString! ++ "_stable_" ++ k.getString!)

private abbrev Fact := Expr × Expr
private abbrev Gen := StateRefT (Std.HashMap (Name × Name) Bool) MetaM

private structure Check where
  family : Name
  oldFrame : Expr
  newFrame : Expr
  stable : Expr

/-- Rebuild the negated precondition from positive atoms. Only transport
post-step atoms to the old frame, never the other way around. -/
private partial def rebuild (c : Check) (atoms : List Fact) (p : Expr) : MetaM (Option Expr) := do
  if let some (_, h) := atoms.find? (fun (q, _) => q == p) then return some h
  if p.isAppOfArity ``And 2 then
    let some l ← rebuild c atoms (p.getArg! 0) | return none
    let some r ← rebuild c atoms (p.getArg! 1) | return none
    return some (← mkAppM ``And.intro #[l, r])
  let .const n _ := p.getAppFn | return none
  let supported :=
    (c.family == ``Family.pending && n == ``Pending) ||
    (c.family == ``Family.now && n == ``Now) ||
    (c.family == ``Family.election && (n == ``Elected || n == ``Led)) ||
    (c.family == ``Family.commit && n == ``Committed)
  unless supported do return none
  let args := p.getAppArgs
  let some i := args.findIdx? (· == c.oldFrame) | return none
  let post := mkAppN p.getAppFn (args.set! i c.newFrame)
  let some (_, hp) := atoms.find? (fun (q, _) => q == post) | return none
  if n == ``Elected then return some (← mkAppM ``oldElected #[c.stable, hp])
  if n == ``Led then return some (← mkAppM ``oldLed #[c.stable, hp])
  if n == ``Committed then return some (← mkAppM ``oldCommitted #[c.stable, hp])
  return some (mkAppN c.stable ((args.extract (i + 1) args.size).push hp))

mutual

/-- Check every arm of a positive disjunction and reuse the certificate for
each shared reach call. Everything not modeled here is an opaque atom. -/
private partial def refute (c : Check) (todo : List Fact) (atoms : List Fact := []) :
    Gen (Option Expr) := do
  let (p, h) :: rest := todo |
    for (p, h) in atoms do
      if p.isAppOfArity ``Not 1 then
        if let some yes ← rebuild c atoms p.appArg! then return some (mkApp h yes)
    return none
  if let some n := reachName? p then
    if ← certify n c.family then
      let .const _ us := p.getAppFn | throwError "expected a reach constant"
      return some (mkAppN (mkConst (certName n c.family) us) (p.getAppArgs ++ #[c.stable, h]))
  if c.family == ``Family.election && p.isAppOf ``ElectStep &&
      p.getArg! 1 == c.oldFrame && p.getArg! 2 == c.newFrame.getArg! 2 then
    return some (mkAppN c.stable ((p.getAppArgs.extract 3 p.getAppNumArgs).push h))
  if c.family == ``Family.commit && p.isAppOf ``CommitStep && p.getArg! 1 == c.newFrame then
    return some (mkAppN c.stable ((p.getAppArgs.extract 2 p.getAppNumArgs).push h))
  if p.isAppOfArity ``And 2 then
    return ← refute c
      ((p.getArg! 0, ← mkAppM ``And.left #[h]) :: (p.getArg! 1, ← mkAppM ``And.right #[h]) :: rest) atoms
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `hq q fun hq => do
      let some result ← refute c ((q, hq) :: rest) atoms | return none
      return some (← mkLambdaFVars #[hq] result)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (← mkAppM ``Or.elim #[h, l, r])
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := p.appArg!.beta #[w]
      withLocalDeclD `hq q fun hq => do
        let some result ← refute c ((q, hq) :: rest) atoms | return none
        return some (← mkAppM ``Exists.elim #[h, ← mkLambdaFVars #[w, hq] result])
  refute c rest ((p, h) :: atoms)

private partial def certify (n k : Name) : Gen Bool := do
  if let some done := (← get)[(n, k)]? then return done
  let .defnInfo ci ← getConstInfo n | throwError "expected generated definition {n}"
  let result ← lambdaTelescope ci.value fun xs p => do
    let stable := mkAppN (mkConst ``Stable) (xs.extract 0 3 |>.push (mkConst k))
    let next := mkAppN (mkConst ``Frame.advance) (xs.extract 0 3)
    withLocalDeclD `stable stable fun hStable => do
      withLocalDeclD `h p fun h => do
        let some proof ← refute ⟨k, xs[1]!, next, hStable⟩ [(p, h)] | return false
        let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
        let type ← mkForallFVars (xs.push hStable) (← mkArrow pred (mkConst ``False))
        let value ← mkLambdaFVars (xs ++ #[hStable, h]) proof
        addDecl (.thmDecl { name := certName n k, levelParams := ci.levelParams, type, value })
        return true
  modify fun m => m.insert (n, k) result
  return result

end

private theorem excludeNil [Config.InitialConfiguration] {f t} {P : Prop} :
    P → ∀ k ∈ ([] : List Family), Stable f t k → False := by simp

private theorem excludeCons [Config.InitialConfiguration] {f t} {P : Prop} {k : Family}
    {ks : List Family} (head : Stable f t k → P → False)
    (tail : P → ∀ j ∈ ks, Stable f t j → False) :
    P → ∀ j ∈ k :: ks, Stable f t j → False := by
  intro yes j mem stable
  rcases List.mem_cons.mp mem with rfl | rest
  · exact head stable yes
  · exact tail yes j rest stable

private def compile : MetaM Unit := do
  let .defnInfo ci ← getConstInfo ``PinnedClasses.dispatch | throwError "expected pinned dispatcher"
  let branch ← getConstInfoInduct ``Classes.StepBranch
  unless (← getConstInfoInduct ``Family).ctors.toArray == families do
    throwError "family enumeration does not match the generator"
  lambdaTelescope ci.value fun xs body => do
    let params := xs.extract 0 4
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == xs[4]! do
      throwError "unexpected pinned dispatcher"
    let arms := args.extract 2 args.size
    let (results, cache) ← (arms.mapM fun arm => do
      let .const n us := arm.getAppFn | throwError "unexpected dispatcher arm {arm}"
      unless n.getPrefix == pinned && n.getString!.startsWith "step_" && arm.getAppArgs == params do
        throwError "unexpected dispatcher arm {arm}"
      let mut proof ← mkAppOptM ``excludeNil
        #[(some xs[0]!), (some xs[1]!), (some xs[2]!), some arm]
      let mut ks := []
      for k in families.reverse do
        if ← certify n k then
          ks := k :: ks
          proof ← mkAppM ``excludeCons #[mkAppN (mkConst (certName n k) us) params, proof]
      return (ks, proof) : Gen _).run {}
    let b := xs[4]!
    let ty := mkApp (mkConst ``List [.zero]) (mkConst ``Family)
    let table := `ConsensusCoverage.DeltaSupport.blockers
    let caseFn u := mkConst ``Classes.StepBranch.casesOn [u]
    let lists ← results.mapM fun (ks, _) => mkListLit (mkConst ``Family) (ks.map mkConst)
    let decl := Declaration.defnDecl {
      name := table, levelParams := [], type := ← mkForallFVars #[b] ty
      value := ← mkLambdaFVars #[b]
        (mkAppN (caseFn (.succ .zero)) (#[← mkLambdaFVars #[b] ty, b] ++ lists))
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let ty ← withLocalDeclD `k (mkConst ``Family) fun k => do
      let mem ← mkAppM ``List.Mem #[k, mkApp (mkConst table) b]
      let stable := mkAppN (mkConst ``Stable) (xs.extract 0 3 |>.push k)
      let tail ← mkArrow mem (← mkArrow stable (mkConst ``False))
      let tail ← mkForallFVars #[k] tail
      mkArrow (mkAppN (mkConst ci.name (ci.levelParams.map mkLevelParam)) xs) tail
    addDecl (.thmDecl {
      name := `ConsensusCoverage.DeltaSupport.dispatch_excluded
      levelParams := ci.levelParams, type := ← mkForallFVars xs ty
      value := ← mkLambdaFVars xs (mkAppN (caseFn .zero)
        (#[← mkLambdaFVars #[b] ty, b] ++ results.map Prod.snd)) })
    logInfo m!"delta support: {arms.size} columns, {results.countP (fun (ks, _) => !ks.isEmpty)} blocked; \
      {cache.size} memoized definition/family pairs; per family \
      {families.toList.map (fun k => (k.getString!, results.countP (fun (ks, _) => ks.contains k)))}"

end

public section

local elab "generate_delta_support" : command => Lean.Elab.Command.liftTermElabM compile
generate_delta_support

/-- Each listed family independently rules out this branch when stable. -/
add_decl_doc blockers

/-- Look up a column in the generated table and test only its certified guards. -/
@[expose] def excluded (e : Evidence) (b : Classes.StepBranch) : Bool :=
  (blockers b).any e.stable

theorem sig_false [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (b : Classes.StepBranch)
    (h : excluded (read (FullProfile.current f) (ActionContext.action c) t) b = true) :
    ¬ PinnedClasses.sig c b := by
  obtain ⟨k, mem, test⟩ := List.any_eq_true.mp h
  exact fun yes => dispatch_excluded _ _ _ _ yes k mem (read_sound c k test)

theorem label_false (s : ActionProfile.Step) (b : Classes.StepBranch)
    (h : excluded (read s.before s.act s.after) b = true) :
    ActionProfile.label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← s.current_eq, ← (s.context_eq s.context).mpr rfl] at h
  exact Bool.eq_false_iff.mpr fun yes =>
    sig_false s.context b h ((ActionProfile.label_true s (.step b)).mp yes)

/-- The numbers count columns in the generated dispatcher, not label vectors
or action kinds. A column can have more than one sufficient blocker. -/
theorem exclusion_counts :
    let columns := FullProfile.stepBranches
    let count := fun k => (columns.filter fun b => decide (k ∈ blockers b)).size
    columns.size = 433 ∧ (columns.filter fun b => !(blockers b).isEmpty).size = 111 ∧
      count .pending = 21 ∧ count .now = 59 ∧ count .election = 20 ∧ count .commit = 11 := by
  decide +kernel

end

private def existingExact (b : Classes.StepBranch) : Bool :=
  decide (b ∈ ReducedQuestions.covered) ||
    match b with
    | .leader_led_now_after_inl | .leader_led_leader_inl | .leader_led_leader_inr => true
    | _ => false

private def excludedColumns (s : ActionProfile.Step) : Array Classes.StepBranch :=
  FullProfile.stepBranches.filter (excluded (read s.before s.act s.after))

/-- Exclusions not already decided by the leader, exact queue, or action-tag readers. -/
private def newColumns (s : ActionProfile.Step) : Array Classes.StepBranch :=
  (excludedColumns s).filter fun b =>
    !existingExact b && decide (EventSupport.actionTag s.act ∈ EventSupport.allowed b)

private theorem newColumns_false (s : ActionProfile.Step) {b : Classes.StepBranch}
    (h : b ∈ newColumns s) : ActionProfile.label s (.step b) = false :=
  label_false s b (Array.mem_filter.mp (Array.mem_filter.mp h).1).2

private def cfg : CCF.Finset NodeID := {0, 1}
private def initial : Model.State :=
  { nodes := [0, 1].map fun n => (n, initialNodeState cfg n) }

private theorem initialized : StateCoverage.Run cfg [0, 1] initial [] := by
  apply StateCoverage.Run.initial
  refine ⟨⟨0, by decide⟩, ?_, ?_⟩ <;> simp [initial, protocol]

private def replay (run : StateCoverage.Run cfg [0, 1] s past) (a : Model.Action)
    (ok : ((transitionSystem cfg [0, 1]).step s a).isSome) : ActionProfile.Step :=
  ⟨cfg, [0, 1], s, past, a, ((transitionSystem cfg [0, 1]).step s a).get ok,
    run, (Option.some_get _).symm⟩

private def queueOnly : ActionProfile.Step :=
  replay initialized (.local 0 (.sendEntries 1 0)) (by decide +kernel)

private def nodesOnly : ActionProfile.Step :=
  replay initialized (.local 0 (.append [{content := .transaction 42 {}}])) (by decide +kernel)

private theorem nodesSame [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (h : Stable f t .now) : f.current.nodes = t.nodes := by
  have same : c.tr.post = c.pre := (stableNow_iff c).mp h
  rw [c.tr.nodesEq, same]
  unfold Concrete.replaceNode
  symm
  calc
    _ = f.current.nodes.map id := List.map_congr_left fun (n, st) mem => by
      by_cases eq : n = c.actor
      · subst n
        have recorded := c.now_pre mem
        simp [recorded]
      · simp [eq]
    _ = _ := List.map_id _

private theorem nodesSame_of_read (s : ActionProfile.Step)
    (test : (read s.before s.act s.after).now = true) : s.before.nodes = s.after.nodes := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← s.current_eq, ← (s.context_eq s.context).mpr rfl] at test
  exact (congrArg (·.nodes) s.current_eq).symm.trans (nodesSame s.context (read_sound s.context .now test))

private def witnessCounts (s : ActionProfile.Step) : Nat × Nat :=
  ((excludedColumns s).size, (newColumns s).size)

/-- An initialized heartbeat changes only the queue and yields 48 false bits
beyond the existing exact and tag readers. -/
public theorem queue_only_witness :
    ∃ s : ActionProfile.Step, s.before.nodes = s.after.nodes ∧ s.before.network ≠ s.after.network ∧
      witnessCounts s = (90, 48) ∧ ∀ b ∈ newColumns s, ActionProfile.label s (.step b) = false := by
  refine ⟨queueOnly, nodesSame_of_read _ (by decide +kernel), ?_, by decide +kernel, fun _ => newColumns_false _⟩
  exact fun eq => (by decide : 0 ≠ 1) (congrArg List.length eq)

/-- An initialized unsigned append changes only the nodes and yields 34 false
bits beyond the existing exact and tag readers. -/
public theorem nodes_only_witness :
    ∃ s : ActionProfile.Step, s.before.network = s.after.network ∧ s.before.nodes ≠ s.after.nodes ∧
      witnessCounts s = (52, 34) ∧ ∀ b ∈ newColumns s, ActionProfile.label s (.step b) = false := by
  refine ⟨nodesOnly, rfl, ?_, by decide +kernel, fun _ => newColumns_false _⟩
  exact fun eq => (by decide : [1, 0] ≠ [2, 0])
    (congrArg (List.map (fun p : NodeID × NodeState => p.2.log.length)) eq)

private def deliverHead (s : Model.State) (present : s.network.head?.isSome) : Model.Action :=
  .deliver (s.network.head?.get present)

private def deliverHeartbeat : ActionProfile.Step :=
  replay (.step queueOnly.run queueOnly.ran) (deliverHead queueOnly.after (by decide +kernel))
    (by decide +kernel)

private def deliverReply : ActionProfile.Step :=
  replay (.step deliverHeartbeat.run deliverHeartbeat.ran)
    (deliverHead deliverHeartbeat.after (by decide +kernel)) (by decide +kernel)

/-- Consuming the acknowledgement can truly shrink the queue, while the
no-fresh-envelope guard still fires for the delivered action. -/
public theorem removal_witness :
    ∃ s : ActionProfile.Step, s.after.network.length < s.before.network.length ∧
      s.before.nodes = s.after.nodes ∧ (read s.before s.act s.after).pending = true :=
  ⟨deliverReply, by decide +kernel, nodesSame_of_read _ (by decide +kernel), by decide +kernel⟩

end ConsensusCoverage.DeltaSupport
