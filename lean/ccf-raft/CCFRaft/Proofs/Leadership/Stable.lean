module

public import CCFRaft.Proofs.Leadership.Quiet
public import CCFRaft.Proofs.Leadership.Timers
public import CCFRaft.Proofs.Replication.Run

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A stable primary from timing

The primary sends every peer a heartbeat within `heartbeatInterval`, and the
heartbeat arrives within `delay`. Each arrival that passes the peer's log check,
which `Matching` assumes, resets the peer's election timer, and an expired timer
has gone at least half an election timeout without a reset.
So if `heartbeatInterval + delay` is below half the election timeout, no tracked
node of the term times out, and by `Quiet.step` the term stays quiet: the primary
keeps its role.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary

section Trace

variable [Config.InitialConfiguration] {trace : Trace} {nodes : List NodeID}
  (execution : trace.ValidFrom Config.INITIAL_CONFIGURATION nodes)

include execution

/-- Crash-stop: a node live at an index was live at every earlier one. -/
theorem live_before {node : NodeID} {earlier index : Nat} (le : earlier <= index)
    (live : node ∈ trace.live index)
    : node ∈ trace.live earlier := by
  induction le with
  | refl => exact live
  | step _ ih => exact ih (CCFRaft.Proofs.Liveness.live_decreases execution _ live)

theorem quiet_leader {leader : NodeID} {term index : Nat}
    (quiet : Quiet leader term (trace.state index))
    : exists state,
        nodeState (trace.state index) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at execution index
  obtain ⟨local_, now, primary, termEq⟩ := quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

end Trace

/-- While the term stays quiet, a live node the primary tracks has its election
timer reset within `heartbeatInterval + delay` of any index. -/
theorem reset_follows (model : LivenessModel) {trace : Trace} (valid : model.Valid trace)
    {leader node : NodeID} {term index : Nat} {delay : Real}
    (quiet : forall earlier, earlier <= index -> Quiet leader term (trace.state earlier))
    (timely : Timely trace leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace leader term)
    (incumbent : Incumbent trace leader) (live : node ∈ trace.live index)
    (tracked
      : forall earlier leaderState,
          earlier <= index
          -> nodeState (trace.state earlier) leader = some leaderState
          -> node ∈ eligiblePeers leaderState leader)
    : forall earlier,
        earlier <= index
        -> trace.time earlier + (model.bounds.heartbeatInterval + delay)
            < trace.time index
        -> exists later,
            earlier < later
            /\ trace.time later
                <= trace.time earlier + (model.bounds.heartbeatInterval + delay)
            /\ trace.ElectionReset node later := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  have due : forall moment, moment <= index -> trace.PeerDue leader node moment := by
    intro moment le
    obtain ⟨state, found, primary, _⟩ := quiet_leader execution (quiet moment le)
    exact ⟨incumbent.live moment, live_before execution le live, state, found, primary,
      incumbent.notRetired moment state found, tracked moment state le found⟩
  intro earlier le early
  obtain ⟨later, after, within, sends⟩ := valid.heartbeats earlier leader node (due earlier le)
  have beforeIndex : later < index := by
    by_contra notBefore
    have := valid.clockMonotone (Nat.le_of_not_lt notBefore)
    linarith
  rcases sends with stopped | ⟨state, frontier, found, event, _⟩
  · exact (stopped (due later beforeIndex.le)).elim
  have stateTerm : state.currentTerm = term := by
    obtain ⟨state', found', _, termEq⟩ := quiet_leader execution (quiet later beforeIndex.le)
    rw [found, Option.some.injEq] at found'
    rw [found']
    exact termEq
  have selected
      : (trace.event later).action = some (.local leader (.sendEntries node frontier)) := by
    rw [event]; rfl
  obtain ⟨actor, localEvent, current, next, outputs, acts, actorFound, ran, _, out, _⟩ :=
    step_found (CCFRaft.Proofs.Liveness.reachable execution later)
      (execution.step later _ selected)
  obtain ⟨same, eventEq⟩ := acts
  subst same eventEq
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨new, eq, single⟩ := sendEntries_sends actor state node frontier {} _ _ ran
  have sent
      : trace.Sent
          ⟨later, 0,
            {
              source := actor
              target := node
              payload :=
                .appendEntriesRequest (makeAppendEntriesRequest state node frontier)
            }⟩ := by
    simp [Trace.Sent, selected, out, eq, single]
  obtain ⟨delivery, afterSend, deliveryTime, delivered⟩ := timely _ sent rfl ⟨_, rfl⟩
  change later < delivery at afterSend
  change trace.time delivery <= trace.time later + delay at deliveryTime
  have deliveryBefore : delivery < index := by
    by_contra notBefore
    have := valid.clockMonotone (Nat.le_of_not_lt notBefore)
    linarith
  rcases delivered with deliverEq | crashed
  · refine ⟨delivery, by omega, by linarith, Or.inr ?_⟩
    have stepped := execution.step delivery _ (by rw [deliverEq]; rfl)
    obtain ⟨target, _, targetState, _, _, targetActs, targetFound, _⟩ :=
      step_found (CCFRaft.Proofs.Liveness.reachable execution delivery) stepped
    obtain ⟨targetEq, _⟩ := targetActs
    rw [targetEq] at targetFound
    refine ⟨
      {
        source := actor
        target := node
        payload := .appendEntriesRequest (makeAppendEntriesRequest state node frontier)
      },
      makeAppendEntriesRequest state node frontier, targetState, by rw [deliverEq]; rfl, rfl,
      rfl, targetFound, ?_⟩
    have le := (quiet delivery deliveryBefore.le).terms _ _ (Concrete.mem_of_nodeState targetFound)
    simp only [makeAppendEntriesRequest]
    rcases Nat.lt_or_ge targetState.currentTerm state.currentTerm with lt | ge
    · exact Or.inl lt
    refine Or.inr ⟨by omega, ?_⟩
    by_cases candidate : targetState.role = .candidate
    · exact Or.inl candidate
    by_cases preVote : targetState.role = .preVoteCandidate
    · exact Or.inr (Or.inl preVote)
    exact Or.inr (Or.inr (matching delivery _ _ targetState deliverEq rfl rfl targetFound
      (by omega) candidate preVote))
  · exact (crashed (live_before execution deliveryBefore.le live)).elim

/-- While the term stays quiet, no tracked node of the term times out. -/
theorem no_timeout (model : LivenessModel) {trace : Trace} (valid : model.Valid trace)
    {leader : NodeID} {term : Nat} {delay : Real}
    (start : QuietStart trace leader term model.bounds.electionTimeout)
    (timely : Timely trace leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace leader term)
    (ratio : model.bounds.heartbeatInterval + delay < model.bounds.electionTimeout / 2)
    (covered : Covered trace leader term) (incumbent : Incumbent trace leader)
    {index : Nat}
    (quiet : forall earlier, earlier <= index -> Quiet leader term (trace.state earlier))
    {node : NodeID} {state : NodeState}
    (event : trace.event index = .local node (.timeout .election))
    (different : Not (node = leader))
    (found : nodeState (trace.state index) node = some state)
    (termEq : state.currentTerm = term)
    : False := by
  have live : node ∈ trace.live index :=
    valid.execution.running index node (by rw [event]; rfl)
  obtain ⟨reset, before, recent, isReset⟩ :=
    recent_reset valid.clockMonotone ratio (start.timers index node state event found termEq)
      (reset_follows model valid quiet timely nonneg matching incumbent live
        (covered index node state event different found termEq))
  have := valid.electionTimers index node reset event before isReset
  linarith

/-- The term stays quiet throughout. -/
theorem quiet_all (model : LivenessModel) {trace : Trace} (valid : model.Valid trace)
    {leader : NodeID} {term : Nat} {delay : Real}
    (start : QuietStart trace leader term model.bounds.electionTimeout)
    (timely : Timely trace leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace leader term)
    (ratio : model.bounds.heartbeatInterval + delay < model.bounds.electionTimeout / 2)
    (covered : Covered trace leader term) (incumbent : Incumbent trace leader)
    : forall index, Quiet leader term (trace.state index) := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      rcases index with _ | index
      · exact start.quiet
      have quiet
          : forall earlier, earlier <= index -> Quiet leader term (trace.state earlier) :=
        fun earlier le => ih earlier (by omega)
      rcases selected : (trace.event index).action with _ | action
      · rw [execution.stutter index selected]
        exact quiet index le_rfl
      obtain ⟨rest, c, acts, _⟩ := ctx_at execution selected
      have local_ : forall input, c.event = .internal input
          -> trace.event index = .local c.actor input := by
        intro input eventEq
        have actionEq := acts_internal acts eventEq
        rw [actionEq] at selected
        exact event_of_local selected
      refine Quiet.step c (quiet index le_rfl) (fun eventEq => ?_)
        (fun same eventEq => incumbent.nominations index (same ▸ local_ _ eventEq))
        (fun same eventEq => incumbent.quorumChecks index (same ▸ local_ _ eventEq))
        fun same => incumbent.notRetired (index + 1) _
          (found_of_now c.exec (same ▸ c.post_now))
      have ran
          : (startElection (Capabilities.record c.tr.actor) c.tr.pre c.tr.actor).run {}
            = some (c.tr.post, c.tr.outputs) := by
        have ran := c.tr.ran
        have eventEq' : c.tr.event = .internal (.timeout .election) := eventEq
        rw [eventEq'] at ran
        exact ran
      obtain ⟨_, _, can⟩ := startElection_guard c.tr.actor c.tr.pre {} _ _ ran
      have preLe : c.tr.pre.currentTerm <= term :=
        (quiet index le_rfl).terms _ _ c.pre_now
      show c.tr.pre.currentTerm < term
      by_contra notLt
      have different : Not (c.actor = leader) := by
        intro same
        obtain ⟨local_, lead⟩ := Quiet.lead c (quiet index le_rfl)
        have primary : c.tr.pre.role = .primary := by
          have now : Now (trace.state index :: rest) c.actor local_ := by
            rw [same]
            exact lead.now
          have := lead.primary
          rwa [c.now_pre now] at this
        rcases can.1 with role | role | role <;> rw [role] at primary <;> cases primary
      exact no_timeout model valid start timely nonneg matching ratio covered incumbent
        quiet (local_ _ eventEq) different c.tr.found (by omega)

/-- `Properties.stable_leader`. -/
theorem stable_leader (model : LivenessModel) {trace : Trace} {leader : NodeID}
    {term : Nat} {delay : Real} (valid : model.Valid trace)
    (start : QuietStart trace leader term model.bounds.electionTimeout)
    (timely : Timely trace leader delay) (nonneg : 0 <= delay)
    (matching : Matching trace leader term)
    (ratio : model.bounds.heartbeatInterval + delay < model.bounds.electionTimeout / 2)
    (covered : Covered trace leader term) (incumbent : Incumbent trace leader)
    : LeadsThroughout trace leader term := by
  let _ : Config.InitialConfiguration := ⟨model.initialConfiguration⟩
  have execution : trace.ValidFrom Config.INITIAL_CONFIGURATION model.nodes := valid.execution
  intro index
  obtain ⟨state, found, primary, termEq⟩ :=
    quiet_leader execution
      (quiet_all model valid start timely nonneg matching ratio covered incumbent index)
  exact ⟨incumbent.live index, state, found, primary, termEq,
    incumbent.notRetired index state found⟩

end CCFRaft.Proofs.Leadership
