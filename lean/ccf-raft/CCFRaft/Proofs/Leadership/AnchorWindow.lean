module

public import CCFRaft.Proofs.Leadership.AnchorBlocks
public import CCFRaft.Proofs.Leadership.Settles

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# An anchored term stays quiet in a window

`window_invariant_core` for an anchored start. The term stays quiet among
participants without the pre-vote clause, the anchor keeps knowing the primary,
and every quorum a participant can count stays blocked by the anchor, at every
recorded state of a good period in which no anchor node retires, provided no
anchor node other than the primary times out in the term at least `fresh` after
the start while the invariant has held so far.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]

/-- The window invariant of an anchored term. -/
structure AnchorInv (participants anchor : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  quiet : QuietTerm participants leader term state
  anchored : Anchor participants anchor leader term state
  blocks : Blocks participants anchor state

/-- The anchored primary tracks every other anchor node at a recorded state. -/
theorem AnchorInv.tracked {participants anchor : Finset NodeID} {leader : NodeID}
    {term : Nat} {point : Model.State}
    (inv : AnchorInv participants anchor leader term point) {node : NodeID}
    (nodeIn : node ∈ anchor) (different : Not (node = leader)) {state : NodeState}
    (leaderFound : nodeState point leader = some state)
    : node ∈ eligiblePeers state leader := by
  have member := inv.anchored.members state (now_of_found leaderFound (rest := []))
    node nodeIn different
  unfold NodeState.activeConfigurations at member
  rw [latest_active] at member
  exact eligible_of_latest member different

private theorem anchor_local_of_internal {event : Liveness.Event} {action : Model.Action}
    {actor : NodeID} {localEvent : Model.Node.Event} {input : Input}
    (selected : event.action = some action) (acts : Acts action actor localEvent)
    (internal : localEvent = .internal input)
    : event = .local actor input := by
  cases action with
  | «local» node input' =>
      obtain ⟨actorEq, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal
      rw [actorEq]
      cases event <;> simp_all [Liveness.Event.action]
  | deliver envelope =>
      obtain ⟨_, eventEq⟩ := acts
      rw [eventEq] at internal
      cases internal

section Recorded

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- With every participant live, `AnchorActive` keeps the primary active. -/
theorem Window.AnchorActive.staysActive {trace : Trace W Liveness.Event} {start : Nat}
    {duration : Real} {participants anchor : Finset NodeID} {leader : NodeID}
    (active : Window.AnchorActive trace start duration anchor)
    (good : GoodPeriod trace start duration participants)
    (leaderIn : leader ∈ anchor) (subset : anchor ⊆ participants)
    : Window.StaysActive trace start duration leader :=
  ⟨
    fun index point within found =>
      good.participantsLive index point leader within found (subset leaderIn),
    fun index point state within found nodeFound =>
      active index point leader state within found leaderIn nodeFound
  ⟩

/-- In a good period the anchored primary has a live quorum within the anchor. -/
theorem AnchorInv.liveQuorum {start : Nat} {duration : Real}
    {participants anchor : Finset NodeID} {leader : NodeID} {term index : Nat} {point : W}
    {trace : Trace W Liveness.Event} (good : GoodPeriod trace start duration participants)
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    (inv : AnchorInv participants anchor leader term (proto point)) {state : NodeState}
    (leaderFound : nodeState (proto point) leader = some state)
    : hasQuorum state.activeConfigurations (Inter.inter (live point) anchor) := by
  refine hasQuorum_mono (inv.anchored.quorum state (now_of_found leaderFound (rest := [])))
    fun node nodeIn => Finset.mem_inter.mpr ⟨?_, nodeIn⟩
  exact good.participantsLive index point node within found (inv.anchored.subset nodeIn)

variable {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- From an anchored start, the term stays quiet among participants, the anchor
keeps knowing the primary, and every quorum a participant can count stays blocked
by the anchor, at every recorded state of a good period in which no anchor node
retires, provided no anchor node other than the primary times out in the term at
least `fresh` after the start while the invariant has held so far. Earlier
timeouts are excluded by `AnchoredStart.timers`. -/
theorem anchor_invariant_core
    {fresh : Real} {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (initial : AnchoredStart trace start leader term participants anchor fresh)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration anchor) {bound : Nat}
    (noLateTimeout
      : forall index step node state first,
          start <= index
          -> index < bound
          -> Within trace start duration index
          -> trace.stepAt index = some step
          -> step.action = .local node (.timeout .election)
          -> nodeState (proto step.before) node = some state
          -> node ∈ anchor
          -> Not (node = leader)
          -> state.currentTerm = term
          -> trace.stateAt start = some first
          -> time first + fresh <= time step.before
          -> (forall earlier point,
                start <= earlier
                -> earlier <= index
                -> trace.stateAt earlier = some point
                -> AnchorInv participants anchor leader term (proto point))
          -> False)
    : forall index point,
        index <= bound
        -> Within trace start duration index
        -> trace.stateAt index = some point
        -> AnchorInv participants anchor leader term (proto point) := by
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      intro point inBound within recorded
      by_cases atStart : index = start
      · subst index
        obtain ⟨first, firstFound, quiet, anchored, blocks⟩ := initial.quiet
        rw [recorded, Option.some.injEq] at firstFound
        subst first
        exact ⟨quiet, anchored, blocks⟩
      rcases index with _ | index
      · exact absurd (Nat.le_zero.mp within.1) (Ne.symm atStart)
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp recorded
      have afterStart : start <= index := by have := within.1; omega
      have windowed
          : forall earlier, start <= earlier -> earlier <= index
              -> Within trace start duration earlier :=
        fun earlier after le => within_of_le admissible within recorded after (by omega)
      have earlier_
          : forall earlier point,
              start <= earlier
              -> earlier <= index
              -> trace.stateAt earlier = some point
              -> AnchorInv participants anchor leader term (proto point) :=
        fun earlier point after le found =>
          ih earlier (by omega) point (by omega) (windowed earlier after le) found
      have indexWithin := windowed index afterStart le_rfl
      have now := earlier_ index step.before afterStart le_rfl (admissible.before stepped)
      rcases selected : step.action.action with _ | action
      · rw [admissible.stutter stepped selected]
        exact now
      obtain ⟨rest, c, acts, _⟩ := ctx_at admissible stepped selected
      have local_ : forall input, c.event = .internal input
          -> step.action = .local c.actor input :=
        fun _ eventEq => anchor_local_of_internal selected acts eventEq
      have isolated
          : c.actor ∈ participants
            -> forall source message,
                c.event = .receive source message -> source ∈ participants := by
        intro actorIn source message eventEq
        cases action with
        | «local» node input =>
            obtain ⟨_, eventEq'⟩ := acts
            cases eventEq'.symm.trans eventEq
        | deliver envelope =>
            obtain ⟨actorEq, eventEq'⟩ := acts
            obtain ⟨sourceEq, _⟩ := Model.Node.Event.receive.inj (eventEq'.symm.trans eventEq)
            rw [← sourceEq]
            exact good.isolated index step envelope indexWithin stepped
              (delivered_of_action selected) (actorEq ▸ actorIn)
      have plain
          : forall contents, c.event = .internal (.append contents)
            -> forall content, content ∈ contents
                -> content.metadata.configuration = none :=
        fun contents eventEq =>
          good.noReconfiguration index step c.actor contents indexWithin stepped
            (local_ _ eventEq)
      have blocked
          : forall node local_,
              (node, local_) ∈ (proto step.before).nodes
              -> node ∈ participants
              -> forall configuration,
                  configuration ∈ local_.activeConfigurations
                  -> Blocked anchor configuration.nodes :=
        fun node local_ member nodeIn => (now.blocks node local_ member nodeIn).1
      have timeout
          : c.actor ∈ anchor
            -> c.event = .internal (.timeout .election)
            -> c.pre.currentTerm < term := by
        intro actorIn eventEq
        have ran
            : (startElection (Capabilities.record c.tr.actor) c.tr.pre c.tr.actor).run {}
              = some (c.tr.post, c.tr.outputs) := by
          have ran := c.tr.ran
          have eventEq' : c.tr.event = .internal (.timeout .election) := eventEq
          rw [eventEq'] at ran
          exact ran
        obtain ⟨_, _, can⟩ := startElection_guard c.tr.actor c.tr.pre {} _ _ ran
        have preLe : c.tr.pre.currentTerm <= term :=
          now.quiet.terms _ _ c.pre_now (now.anchored.subset actorIn)
        show c.tr.pre.currentTerm < term
        by_contra notLt
        have different : Not (c.actor = leader) := by
          intro same
          obtain ⟨local_, lead⟩ := QuietTerm.lead c now.quiet
          have primary : c.tr.pre.role = .primary := by
            have now' : Now (proto step.before :: rest) c.actor local_ := by
              rw [same]
              exact lead.now
            have := lead.primary
            rwa [c.now_pre now'] at this
          rcases can.1 with role | role | role <;> rw [role] at primary <;> cases primary
        have timeout := local_ _ eventEq
        obtain ⟨first, firstFound, _⟩ := initial.quiet
        exact noLateTimeout index step c.actor c.tr.pre first afterStart (by omega)
          indexWithin stepped timeout c.tr.found actorIn different (by omega) firstFound
          (initial.timers first index step c.actor c.tr.pre firstFound afterStart stepped
            timeout c.tr.found actorIn (by omega))
          earlier_
      have check
          : c.actor ∈ anchor -> Not (c.event = .internal (.timeout .checkQuorum)) :=
        fun actorIn eventEq =>
          good.noQuorumChecks index step c.actor indexWithin stepped
            (now.anchored.subset actorIn) (local_ _ eventEq)
      have retired : c.actor ∈ anchor -> Not (c.post.isRetiredCommitted c.actor) :=
        fun actorIn =>
          active (index + 1) step.after c.actor c.post within
            (Trace.stateAt_succ_of_stepAt stepped) actorIn (found_of_now c.exec c.post_now)
      exact ⟨
        QuietTerm.step c now.quiet now.anchored blocked isolated timeout
          (fun same eventEq =>
            good.noNominations index step leader indexWithin stepped
              (same ▸ local_ _ eventEq))
          check retired,
        Anchor.step c now.quiet now.anchored blocked isolated timeout check retired plain,
        Blocks.step c isolated plain now.blocks
      ⟩

/-- An anchor node is no pre-vote candidate, so the term is quiet among the
anchor with the pre-vote clause. -/
theorem AnchorInv.quietAmong {participants anchor : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (inv : AnchorInv participants anchor leader term (proto point))
    : QuietAmong anchor leader term (proto point) := by
  obtain ⟨_, exec⟩ := history_at admissible found
  refine ⟨
    fun node local_ member nodeIn =>
      inv.quiet.terms node local_ member (inv.anchored.subset nodeIn),
    fun node local_ member nodeIn role => ?_,
    fun envelope member sourceIn targetIn =>
      inv.quiet.messages envelope member (inv.anchored.subset sourceIn)
        (inv.anchored.subset targetIn),
    fun envelope member sourceIn targetIn =>
      inv.quiet.proposals envelope member (inv.anchored.subset sourceIn)
        (inv.anchored.subset targetIn),
    inv.quiet.leader
  ⟩
  exfalso
  obtain ⟨settled, settledNow, _, _, followerOrPrimary⟩ := inv.anchored.settled node nodeIn
  have same := (found_of_now exec settledNow).symm.trans (found_of_now exec member)
  rw [Option.some.injEq] at same
  subst same
  rcases followerOrPrimary with r | r <;> rw [r] at role <;> cases role

/-- The anchored primary leads `term` at a recorded state. -/
theorem AnchorInv.leads {participants anchor : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (inv : AnchorInv participants anchor leader term (proto point))
    : exists state,
        nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨local_, now, primary, termEq⟩ := inv.quiet.leader
  exact ⟨local_, found_of_now exec now, primary, termEq⟩

/-- An anchor node is in `term` at a recorded state. -/
theorem AnchorInv.anchorTerm {participants anchor : Finset NodeID} {leader : NodeID}
    {term index : Nat} {point : W} (found : trace.stateAt index = some point)
    (inv : AnchorInv participants anchor leader term (proto point)) {node : NodeID}
    (nodeIn : node ∈ anchor) {state : NodeState}
    (nodeFound : nodeState (proto point) node = some state)
    : state.currentTerm = term := by
  obtain ⟨_, exec⟩ := history_at admissible found
  obtain ⟨settled, now, termEq, _⟩ := inv.anchored.settled node nodeIn
  rw [found_of_now exec now, Option.some.injEq] at nodeFound
  rw [← nodeFound]
  exact termEq

end Recorded

end CCFRaft.Proofs.Leadership
