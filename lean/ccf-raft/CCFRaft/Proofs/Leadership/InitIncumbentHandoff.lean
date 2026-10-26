module

public import CCFRaft.Proofs.Leadership.InitIncumbentSettle

@[expose] public section

set_option linter.unusedSectionVars false

/-!
The capped incumbent window ends in an anchored handoff.
-/

namespace CCFRaft.Proofs.Leadership.InitIncumbent

open CCF CCF.MultiNodeTransitionSystem
open Model.Node CCFRaft.Liveness
open CCFRaft.Proofs.Safety CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable [Config.InitialConfiguration]
  {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]
  {trace : Trace W Liveness.Event} {nodes : List NodeID}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- A capped incumbent window supplies a handoff with all participants anchored. -/
theorem handoff_capped {start : Nat}
    {duration heartbeat maxDelay electionTimeout fresh : Real}
    {participants members : Finset NodeID} {leader : NodeID} {term : Nat}
    (delay : trace.Valid (boundedDelayModel maxDelay))
    (timers : trace.Valid (timerModel electionTimeout)) (diverges : TimeDiverges trace)
    (heartbeats : trace.HeartbeatScheduling (some heartbeat))
    (nonnegative : 0 <= maxDelay) (heartbeatNonnegative : 0 <= heartbeat)
    (room : 2 * (heartbeat + maxDelay) <= duration) (flushRoom : maxDelay <= duration)
    (ratio : duration < electionTimeout / 2)
    (freshLe : fresh <= electionTimeout / 2 - duration)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration participants)
    (matching : Window.Matching trace start duration participants)
    (membership
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> Membership participants members (proto point))
    (subset : participants ⊆ members) (leaderIn : leader ∈ participants)
    (roled
      : forall index point node state,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> node ∈ participants
          -> nodeState (proto point) node = some state
          -> Not (state.role = .none))
    (low
      : forall index,
          Within trace start duration index -> Low trace participants index term)
    {first : W} {state : NodeState} (firstFound : trace.stateAt start = some first)
    (nodeFound : nodeState (proto first) leader = some state)
    (stateTerm : state.currentTerm = term) (primary : state.role = .primary)
    : HandoffBy trace participants start duration fresh := by
  have durationNonnegative : 0 <= duration := by linarith
  have leads := fun index point within found =>
    primary_kept admissible good active low firstFound leaderIn nodeFound stateTerm primary
      (index := index) (point := point) within found
  obtain ⟨stop, cross, lower, crossed, near, far⟩ :=
    InitRaise.boundary admissible diverges firstFound (by linarith : time first <= time first + duration)
  have found := admissible.before crossed
  have within : Within trace start duration stop := by
    refine ⟨lower, fun f p ff pf => ?_⟩
    rw [firstFound, Option.some.injEq] at ff
    rw [found, Option.some.injEq] at pf
    subst f p
    exact near
  obtain ⟨primaryState, primaryFound, primaryTerm, primaryRole⟩ :=
    leads stop cross.before within found
  have settled := settled_by admissible delay timers diverges heartbeats nonnegative
    heartbeatNonnegative room ratio good active matching membership subset leaderIn roled low leads
    firstFound lower crossed near far
  have settledAll : forall node, node ∈ participants ->
      exists state, nodeState (proto cross.before) node = some state
        /\ state.currentTerm = term /\ state.primaryKnown = true
        /\ (state.role = .follower \/ state.role = .primary) := by
    intro node member
    by_cases same : node = leader
    · subst node
      exact ⟨primaryState, primaryFound, primaryTerm,
        knows_at admissible found primaryFound primaryRole, Or.inr primaryRole⟩
    · obtain ⟨state, _, _, stateFound, stateTerm, stateRole, stateKnown, _⟩ := settled node member same
      exact ⟨state, stateFound, stateTerm, stateKnown, Or.inl stateRole⟩
  have fixed := membership stop cross.before within found
  have quorum := good.quorum stop cross.before leader primaryState within found
    (good.participantsLive stop cross.before leader within found leaderIn) primaryFound
  have anchorQuorum := CCFRaft.Proofs.StablePrimary.hasQuorum_mono quorum Finset.inter_subset_right
  have blocked : Blocked participants members := by
    obtain ⟨config, configIn⟩ := List.exists_mem_of_ne_nil _ anchorQuorum.1
    have majority := of_decide_eq_true (List.all_eq_true.mp anchorQuorum.2 config configIn)
    unfold hasConfigurationMajority at majority
    rw [(fixed leader primaryState (Concrete.mem_of_nodeState primaryFound) leaderIn).1 config configIn]
      at majority
    have card := Finset.card_sdiff_add_card_inter members participants
    rw [Finset.inter_comm members participants] at card
    unfold Blocked
    omega
  refine ⟨
    stop,
    leader,
    term,
    participants,
    first,
    cross.before,
    lower,
    firstFound,
    found,
    near,
    ?_
  ⟩
  constructor
  · refine ⟨cross.before, found, ?_, ?_, ?_, fixed.blocks blocked⟩
    · refine ⟨?_, ?_, primaryState, Concrete.mem_of_nodeState primaryFound, primaryRole, primaryTerm⟩
      · intro node local_ mem member
        exact low stop within cross.before node local_ found member
          (Direct.nodeState_of_mem (Direct.keys_nodup (admissible.reachable found)) mem)
      · intro envelope queued sourceIn _
        obtain ⟨sender, senderMem, sentLe⟩ :=
          CCFRaft.Proofs.Duel.Elected.network_terms (admissible.reachable found) envelope queued
        exact sentLe.trans (low stop within cross.before _ sender found sourceIn
          (Direct.nodeState_of_mem (Direct.keys_nodup (admissible.reachable found)) senderMem))
    · exact proposals_flushed admissible delay good active roled leads firstFound lower crossed near far flushRoom
    · refine {
        subset := Finset.Subset.refl _
        leaderIn := leaderIn
        quorum := ?_
        members := ?_
        settled := ?_
        noGrants := ?_
        notCounted := ?_
      }
      · intro local_ mem
        have eq := state_unique (Direct.keys_nodup (admissible.reachable found))
          mem (Concrete.mem_of_nodeState primaryFound)
        subst local_
        exact anchorQuorum
      · intro local_ mem node member _
        have eq := state_unique (Direct.keys_nodup (admissible.reachable found))
          mem (Concrete.mem_of_nodeState primaryFound)
        subst local_
        have latest := (fixed.latest (Concrete.mem_of_nodeState primaryFound) leaderIn).resolve_left quorum.1
        rw [latest]
        exact subset member
      · intro node member
        obtain ⟨state, sf, st, known, role⟩ := settledAll node member
        exact ⟨state, Concrete.mem_of_nodeState sf, st, known, role⟩
      · intro envelope _ _ outside
        simp at outside
      · intro node local_ mem member preVote _
        obtain ⟨state, sf, _, _, role⟩ := settledAll node member
        have eq := state_unique (Direct.keys_nodup (admissible.reachable found))
          mem (Concrete.mem_of_nodeState sf)
        subst local_
        rcases role with follower | primary <;> rw [preVote] at * <;> contradiction
  · intro origin index step node local_ originFound later stepped timeout _ member _
    rw [found, Option.some.injEq] at originFound
    subst origin
    by_cases same : node = leader
    · subst node
      have late := primary_timeout_late admissible timers found primaryFound primaryRole later stepped timeout
      linarith
    · obtain ⟨_, resetIndex, reset, _, _, _, _, afterStart, beforeStop, resetAt, resets⟩ :=
        settled node member same
      have scheduled := CCFRaft.Proofs.Liveness.electionScheduling_of_timerModel
        admissible.coherent admissible.timing timers resetIndex index reset step node
        (by omega) resetAt stepped timeout resets
      have elapsed := admissible.time_le afterStart firstFound (admissible.before resetAt)
      linarith

end CCFRaft.Proofs.Leadership.InitIncumbent
