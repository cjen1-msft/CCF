module

public import CCFRaft.Proofs.Leadership.AnchorWindow
public import CCFRaft.Proofs.Leadership.InSync

@[expose] public section

/-!
# A stable window from an anchor in sync

`stable_window_inSync` for an anchored start. With every anchor node in sync
with the primary at the start, the primary's AppendEntries pass the anchor's log
checks throughout the window, so the anchor's election timers keep being reset
and `anchor_invariant_core` holds for the whole window. The window is then stable
over the anchor, and the term stays quiet, without the pre-vote clause, over all
participants: lagging participants never move past it.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

section Recorded

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace)

include admissible

/-- `anchor_invariant_core` up to `bound`, while the primary's requests pass the
anchor's log checks before it. -/
theorem anchor_invariant_before {bounds : Bounds} {maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (initial : AnchoredStart trace start leader term participants anchor fresh)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration anchor) {bound : Nat}
    (matching
      : forall moment,
          moment < bound -> MatchesAt trace start duration leader term anchor moment)
    : forall index point,
        index <= bound
        -> Within trace start duration index
        -> trace.stateAt index = some point
        -> AnchorInv participants anchor leader term (proto point)
            /\ NoProposals participants term point := by
  obtain ⟨_, _, _, _, anchored, _⟩ := initial.quiet
  have staysActive :=
    Window.AnchorActive.staysActive active good anchored.leaderIn anchored.subset
  exact anchor_invariant_core admissible initial good active
    (fun index step node _ _ afterStart lt within stepped timeout _ nodeIn different _
        firstFound late earlier_ =>
      window_no_timeout admissible heartbeats elections bounded nonneg ratio freshLe good
        staysActive (anchored.subset anchored.leaderIn) (anchored.subset nodeIn) different
        nodeIn (fun moment before => matching moment (by omega)) afterStart stepped within
        timeout firstFound late
        (fun earlier point after le found =>
          AnchorInv.leads admissible found (earlier_ earlier point after le found).1)
        (fun earlier point state after le found nodeFound =>
          (earlier_ earlier point after le found).1.quiet.terms _ _
            (Concrete.mem_of_nodeState nodeFound) (anchored.subset nodeIn))
        (fun earlier point _ after le found leaderFound =>
          AnchorInv.tracked (earlier_ earlier point after le found).1 nodeIn different
            leaderFound))

/-- From an anchored start with every anchor node in sync with the primary, the
primary's AppendEntries in the window pass the anchor's log checks. -/
theorem window_matching_anchored {bounds : Bounds} {maxDelay : Real}
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    (elections : trace.ElectionScheduling (some (bounds.electionTimeout / 2)))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (initial : AnchoredStart trace start leader term participants anchor fresh)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration anchor)
    (sync : InSync trace start leader term anchor)
    : WindowMatching trace start duration leader term anchor := by
  obtain ⟨_, _, _, _, anchored, _⟩ := initial.quiet
  have staysActive :=
    Window.AnchorActive.staysActive active good anchored.leaderIn anchored.subset
  have invAt := fun bound matching =>
    anchor_invariant_before admissible heartbeats elections bounded nonneg ratio freshLe
      initial good active (bound := bound) matching
  have claim
      : forall index,
          (forall moment,
            moment < index -> MatchesAt trace start duration leader term anchor moment)
          /\ forall point,
              Within trace start duration index
              -> trace.stateAt index = some point
              -> forall peer,
                  peer ∈ anchor
                  -> Not (peer = leader)
                  -> exists leaderState state,
                      InSyncWith leader term peer point leaderState state := by
    intro index
    induction index with
    | zero =>
        refine ⟨fun _ lt => absurd lt (Nat.not_lt_zero _), fun point within found => ?_⟩
        have atStart : start = 0 := Nat.le_zero.mp within.1
        subst atStart
        exact fun peer => sync point peer found
    | succ index ih =>
        obtain ⟨earlier, syncAt⟩ := ih
        have matching
            : forall moment,
                moment < index + 1
                -> MatchesAt trace start duration leader term anchor moment := by
          intro moment lt
          rcases Nat.lt_succ_iff_lt_or_eq.mp lt with lt | rfl
          · exact earlier moment lt
          · intro step packet request state within stepped
            have found := admissible.before stepped
            exact matches_at admissible stepped
              ((invAt moment earlier moment step.before le_rfl within found).1.quietAmong
                admissible found).quietTerm
              (syncAt step.before within found) step packet request state within stepped
        refine ⟨matching, fun point within found peer peerIn different => ?_⟩
        by_cases atStart : index + 1 = start
        · rw [atStart] at found
          exact sync point peer found peerIn different
        obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
        have afterStart : start <= index := by
          have := within.1
          omega
        have within' := within_of_le admissible within found afterStart (Nat.le_succ index)
        have before := admissible.before stepped
        obtain ⟨_, _, syncPeer⟩ := syncAt step.before within' before peer peerIn different
        exact sync_step admissible stepped within' good staysActive
          (anchored.subset anchored.leaderIn)
          (invAt (index + 1) matching index step.before (Nat.le_succ index) within'
            before).1.quiet
          (invAt (index + 1) matching (index + 1) step.after le_rfl within found).1.quiet
          (anchored.subset peerIn) different syncPeer
  exact fun index => (claim (index + 1)).1 index (Nat.lt_succ_self index)

/-- A stable window over the anchor from an anchored start with every anchor node
in sync with the primary, in which the term also stays quiet, without the
pre-vote clause, over all participants. -/
theorem stable_window_anchored [HasTimers W] {bounds : Bounds} {maxDelay : Real}
    (timers : trace.Valid (timerModel bounds.electionTimeout))
    (bounded : trace.Valid (boundedDelayModel maxDelay)) (nonneg : 0 <= maxDelay)
    (heartbeats : trace.HeartbeatScheduling (some bounds.heartbeatInterval))
    {fresh : Real} (ratio : bounds.heartbeatInterval + maxDelay < fresh)
    (freshLe : fresh <= bounds.electionTimeout / 2)
    {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants anchor : Finset NodeID}
    (initial : AnchoredStart trace start leader term participants anchor fresh)
    (good : GoodPeriod trace start duration participants)
    (active : Window.AnchorActive trace start duration anchor)
    (sync : InSync trace start leader term anchor)
    : StableWindow trace start duration leader term anchor
      /\ Window.StableTerm trace start duration leader term participants := by
  have elections :=
    Liveness.electionScheduling_of_timerModel admissible.coherent admissible.timing timers
  have matching :=
    window_matching_anchored admissible heartbeats elections bounded nonneg ratio freshLe
      initial good active sync
  have inv
      : forall index point,
          Within trace start duration index
          -> trace.stateAt index = some point
          -> AnchorInv participants anchor leader term (proto point)
              /\ NoProposals participants term point :=
    fun index point =>
      anchor_invariant_before admissible heartbeats elections bounded nonneg ratio freshLe
        initial good active (bound := index) (fun moment _ => matching moment) index point
        le_rfl
  obtain ⟨_, _, _, _, anchored, _⟩ := initial.quiet
  refine ⟨
    {
      stableLeader := fun index point within found =>
        ⟨(inv index point within found).1.quietAmong admissible found,
          NoProposals.mono (inv index point within found).2 anchored.subset⟩
      staysActive :=
        Window.AnchorActive.staysActive active good anchored.leaderIn anchored.subset
      liveQuorum := fun index point _ within found leaderFound =>
        (inv index point within found).1.liveQuorum good within found leaderFound
      lossless := fun index step packet within stepped dropped => by
        rintro (⟨source, target⟩ | ⟨source, target⟩)
        · exact good.lossless index step packet within stepped dropped
            ⟨source ▸ anchored.subset anchored.leaderIn, anchored.subset target⟩
        · exact good.lossless index step packet within stepped dropped
            ⟨anchored.subset source, target ▸ anchored.subset anchored.leaderIn⟩
    },
    fun index point within found =>
      ⟨(inv index point within found).1.quiet, (inv index point within found).2⟩
  ⟩

end Recorded

end CCFRaft.Proofs.Leadership
