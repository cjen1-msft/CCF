module

public import CCFRaft.Proofs.Duel.ElectedShort
public import CCFRaft.Proofs.Duel.SplitRace
public import CCFRaft.Proofs.Duel.CommittedWindow

@[expose] public section

/-!
# The duel round

NOT IMPORTED BY `Properties`. Public statement (i): one duel round reaches an
anchored start or the next round, and with a margin an anchored start.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open HasNetwork (pending)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## Steps of the composition -/

omit [HasLive W] [HasTimers W] [Config.InitialConfiguration] in
/-- A handoff within `later` of an index at most `bound` after `c` is a handoff within
`bound + later` of `c`. -/
theorem HandoffBy.shift {next : Nat} {origin nextPoint : W} {bound later fresh : Real}
    (le : c <= next) (originFound : trace.stateAt c = some origin)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + bound)
    (handoff : HandoffBy trace participants next later fresh)
    : HandoffBy trace participants c (bound + later) fresh := by
  sorry

omit [HasLive W] [HasTimers W] [Config.InitialConfiguration] in
theorem HandoffBy.mono {bound larger fresh : Real} (le : bound <= larger)
    (handoff : HandoffBy trace participants c bound fresh)
    : HandoffBy trace participants c larger fresh := by
  sorry

section Steps

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)

include setup originFound

/-- A primary of `term + 1` in the round hands off within four delays. -/
theorem RoundSetup.elected_case {index : Nat} {point : W} {leader : NodeID}
    {state : NodeState} (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : HandoffBy trace participants c (4 * maxDelay)
        (electionTimeout / 2 - 4 * maxDelay) := by
  sorry

/-- Every capped index of a leaderless round is within the round length plus the
overshoot. -/
theorem RoundSetup.capped_time
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    : forall index point,
        Capped trace participants c term index
        -> trace.stateAt index = some point
        -> time point <= time origin + roundLength electionTimeout maxDelay + jump := by
  sorry

/-- A leaderless round ends: some capped step moves a participant past `term + 1`. -/
theorem RoundSetup.first_raise
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    : exists next nextPoint,
        Capped trace participants c term next
        /\ trace.stateAt next = some nextPoint
        /\ exists step node state,
            trace.stepAt next = some step
            /\ node ∈ participants
            /\ nodeState (proto step.after) node = some state
            /\ term + 1 < state.currentTerm := by
  sorry

/-- The round's first step keeps every participant at most `term + 1`. -/
theorem RoundSetup.start_capped : Capped trace participants c term (c + 1) := by
  sorry

/-- The step that ends the round starts the next round. -/
theorem RoundSetup.next_start {next : Nat} {nextPoint : W}
    (capped : Capped trace participants c term next)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + roundLength electionTimeout maxDelay + jump)
    (raise
      : exists step node state,
          trace.stepAt next = some step
          /\ node ∈ participants
          /\ nodeState (proto step.after) node = some state
          /\ term + 1 < state.currentTerm)
    : c < next /\ RoundStart trace participants next (term + 1) := by
  sorry

/-- The next round, started within the round length, has the round's base, and the
window covers its first four delays. -/
theorem RoundSetup.base_at {next : Nat} {nextPoint : W} (le : c <= next)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + roundLength electionTimeout maxDelay)
    (round : RoundStart trace participants next (term + 1))
    : RoundBase nodes trace electionTimeout maxDelay jump start duration participants
        members next (term + 1)
      /\ forall index point,
          next <= index
          -> trace.stateAt index = some point
          -> time point <= time nextPoint + 4 * maxDelay
          -> Within trace start duration index := by
  sorry

end Steps

/-! ## The round -/

/-- (i) One duel round. From a round start at `c`, the run reaches an anchored start,
or the next round start, within a round length plus the overshoot. The next round
start is the first step after `c` that moves a participant past `term + 1`. If no
step of the round overshoots, the next round starts within a round length; if the
round also keeps a margin of `4 * maxDelay`, it reaches an anchored start within a
round length and four delays. -/
theorem duel_round
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    : HandoffBy trace participants c (roundLength electionTimeout maxDelay + jump)
        (electionTimeout / 2 - 4 * maxDelay)
      \/ exists next origin point,
          c < next
          /\ trace.stateAt c = some origin
          /\ trace.stateAt next = some point
          /\ Capped trace participants c term next
          /\ time point <= time origin + roundLength electionTimeout maxDelay + jump
          /\ RoundStart trace participants next (term + 1)
          /\ ((forall index step node,
                node ∈ participants
                -> c <= index
                -> index < next
                -> trace.stepAt index = some step
                -> NoOvershoot (some 0) step node)
              -> time point <= time origin + roundLength electionTimeout maxDelay
                  /\ (RoundMargin trace participants c term (4 * maxDelay)
                      -> HandoffBy trace participants c
                          (roundLength electionTimeout maxDelay + 4 * maxDelay)
                          (electionTimeout / 2 - 4 * maxDelay))) := by
  obtain ⟨step0, node0, state0, stepped0, -⟩ := setup.round.raise
  obtain ⟨origin, originFound⟩ : exists origin, trace.stateAt c = some origin :=
    ⟨_, setup.admissible.before stepped0⟩
  by_cases elected
    : exists index point leader state,
        Capped trace participants c term index
        /\ trace.stateAt index = some point
        /\ time point <= time origin + roundLength electionTimeout maxDelay + jump
        /\ leader ∈ participants
        /\ nodeState (proto point) leader = some state
        /\ state.role = .primary
        /\ state.currentTerm = term + 1
  · obtain ⟨index, point, leader, state, capped, found, timeLe, member, leaderFound, primary,
      termEq⟩ := elected
    left
    exact HandoffBy.mono
      (by
        unfold roundLength
        linarith [setup.nonnegative, setup.jumpNonnegative, setup.timeout_pos])
      (setup.elected_case originFound capped found timeLe member leaderFound primary termEq)
  have noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump) := by
    intro index point leader state capped found timeLe member leaderFound termEq primary
    exact elected ⟨index, point, leader, state, capped, found, by linarith, member,
      leaderFound, primary, termEq⟩
  obtain ⟨next, nextPoint, capped, nextFound, raise⟩ := setup.first_raise originFound noElection
  have timeNext := setup.capped_time originFound noElection next nextPoint capped nextFound
  obtain ⟨lt, roundStart⟩ := setup.next_start originFound capped nextFound timeNext raise
  right
  refine ⟨
    next,
    origin,
    nextPoint,
    lt,
    originFound,
    nextFound,
    capped,
    timeNext,
    roundStart,
    fun noOvershoot => ?_
  ⟩
  have timeZero
      : time nextPoint <= time origin + roundLength electionTimeout maxDelay := by
    have := setup.progress originFound noElection le_rfl setup.jumpNonnegative capped nextFound
      fun earlier step node member first last stepped =>
        noOvershoot earlier step node member first last stepped
    linarith
  refine ⟨timeZero, fun margin => ?_⟩
  obtain ⟨first, winner, step, cLe, firstLe, stepped, race⟩ :=
    setup.race_found originFound noElection capped nextFound timeZero raise noOvershoot margin
  obtain ⟨leaderIndex, won⟩ :=
    Racing.race_won setup.admissible setup.delay setup.timers setup.diverges
      setup.nonnegative setup.ratio race stepped
  obtain ⟨firstPoint, leaderPoint, firstFound, leaderFound, firstLeLeader, leaderTime, -,
    leaderState, leaderStateFound, primary, termEq⟩ := won.found
  have member := (race.competes firstPoint firstFound).1
  have nextLt : next < leaderIndex := by
    by_contra notLt
    have := (capped.down (le_trans cLe firstLeLeader) (by omega)).2 leaderIndex leaderPoint
      winner leaderState (le_trans cLe firstLeLeader) le_rfl leaderFound member
      leaderStateFound
    omega
  obtain ⟨base, inside⟩ := setup.base_at originFound (le_trans cLe firstLe) nextFound timeZero
    roundStart
  have firstTime := setup.admissible.time_le firstLe firstFound nextFound
  have handoff :=
    base.handoff_within nextFound inside nextLt.le leaderFound (by linarith) member
      leaderStateFound primary termEq
  exact HandoffBy.shift (le_trans cLe firstLe) originFound nextFound timeZero handoff

end CCFRaft.Proofs.Duel.Round
