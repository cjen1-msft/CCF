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

omit [HasLive W] [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
/-- A handoff within `later` of an index at most `bound` after `c` is a handoff within
`bound + later` of `c`. -/
theorem HandoffBy.shift {next : Nat} {origin nextPoint : W} {bound later fresh : Real}
    (le : c <= next) (originFound : trace.stateAt c = some origin)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + bound)
    (handoff : HandoffBy trace participants next later fresh)
    : HandoffBy trace participants c (bound + later) fresh := by
  obtain ⟨index, leader, term', anchor, nextOrigin, point, nextLe, nextOriginFound, found,
    timeLe', anchored⟩ := handoff
  rw [nextFound, Option.some.injEq] at nextOriginFound
  subst nextOriginFound
  exact ⟨
    index,
    leader,
    term',
    anchor,
    origin,
    point,
    le_trans le nextLe,
    originFound,
    found,
    by linarith,
    anchored
  ⟩

omit [HasLive W] [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
theorem HandoffBy.mono {bound larger fresh : Real} (le : bound <= larger)
    (handoff : HandoffBy trace participants c bound fresh)
    : HandoffBy trace participants c larger fresh := by
  obtain ⟨index, leader, term', anchor, origin, point, cLe, originFound, found, timeLe,
    anchored⟩ := handoff
  exact ⟨
    index,
    leader,
    term',
    anchor,
    origin,
    point,
    cLe,
    originFound,
    found,
    by linarith,
    anchored
  ⟩

omit [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
/-- A good period seen from a later index `c`, up to the same end. -/
theorem GoodPeriod.later {origin point : W}
    (period : GoodPeriod trace start duration participants) (le : start <= c)
    (originFound : trace.stateAt start = some origin)
    (found : trace.stateAt c = some point)
    : GoodPeriod trace c (time origin + duration - time point) participants := by
  have within
      : forall index, Within trace c (time origin + duration - time point) index
          -> Within trace start duration index := by
    intro index inside
    refine ⟨le_trans le inside.1, fun first last firstFound lastFound => ?_⟩
    rw [originFound, Option.some.injEq] at firstFound
    subst firstFound
    have := inside.2 point last found lastFound
    linarith
  exact {
    participantsLive := fun index point node inside =>
      period.participantsLive index point node (within index inside)
    quorum := fun index point node state inside =>
      period.quorum index point node state (within index inside)
    noReconfiguration := fun index step node entries inside =>
      period.noReconfiguration index step node entries (within index inside)
    noNominations := fun index step node inside =>
      period.noNominations index step node (within index inside)
    noQuorumChecks := fun index step node inside =>
      period.noQuorumChecks index step node (within index inside)
    lossless := fun index step packet inside =>
      period.lossless index step packet (within index inside)
    isolated := fun index step envelope inside =>
      period.isolated index step envelope (within index inside) }

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
  obtain ⟨elected, origin', electedPoint, electedState, first, -, originFound', electedFound,
    electedTime, electedNode, electedPrimary, electedTerm⟩ :=
    setup.elected_early capped found
      (fun other otherFound => by
        rw [originFound, Option.some.injEq] at otherFound
        subst otherFound
        exact timeLe)
      member leaderFound primary termEq
  rw [originFound, Option.some.injEq] at originFound'
  subst originFound'
  exact setup.toRoundBase.handoff_within originFound
    ((setup.inside originFound).mono
      (by
        unfold roundLength
        linarith [setup.nonnegative, setup.jumpNonnegative, setup.timeout_pos]))
    first electedFound
    (by linarith [setup.nonnegative])
    member electedNode electedPrimary electedTerm

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
  intro index
  induction index using Nat.strong_induction_on with
  | _ index ih =>
      intro point capped found
      refine setup.progress originFound noElection setup.jumpNonnegative le_rfl capped
        found ?_
      intro earlier step node member first last stepped
      have beforeFound := setup.admissible.before stepped
      have earlierTime :=
        ih earlier last step.before (capped.down first last.le) beforeFound
      exact setup.overshoot earlier step node member
        (setup.inside originFound earlier step.before first beforeFound (by linarith))
        stepped

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
  classical
  obtain ⟨far, farPoint, farFound, farTime⟩ :=
    setup.diverges (time origin + roundLength electionTimeout maxDelay + jump + 1)
  have cappedStart : Capped trace participants c term c := by
    refine ⟨le_rfl, fun earlier point node state first last found member nodeFound => ?_⟩
    have : earlier = c := by omega
    subst this
    have := setup.round.low point node state found member nodeFound
    omega
  have ended : exists index, c <= index /\ Not (Capped trace participants c term index) := by
    have cLe : c <= far := by
      by_contra lt
      have := setup.admissible.time_le (Nat.le_of_not_le lt) farFound originFound
      unfold roundLength at farTime
      linarith [setup.nonnegative, setup.jumpNonnegative, setup.timeout_pos]
    refine ⟨far, cLe, fun capped => ?_⟩
    have := setup.capped_time originFound noElection far farPoint capped farFound
    linarith
  have spec := Nat.find_spec ended
  have notStart : Nat.find ended ≠ c := fun eq => spec.2 (by rw [eq]; exact cappedStart)
  obtain ⟨next, nextEq⟩ : exists next, Nat.find ended = next + 1 := by
    rcases h : Nat.find ended with _ | next
    · rw [h] at spec notStart
      have : c = 0 := by omega
      exact absurd this.symm notStart
    · exact ⟨next, rfl⟩
  rw [nextEq] at spec notStart
  have cLe : c <= next := by omega
  have capped : Capped trace participants c term next := by
    by_contra notCapped
    have := Nat.find_min' ended ⟨cLe, notCapped⟩
    omega
  have notCapped := spec.2
  simp only [Capped, not_and, not_forall, not_le] at notCapped
  obtain ⟨earlier, point, node, state, first, last, found, member, nodeFound, gt⟩ :=
    notCapped spec.1
  have earlierEq : earlier = next + 1 := by
    by_contra ne
    have := capped.2 earlier point node state first (by omega) found member nodeFound
    omega
  subst earlierEq
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
  exact ⟨
    next,
    step.before,
    capped,
    setup.admissible.before stepped,
    step,
    node,
    state,
    stepped,
    member,
    nodeFound,
    gt
  ⟩

/-- The round's first step keeps every participant at most `term + 1`. -/
theorem RoundSetup.start_capped : Capped trace participants c term (c + 1) := by
  have cappedStart : Capped trace participants c term c := by
    refine ⟨le_rfl, fun earlier point node state first last found member nodeFound => ?_⟩
    have : earlier = c := by omega
    subst this
    have := setup.round.low point node state found member nodeFound
    omega
  refine ⟨
    Nat.le_succ c,
    fun earlier point node state first last found nodeIn nodeFound => ?_
  ⟩
  rcases Nat.lt_or_ge earlier (c + 1) with lt | ge
  · exact cappedStart.2 earlier point node state first (by omega) found nodeIn nodeFound
  have earlierEq : earlier = c + 1 := by omega
  subst earlierEq
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
  have beforeFound := setup.admissible.before stepped
  rw [originFound, Option.some.injEq] at beforeFound
  subst beforeFound
  have within :=
    setup.inside originFound c step.before le_rfl originFound
      (by
        unfold roundLength
        linarith [setup.nonnegative, setup.jumpNonnegative, setup.timeout_pos])
  have isolated
      : forall packet,
          step.action = .deliver packet
          -> packet.envelope.target ∈ participants
          -> packet.envelope.source ∈ participants :=
    fun packet delivery targetIn =>
      setup.period.isolated c step packet.envelope within stepped
        (by simp [delivery, Liveness.Event.delivered]) targetIn
  have low := fun node state =>
    cappedStart.2 c step.before node state le_rfl le_rfl originFound
  rcases selected : step.action.action with _ | action
  · have same := setup.admissible.stutter stepped selected
    rw [same] at nodeFound
    have := low node state nodeIn nodeFound
    omega
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, ledger⟩ :=
    setup.view stepped selected
  have sum := Racing.sends_run (Safety.summary actor pre event) ran
  by_cases actorEq : node = actor
  swap
  · rw [others node actorEq] at nodeFound
    have := low node state nodeIn nodeFound
    omega
  subst actorEq
  rw [postFound, Option.some.injEq] at nodeFound
  subst nodeFound
  have preLe := setup.round.low step.before node pre originFound nodeIn preFound
  rcases Safety.Summary.term_cause sum with termLe | ⟨termEq, _⟩ | ⟨source, message, eventEq, termLe⟩
  · omega
  · omega
  · obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, payload⟩ :=
      setup.received stepped cause eventEq
    have sourceIn := isolated delivered delivery (targetEq ▸ nodeIn)
    have := (setup.packets cappedStart originFound originFound consumed sourceIn
      (targetEq ▸ nodeIn)).1
    rw [payload] at this
    omega

/-- The step that ends the round starts the next round. -/
theorem RoundSetup.next_start {next : Nat} {nextPoint : W}
    (capped : Capped trace participants c term next)
    (nextFound : trace.stateAt next = some nextPoint)
    (raise
      : exists step node state,
          trace.stepAt next = some step
          /\ node ∈ participants
          /\ nodeState (proto step.after) node = some state
          /\ term + 1 < state.currentTerm)
    : c < next /\ RoundStart trace participants next (term + 1) := by
  obtain ⟨step, node, state, stepped, member, nodeFound, gt⟩ := raise
  refine ⟨?_, ⟨fun point node state found member nodeFound => ?_,
    fun point packet found pending sourceIn targetIn => ?_,
    ⟨step, node, state, stepped, member, nodeFound, gt⟩⟩⟩
  · by_contra notLt
    have : next = c := by have := capped.1; omega
    subst this
    have := (setup.start_capped originFound).2 (next + 1) step.after node state
      (Nat.le_succ _) le_rfl (Trace.stateAt_succ_of_stepAt stepped) member nodeFound
    omega
  · exact capped.2 next point node state capped.1 le_rfl found member nodeFound
  · rw [nextFound, Option.some.injEq] at found
    subst found
    exact (setup.packets capped originFound nextFound pending sourceIn targetIn).1

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
  obtain ⟨periodOrigin, periodFound⟩ := Trace.stateAt_of_le setup.startLe originFound
  have covers := setup.covers periodOrigin origin periodFound originFound
  have later := GoodPeriod.later setup.period setup.startLe periodFound originFound
  have nextWithin
      : Within trace c (time periodOrigin + duration - time origin) next := by
    refine ⟨le, fun first last firstFound lastFound => ?_⟩
    rw [originFound, Option.some.injEq] at firstFound
    rw [nextFound, Option.some.injEq] at lastFound
    subst firstFound lastFound
    unfold roundLength at covers timeLe
    linarith [setup.nonnegative, setup.jumpNonnegative]
  refine ⟨
    {
      setup.toRoundBase with
        round
        startLe := le_trans setup.startLe le
        membership :=
          fun point found =>
            Leadership.Membership.window setup.admissible later setup.membership next
              point nextWithin found
        configured :=
          fun point found =>
            Duel.ConfigurationCommitted.window setup.admissible later setup.configured
              next point nextWithin found
    },
    ?_
  ⟩
  intro index point first found timeLe'
  refine ⟨
    le_trans setup.startLe (le_trans le first),
    fun start' last startFound lastFound => ?_
  ⟩
  rw [periodFound, Option.some.injEq] at startFound
  rw [found, Option.some.injEq] at lastFound
  subst startFound lastFound
  unfold roundLength at covers timeLe
  linarith [setup.nonnegative, setup.jumpNonnegative]

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
  obtain ⟨lt, roundStart⟩ := setup.next_start originFound capped nextFound raise
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
