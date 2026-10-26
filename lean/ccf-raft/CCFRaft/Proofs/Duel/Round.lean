module

public import CCFRaft.Proofs.Duel.RoundInv

@[expose] public section

/-!
# One duel round

NOT IMPORTED BY `Properties`. The deterministic step of the duel.

A round of term `term + 1` starts at a raise: at index `c` every participant, and
every packet between participants, is at most `term`, and step `c` moves a
participant past `term` (a candidacy of `term + 1`). Within `electionTimeout +
4 * maxDelay` (plus any overshoot `jump`) the run reaches either an anchored start
or the next round, of `term + 2`. If the round's draws keep a margin, it reaches an
anchored start.

The round runs in three phases.
- By `time c + maxDelay` every participant has adopted `term + 1`: the raiser's
  RequestVote reaches all of them.
- Candidacies of `term + 1` start before that, so any election of `term + 1`
  happens by `time c + 3 * maxDelay`. Its voters then settle on the first
  AppendEntries by `time c + 4 * maxDelay` (`round_elected`).
- Otherwise every participant's deadline is fixed by `time c + 2 * maxDelay`,
  and no participant of `term + 1` times out before `time c + electionTimeout / 2`.
  The first participant that can still win a pre-vote quorum and times out starts
  a race (`Racing.Race`). With a margin the race is won (`Racing.race_won`) and
  the winner's round is elected; without one, its pre-vote completes, or someone
  else raises, within two delays.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

section Lemmas

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## The round's packets and terms -/

/-- By `time c + maxDelay` every participant has adopted `term + 1`. -/
theorem RoundSetup.adopted
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {index : Nat} {origin point : W} (capped : Capped trace participants c term index)
    (originFound : trace.stateAt c = some origin)
    (found : trace.stateAt index = some point)
    (late : time origin + maxDelay < time point)
    : forall node state,
        node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1 := by
  intro node state nodeIn nodeFound
  obtain ⟨step, stepped, reached⟩ := setup.reached_start originFound
  have upper := capped.2 index point node state capped.1 le_rfl found nodeIn nodeFound
  have next : c + 1 <= index := by
    by_contra small
    have : index = c := by have := capped.1; omega
    subst this
    rw [originFound, Option.some.injEq] at found
    subst found
    linarith [setup.nonnegative]
  rcases setup.reached_from originFound nodeIn (Nat.le_succ c)
      (Trace.stateAt_succ_of_stepAt stepped) (reached node nodeIn) index point next found with
    high | ⟨packet, _, member, alive, _, targetEq, _, _, sentLe⟩
  · have := high state nodeFound
    omega
  · have := setup.delay_at found member (targetEq ▸ alive)
    linarith

theorem RoundSetup.packets_base
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin) {packet : Packet}
    (member : packet ∈ pending origin) (source : packet.envelope.source ∈ participants)
    (target : packet.envelope.target ∈ participants)
    : Shape term (time origin) electionTimeout maxDelay packet := by
  have low := setup.round.messages origin packet originFound member source target
  have sentLe := setup.sent_le originFound member
  have := setup.nonnegative
  refine ⟨
    by omega,
    fun _ _ => by linarith,
    fun _ _ => by linarith,
    fun payload => ?_,
    fun request payload termEq => ?_,
    fun payload => ?_
  ⟩
  · rw [payload] at low
    simp [Message.term] at low
  · rw [payload] at low
    simp [Message.term] at low
    omega
  · rw [payload] at low
    simp [Message.term] at low

theorem RoundSetup.packets_step
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event} (le : c <= index)
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (before
      : forall packet,
          packet ∈ pending step.before
          -> packet.envelope.source ∈ participants
          -> packet.envelope.target ∈ participants
          -> Shape term (time origin) electionTimeout maxDelay packet)
    : forall packet,
        packet ∈ pending step.after
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> Shape term (time origin) electionTimeout maxDelay packet := by
  intro packet member sourceIn targetIn
  rcases selected : step.action.action with _ | action
  · exact before packet (setup.pending_env stepped selected member) sourceIn targetIn
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, _, cause, ran, ledger⟩ :=
    setup.view stepped selected
  rcases Racing.pending_after_cases ledger member with old | ⟨new, sentEq⟩
  · exact before packet old sourceIn targetIn
  have sum := Racing.sends_run (summary actor pre event) ran
  have ok := Summary.sends sum _ new
  have round := Racing.sends_run (round_sends actor pre event) ran _ new
  have actorEq : packet.envelope.source = actor := ok.1
  have actorIn : actor ∈ participants := actorEq ▸ sourceIn
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have postLe := capped.2 (index + 1) step.after actor post capped.1 le_rfl afterFound actorIn
    postFound
  have termLe := Summary.term_le sum
  have adopted : time origin + maxDelay < time step.before -> pre.currentTerm = term + 1 :=
    fun late =>
      setup.adopted (capped.down le (Nat.le_succ index)) originFound beforeFound late actor pre
        actorIn preFound
  obtain ⟨payloadLe, payloadEq⟩ := sendOK_terms ok (setup.log_le afterFound postFound)
  have := setup.nonnegative
  unfold Shape
  rw [sentEq]
  refine ⟨
    by omega,
    fun low notResponse => ?_,
    fun request payload => ?_,
    fun payload => ?_,
    fun request payload termEq => ?_,
    fun payload => ?_
  ⟩
  · by_contra late
    have := adopted (lt_of_not_ge late)
    have := payloadEq notResponse
    omega
  · have rv := ok.2
    simp only [payload] at rv
    by_contra late
    have := adopted (lt_of_not_ge late)
    omega
  · have rv := ok.2
    simp only [payload] at rv
    obtain ⟨request, eventEq, _, _, _⟩ := rv.2 trivial
    obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, deliveredPayload⟩ :=
      setup.received stepped cause eventEq
    have shape := before delivered consumed (sourceEq ▸ targetIn) (targetEq ▸ actorIn)
    have sentLe := shape.2.2.1 request deliveredPayload
    have alive : delivered.envelope.target ∈ live step.before :=
      setup.admissible.actor_live stepped (by simp [delivery, Liveness.Event.actor])
    have := setup.delay_at beforeFound consumed alive
    linarith
  · obtain ⟨eventEq, requestEq⟩ := round.1 request payload
    have action := setup.local_of_event cause eventEq
    exact setup.timeout_late originFound le stepped actorIn preFound (by omega) action
  · obtain ⟨request, eventEq, requestEq⟩ := round.2.1 _ payload rfl
    obtain ⟨delivered, _, consumed, targetEq, sourceEq, deliveredPayload⟩ :=
      setup.received stepped cause eventEq
    have shape := before delivered consumed (sourceEq ▸ targetIn) (targetEq ▸ actorIn)
    have late := shape.2.2.2.2.1 request deliveredPayload requestEq
    linarith [setup.sent_le beforeFound consumed]

/-- What a packet between participants in the round can be, by when it was sent. -/
theorem RoundSetup.packets
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {index : Nat} {origin point : W} (capped : Capped trace participants c term index)
    (originFound : trace.stateAt c = some origin)
    (found : trace.stateAt index = some point) {packet : Packet}
    (member : packet ∈ pending point) (source : packet.envelope.source ∈ participants)
    (target : packet.envelope.target ∈ participants)
    : packet.envelope.payload.term <= term + 1
      /\ (packet.envelope.payload.term <= term
          -> (forall response,
                Not (packet.envelope.payload = .appendEntriesResponse response))
          -> packet.sentAt <= time origin + maxDelay)
      /\ (forall request,
            packet.envelope.payload = .requestVoteRequest request
            -> packet.sentAt <= time origin + maxDelay)
      /\ (packet.envelope.payload
            = .requestVoteResponse { term := term + 1, voteGranted := true }
          -> packet.sentAt <= time origin + 2 * maxDelay)
      /\ (forall request,
            packet.envelope.payload = .requestPreVoteRequest request
            -> request.term = term + 1
            -> time origin + electionTimeout / 2 <= packet.sentAt)
      /\ (packet.envelope.payload
            = .requestPreVoteResponse { term := term + 1, voteGranted := true }
          -> time origin + electionTimeout / 2 <= packet.sentAt) := by
  suffices all
      : forall earlier earlierPoint,
          c <= earlier
          -> earlier <= index
          -> trace.stateAt earlier = some earlierPoint
          -> forall packet,
              packet ∈ pending earlierPoint
              -> packet.envelope.source ∈ participants
              -> packet.envelope.target ∈ participants
              -> Shape term (time origin) electionTimeout maxDelay packet from
    all index point capped.1 le_rfl found packet member source target
  intro earlier
  induction earlier with
  | zero =>
      intro earlierPoint le _ earlierFound
      have : c = 0 := by omega
      subst this
      rw [originFound, Option.some.injEq] at earlierFound
      subst earlierFound
      exact fun packet member source target =>
        setup.packets_base originFound member source target
  | succ earlier ih =>
      intro earlierPoint le bound earlierFound
      by_cases atStart : c = earlier + 1
      · subst atStart
        rw [originFound, Option.some.injEq] at earlierFound
        subst earlierFound
        exact fun packet member source target =>
          setup.packets_base originFound member source target
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp earlierFound
      exact setup.packets_step originFound (by omega) stepped (capped.down le bound)
        (ih step.before (by omega) (by omega) (setup.admissible.before stepped))

omit [HasTime W] [HasLive W] [HasTimers W] in
/-- No vote proposal of `term + 1` is pending between participants. -/
def NoProposal (participants : Finset NodeID) (term : Nat) (point : W) : Prop :=
  forall packet,
    packet ∈ pending point
    -> packet.envelope.source ∈ participants
    -> packet.envelope.target ∈ participants
    -> Not (packet.envelope.payload = .proposeRequestVoteRequest (term + 1))

/-- A step early in the round keeps every participant at most `term + 1`, and sends no
vote proposal between participants. -/
theorem RoundSetup.capped_step
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event} (le : c <= index)
    (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term index)
    (early : time step.after < time origin + electionTimeout / 2)
    (quiet : NoProposal participants term step.before)
    : (forall node state,
        node ∈ participants
        -> nodeState (proto step.after) node = some state
        -> state.currentTerm <= term + 1)
      /\ NoProposal participants term step.after := by
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeLe := (setup.admissible.timing.next stepped).1
  have within := setup.within_of_time originFound le beforeFound (by linarith)
  have withinAfter :=
    setup.within_of_time originFound (Nat.le_succ_of_le le) afterFound (by linarith)
  have isolated
      : forall packet,
          step.action = .deliver packet
          -> packet.envelope.target ∈ participants
          -> packet.envelope.source ∈ participants :=
    fun packet delivery targetIn =>
      setup.period.isolated index step packet.envelope within stepped
        (by simp [delivery, Liveness.Event.delivered]) targetIn
  have shape
      : forall packet,
          packet ∈ pending step.before
          -> packet.envelope.source ∈ participants
          -> packet.envelope.target ∈ participants
          -> Shape term (time origin) electionTimeout maxDelay packet :=
    fun packet member sourceIn targetIn =>
      setup.packets capped originFound beforeFound member sourceIn targetIn
  rcases selected : step.action.action with _ | action
  · have same := setup.admissible.stutter stepped selected
    refine ⟨fun node state nodeIn found => ?_, fun packet member => ?_⟩
    · rw [same] at found
      exact capped.2 index step.before node state capped.1 le_rfl beforeFound nodeIn found
    · exact quiet packet (setup.pending_env stepped selected member)
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, ledger⟩ :=
    setup.view stepped selected
  have sum := Racing.sends_run (summary actor pre event) ran
  refine ⟨fun node state nodeIn found => ?_, fun packet member sourceIn targetIn => ?_⟩
  · by_cases actorEq : node = actor
    swap
    · rw [others node actorEq] at found
      exact capped.2 index step.before node state capped.1 le_rfl beforeFound nodeIn found
    subst actorEq
    rw [postFound, Option.some.injEq] at found
    subst found
    have preLe := capped.2 index step.before node pre capped.1 le_rfl beforeFound nodeIn preFound
    rcases Summary.term_cause sum with termLe | ⟨termEq, fresh⟩ | ⟨source, message, eventEq, termLe⟩
    · omega
    · by_cases low : pre.currentTerm <= term
      · omega
      have preEq : pre.currentTerm = term + 1 := by omega
      rcases fresh with eventEq | ⟨source, response, eventEq, _⟩ | ⟨source, eventEq⟩
      · have := setup.timeout_late originFound le stepped nodeIn preFound preEq
          (setup.local_of_event cause eventEq)
        linarith
      · obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, payload⟩ :=
          setup.received stepped cause eventEq
        have sourceIn := isolated delivered delivery (targetEq ▸ nodeIn)
        have deliveredShape := shape delivered consumed sourceIn (targetEq ▸ nodeIn)
        have responseLe := deliveredShape.1
        rw [payload] at responseLe
        simp only [Message.term] at responseLe
        have notGranted
            : Not (response.term = term + 1 /\ response.voteGranted = true) := by
          rintro ⟨responseTerm, granted⟩
          have late := deliveredShape.2.2.2.2.2 (by
            rw [payload]
            obtain ⟨t, g⟩ := response
            simp only at responseTerm granted
            subst responseTerm granted
            rfl)
          linarith [setup.sent_le beforeFound consumed]
        rw [eventEq] at ran
        obtain ⟨middle, observed, rest⟩ :=
          Racing.sends_run (Racing.preVoteResponse_receive node source pre response) ran
        split at rest
        · rename_i condition
          exfalso
          rcases observed with rfl | ⟨_, rfl⟩
          · exact notGranted ⟨by omega, condition.2.2.2⟩
          · simp [bumpedState] at condition
        · rw [rest.1]
          rcases observed with rfl | ⟨_, rfl⟩
          · exact preLe
          · simpa [bumpedState] using responseLe
      · obtain ⟨delivered, _, consumed, targetEq, sourceEq, payload⟩ :=
          setup.received stepped cause eventEq
        exact absurd (by rw [payload, preEq])
          (quiet delivered consumed (isolated delivered (by assumption) (targetEq ▸ nodeIn))
            (targetEq ▸ nodeIn))
    · obtain ⟨delivered, delivery, consumed, targetEq, sourceEq, payload⟩ :=
        setup.received stepped cause eventEq
      have sourceIn := isolated delivered delivery (targetEq ▸ nodeIn)
      have := (shape delivered consumed sourceIn (targetEq ▸ nodeIn)).1
      rw [payload] at this
      omega
  · rcases Racing.pending_after_cases ledger member with old | ⟨new, _⟩
    · exact quiet packet old sourceIn targetIn
    intro payload
    have actorEq : packet.envelope.source = actor := (Summary.sends sum _ new).1
    have actorIn : actor ∈ participants := actorEq ▸ sourceIn
    rcases (Racing.sends_run (round_sends actor pre event) ran _ new).2.2 _ payload with
      eventEq | retired
    · exact setup.period.noNominations index step actor within stepped
        (setup.local_of_event cause eventEq)
    · exact setup.active (index + 1) step.after actor post withinAfter afterFound actorIn
        postFound retired

theorem RoundSetup.capped_from
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    : forall index point,
        c <= index
        -> trace.stateAt index = some point
        -> time point < time origin + electionTimeout / 2
        -> Capped trace participants c term index
            /\ NoProposal participants term point := by
  have base
      : Capped trace participants c term c /\ NoProposal participants term origin := by
    refine ⟨⟨le_rfl, fun earlier point node state first last found nodeIn nodeFound => ?_⟩,
      fun packet member sourceIn targetIn payload => ?_⟩
    · have : earlier = c := by omega
      subst this
      rw [originFound, Option.some.injEq] at found
      subst found
      have := setup.round.low origin node state originFound nodeIn nodeFound
      omega
    · have := setup.round.messages origin packet originFound member sourceIn targetIn
      rw [payload] at this
      simp [Message.term] at this
  intro index
  induction index with
  | zero =>
      intro point le found _
      have : c = 0 := by omega
      subst this
      rw [originFound, Option.some.injEq] at found
      subst found
      exact base
  | succ index ih =>
      intro point le found early
      by_cases atStart : c = index + 1
      · subst atStart
        rw [originFound, Option.some.injEq] at found
        subst found
        exact base
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      have beforeFound := setup.admissible.before stepped
      obtain ⟨capped, quiet⟩ :=
        ih step.before (by omega) beforeFound
          (lt_of_le_of_lt (setup.admissible.timing.next stepped).1 early)
      obtain ⟨terms, quietAfter⟩ :=
        setup.capped_step originFound (by omega) stepped capped early quiet
      refine ⟨⟨le, fun earlier point node state first last found nodeIn nodeFound => ?_⟩,
        quietAfter⟩
      by_cases atEnd : earlier = index + 1
      · subst atEnd
        rw [Trace.stateAt_succ_of_stepAt stepped, Option.some.injEq] at found
        subst found
        exact terms node state nodeIn nodeFound
      · exact capped.2 earlier point node state first (by omega) found nodeIn nodeFound

/-- No participant moves past `term + 1` before half an election timeout into the
round: that needs a timeout in `term + 1`. -/
theorem RoundSetup.capped
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    : forall index point,
        c <= index
        -> trace.stateAt index = some point
        -> time point < time origin + electionTimeout / 2
        -> Capped trace participants c term index :=
  fun index point le found early =>
    (setup.capped_from originFound index point le found early).1

/-- A primary of `term + 1` in the round was elected by `time c + 3 * maxDelay`. -/
theorem RoundSetup.elected_early
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {index : Nat} {point : W} {leader : NodeID} {state : NodeState}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point) (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : exists elected origin electedPoint electedState,
        c <= elected
        /\ elected <= index
        /\ trace.stateAt c = some origin
        /\ trace.stateAt elected = some electedPoint
        /\ time electedPoint <= time origin + 3 * maxDelay
        /\ nodeState (proto electedPoint) leader = some electedState
        /\ electedState.role = .primary
        /\ electedState.currentTerm = term + 1 := by
  sorry

end Lemmas

end CCFRaft.Proofs.Duel.Round
