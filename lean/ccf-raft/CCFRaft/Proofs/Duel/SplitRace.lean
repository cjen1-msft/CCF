module

public import CCFRaft.Proofs.Duel.SplitResets
public import CCFRaft.Proofs.Duel.SplitProgress
public import CCFRaft.Proofs.Duel.ElectedVoters

@[expose] public section

/-!
# The leaderless round: the race

NOT IMPORTED BY `Properties`. A raise of a leaderless round needs a pre-vote quorum,
so some participant that can gather one timed out first. With no overshoot its
timeout is at its deadline, and with a margin every other such participant's
deadline is more than four delays later: each was last reset at most its second
time in the round, and only by adoption, a vote, or its own timeouts. That is a
`Racing.Race`.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.StablePrimary (hasQuorum_mono)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## What raises a node's term -/

section Node

open CCF
open CCFRaft.Proofs.Safety

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

/-- The fresh campaigns that raise a node's term by one without a message of the new
term: a timeout with a self quorum, a pre-vote quorum, or a vote proposal. -/
def Fire (self : NodeID) (before : NodeState) (event : Model.Node.Event) : Prop :=
  (event = .internal (.timeout .election) /\ hasQuorum before.activeConfigurations {self})
  \/ (exists source,
        event
          = .receive source
              (.requestPreVoteResponse
                { term := before.currentTerm, voteGranted := true })
        /\ before.role = .preVoteCandidate
        /\ hasQuorum before.activeConfigurations (insert source before.preVotesGranted))
  \/ exists source,
      event = .receive source (.proposeRequestVoteRequest before.currentTerm)

/-- A raise either received a message of at least the new term or is a fresh
campaign. -/
def Trigger (self : NodeID) (before : NodeState) (event : Model.Node.Event)
    (after : NodeState)
    : Prop :=
  before.currentTerm < after.currentTerm
  -> (exists source message,
        event = .receive source message /\ after.currentTerm <= message.term)
      \/ Fire self before event

omit [Config.InitialConfiguration] in
theorem trigger_generic (before : NodeState) (event : Model.Node.Event)
    (fresh : Not (FreshCause before event))
    : Sends (fun after _ => Trigger self before event after)
        (Model.Node.step caps self before event) :=
  Sends.mono (summary self before event)
    fun _ _ sum lt => by
      rcases Summary.term_cause sum with le | ⟨_, cause⟩ | message
      · omega
      · exact absurd cause fresh
      · exact Or.inl message

omit [Config.InitialConfiguration] in
theorem trigger_sends (before : NodeState) (event : Model.Node.Event)
    : Sends (fun after _ => Trigger self before event after)
        (Model.Node.step caps self before event) := by
  cases event with
  | internal input =>
      cases input with
      | timeout kind =>
          cases kind with
          | election =>
              refine Sends.mono (Racing.startElection_outcome self before)
                fun after sent ⟨_, outcome⟩ lt => ?_
              split at outcome
              · rename_i quorum
                exact Or.inr (Or.inl ⟨rfl, quorum⟩)
              · rw [outcome.1] at lt
                simp [preVoteState] at lt
          | checkQuorum => exact trigger_generic self before _ (by simp [FreshCause])
      | _ => exact trigger_generic self before _ (by simp [FreshCause])
  | receive source message =>
      cases message with
      | requestPreVoteResponse response =>
          refine Sends.mono (Racing.preVoteResponse_receive self source before response)
            fun after sent ⟨middle, observed, rest⟩ lt => ?_
          have bumped : before.currentTerm < middle.currentTerm
              -> middle.currentTerm <= response.term := by
            rcases observed with rfl | ⟨_, rfl⟩
            · intro h
              omega
            · intro _
              simp [bumpedState]
          split at rest
          · rename_i cond
            obtain ⟨_, preVote, termEq, granted⟩ := cond
            unfold Racing.PreVoted at rest
            split at rest
            · rename_i quorum
              rcases observed with rfl | ⟨_, rfl⟩
              · refine Or.inr (Or.inr (Or.inl ⟨source, ?_, preVote, quorum⟩))
                obtain ⟨t, g⟩ := response
                simp only at termEq granted
                subst termEq granted
                rfl
              · simp [bumpedState] at preVote
            · rw [rest.1] at lt ⊢
              exact Or.inl ⟨source, _, rfl, by simpa [Message.term] using bumped lt⟩
          · rw [rest.1] at lt ⊢
            exact Or.inl ⟨source, _, rfl, by simpa [Message.term] using bumped lt⟩
      | proposeRequestVoteRequest term =>
          simp only [Model.Node.step, receive]
          refine Sends.ite' (fun _ => Sends.pure' fun lt => absurd lt (lt_irrefl _))
            fun _ => ?_
          simp only [observeTerm, handleProposeRequestVoteRequest]
          refine Sends.ite' (fun cond => ?_) fun _ =>
            Sends.pure' fun lt => absurd lt (lt_irrefl _)
          exact Sends.mono (Racing.becomeCandidate_candidacy self before)
            fun _ _ _ _ => Or.inr (Or.inr (Or.inr ⟨source, by rw [cond.1]⟩))
      | _ => exact trigger_generic self before _ (by simp [FreshCause])

omit [Config.InitialConfiguration] in
/-- A raise received a message of at least the new term, or is a fresh campaign one
term up. -/
theorem raise_cause (before : NodeState) (event : Model.Node.Event)
    : Sends
        (fun after _ =>
          before.currentTerm < after.currentTerm
          -> (exists source message,
                event = .receive source message /\ after.currentTerm <= message.term)
              \/ (after.currentTerm = before.currentTerm + 1 /\ Fire self before event))
        (Model.Node.step caps self before event) :=
  Sends.mono (Sends.and' (summary self before event) (trigger_sends self before event))
    fun _ _ ⟨sum, trigger⟩ lt => by
      rcases trigger lt with message | fire
      · exact Or.inl message
      · rcases Summary.term_cause sum with le | ⟨eq, _⟩ | message
        · omega
        · exact Or.inr ⟨eq, fire⟩
        · exact Or.inl message

end Node

/-! ## Trace utilities -/

section Utilities

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)

include setup

/-- A node recorded before a step is recorded after it. -/
theorem RoundSetup.race_state_step {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {node : NodeID} {state : NodeState}
    (found : nodeState (proto step.before) node = some state)
    : exists state', nodeState (proto step.after) node = some state' := by
  rcases selected : step.action.action with _ | action
  · exact ⟨state, by rw [setup.admissible.stutter stepped selected]; exact found⟩
  obtain ⟨actor, _, post, _, _, _, postFound, others, _⟩ := setup.view stepped selected
  by_cases eq : node = actor
  · subst eq
    exact ⟨post, postFound⟩
  · exact ⟨state, by rw [others node eq]; exact found⟩

/-- A recorded node stays recorded. -/
theorem RoundSetup.state_later {index later : Nat} (le : index <= later)
    {point laterPoint : W} (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint) {node : NodeID}
    {state : NodeState} (nodeFound : nodeState (proto point) node = some state)
    : exists state', nodeState (proto laterPoint) node = some state' := by
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le le
  clear le
  induction k generalizing laterPoint with
  | zero =>
      rw [Nat.add_zero, found, Option.some.injEq] at laterFound
      subst laterFound
      exact ⟨state, nodeFound⟩
  | succ k ih =>
      rw [← Nat.add_assoc] at laterFound
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
      obtain ⟨middle, middleFound⟩ := ih (setup.admissible.before stepped)
      exact setup.race_state_step stepped middleFound

/-- A node recorded later was recorded earlier. -/
theorem RoundSetup.state_earlier {index later : Nat} (le : index <= later)
    {point laterPoint : W} (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint) {node : NodeID}
    {state : NodeState} (nodeFound : nodeState (proto laterPoint) node = some state)
    : exists state', nodeState (proto point) node = some state' := by
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le le
  clear le
  induction k generalizing laterPoint state with
  | zero =>
      rw [Nat.add_zero, found, Option.some.injEq] at laterFound
      subst laterFound
      exact ⟨state, nodeFound⟩
  | succ k ih =>
      rw [← Nat.add_assoc] at laterFound
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
      obtain ⟨middle, middleFound, _⟩ := Racing.node_before setup.admissible stepped nodeFound
      exact ih (laterFound := setup.admissible.before stepped) (nodeFound := middleFound)

/-- Without resets a deadline stays put. -/
theorem RoundSetup.deadline_steady {index later : Nat} (le : index <= later)
    {point laterPoint : W} (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint) {node : NodeID}
    (quiet
      : forall m step,
          index <= m
          -> m < later
          -> trace.stepAt m = some step
          -> Not (ElectionReset step node))
    : deadline laterPoint node = deadline point node := by
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le le
  clear le
  induction k generalizing laterPoint with
  | zero =>
      rw [Nat.add_zero, found, Option.some.injEq] at laterFound
      subst laterFound
      rfl
  | succ k ih =>
      rw [← Nat.add_assoc] at laterFound
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
      rw [((setup.timers.next stepped) node).2.1
          (quiet _ step (Nat.le_add_right _ _) (by omega) stepped)]
      exact ih (setup.admissible.before stepped)
        fun m step' le lt stepped' =>
          quiet m step' le (by omega) stepped'

/-- A rise of a node's term passes through a reset. -/
theorem RoundSetup.reset_of_rise {index later : Nat} (le : index <= later)
    {point laterPoint : W} (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint) {node : NodeID}
    {state laterState : NodeState} (nodeFound : nodeState (proto point) node = some state)
    (laterNodeFound : nodeState (proto laterPoint) node = some laterState)
    (lt : state.currentTerm < laterState.currentTerm)
    : exists m step,
        index <= m
        /\ m < later
        /\ trace.stepAt m = some step
        /\ ElectionReset step node := by
  obtain ⟨k, rfl⟩ := Nat.exists_eq_add_of_le le
  clear le
  induction k generalizing laterPoint laterState with
  | zero =>
      rw [Nat.add_zero, found, Option.some.injEq] at laterFound
      subst laterFound
      rw [nodeFound, Option.some.injEq] at laterNodeFound
      subst laterNodeFound
      omega
  | succ k ih =>
      rw [← Nat.add_assoc] at laterFound
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp laterFound
      obtain ⟨middle, middleFound, middleLe⟩ :=
        Racing.node_before setup.admissible stepped laterNodeFound
      by_cases rose : state.currentTerm < middle.currentTerm
      · obtain ⟨m, step', first, last, stepped', reset⟩ :=
          ih (laterFound := setup.admissible.before stepped) (laterNodeFound := middleFound)
            (lt := rose)
        exact ⟨m, step', first, by omega, stepped', reset⟩
      · exact ⟨index + k, step, Nat.le_add_right _ _, by omega, stepped,
          Racing.reset_of_term_lt setup.admissible stepped middleFound laterNodeFound
            (by omega)⟩

/-- A packet sent by a step to a participant arrives within a delay, so the step
itself takes at most a delay. -/
theorem RoundSetup.sent_bound {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (within : Within trace start duration (index + 1)) {packet : Packet}
    (member : packet ∈ pending step.after)
    (target : packet.envelope.target ∈ participants)
    (sentEq : packet.sentAt = time step.before)
    : time step.after <= time step.before + maxDelay := by
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have alive := setup.period.participantsLive (index + 1) step.after _ within afterFound target
  have := setup.delay_at afterFound member alive
  linarith

end Utilities

/-! ## The round's start -/

section Start

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- The round's first step leaves its raiser recorded and a packet sent at the round
start pending to every other participant. -/
theorem RoundSetup.start_reach
    : exists step raiser,
        trace.stepAt c = some step
        /\ raiser ∈ participants
        /\ (exists state, nodeState (proto step.after) raiser = some state)
        /\ forall node,
            node ∈ participants
            -> node ≠ raiser
            -> exists packet,
                packet ∈ pending step.after
                /\ packet.envelope.target = node
                /\ packet.envelope.source ∈ participants
                /\ packet.sentAt <= time origin
                /\ node ∈ live step.after := by
  obtain ⟨step, raiser, raised, stepped, raiserIn, raisedFound, above⟩ := setup.round.raise
  refine ⟨
    step,
    raiser,
    stepped,
    raiserIn,
    ⟨raised, raisedFound⟩,
    fun node nodeIn self => ?_
  ⟩
  have beforeFound := setup.admissible.before stepped
  rw [originFound, Option.some.injEq] at beforeFound
  subst beforeFound
  have within :=
    setup.inside originFound c step.before le_rfl (setup.admissible.before stepped)
      (by
        unfold roundLength
        linarith [setup.nonnegative, setup.jumpNonnegative, setup.timeout_pos])
  have low := setup.round.low step.before
  rcases selected : step.action.action with _ | action
  · rw [setup.admissible.stutter stepped selected] at raisedFound
    have := low raiser raised originFound raiserIn raisedFound
    omega
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, ledger⟩ :=
    setup.view stepped selected
  by_cases actorEq : raiser = actor
  swap
  · rw [others raiser actorEq] at raisedFound
    have := low raiser raised originFound raiserIn raisedFound
    omega
  subst actorEq
  rw [postFound, Option.some.injEq] at raisedFound
  subst raisedFound
  have preLe := low raiser pre originFound raiserIn preFound
  rcases Racing.sends_run (raise_sends raiser pre event) ran (by omega) with
    ⟨source, message, eventEq, termLe⟩ | ⟨request, requestGe, sends⟩
  · exfalso
    rcases cause with ⟨input, _, eventIs⟩ | ⟨packet, delivered, targetEq, eventIs⟩
    · rw [eventIs] at eventEq
      cases eventEq
    rw [eventIs] at eventEq
    cases eventEq
    have member :=
      setup.admissible.consumed_pending stepped
        (packet := packet) (by simp [delivered, Liveness.Event.consumedPacket])
    have sourceIn :=
      setup.period.isolated c step packet.envelope within stepped
        (by simp [delivered, Liveness.Event.delivered]) (targetEq ▸ raiserIn)
    have := setup.round.messages step.before packet originFound member sourceIn
      (targetEq ▸ raiserIn)
    omega
  have alive := setup.period.participantsLive c step.before raiser within originFound raiserIn
  have quorum := setup.period.quorum c step.before raiser pre within originFound alive preFound
  have targetIn : node ∈ pre.activeMembers.erase raiser := by
    rcases (setup.membership step.before originFound).activeMembers
        (Concrete.mem_of_nodeState preFound) raiserIn with empty | membersEq
    · exact absurd empty quorum.1
    · rw [membersEq]
      exact Finset.mem_erase.mpr ⟨self, setup.subset nodeIn⟩
  obtain ⟨packet, member, envelopeEq, sentEq⟩ :=
    Racing.pending_of_sent ledger (sends node targetIn)
  exact ⟨
    packet,
    member,
    by rw [envelopeEq],
    by rw [envelopeEq]; exact raiserIn,
    le_of_eq sentEq,
    setup.stays_live within stepped nodeIn
  ⟩

/-- With two participants, the round's first step takes at most a delay. -/
theorem RoundSetup.start_time {u v : NodeID} (uIn : u ∈ participants)
    (vIn : v ∈ participants) (ne : u ≠ v) {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt c = some step)
    : time step.after <= time origin + maxDelay := by
  obtain ⟨step', raiser, stepped', _, _, packets⟩ := setup.start_reach originFound noElection
  rw [stepped, Option.some.injEq] at stepped'
  subst stepped'
  have other : exists node, node ∈ participants /\ node ≠ raiser := by
    by_cases eq : u = raiser
    · exact ⟨v, vIn, fun h => ne (eq.trans h.symm)⟩
    · exact ⟨u, uIn, eq⟩
  obtain ⟨node, nodeIn, nodeNe⟩ := other
  obtain ⟨packet, member, targetEq, _, sentLe, alive⟩ := packets node nodeIn nodeNe
  have := setup.delay_at (Trace.stateAt_succ_of_stepAt stepped) member (targetEq ▸ alive)
  linarith

/-- One delay into the round every participant is recorded: the round's first step
sent each a packet, which only a recorded node can receive. -/
theorem RoundSetup.has_state {index : Nat} {point : W} (le : c <= index)
    (found : trace.stateAt index = some point)
    (late : time origin + maxDelay < time point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants)
    : exists state, nodeState (proto point) node = some state := by
  obtain ⟨step, raiser, stepped, _, raisedState, packets⟩ :=
    setup.start_reach originFound noElection
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have lt : c < index := by
    rcases Nat.lt_or_eq_of_le le with lt | eq
    · exact lt
    · subst eq
      rw [originFound, Option.some.injEq] at found
      subst found
      linarith [setup.nonnegative]
  by_cases self : node = raiser
  · subst self
    obtain ⟨raised, raisedFound⟩ := raisedState
    exact setup.state_later lt afterFound found raisedFound
  by_contra none
  obtain ⟨packet, member0, targetEq, sourceIn, sentLe, _⟩ := packets node member self
  have targetIn : packet.envelope.target ∈ participants := targetEq ▸ member
  have kept
      : forall k q,
          c + 1 + k <= index -> trace.stateAt (c + 1 + k) = some q -> packet ∈ pending q := by
    intro k
    induction k with
    | zero =>
        intro q _ qFound
        rw [Nat.add_zero, afterFound, Option.some.injEq] at qFound
        subst qFound
        exact member0
    | succ k ih =>
        intro q le' qFound
        rw [← Nat.add_assoc] at qFound
        obtain ⟨step', stepped', rfl⟩ := Trace.stateAt_succ_eq_some.mp qFound
        have bf := setup.admissible.before stepped'
        have pend := ih step'.before (by omega) bf
        have bTime := setup.admissible.time_le (by omega : c + 1 + k <= index) bf found
        have within :=
          setup.inside originFound (c + 1 + k) step'.before (by omega) bf (by linarith)
        refine setup.kept within stepped' pend sourceIn targetIn fun delivered => ?_
        have selected : step'.action.action = some (.deliver packet.envelope) := by
          rw [delivered]
          rfl
        obtain ⟨actor, pre, _, _, _, preFound, _, _, cause, _⟩ := setup.view stepped' selected
        rcases cause with ⟨input, actionEq, _⟩ | ⟨packet', actionEq, targetEq', _⟩
        · rw [delivered] at actionEq
          cases actionEq
        · rw [delivered] at actionEq
          injection actionEq with packetEq
          subst packetEq
          rw [targetEq] at targetEq'
          subst targetEq'
          obtain ⟨s, h⟩ := setup.state_later (by omega : c + 1 + k <= index) bf found preFound
          exact none ⟨s, h⟩
  have pend :=
    kept (index - (c + 1)) point (by omega)
      (by
        rw [show c + 1 + (index - (c + 1)) = index by omega]
        exact found)
  have alive :=
    setup.period.participantsLive index point node
      (setup.inside originFound index point le found (by linarith)) found member
  have := setup.delay_at found pend (targetEq ▸ alive)
  linarith

/-- Hopelessness persists through the frozen part of the round. -/
theorem RoundSetup.hopeless_later {index later : Nat} (le : index <= later)
    {point laterPoint : W} (capped : Capped trace participants c term later)
    (found : trace.stateAt index = some point)
    (laterFound : trace.stateAt later = some laterPoint)
    (late : time origin + maxDelay < time point)
    (timeLe
      : time laterPoint <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants)
    (hopeless : Racing.Hopeless participants point node)
    : Racing.Hopeless participants laterPoint node := by
  obtain ⟨state, nodeFound, noQuorum⟩ := hopeless
  obtain ⟨laterState, laterNodeFound⟩ := setup.state_later le found laterFound nodeFound
  refine ⟨laterState, laterNodeFound, fun quorum => noQuorum ?_⟩
  have indexLe := setup.start_le originFound noElection found setup.nonnegative late
  have timeMono := setup.admissible.time_le le found laterFound
  have laterLate : time origin + maxDelay < time laterPoint := by linarith
  have frozen := setup.frozen originFound noElection capped laterFound laterLate timeLe
  have keeps :=
    setup.frozen_keeps originFound noElection capped le found laterFound late timeLe member
      nodeFound laterNodeFound
  have termEq :=
    setup.adopted (capped.down indexLe le) originFound found late node state member nodeFound
  have laterTerm :=
    setup.adopted capped originFound laterFound laterLate node laterState member
      laterNodeFound
  rw [keeps.configurations] at quorum
  refine hasQuorum_mono quorum fun voter voterIn => ?_
  have grantor
      : voter ∈ Grantors participants laterPoint laterState
        -> voter ∈ Racing.PreVoters participants point node state := by
    intro g
    simp only [Grantors, Finset.mem_filter] at g
    obtain ⟨voterIn', voterState', voterFound', upToDate⟩ := g
    obtain ⟨voterState, voterFound⟩ :=
      setup.has_state originFound noElection indexLe found late (by linarith) voterIn'
    have voterKeeps :=
      setup.frozen_keeps originFound noElection capped le found laterFound late timeLe
        voterIn' voterFound voterFound'
    rw [request_keeps keeps (by omega)] at upToDate
    simp only [Racing.PreVoters, Finset.mem_insert, Finset.mem_union, Finset.mem_filter]
    exact Or.inr (Or.inr ⟨voterIn', voterState, voterFound, (voterKeeps.upToDate _).mp upToDate⟩)
  simp only [Racing.PreVoters, Finset.mem_insert, Finset.mem_union] at voterIn
  rcases voterIn with eq | granted | filtered
  · simp [Racing.PreVoters, eq]
  · have sub := (frozen.polling node laterState member laterNodeFound).1 granted
    rw [Finset.mem_insert] at sub
    rcases sub with eq | g
    · simp [Racing.PreVoters, eq]
    · exact grantor g
  · exact grantor (by simpa [Grantors] using filtered)

end Start

/-! ## Timers in the round -/

section Timers

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup

/-- A delivered vote request is answered, so its step takes at most a delay. -/
theorem RoundSetup.vote_reply {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    (within : Within trace start duration index)
    (withinAfter : Within trace start duration (index + 1)) {packet : Packet}
    (delivered : step.action = .deliver packet)
    (target : packet.envelope.target ∈ participants) {request : RequestVoteRequest}
    (payload : packet.envelope.payload = .requestVoteRequest request)
    : time step.after <= time step.before + maxDelay := by
  have selected : step.action.action = some (.deliver packet.envelope) := by
    simp [delivered, Liveness.Event.action]
  obtain ⟨actor, pre, post, event, outputs, _, _, _, cause, ran, ledger⟩ :=
    setup.view stepped selected
  rcases cause with ⟨input, eventEq, _⟩ | ⟨other, eventEq, actorEq, eventIs⟩
  · rw [delivered] at eventEq
    cases eventEq
  rw [delivered] at eventEq
  cases eventEq
  have sourceIn :=
    setup.period.isolated index step packet.envelope within stepped
      (by simp [delivered, Liveness.Event.delivered]) target
  rw [eventIs, payload] at ran
  obtain ⟨_, _, _, _, _, _, sentEq⟩ :=
    Racing.sends_run (Racing.voteRequest_receive actor packet.envelope.source pre request)
      ran
  obtain ⟨reply, member, envelopeEq, sentAt⟩ :=
    Racing.pending_of_sent ledger (by rw [sentEq]; exact List.mem_singleton_self _)
  exact setup.sent_bound stepped withinAfter member (by rw [envelopeEq]; exact sourceIn)
    sentAt

include originFound noElection

/-- Early in the round, a step that resets a participant without its timing out in
`term + 1` ends within three delays of the round start. -/
theorem RoundSetup.early_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : c <= index) (stepped : trace.stepAt index = some step)
    (capped : Capped trace participants c term (index + 1))
    (early : time step.before <= time origin + 2 * maxDelay)
    (timeLe
      : time step.after <= time origin + roundLength electionTimeout maxDelay + jump)
    {node other : NodeID} (member : node ∈ participants) (otherIn : other ∈ participants)
    (ne : node ≠ other) (reset : ElectionReset step node)
    (quiet : Not (TermTimeout trace term index node))
    : time step.after <= time origin + 3 * maxDelay := by
  have nonneg := setup.nonnegative
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have timeMono := (setup.admissible.timing.next stepped).1
  have within := setup.inside originFound index step.before le beforeFound (by linarith)
  have withinAfter :=
    setup.inside originFound (index + 1) step.after (by omega) afterFound (by linarith)
  rcases Nat.lt_or_eq_of_le le with lt | eq
  swap
  · subst eq
    have := setup.start_time originFound noElection member otherIn ne stepped
    rw [originFound, Option.some.injEq] at beforeFound
    linarith
  have voted
      : forall packet request,
          step.action = .deliver packet
          -> packet.envelope.target ∈ participants
          -> packet.envelope.payload = .requestVoteRequest request
          -> time step.after <= time origin + 3 * maxDelay := by
    intro packet request delivered target payload
    have := setup.vote_reply stepped within withinAfter delivered target payload
    linarith
  have inside : Inside trace start duration c origin maxDelay :=
    (setup.inside originFound).mono
      (by
        unfold roundLength
        linarith [setup.jumpNonnegative, setup.timeout_pos])
  obtain ⟨first, firstStepped, reachedAll⟩ := setup.reached_start originFound inside
  have reached :=
    setup.reached_from inside member (Nat.le_succ c)
      (Trace.stateAt_succ_of_stepAt firstStepped) (reachedAll node member) index
      step.before (by omega) beforeFound
  rcases reached with
    high | ⟨packet, request, pending, alive, sourceIn, targetEq, payload, _, sentLe⟩
  swap
  · by_cases delivered : step.action = .deliver packet
    · exact voted packet request delivered (targetEq ▸ member) payload
    · have kept := setup.kept within stepped pending sourceIn (targetEq ▸ member) delivered
      have := setup.delay_at afterFound kept
        (targetEq ▸ setup.stays_live within stepped member)
      linarith
  have cappedBefore := capped.down le (Nat.le_succ index)
  unfold ElectionReset at reset
  split at reset
  · rename_i timedOut kind action
    rw [reset] at action
    clear reset timedOut
    have selected : step.action.action = some (.local node (.timeout kind)) := by
      rw [action]
      rfl
    obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, _⟩ :=
      setup.view stepped selected
    rcases cause with ⟨input, actionEq, eventEq⟩ | ⟨packet, actionEq, _⟩
    · rw [action] at actionEq
      injection actionEq with nodeEq inputEq
      subst nodeEq inputEq eventEq
      have preHigh := high pre preFound
      have preLe := capped.2 index step.before node pre le (Nat.le_succ index) beforeFound
        member preFound
      cases kind with
      | election => exact (quiet ⟨step, pre, stepped, action, preFound, by omega⟩).elim
      | checkQuorum => exact (setup.period.noQuorumChecks index step node within stepped
          member action).elim
    · rw [action] at actionEq
      cases actionEq
  · rename_i packet action
    obtain ⟨targetEq, reset⟩ := reset
    have consumed : packet ∈ pending step.before :=
      setup.admissible.consumed_pending stepped
        (by simp [action, Liveness.Event.consumedPacket])
    have targetIn : packet.envelope.target ∈ participants := by rw [targetEq]; exact member
    have sourceIn :=
      setup.period.isolated index step packet.envelope within stepped
        (by simp [action, Liveness.Event.delivered]) targetIn
    split at reset
    · exact reset.elim
    rename_i state stateFound
    have stateHigh := high state stateFound
    rcases reset with raised | received
    · split at raised
      · rename_i after afterStateFound
        have := capped.2 (index + 1) step.after node after (by omega) le_rfl
          afterFound member afterStateFound
        omega
      · exact raised.elim
    · have calm :=
        setup.calm_from originFound noElection index step.before cappedBefore beforeFound
          (by linarith)
      split at received
      · rename_i request payload
        have := (calm.packets packet consumed sourceIn targetIn).1 request payload
        omega
      · rename_i request payload
        exact voted packet request action targetIn payload
      · exact received.elim
  · exact reset.elim

/-- A participant that has not timed out in `term + 1` is not overdue: with no
overshoot, a passed deadline fires. -/
theorem RoundSetup.not_overdue {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (late : time origin + electionTimeout / 2 <= time point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node other : NodeID} (member : node ∈ participants) (otherIn : other ∈ participants)
    (ne : node ≠ other)
    (quiet
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier node))
    (overshoot
      : forall earlier step,
          c <= earlier
          -> earlier < index
          -> trace.stepAt earlier = some step
          -> NoOvershoot (some 0) step node)
    : time point <= deadline point node := by
  classical
  by_contra overdue
  rw [not_le] at overdue
  have ratio := setup.ratio
  have nonneg := setup.nonnegative
  have lateD : time origin + maxDelay < time point := by linarith
  obtain ⟨state, nodeFound⟩ :=
    setup.has_state originFound noElection capped.1 found lateD timeLe member
  have termEq := setup.adopted capped originFound found lateD node state member nodeFound
  have fresh :=
    Racing.term_fresh setup.admissible setup.timers originFound
      (fun node state member found =>
        setup.round.low origin node state originFound member found)
      index point node state capped.1 found member nodeFound termEq
  have atIndex : trace.stateAt (c + (index - c)) = some point := by
    rw [Nat.add_sub_cancel' capped.1]
    exact found
  have past
      : exists k p, trace.stateAt (c + k) = some p /\ deadline point node < time p :=
    ⟨index - c, point, atIndex, overdue⟩
  have kLe : Nat.find past <= index - c := Nat.find_min' past ⟨point, atIndex, overdue⟩
  obtain ⟨pk, kFound, kPast⟩ := Nat.find_spec past
  have kPos : 0 < Nat.find past := by
    rcases Nat.eq_zero_or_pos (Nat.find past) with zero | pos
    · rw [zero, Nat.add_zero, originFound, Option.some.injEq] at kFound
      subst kFound
      linarith [setup.timeout_pos]
    · exact pos
  have beforeLe : forall p,
      trace.stateAt (c + (Nat.find past - 1)) = some p -> time p <= deadline point node := by
    have := Nat.find_min past (by omega : Nat.find past - 1 < Nat.find past)
    push Not at this
    exact this
  obtain ⟨j, jEq⟩ : exists j, c + Nat.find past = j + 1 := ⟨c + Nat.find past - 1, by omega⟩
  have jPrev : c + (Nat.find past - 1) = j := by omega
  rw [jPrev] at beforeLe
  rw [jEq] at kFound
  obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp kFound
  have beforeFound := setup.admissible.before stepped
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have jLe : c <= j := by omega
  have jLt : j < index := by omega
  have beforeTime := beforeLe step.before beforeFound
  have afterLe := setup.admissible.time_le (by omega : j + 1 <= index) afterFound found
  have timeMono := (setup.admissible.timing.next stepped).1
  have noReset
      : forall m step',
          j + 1 <= m -> m < index -> trace.stepAt m = some step'
          -> Not (ElectionReset step' node) := by
    intro m step' first last stepped' reset
    have bf := setup.admissible.before stepped'
    have af := Trace.stateAt_succ_of_stepAt stepped'
    have t1 := setup.admissible.time_le (by omega : j + 1 <= m) afterFound bf
    have t2 := setup.admissible.time_le (by omega : m + 1 <= index) af found
    exact quiet m (by omega) last
      (setup.reset_late originFound noElection (capped.down (by omega) (by omega)) stepped'
        (by linarith) (by linarith) member reset)
  have steady := setup.deadline_steady (by omega : j + 1 <= index) afterFound found noReset
  by_cases reset : ElectionReset step node
  · have early : time step.before <= time origin + 2 * maxDelay := by
      by_contra lateJ
      push Not at lateJ
      exact quiet j jLe jLt
        (setup.reset_late originFound noElection (capped.down (by omega) (by omega)) stepped
          lateJ (by linarith) member reset)
    have := setup.early_step originFound noElection jLe stepped
      (capped.down (by omega) (by omega)) early (by linarith) member otherIn ne reset
      (quiet j jLe jLt)
    linarith
  have dlEq := ((setup.timers.next stepped) node).2.1 reset
  obtain ⟨jState, jFound⟩ :=
    setup.state_earlier (by omega : j <= index) beforeFound found nodeFound
  have cappedJ := capped.down jLe (by omega)
  have jTerm : jState.currentTerm = term + 1 := by
    have hi := capped.2 j step.before node jState jLe (by omega) beforeFound member jFound
    by_contra neq
    obtain ⟨m, step', first, last, stepped', reset'⟩ :=
      setup.reset_of_rise (by omega : j <= index) beforeFound found jFound nodeFound
        (by omega)
    rcases Nat.lt_or_eq_of_le first with lt | eq
    · exact noReset m step' (by omega) last stepped' reset'
    · subst eq
      rw [stepped, Option.some.injEq] at stepped'
      subst stepped'
      exact reset reset'
  have withinJ := setup.inside originFound j step.before jLe beforeFound (by linarith)
  have alive := setup.period.participantsLive j step.before node withinJ beforeFound member
  have calm :=
    setup.calm_from originFound noElection j step.before cappedJ beforeFound (by linarith)
  have notNone := (calm.nodes node jState member jFound jTerm).2.2.1
  have notPrimary :=
    noElection j step.before node jState cappedJ beforeFound (by linarith) member jFound
      jTerm
  have can :=
    setup.can_start originFound noElection jLe beforeFound (by linarith) member jFound
      notNone notPrimary
  rcases lt_or_eq_of_le beforeTime with lt | eq
  · have no := overshoot j step jLe jLt stepped
    simp only [NoOvershoot] at no
    have := no alive ⟨jState, jFound, can⟩ (by linarith)
    linarith
  · have due : TimeoutDue step.before node := ⟨alive, by linarith, jState, jFound, can⟩
    obtain ⟨l, pl, lLe, lFound, lTime, resolved⟩ :=
      setup.firing node member j step.before beforeFound due
    simp only [Deadline] at lTime
    rcases Nat.lt_or_eq_of_le lLe with lt | eq
    · have := setup.admissible.time_le (by omega : j + 1 <= l) afterFound lFound
      linarith
    · subst eq
      rw [beforeFound, Option.some.injEq] at lFound
      subst lFound
      rcases resolved with notDue | ⟨step', stepped', fires⟩
      · exact notDue due
      · rw [stepped, Option.some.injEq] at stepped'
        subst stepped'
        exact reset (by simp [ElectionReset, fires])

end Timers

/-! ## The first hopeful timeout -/

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] [Config.InitialConfiguration] in
/-- A grantor is a pre-voter. -/
theorem grantors_sub {point : W} {node : NodeID} {state : NodeState}
    : Grantors participants point state
      ⊆ Racing.PreVoters participants point node state := by
  intro voter voterIn
  simp only [Grantors, Finset.mem_filter] at voterIn
  simp only [Racing.PreVoters, Finset.mem_insert, Finset.mem_union, Finset.mem_filter]
  exact Or.inr (Or.inr voterIn)

section Hopeful

variable
  (setup
    : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
        members c term)
  {origin : W} (originFound : trace.stateAt c = some origin)
  (noElection
    : NoElection trace participants c term origin
        (roundLength electionTimeout maxDelay + jump))

include setup originFound noElection

/-- A participant hopeless when it timed out stays hopeless. -/
theorem RoundSetup.hopeless_of_timeout {earlier index : Nat} (first : c <= earlier)
    (le : earlier <= index) {point : W} (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    {node : NodeID} (member : node ∈ participants)
    (timeout : TermTimeout trace term earlier node)
    (hopeless
      : exists earlierPoint,
          trace.stateAt earlier = some earlierPoint
          /\ Racing.Hopeless participants earlierPoint node)
    : Racing.Hopeless participants point node := by
  obtain ⟨step, state, stepped, action, stateFound, stateTerm⟩ := timeout
  obtain ⟨earlierPoint, earlierFound, hopeless⟩ := hopeless
  have beforeFound := setup.admissible.before stepped
  rw [beforeFound, Option.some.injEq] at earlierFound
  subst earlierFound
  have lateE := setup.timeout_late originFound first stepped member stateFound stateTerm action
  exact setup.hopeless_later originFound noElection le capped beforeFound found
    (by linarith [setup.ratio, setup.nonnegative]) timeLe member hopeless

/-- A raise past `term + 1` needs a pre-vote quorum, so a participant that could
gather one timed out in `term + 1`. -/
theorem RoundSetup.exists_hopeful {next : Nat} {nextPoint : W}
    (capped : Capped trace participants c term next)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + roundLength electionTimeout maxDelay + jump)
    (raise
      : exists step node state,
          trace.stepAt next = some step
          /\ node ∈ participants
          /\ nodeState (proto step.after) node = some state
          /\ term + 1 < state.currentTerm)
    : exists index node,
        c <= index
        /\ index <= next
        /\ node ∈ participants
        /\ TermTimeout trace term index node
        /\ forall point,
            trace.stateAt index = some point
            -> Not (Racing.Hopeless participants point node) := by
  obtain ⟨step, node, raised, stepped, member, raisedFound, above⟩ := raise
  have beforeFound := setup.admissible.before stepped
  rw [nextFound, Option.some.injEq] at beforeFound
  subst beforeFound
  have within := setup.inside originFound next step.before capped.1 nextFound (by linarith)
  have calm := setup.calm_from originFound noElection next step.before capped nextFound timeLe
  rcases selected : step.action.action with _ | action
  · rw [setup.admissible.stutter stepped selected] at raisedFound
    have := capped.2 next step.before node raised capped.1 le_rfl nextFound member raisedFound
    omega
  obtain ⟨actor, pre, post, event, outputs, preFound, postFound, others, cause, ran, _⟩ :=
    setup.view stepped selected
  by_cases actorEq : node = actor
  swap
  · rw [others node actorEq] at raisedFound
    have := capped.2 next step.before node raised capped.1 le_rfl nextFound member raisedFound
    omega
  subst actorEq
  rw [postFound, Option.some.injEq] at raisedFound
  subst raisedFound
  have preLe := capped.2 next step.before node pre capped.1 le_rfl nextFound member preFound
  have hopeful
      : forall voters,
          hasQuorum pre.activeConfigurations voters
          -> voters ⊆ Racing.PreVoters participants step.before node pre
          -> forall point,
              trace.stateAt next = some point
              -> Not (Racing.Hopeless participants point node) := by
    intro voters quorum sub point pointFound hopeless
    rw [nextFound, Option.some.injEq] at pointFound
    subst pointFound
    obtain ⟨state, stateFound, noQuorum⟩ := hopeless
    rw [preFound, Option.some.injEq] at stateFound
    subst stateFound
    exact noQuorum (hasQuorum_mono quorum sub)
  have delivered_packet
      : forall source message,
          event = .receive source message
          -> exists packet,
              packet ∈ pending step.before
              /\ packet.envelope.source = source
              /\ packet.envelope.target = node
              /\ packet.envelope.payload = message
              /\ packet.envelope.source ∈ participants := by
    intro source message eventEq
    rcases cause with ⟨input, _, eventIs⟩ | ⟨packet, delivered, targetEq, eventIs⟩
    · rw [eventIs] at eventEq
      cases eventEq
    rw [eventIs] at eventEq
    injection eventEq with sourceEq payloadEq
    have consumed :=
      setup.admissible.consumed_pending stepped (packet := packet)
        (by simp [delivered, Liveness.Event.consumedPacket])
    have sourceIn :=
      setup.period.isolated next step packet.envelope within stepped
        (by simp [delivered, Liveness.Event.delivered]) (targetEq ▸ member)
    exact ⟨packet, consumed, sourceEq, targetEq, payloadEq, sourceIn⟩
  rcases Racing.sends_run (raise_cause node pre event) ran (by omega) with
    ⟨source, message, eventEq, termLe⟩ | ⟨termEq, fire⟩
  · exfalso
    obtain ⟨packet, consumed, _, targetEq, payloadEq, sourceIn⟩ :=
      delivered_packet source message eventEq
    have := (setup.packets capped originFound nextFound consumed sourceIn
      (targetEq ▸ member)).1
    rw [payloadEq] at this
    omega
  have preTerm : pre.currentTerm = term + 1 := by omega
  rcases fire with ⟨eventIs, selfQuorum⟩ | ⟨source, eventIs, role, quorum⟩ | ⟨source, eventIs⟩
  · rcases cause with ⟨input, actionEq, eventEq⟩ | ⟨packet, _, _, eventEq⟩
    · rw [eventEq] at eventIs
      cases eventIs
      exact ⟨next, node, capped.1, le_rfl, member, ⟨step, pre, stepped, actionEq, preFound, preTerm⟩,
        hopeful {node} selfQuorum
          (Finset.singleton_subset_iff.mpr (Finset.mem_insert_self _ _))⟩
    · rw [eventEq] at eventIs
      cases eventIs
  · obtain ⟨packet, consumed, sourceEq, targetEq, payloadEq, sourceIn⟩ :=
      delivered_packet _ _ eventIs
    rw [preTerm] at payloadEq
    have targetIn : packet.envelope.target ∈ participants := targetEq ▸ member
    have granted := (calm.packets packet consumed sourceIn targetIn).2.2.2 payloadEq
    have sourceGrantor := granted.1 pre (by rw [targetEq]; exact preFound)
    rw [sourceEq] at sourceGrantor
    have polling := (calm.nodes node pre member preFound preTerm).2.2.2 role
    obtain ⟨earlier, earlierLe, earlierLt, timeout⟩ := polling.2
    have insertSub
        : insert node (Grantors participants step.before pre)
          ⊆ Racing.PreVoters participants step.before node pre :=
      Finset.insert_subset_iff.mpr ⟨Finset.mem_insert_self _ _, grantors_sub⟩
    have hopefulNext :=
      hopeful _ quorum
        (Finset.insert_subset_iff.mpr ⟨grantors_sub sourceGrantor, polling.1.trans insertSub⟩)
    refine ⟨earlier, node, earlierLe, earlierLt.le, member, timeout,
      fun point pointFound hopeless => hopefulNext step.before nextFound ?_⟩
    exact setup.hopeless_of_timeout originFound noElection earlierLe earlierLt.le capped
      nextFound timeLe member timeout ⟨point, pointFound, hopeless⟩
  · exfalso
    obtain ⟨packet, consumed, _, targetEq, payloadEq, sourceIn⟩ :=
      delivered_packet _ _ eventIs
    rw [preTerm] at payloadEq
    exact (calm.packets packet consumed sourceIn (targetEq ▸ member)).2.1 payloadEq

/-- Two participants without a timeout in `term + 1` keep the margin of their last
resets. -/
theorem RoundSetup.margin_gap {index : Nat} {point : W}
    (capped : Capped trace participants c term index)
    (found : trace.stateAt index = some point)
    (late : time origin + maxDelay < time point)
    (timeLe : time point <= time origin + roundLength electionTimeout maxDelay + jump)
    (margin : RoundMargin trace participants c term (4 * maxDelay))
    {u v : NodeID} (uIn : u ∈ participants) (vIn : v ∈ participants) (ne : u ≠ v)
    (quietU
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier u))
    (quietV
      : forall earlier,
          c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier v))
    : 4 * maxDelay < |deadline point u - deadline point v| := by
  classical
  have someReset
      : forall w,
          w ∈ participants
          -> exists m step,
              c <= m /\ m < index /\ trace.stepAt m = some step /\ ElectionReset step w := by
    intro w wIn
    obtain ⟨state, stateFound⟩ :=
      setup.has_state originFound noElection capped.1 found late timeLe wIn
    have termEq := setup.adopted capped originFound found late w state wIn stateFound
    obtain ⟨low, lowFound⟩ := setup.state_earlier capped.1 originFound found stateFound
    have lowLe := setup.round.low origin w low originFound wIn lowFound
    exact setup.reset_of_rise capped.1 originFound found lowFound stateFound (by omega)
  let S :=
    (Finset.Ico c index).filter
      fun m =>
        exists step, trace.stepAt m = some step /\ (ElectionReset step u \/ ElectionReset step v)
  have nonempty : S.Nonempty := by
    obtain ⟨m, step, first, last, stepped, reset⟩ := someReset u uIn
    exact ⟨m, Finset.mem_filter.mpr ⟨Finset.mem_Ico.mpr ⟨first, last⟩, step, stepped,
      Or.inl reset⟩⟩
  have rMem := Finset.max'_mem S nonempty
  obtain ⟨r, rEq⟩ : exists r, r = S.max' nonempty := ⟨_, rfl⟩
  rw [← rEq] at rMem
  obtain ⟨rRange, step, stepped, resetUV⟩ := Finset.mem_filter.mp rMem
  obtain ⟨rFirst, rLast⟩ := Finset.mem_Ico.mp rRange
  have afterR
      : forall m step',
          r < m -> m < index -> trace.stepAt m = some step'
          -> Not (ElectionReset step' u) /\ Not (ElectionReset step' v) := by
    intro m step' lt last stepped'
    have notIn : m ∉ S := by
      intro mem
      have := Finset.le_max' S m mem
      rw [← rEq] at this
      omega
    constructor
    · exact fun reset' => notIn (Finset.mem_filter.mpr
        ⟨Finset.mem_Ico.mpr ⟨by omega, last⟩, step', stepped', Or.inl reset'⟩)
    · exact fun reset' => notIn (Finset.mem_filter.mpr
        ⟨Finset.mem_Ico.mpr ⟨by omega, last⟩, step', stepped', Or.inr reset'⟩)
  have afterFound := Trace.stateAt_succ_of_stepAt stepped
  have dlU :=
    setup.deadline_steady (by omega : r + 1 <= index) afterFound found
      fun m step' first last stepped' => (afterR m step' (by omega) last stepped').1
  have dlV :=
    setup.deadline_steady (by omega : r + 1 <= index) afterFound found
      fun m step' first last stepped' => (afterR m step' (by omega) last stepped').2
  have key
      : forall a b,
          a ∈ participants
          -> b ∈ participants
          -> b ≠ a
          -> ElectionReset step a
          -> (forall m step',
                r < m -> m < index -> trace.stepAt m = some step'
                -> Not (ElectionReset step' a))
          -> (forall earlier,
                c <= earlier -> earlier < index -> Not (TermTimeout trace term earlier a))
          -> 4 * maxDelay < |deadline step.after a - deadline step.after b| := by
    intro a b aIn bIn ba reset noLater quiet
    obtain ⟨aState, aFound⟩ :=
      setup.has_state originFound noElection capped.1 found late timeLe aIn
    have aTerm := setup.adopted capped originFound found late a aState aIn aFound
    obtain ⟨rState, rFound⟩ :=
      setup.state_earlier (by omega : r + 1 <= index) afterFound found aFound
    have rTerm : rState.currentTerm = term + 1 := by
      have hi := capped.2 (r + 1) step.after a rState (by omega) (by omega) afterFound aIn rFound
      by_contra neq
      obtain ⟨m, step', first, last, stepped', reset'⟩ :=
        setup.reset_of_rise (by omega : r + 1 <= index) afterFound found rFound aFound
          (by omega)
      exact noLater m step' (by omega) last stepped' reset'
    have bound := setup.resets_le_two originFound noElection capped found timeLe aIn quiet
    have prior : priorResets trace c r a term < 2 := by
      have lt : priorResets trace c r a term < priorResets trace c index a term := by
        unfold priorResets
        apply Finset.card_lt_card
        refine (Finset.ssubset_iff_of_subset ?_).mpr ⟨r, ?_, ?_⟩
        · intro m mIn
          simp only [Finset.mem_filter, Finset.mem_Ico] at mIn ⊢
          exact ⟨⟨mIn.1.1, by omega⟩, mIn.2⟩
        · simp only [Finset.mem_filter, Finset.mem_Ico]
          exact ⟨⟨rFirst, rLast⟩, step, rState, stepped, reset, rFound, rTerm⟩
        · simp [Finset.mem_filter, Finset.mem_Ico]
      omega
    exact margin r step a rState (capped.down rFirst rLast.le) stepped aIn reset rFound rTerm
      prior b bIn ba
  rw [dlU, dlV]
  rcases resetUV with resetU | resetV
  · exact key u v uIn vIn (Ne.symm ne) resetU
      (fun m step' lt last stepped' => (afterR m step' lt last stepped').1) quietU
  · rw [abs_sub_comm]
    exact key v u vIn uIn ne resetV
      (fun m step' lt last stepped' => (afterR m step' lt last stepped').2) quietV

end Hopeful

/-- The step that ends a leaderless round without overshoot and with a margin is
preceded by a race of `term + 1`. -/
theorem RoundSetup.race_found
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {origin : W} (originFound : trace.stateAt c = some origin)
    (noElection
      : NoElection trace participants c term origin
          (roundLength electionTimeout maxDelay + jump))
    {next : Nat} {nextPoint : W} (capped : Capped trace participants c term next)
    (nextFound : trace.stateAt next = some nextPoint)
    (timeLe : time nextPoint <= time origin + roundLength electionTimeout maxDelay)
    (raise
      : exists step node state,
          trace.stepAt next = some step
          /\ node ∈ participants
          /\ nodeState (proto step.after) node = some state
          /\ term + 1 < state.currentTerm)
    (overshoot
      : forall index step node,
          node ∈ participants
          -> c <= index
          -> index < next
          -> trace.stepAt index = some step
          -> NoOvershoot (some 0) step node)
    (margin : RoundMargin trace participants c term (4 * maxDelay))
    : exists first winner step,
        c <= first
        /\ first <= next
        /\ trace.stepAt first = some step
        /\ Racing.Race trace electionTimeout maxDelay participants first winner
            (term + 1) := by
  classical
  have ratio := setup.ratio
  have nonneg := setup.nonnegative
  have jumpNonneg := setup.jumpNonnegative
  have timeLe' : time nextPoint <= time origin + roundLength electionTimeout maxDelay + jump := by
    linarith
  have offset
      : exists k node,
          c + k <= next
          /\ node ∈ participants
          /\ TermTimeout trace term (c + k) node
          /\ forall point,
              trace.stateAt (c + k) = some point
              -> Not (Racing.Hopeless participants point node) := by
    obtain ⟨index, node, le, le', member, timeout, hopeful⟩ :=
      setup.exists_hopeful originFound noElection capped nextFound timeLe' raise
    refine ⟨index - c, node, by omega, member, ?_, ?_⟩
    · rw [Nat.add_sub_cancel' le]
      exact timeout
    · rw [Nat.add_sub_cancel' le]
      exact hopeful
  obtain ⟨winner, firstLe, winnerIn, winnerTimeout, hopefulW⟩ := Nat.find_spec offset
  have minimal
      : forall earlier node,
          c <= earlier
          -> earlier < c + Nat.find offset
          -> node ∈ participants
          -> TermTimeout trace term earlier node
          -> exists point,
              trace.stateAt earlier = some point
              /\ Racing.Hopeless participants point node := by
    intro earlier node le lt member timeout
    have := Nat.find_min offset (by omega : earlier - c < Nat.find offset)
    rw [Nat.add_sub_cancel' le] at this
    push Not at this
    exact this node (by omega) member timeout
  obtain ⟨first, firstEq⟩ : exists first, first = c + Nat.find offset := ⟨_, rfl⟩
  rw [← firstEq] at firstLe winnerTimeout hopefulW minimal
  obtain ⟨step, wState, stepped, action, wFound, wTerm⟩ := winnerTimeout
  have found := setup.admissible.before stepped
  have cFirst : c <= first := by omega
  have late := setup.timeout_late originFound cFirst stepped winnerIn wFound wTerm action
  have timeFirst := setup.admissible.time_le firstLe found nextFound
  have cappedF := capped.down cFirst firstLe
  have timeLeF
      : time step.before <= time origin + roundLength electionTimeout maxDelay + jump := by
    linarith
  have lateD : time origin + maxDelay < time step.before := by linarith
  have frozen := setup.frozen originFound noElection cappedF found lateD timeLeF
  have withinF := setup.inside originFound first step.before cFirst found (by linarith)
  have hopeless_of
      : forall node,
          node ∈ participants
          -> (exists earlier,
                c <= earlier /\ earlier < first /\ TermTimeout trace term earlier node)
          -> Racing.Hopeless participants step.before node := by
    rintro node member ⟨earlier, earlierLe, earlierLt, timeout⟩
    exact setup.hopeless_of_timeout originFound noElection earlierLe earlierLt.le cappedF
      found timeLeF member timeout (minimal earlier node earlierLe earlierLt member timeout)
  have quietOf
      : forall node,
          node ∈ participants
          -> Not (Racing.Hopeless participants step.before node)
          -> forall earlier,
              c <= earlier -> earlier < first -> Not (TermTimeout trace term earlier node) :=
    fun node member hopeful earlier earlierLe earlierLt timeout =>
      hopeful (hopeless_of node member ⟨earlier, earlierLe, earlierLt, timeout⟩)
  have hopefulW' := hopefulW step.before found
  have notWinner
      : forall node, Racing.Hopeless participants step.before node -> node ≠ winner :=
    fun node hopeless eq => hopefulW' (eq ▸ hopeless)
  refine ⟨first, winner, step, cFirst, firstLe, stepped, ?_⟩
  refine {
    timeout := ?_
    competes := ?_
    settled := ?_
    inert := ?_
    margin := ?_
    capable := ?_
    covered := ?_
  }
  · intro step' stepped'
    rw [stepped, Option.some.injEq] at stepped'
    subst stepped'
    exact action
  · intro point pointFound
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    exact ⟨winnerIn, wState, wFound, wTerm⟩
  · intro point node state pointFound member nodeFound
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    have termEq := (frozen.nodes node state member nodeFound).1
    exact ⟨by omega,
      noElection first step.before node state cappedF found (by linarith) member nodeFound
        termEq⟩
  · intro point packet pointFound member sourceIn targetIn
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    obtain ⟨termLe, lowSent, voteSent, grantSent, _, _⟩ :=
      setup.packets cappedF originFound found member sourceIn targetIn
    have alive :=
      setup.period.participantsLive first step.before _ withinF found targetIn
    have delay := setup.delay_at found member alive
    obtain ⟨aeLe, noPropose, preRequest, preGrant⟩ :=
      frozen.packets packet member sourceIn targetIn
    refine ⟨termLe, ?_⟩
    have notLow
        : packet.envelope.payload.term <= term
          -> (forall response,
                Not (packet.envelope.payload = .appendEntriesResponse response))
          -> False := by
      intro low notResponse
      have := lowSent low notResponse
      linarith
    cases payloadEq : packet.envelope.payload with
    | appendEntriesRequest request =>
        exfalso
        have := aeLe request payloadEq
        exact notLow
          (by rw [payloadEq]; exact this)
          (by rw [payloadEq]; intro r h; cases h)
    | appendEntriesResponse response => exact Or.inl (by simp [Racing.Inert])
    | requestVoteRequest request =>
        exfalso
        have := voteSent request payloadEq
        linarith
    | requestVoteResponse response =>
        obtain ⟨t, granted⟩ := response
        cases granted with
        | false => exact Or.inl (by simp [Racing.Inert])
        | true =>
            exfalso
            have tLe : t <= term + 1 := by
              have := termLe
              rw [payloadEq] at this
              exact this
            rcases Nat.lt_or_ge t (term + 1) with lt | ge
            · exact notLow (by rw [payloadEq]; show t <= term; omega)
                (by rw [payloadEq]; intro r h; cases h)
            · have := grantSent (by rw [payloadEq, show t = term + 1 by omega])
              linarith
    | proposeRequestVoteRequest t =>
        exfalso
        have tLe : t <= term + 1 := by
          have := termLe
          rw [payloadEq] at this
          exact this
        rcases Nat.lt_or_ge t (term + 1) with lt | ge
        · exact notLow (by rw [payloadEq]; show t <= term; omega)
            (by rw [payloadEq]; intro r h; cases h)
        · exact noPropose (by rw [payloadEq, show t = term + 1 by omega])
    | requestPreVoteRequest request =>
        have tLe : request.term <= term + 1 := by
          have := termLe
          rw [payloadEq] at this
          exact this
        rcases Nat.lt_or_ge request.term (term + 1) with lt | ge
        · exact (notLow (by rw [payloadEq]; show request.term <= term; omega)
            (by rw [payloadEq]; intro r h; cases h)).elim
        obtain ⟨⟨state, stateFound, requestEq⟩, earlier⟩ :=
          preRequest request payloadEq (by omega)
        have hopeless := hopeless_of _ sourceIn earlier
        have stateTerm := (frozen.nodes _ state sourceIn stateFound).1
        subst requestEq
        refine Or.inr
          (Or.inl
            ⟨notWinner _ hopeless, hopeless, term + 1, state, stateFound, ?_, le_rfl⟩)
        simp [makeRequestVoteRequest, stateTerm]
    | requestPreVoteResponse response =>
        obtain ⟨t, granted⟩ := response
        cases granted with
        | false => exact Or.inl (by simp [Racing.Inert])
        | true =>
            have tLe : t <= term + 1 := by
              have := termLe
              rw [payloadEq] at this
              exact this
            rcases Nat.lt_or_ge t (term + 1) with lt | ge
            · exact (notLow (by rw [payloadEq]; show t <= term; omega)
                (by rw [payloadEq]; intro r h; cases h)).elim
            obtain ⟨grantors, earlier⟩ :=
              preGrant (by rw [payloadEq, show t = term + 1 by omega])
            have hopeless := hopeless_of _ targetIn earlier
            exact Or.inr
              (Or.inr
                ⟨
                  notWinner _ hopeless,
                  hopeless,
                  ⟨t, rfl, tLe⟩,
                  fun requester requesterFound =>
                    grantors_sub (grantors requester requesterFound)
                ⟩)
  · intro point node pointFound member ne hopeful
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    have quietW := quietOf winner winnerIn hopefulW'
    have quietY := quietOf node member hopeful
    have dlW :=
      setup.not_overdue originFound noElection cappedF found late timeLeF winnerIn member
        (Ne.symm ne) quietW
        fun earlier step' le lt stepped' =>
          overshoot earlier step' winner winnerIn le (by omega) stepped'
    have dlW' := ((setup.timers.next stepped) winner).2.2 action
    have dlY :=
      setup.not_overdue originFound noElection cappedF found late timeLeF member winnerIn ne
        quietY
        fun earlier step' le lt stepped' =>
          overshoot earlier step' node member le (by omega) stepped'
    have gap :=
      setup.margin_gap originFound noElection cappedF found lateD timeLeF margin winnerIn
        member (Ne.symm ne) quietW quietY
    rcases lt_abs.mp gap with h | h <;> linarith
  · intro point state pointFound stateFound
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    rw [wFound, Option.some.injEq] at stateFound
    subst stateFound
    have quorum
        : hasQuorum wState.activeConfigurations
            (Racing.PreVoters participants step.before winner wState) := by
      by_contra no
      exact hopefulW' ⟨wState, wFound, no⟩
    have polling := (frozen.polling winner wState winnerIn wFound).1
    have sub
        : Racing.PreVoters participants step.before winner wState
          ⊆ insert winner (Grantors participants step.before wState) := by
      intro voter voterIn
      simp only [Racing.PreVoters, Finset.mem_insert, Finset.mem_union] at voterIn
      rcases voterIn with eq | granted | filtered
      · rw [eq]
        exact Finset.mem_insert_self _ _
      · exact polling granted
      · exact Finset.mem_insert_of_mem (by simpa [Grantors] using filtered)
    have membership := setup.round_membership originFound noElection cFirst found timeLeF
    refine ⟨_, hasQuorum_mono quorum sub, fun voter voterIn ne => ?_⟩
    rw [Finset.mem_insert] at voterIn
    rcases voterIn with eq | grantor
    · exact absurd eq ne
    simp only [Grantors, Finset.mem_filter] at grantor
    obtain ⟨voterIn', voterState, voterFound, upToDate⟩ := grantor
    rcases membership.activeMembers (Concrete.mem_of_nodeState wFound) winnerIn
      with empty | same
    · exact absurd empty quorum.1
    have active : voter ∈ wState.activeMembers := by
      rw [same]
      exact setup.subset voterIn'
    refine ⟨voterIn', Finset.mem_erase.mpr ⟨ne, active⟩, ?_, voterState, voterFound,
      upToDate, (frozen.nodes voter voterState voterIn' voterFound).2.1⟩
    unfold eligiblePeers
    exact Finset.mem_erase.mpr ⟨ne, Finset.mem_union_left _ active⟩
  · intro point pointFound
    rw [found, Option.some.injEq] at pointFound
    subst pointFound
    obtain ⟨periodOrigin, periodFound⟩ := Trace.stateAt_of_le setup.startLe originFound
    have covers := setup.covers periodOrigin origin periodFound originFound
    exact ⟨start, duration, periodOrigin, setup.period, setup.startLe.trans cFirst,
      periodFound, by linarith⟩

end CCFRaft.Proofs.Duel.Round
