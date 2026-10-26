module

public import CCFRaft.Proofs.Duel.Race

@[expose] public section

/-!
# Running the race

The invariant behind `race_won`: until the winner of the race is primary, every step
keeps the other participants and the packets between participants in a small set of
shapes, the winner's tally only grows, and every voter still missing from it has its
request or its grant in flight.
-/

namespace CCFRaft.Proofs.Duel.Racing

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open HasTimers (deadline)
open CCF.MultiNodeTransitionSystem (nodeState)
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- The packets the race may have in flight: inert ones, the winner's requests to
others, grants to the winner, a hopeless node's pre-vote requests of at most `term`
carrying its log at `origin`, and pre-vote grants of at most `term` to a hopeless node
from one of its pre-voters. -/
def Allowed (participants : Finset NodeID) (origin : W) (winner : NodeID)
    (base : RequestVoteRequest) (term : Nat) (envelope : Model.Envelope)
    : Prop :=
  Inert envelope.payload
  \/ (envelope.source = winner
      /\ envelope.target ≠ winner
      /\ (envelope.payload = .requestPreVoteRequest { base with term := term }
          \/ envelope.payload = .requestVoteRequest { base with term := term + 1 }))
  \/ (envelope.target = winner
      /\ (envelope.payload = .requestPreVoteResponse { term := term, voteGranted := true }
          \/ envelope.payload
              = .requestVoteResponse { term := term + 1, voteGranted := true }))
  \/ (envelope.source ≠ winner
      /\ Hopeless participants origin envelope.source
      /\ exists requestTerm requester,
          nodeState (proto origin) envelope.source = some requester
          /\ envelope.payload
              = .requestPreVoteRequest
                  { makeRequestVoteRequest requester with term := requestTerm }
          /\ requestTerm <= term)
  \/ (envelope.target ≠ winner
      /\ Hopeless participants origin envelope.target
      /\ (exists grantTerm,
            envelope.payload
              = .requestPreVoteResponse { term := grantTerm, voteGranted := true }
            /\ grantTerm <= term)
      /\ forall requester,
          nodeState (proto origin) envelope.target = some requester
          -> envelope.source ∈ PreVoters participants origin envelope.target requester)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A hopeless node at most `term` has only pre-votes from its pre-voters. -/
def Bounded (participants : Finset NodeID) (origin : W) (term : Nat) (node : NodeID)
    (state : NodeState)
    : Prop :=
  Hopeless participants origin node
  -> state.currentTerm <= term
  -> forall initial,
      nodeState (proto origin) node = some initial
      -> state.preVotesGranted ⊆ PreVoters participants origin node initial

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- A hopeless node whose configurations are kept has no quorum among its pre-voters. -/
theorem Hopeless.not_quorum {participants : Finset NodeID} {origin : W} {node : NodeID}
    {initial state : NodeState} {voters : Finset NodeID}
    (hopeless : Hopeless participants origin node)
    (found : nodeState (proto origin) node = some initial) (keeps : Keeps initial state)
    (sub : voters ⊆ PreVoters participants origin node initial)
    : Not (hasQuorum state.activeConfigurations voters) := by
  obtain ⟨hopelessState, hopelessFound, noQuorum⟩ := hopeless
  rw [found, Option.some.injEq] at hopelessFound
  subst hopelessFound
  intro quorum
  rw [keeps.configurations] at quorum
  exact noQuorum (hasQuorum_mono quorum sub)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
theorem Bounded.observed {participants : Finset NodeID} {origin : W}
    {term observedTerm : Nat} {node : NodeID} {before after : NodeState}
    (bounded : Bounded participants origin term node before)
    (observed : Observed before observedTerm after)
    : Bounded participants origin term node after := by
  rcases observed with rfl | ⟨_, rfl⟩
  · exact bounded
  · intro _ _ _ _
    simp [bumpedState]

/-- A voter has granted, or the request sent at `sent` or its grant is in flight. -/
def Progress (point : W) (winner voter : NodeID) (granted : Finset NodeID)
    (request response : Message) (sent maxDelay : Real)
    : Prop :=
  voter ∈ granted
  \/ exists packet,
      packet ∈ pending point
      /\ ((packet.envelope = { source := winner, target := voter, payload := request }
            /\ packet.sentAt = sent)
          \/ (packet.envelope = { source := voter, target := winner, payload := response }
              /\ packet.sentAt <= sent + maxDelay))

/-- What the race keeps of a node other than the winner. -/
def Other (origin : W) (winner : NodeID) (term cap : Nat) (node : NodeID)
    (state : NodeState)
    : Prop :=
  (exists initial,
    nodeState (proto origin) node = some initial
    /\ Keeps initial state
    /\ (initial.primaryKnown = false -> state.primaryKnown = false))
  /\ state.role ≠ .primary
  /\ state.currentTerm <= cap
  /\ (state.currentTerm = term + 1
      -> state.role = .follower
          /\ state.primaryKnown = false
          /\ (state.votedFor = none \/ state.votedFor = some winner))

/-- Everything `race_won` uses, fixed once. -/
structure Setup [Config.InitialConfiguration] (nodes : List NodeID)
    (trace : Trace W Liveness.Event) (electionTimeout maxDelay : Real)
    (participants : Finset NodeID) (first : Nat) (winner : NodeID) (term : Nat) where
  admissible
    : Admissible (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) trace
  delay : trace.Valid (boundedDelayModel maxDelay)
  timers : trace.Valid (timerModel electionTimeout)
  nonnegative : 0 <= maxDelay
  ratio : 4 * maxDelay < electionTimeout / 2
  race : Race trace electionTimeout maxDelay participants first winner term
  origin : W
  originFound : trace.stateAt first = some origin
  initial : NodeState
  initialFound : nodeState (proto origin) winner = some initial
  initialTerm : initial.currentTerm = term
  notRetired : Not (initial.isRetiredCommitted winner)
  winnerIn : winner ∈ participants
  voters : Finset NodeID
  quorate : hasQuorum initial.activeConfigurations voters
  voterFacts
    : forall voter,
        voter ∈ voters
        -> voter ≠ winner
        -> voter ∈ participants
            /\ voter ∈ initial.activeMembers.erase winner
            /\ voter ∈ eligiblePeers initial winner
            /\ exists voterState,
                nodeState (proto origin) voter = some voterState
                /\ voteLogUpToDate voterState (makeRequestVoteRequest initial)
                /\ voterState.primaryKnown = false
  start : Nat
  duration : Real
  period : GoodPeriod trace start duration participants
  startLe : start <= first
  periodOrigin : W
  periodFound : trace.stateAt start = some periodOrigin
  covers : time origin + 4 * maxDelay <= time periodOrigin + duration

namespace Setup

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  {electionTimeout maxDelay : Real} {participants : Finset NodeID} {first : Nat}
  {winner : NodeID} {term : Nat}
  (s : Setup nodes trace electionTimeout maxDelay participants first winner term)

/-- No other participant that could win a pre-vote quorum times out before this. -/
def margin : Real := time s.origin + 4 * maxDelay

/-- The winner's requests, but for their term. -/
def base : RequestVoteRequest := makeRequestVoteRequest s.initial

/-- What the race keeps of the other participants and the packets between
participants. Only a participant hopeless at `origin` and not yet in `term + 1` may time
out. -/
structure Common (point : W) (cap : Nat) : Prop where
  deadlines
    : forall node state,
        node ∈ participants
        -> node ≠ winner
        -> nodeState (proto point) node = some state
        -> (Hopeless participants s.origin node -> state.currentTerm = term + 1)
        -> s.margin < deadline point node
  nodes
    : forall node state,
        node ∈ participants
        -> node ≠ winner
        -> nodeState (proto point) node = some state
        -> Other s.origin winner term cap node state
  granted
    : forall node state,
        node ∈ participants
        -> node ≠ winner
        -> nodeState (proto point) node = some state
        -> Bounded participants s.origin term node state
  packets
    : forall packet,
        packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> packet.envelope.payload.term <= cap
            /\ Allowed participants s.origin winner s.base term packet.envelope

/-- The pre-vote phase: the winner collects pre-votes of `term`. -/
def Polling (point : W) : Prop :=
  s.margin < deadline point winner
  /\ exists state,
      nodeState (proto point) winner = some state
      /\ state.role = .preVoteCandidate
      /\ state.currentTerm = term
      /\ Keeps s.initial state
      /\ winner ∈ state.preVotesGranted
      /\ Not (hasQuorum state.activeConfigurations state.preVotesGranted)
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress point winner voter state.preVotesGranted
              (.requestPreVoteRequest { s.base with term := term })
              (.requestPreVoteResponse { term := term, voteGranted := true })
              (time s.origin) maxDelay

/-- The vote phase: the winner, a candidate since `sent`, collects votes of `term + 1`. -/
def Voting (point : W) (sent : Real) : Prop :=
  s.margin < deadline point winner
  /\ exists state,
      nodeState (proto point) winner = some state
      /\ state.role = .candidate
      /\ state.currentTerm = term + 1
      /\ Keeps s.initial state
      /\ winner ∈ state.votesGranted
      /\ Not (hasQuorum state.activeConfigurations state.votesGranted)
      /\ forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress point winner voter state.votesGranted
              (.requestVoteRequest { s.base with term := term + 1 })
              (.requestVoteResponse { term := term + 1, voteGranted := true })
              sent maxDelay

/-- The race is still on at `index`, in one of its two phases. -/
def Running (index : Nat) : Prop :=
  exists point,
    trace.stateAt index = some point
    /\ first < index
    /\ Within trace s.start s.duration index
    /\ ((s.Common point term
          /\ s.Polling point
          /\ time point <= time s.origin + 2 * maxDelay)
        \/ exists candidateIndex candidatePoint,
            first <= candidateIndex
            /\ candidateIndex < index
            /\ trace.stateAt candidateIndex = some candidatePoint
            /\ time candidatePoint <= time s.origin + 2 * maxDelay
            /\ (forall node state,
                  node ∈ participants
                  -> nodeState (proto candidatePoint) node = some state
                  -> state.currentTerm <= term)
            /\ s.Common point (term + 1)
            /\ s.Voting point (time candidatePoint)
            /\ time point <= time candidatePoint + 2 * maxDelay)

end Setup

section Lemmas

variable [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  {electionTimeout maxDelay : Real} {participants : Finset NodeID} {first : Nat}
  {winner : NodeID} {term : Nat}
  (s : Setup nodes trace electionTimeout maxDelay participants first winner term)

include s

namespace Setup

theorem delay_at {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    (alive : packet.envelope.target ∈ live point)
    : time point <= packet.sentAt + maxDelay := by
  cases index with
  | zero =>
      simp only [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      exact s.delay.1 packet member alive
  | succ index =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      exact s.delay.next stepped packet member alive

theorem stays_live {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (within : Within trace s.start s.duration index)
    (stepped : trace.stepAt index = some step) {node : NodeID}
    (member : node ∈ participants) (alive : node ∈ live step.before)
    : node ∈ live step.after := by
  by_contra dead
  have crashed := s.admissible.crashes stepped alive dead
  have next := s.admissible.within_after within stepped (fun idle => by
    rw [crashed] at idle
    cases idle)
  exact dead (s.period.participantsLive (index + 1) step.after node next
    (Trace.stateAt_succ_of_stepAt stepped) member)

theorem participants_live {index : Nat} {point : W}
    (within : Within trace s.start s.duration index)
    (found : trace.stateAt index = some point) {node : NodeID}
    (member : node ∈ participants)
    : node ∈ live point :=
  s.period.participantsLive index point node within found member

theorem margin_reset {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (stepped : trace.stepAt index = some step) {node : NodeID}
    (reset : ElectionReset step node)
    : s.margin < deadline step.after node := by
  have timeLe := s.admissible.time_le le s.originFound (s.admissible.before stepped)
  unfold margin
  linarith [(((s.timers.next stepped) node).1 reset).1, s.ratio]

theorem margin_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (stepped : trace.stepAt index = some step) {node : NodeID}
    (before : s.margin < deadline step.before node)
    : s.margin < deadline step.after node := by
  by_cases reset : ElectionReset step node
  · exact s.margin_reset le stepped reset
  · rw [((s.timers.next stepped) node).2.1 reset]
    exact before

/-- Every step keeps `Common.deadlines`: a node whose term rises is reset. -/
theorem deadlines_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (stepped : trace.stepAt index = some step)
    (before
      : forall node state,
          node ∈ participants
          -> node ≠ winner
          -> nodeState (proto step.before) node = some state
          -> (Hopeless participants s.origin node -> state.currentTerm = term + 1)
          -> s.margin < deadline step.before node)
    : forall node state,
        node ∈ participants
        -> node ≠ winner
        -> nodeState (proto step.after) node = some state
        -> (Hopeless participants s.origin node -> state.currentTerm = term + 1)
        -> s.margin < deadline step.after node := by
  intro node state member ne found top
  obtain ⟨previous, previousFound, termLe⟩ := node_before s.admissible stepped found
  by_cases lt : previous.currentTerm < state.currentTerm
  · exact s.margin_reset le stepped
      (reset_of_term_lt s.admissible stepped previousFound found lt)
  · exact s.margin_after le stepped (before node previous member ne previousFound
      fun hopeless => by have := top hopeless; omega)

theorem kept {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (member : packet ∈ pending step.before)
    (other : step.action.consumedPacket ≠ some packet)
    : packet ∈ pending step.after := by
  by_contra gone
  exact other (s.admissible.consumed_of_left stepped member gone)

theorem progress_time {point : W} {index : Nat} (found : trace.stateAt index = some point)
    {state : NodeState} (keeps : Keeps s.initial state) {granted : Finset NodeID}
    {request response : Message} {sent : Real}
    (member : winner ∈ granted)
    (noQuorum : Not (hasQuorum state.activeConfigurations granted))
    (progress
      : forall voter,
          voter ∈ s.voters
          -> voter ≠ winner
          -> Progress point winner voter granted request response sent maxDelay)
    (alive : forall node, node ∈ participants -> node ∈ live point)
    : time point <= sent + 2 * maxDelay := by
  by_contra late
  apply noQuorum
  rw [keeps.configurations]
  refine hasQuorum_mono s.quorate fun voter voterIn => ?_
  by_cases same : voter = winner
  · exact same ▸ member
  rcases progress voter voterIn same with
    granted | ⟨packet, pend, ⟨envEq, sentEq⟩ | ⟨envEq, sentLe⟩⟩
  · exact granted
  · have := s.delay_at found pend
      (by simpa [envEq] using alive voter (s.voterFacts voter voterIn same).1)
    linarith [s.nonnegative]
  · have := s.delay_at found pend (by simpa [envEq] using alive winner s.winnerIn)
    linarith

theorem Common.mono {point : W} (common : s.Common point term)
    : s.Common point (term + 1) where
  deadlines := common.deadlines
  granted := common.granted
  nodes node state member ne found := by
    obtain ⟨a, b, c, d⟩ := common.nodes node state member ne found
    exact ⟨a, b, by omega, d⟩
  packets packet member source target := by
    obtain ⟨le, allowed⟩ := common.packets packet member source target
    exact ⟨by omega, allowed⟩

end Setup

end Lemmas

end CCFRaft.Proofs.Duel.Racing
