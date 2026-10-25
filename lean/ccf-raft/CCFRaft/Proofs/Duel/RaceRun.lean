module

public import CCFRaft.Proofs.Duel.Race

@[expose] public section

/-!
# Running the race

NOT IMPORTED BY `Properties`. The invariant behind `race_won`: until the winner of
the race is primary, every step keeps the other participants and the packets between
participants in a small set of shapes, the winner's tally only grows, and every voter still
missing from it has its request or its grant in flight.
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

/-- The packets the race may have in flight: inert ones, the winner's requests to
others, and grants to the winner. -/
def Allowed (winner : NodeID) (base : RequestVoteRequest) (term : Nat)
    (envelope : Model.Envelope)
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

/-- No other participant times out before this. -/
def margin : Real := time s.origin + 4 * maxDelay

/-- The winner's requests, but for their term. -/
def base : RequestVoteRequest := makeRequestVoteRequest s.initial

/-- What the race keeps of the other participants and the packets between
participants. -/
structure Common (point : W) (cap : Nat) : Prop where
  deadlines
    : forall node, node ∈ participants -> node ≠ winner -> s.margin < deadline point node
  nodes
    : forall node state,
        node ∈ participants
        -> node ≠ winner
        -> nodeState (proto point) node = some state
        -> Other s.origin winner term cap node state
  packets
    : forall packet,
        packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> packet.envelope.payload.term <= cap
            /\ Allowed winner s.base term packet.envelope

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

theorem margin_after {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (le : first <= index) (stepped : trace.stepAt index = some step) {node : NodeID}
    (before : s.margin < deadline step.before node)
    : s.margin < deadline step.after node := by
  have timeLe := s.admissible.time_le le s.originFound (s.admissible.before stepped)
  have rule := (s.timers.next stepped) node
  unfold margin at *
  by_cases reset : ElectionReset step node
  · linarith [(rule.1 reset).1, s.ratio]
  · rw [rule.2.1 reset]
    exact before

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
  nodes node state member ne found := by
    obtain ⟨a, b, c, d⟩ := common.nodes node state member ne found
    exact ⟨a, b, by omega, d⟩
  packets packet member source target := by
    obtain ⟨le, allowed⟩ := common.packets packet member source target
    exact ⟨by omega, allowed⟩

end Setup

end Lemmas

end CCFRaft.Proofs.Duel.Racing
