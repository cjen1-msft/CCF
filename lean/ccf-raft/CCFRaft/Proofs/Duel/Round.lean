module

public import CCFRaft.Proofs.Duel.RoundDefs

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
  sorry

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
  sorry

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
        -> Capped trace participants c term index := by
  sorry

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
