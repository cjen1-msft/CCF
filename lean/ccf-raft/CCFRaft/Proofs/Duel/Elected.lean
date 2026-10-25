module

public import CCFRaft.Proofs.Duel.RoundDefs

@[expose] public section

/-!
# The elected case of a duel round

NOT IMPORTED BY `Properties`. A primary of `term + 1` elected early in a round
settles its voters into an anchored start four delays after the round starts.
The facts about the round's terms and packets (`Round.RoundSetup.adopted` and
`Round.RoundSetup.packets`) are hypotheses here, proved in `Duel.Round`.
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
  [HasTimers W] [Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event} {electionTimeout maxDelay jump : Real} {start : Nat}
  {duration : Real} {participants members : Finset NodeID} {c term : Nat}

/-! ## The elected case -/

/-- An election of `term + 1` early in the round settles its voters into an anchored
start by `time c + 4 * maxDelay`. The anchor is the primary's voters. -/
theorem RoundSetup.handoff_of_elected
    (setup
      : RoundSetup nodes trace electionTimeout maxDelay jump start duration participants
          members c term)
    {index : Nat} {origin point : W} {leader : NodeID} {state : NodeState}
    (originFound : trace.stateAt c = some origin)
    (adopted
      : forall index point,
          Capped trace participants c term index
          -> trace.stateAt index = some point
          -> time origin + maxDelay < time point
          -> forall node state,
              node ∈ participants
              -> nodeState (proto point) node = some state
              -> state.currentTerm = term + 1)
    (packets
      : forall index point packet,
          Capped trace participants c term index
          -> trace.stateAt index = some point
          -> packet ∈ pending point
          -> packet.envelope.source ∈ participants
          -> packet.envelope.target ∈ participants
          -> packet.envelope.payload.term <= term + 1
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
                  -> time origin + electionTimeout / 2 <= packet.sentAt))
    (capped
      : forall index point,
          c <= index
          -> trace.stateAt index = some point
          -> time point < time origin + electionTimeout / 2
          -> Capped trace participants c term index)
    (indexLe : c <= index)
    (found : trace.stateAt index = some point)
    (early : time point <= time origin + 3 * maxDelay) (member : leader ∈ participants)
    (leaderFound : nodeState (proto point) leader = some state)
    (primary : state.role = .primary) (termEq : state.currentTerm = term + 1)
    : HandoffBy trace participants c (4 * maxDelay)
        (electionTimeout / 2 - 4 * maxDelay) := by
  sorry

end CCFRaft.Proofs.Duel.Round
