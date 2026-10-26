module

public import CCFRaft.Proofs.Duel.Round

@[expose] public section

/-!
# The leaderless round: definitions

NOT IMPORTED BY `Properties`. The definitions for the round's leaderless case. When
no participant becomes primary of `term + 1`, the round freezes once every
participant has adopted `term + 1`: logs, commit indices and configurations stay put,
nobody knows a primary, and the only live traffic of `term + 1` between participants
is pre-vote polling of participants that timed out. Whether a participant can gather a
pre-vote quorum is then fixed, so the first participant that can and times out either
raises the next round within two delays or, with a margin, wins a race.
-/

namespace CCFRaft.Proofs.Duel.Round

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending)
open CCF.MultiNodeTransitionSystem (nodeState)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [HasTimers W]

omit [HasLive W] [HasNetwork W] [HasTimers W] in
/-- No participant is primary of `term + 1` at a capped index at most `bound` after
the round start. -/
def NoElection (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term : Nat) (origin : W) (bound : Real)
    : Prop :=
  forall index point node state,
    Capped trace participants c term index
    -> trace.stateAt index = some point
    -> time point <= time origin + bound
    -> node ∈ participants
    -> nodeState (proto point) node = some state
    -> state.currentTerm = term + 1
    -> state.role ≠ .primary

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
open Classical in
/-- The participants whose logs a request from `state` covers. -/
noncomputable def Grantors (participants : Finset NodeID) (point : W) (state : NodeState)
    : Finset NodeID :=
  participants.filter
    fun voter =>
      exists voterState,
        nodeState (proto point) voter = some voterState
        /\ voteLogUpToDate voterState (makeRequestVoteRequest state)

omit [HasTime W] [HasLive W] [HasNetwork W] [HasTimers W] in
/-- Step `index` is an election timeout of `node` in `term + 1`. -/
def TermTimeout (trace : Trace W Liveness.Event) (term index : Nat) (node : NodeID)
    : Prop :=
  exists step state,
    trace.stepAt index = some step
    /\ step.action = .local node (.timeout .election)
    /\ nodeState (proto step.before) node = some state
    /\ state.currentTerm = term + 1

omit [HasTime W] [HasLive W] [HasTimers W] in
/-- The frozen state of a leaderless round at `index`: every participant is in
`term + 1`, knows no primary and can campaign; a pre-vote candidate timed out in the
round and holds only grants from participants its log covers; and between
participants nothing of `term + 1` is in flight except pre-vote polling of
participants that timed out in the round. -/
structure Frozen (trace : Trace W Liveness.Event) (participants : Finset NodeID)
    (c term index : Nat) (point : W)
    : Prop where
  nodes
    : forall node state,
        node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.currentTerm = term + 1
            /\ state.primaryKnown = false
            /\ canStartElection state node
  polling
    : forall node state,
        node ∈ participants
        -> nodeState (proto point) node = some state
        -> state.preVotesGranted ⊆ insert node (Grantors participants point state)
            /\ (state.role = .preVoteCandidate
                -> exists earlier,
                    c <= earlier
                    /\ earlier < index
                    /\ TermTimeout trace term earlier node)
  packets
    : forall packet,
        packet ∈ pending point
        -> packet.envelope.source ∈ participants
        -> packet.envelope.target ∈ participants
        -> (forall request,
              packet.envelope.payload = .appendEntriesRequest request
              -> request.term <= term)
            /\ packet.envelope.payload ≠ .proposeRequestVoteRequest (term + 1)
            /\ (forall request,
                  packet.envelope.payload = .requestPreVoteRequest request
                  -> request.term = term + 1
                  -> (exists state,
                        nodeState (proto point) packet.envelope.source = some state
                        /\ request = makeRequestVoteRequest state)
                      /\ exists earlier,
                          c <= earlier
                          /\ earlier < index
                          /\ TermTimeout trace term earlier packet.envelope.source)
            /\ (packet.envelope.payload
                  = .requestPreVoteResponse { term := term + 1, voteGranted := true }
                -> (forall state,
                      nodeState (proto point) packet.envelope.target = some state
                      -> packet.envelope.source ∈ Grantors participants point state)
                    /\ exists earlier,
                        c <= earlier
                        /\ earlier < index
                        /\ TermTimeout trace term earlier packet.envelope.target)

end CCFRaft.Proofs.Duel.Round
