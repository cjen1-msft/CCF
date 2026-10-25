module

public import CCFRaft.Liveness.Assumptions.Window

@[expose] public section

/-!
# Premises at the start of a settling window

`Properties.signature_settles` and `Properties.signature_settles_catchup` derive a
stable window from a fresh start: the term is quiet among participants and no
participant of it times out for a while (`FreshStart`), and the primary tracks
every participant (`LatestMembers`). The common case adds that every participant
is in sync with the primary (`InSync`); the catch-up case bounds its backlog
instead (`BacklogTerms`, `InTermAt`).
-/

namespace CCFRaft.Liveness

open Model.Node
open CCF.MultiNodeTransitionSystem (nodeState)
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending)

/-- The AppendEntries request an envelope carries from `leader` to `peer`, if any. -/
def requestFor (leader peer : NodeID) (envelope : Model.Envelope)
    : Option AppendEntriesRequest :=
  if envelope.source = leader /\ envelope.target = peer then
    match envelope.payload with
    | .appendEntriesRequest request => some request
    | _ => none
  else
    none

/-- The AppendEntries requests outstanding from `leader` to `peer`, in ledger order. -/
def queued (leader peer : NodeID) (packets : List Packet) : List AppendEntriesRequest :=
  packets.filterMap fun packet => requestFor leader peer packet.envelope

/-- Requests of `term` that chain from `low` to `high`: each starts where the last
ended. -/
def Chain (term : Nat) : Nat -> List AppendEntriesRequest -> Nat -> Prop
  | low, [], high => low = high
  | low, request :: rest, high =>
      request.term = term
      /\ request.prevLogIndex = low
      /\ Chain term (low + request.entries.length) rest high

/-- A rejection from `peer` to `leader`. -/
def Nack (peer leader : NodeID) (envelope : Model.Envelope) : Prop :=
  envelope.source = peer
  /\ envelope.target = leader
  /\ exists response,
      envelope.payload = .appendEntriesResponse response /\ response.success = false

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- At `start` every participant other than the primary is in the primary's
latest active configuration, and so is one of its replication peers. -/
def LatestMembers (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall first state node,
    trace.stateAt start = some first
    -> nodeState (proto first) leader = some state
    -> node ∈ participants
    -> Not (node = leader)
    -> node ∈ latestConfigurationMembers state.activeConfigurations

/-- `QuietStart` among `participants`, with a freshness `fresh` in place of half
an election timeout: the term is quiet among participants at `start`, and no
participant of the term times out before `fresh` after it. An election spreads
the participants' timer resets over a few message delays, so the duel that ends
in `start` can only promise some `fresh` below `electionTimeout / 2`. -/
structure FreshStart (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID)
    (term : Nat) (participants : Finset NodeID) (fresh : Real)
    : Prop where
  quiet
    : exists first,
        trace.stateAt start = some first
        /\ QuietAmong participants leader term (proto first)
  timers
    : forall first index step node state,
        trace.stateAt start = some first
        -> start <= index
        -> trace.stepAt index = some step
        -> step.action = .local node (.timeout .election)
        -> nodeState (proto step.before) node = some state
        -> node ∈ participants
        -> state.currentTerm = term
        -> time first + fresh <= time step.before

omit [HasLive W] [HasNetwork W] in
/-- A quiet start is fresh for half an election timeout among any participants. -/
theorem FreshStart.of_quietStart {trace : Trace W Liveness.Event} {start : Nat}
    {leader : NodeID} {term : Nat} {electionTimeout : Real}
    (initial : QuietStart trace start leader term electionTimeout)
    (participants : Finset NodeID)
    : FreshStart trace start leader term participants (electionTimeout / 2) := by
  obtain ⟨first, found, quiet⟩ := initial.quiet
  exact ⟨⟨first, found, quiet.among participants⟩,
    fun first index step node state found afterStart stepped event nodeFound _ current =>
      initial.timers first index step node state found afterStart stepped event nodeFound
        current⟩

/-- `peer`, in state `state`, is in sync with `leader`, in state `leaderState`, at
`point`. -/
structure InSyncWith (leader : NodeID) (term : Nat) (peer : NodeID) (point : W)
    (leaderState state : NodeState)
    : Prop where
  leaderFound : nodeState (proto point) leader = some leaderState
  found : nodeState (proto point) peer = some state
  /-- Needed: a participant of an older term still accepts AppendEntries from a
  participant that was primary of that term. That old primary can rewrite the
  participant's log after the primary of `term` has sent it requests chained
  from the old log, and the next of those requests then fails its log check. -/
  current : state.currentTerm = term
  prefix_ : state.log <+: leaderState.log
  inflightChain
    : Chain term state.log.length (queued leader peer (pending point))
        (leaderState.sentIndex peer)
  /-- Needed: the primary handles a rejection of any term by rewinding its
  `sentIndex` for the peer to the retry hint, but not below its `matchIndex`. A
  stale rejection with a stale `matchIndex` rewinds it below the peer's commit
  index. The peer silently ignores the batch from there, as it starts below its
  commit index, and the next heartbeat, chained from that batch's end, fails its
  log check. -/
  noNack : forall packet, packet ∈ pending point -> Not (Nack peer leader packet.envelope)

/-- At `start`, every participant other than the primary is in sync with it. -/
def InSync (trace : Trace W Liveness.Event) (start : Nat) (leader : NodeID) (term : Nat)
    (participants : Finset NodeID)
    : Prop :=
  forall first peer,
    trace.stateAt start = some first
    -> peer ∈ participants
    -> Not (peer = leader)
    -> exists leaderState state, InSyncWith leader term peer first leaderState state

end CCFRaft.Liveness
