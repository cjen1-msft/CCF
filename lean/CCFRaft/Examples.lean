-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs

set_option autoImplicit false

/-!
# Slice 1 non-vacuity examples

This is the public behavior seam for the single-term AppendEntries slice. The
examples construct an ordinary five-node request, replication, ACK, and quorum
commit path through the same executable `Enabled`/`next` semantics used by the
simulator.
-/

namespace CCFRaft.Examples

/-- Eight transaction IDs are enough for the concrete non-vacuity path. -/
abbrev TxId := Fin 8
/-- The concrete state type used by this example. -/
abbrev RaftState := State TxId

/-- The first follower used to form a majority. -/
def followerOne : Node := ⟨1, by decide⟩
/-- The second follower used to form a majority. -/
def followerTwo : Node := ⟨2, by decide⟩

/-- The empty five-node initial state. -/
def initial : RaftState :=
  initialState

/-- State after the leader accepts transaction zero. -/
def requested : RaftState :=
  next initial (.clientRequest LEADER 0)

/-- State after sending the entry to the first follower. -/
def sentOne : RaftState :=
  next requested (.appendEntries LEADER followerOne 1)

/-- State after the first follower appends the entry and sends an ACK. -/
def receivedOne : RaftState :=
  next sentOne (.receive LEADER followerOne)

/-- State after the leader records the first follower's ACK. -/
def ackedOne : RaftState :=
  next receivedOne (.receive followerOne LEADER)

/-- State after sending the entry to the second follower. -/
def sentTwo : RaftState :=
  next ackedOne (.appendEntries LEADER followerTwo 1)

/-- State after the second follower appends the entry and sends an ACK. -/
def receivedTwo : RaftState :=
  next sentTwo (.receive LEADER followerTwo)

/-- State after the leader records enough ACKs for a majority. -/
def ackedTwo : RaftState :=
  next receivedTwo (.receive followerTwo LEADER)

/-- State after the leader advances its commit index to one. -/
def committed : RaftState :=
  next ackedTwo (.advanceCommitIndex LEADER)

/-- The request, replication, ACK, and quorum-commit path is genuinely reachable. -/
theorem requestReplicateCommitReachable :
    Reachable committed := by
  have requestedReachable : Reachable requested :=
    Reachable.step Reachable.initial (by decide)
  have sentOneReachable : Reachable sentOne :=
    Reachable.step requestedReachable (by decide)
  have receivedOneReachable : Reachable receivedOne :=
    Reachable.step sentOneReachable (by decide)
  have ackedOneReachable : Reachable ackedOne :=
    Reachable.step receivedOneReachable (by decide)
  have sentTwoReachable : Reachable sentTwo :=
    Reachable.step ackedOneReachable (by decide)
  have receivedTwoReachable : Reachable receivedTwo :=
    Reachable.step sentTwoReachable (by decide)
  have ackedTwoReachable : Reachable ackedTwo :=
    Reachable.step receivedTwoReachable (by decide)
  exact Reachable.step ackedTwoReachable (by decide)

/-- The example ends with transaction zero in the committed leader log. -/
theorem committedLogIsNonempty :
    (committed.nodes LEADER).committedLog =
      [{ term := TERM_ONE, txId := 0 }] := by
  decide

/-- The concrete committed state satisfies committed-log prefix safety. -/
theorem exampleCommittedLogsPrefix :
    CommittedLogsPrefix committed :=
  reachableCommittedLogsPrefix requestReplicateCommitReachable

/-- The concrete committed state satisfies Raft log matching. -/
theorem exampleLogMatching :
    LogMatching committed :=
  reachableLogMatching requestReplicateCommitReachable

end CCFRaft.Examples
