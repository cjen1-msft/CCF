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

abbrev TxId := Fin 8
abbrev RaftState := State TxId

def followerOne : Node := ⟨1, by decide⟩
def followerTwo : Node := ⟨2, by decide⟩

def initial : RaftState :=
  initialState

def requested : RaftState :=
  next initial (.clientRequest LEADER 0)

def sentOne : RaftState :=
  next requested (.appendEntries LEADER followerOne 1)

def receivedOne : RaftState :=
  next sentOne (.receive LEADER followerOne)

def ackedOne : RaftState :=
  next receivedOne (.receive followerOne LEADER)

def sentTwo : RaftState :=
  next ackedOne (.appendEntries LEADER followerTwo 1)

def receivedTwo : RaftState :=
  next sentTwo (.receive LEADER followerTwo)

def ackedTwo : RaftState :=
  next receivedTwo (.receive followerTwo LEADER)

def committed : RaftState :=
  next ackedTwo (.advanceCommitIndex LEADER)

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

theorem committedLogIsNonempty :
    (committed.nodes LEADER).committedLog =
      [{ term := TERM_ONE, txId := 0 }] := by
  decide

theorem exampleCommittedLogsPrefix :
    CommittedLogsPrefix committed :=
  reachableCommittedLogsPrefix requestReplicateCommitReachable

theorem exampleLogMatching :
    LogMatching committed :=
  reachableLogMatching requestReplicateCommitReachable

end CCFRaft.Examples
