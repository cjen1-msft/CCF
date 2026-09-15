-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncodingProofs

set_option autoImplicit false

namespace CCFRaft.ReceiveTraceTests

open TraceSmt TraceEncoding

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩
def start : Frame 0 := { state := initialState, tracking := initialTracking initialState, pathId := 0 }
def offered : Frame 0 := controlFrame 1 (.proposeVote node0 node1) start
def elected : Frame 0 := (receiveFrames 2 offered node0 node1).eval Fin.elim0

#guard (elected.state.nodes node1).role == .candidate
#guard (elected.state.nodes node1).currentTerm == 2
#guard (elected.tracking.currentTerms node1).eval Fin.elim0 == 2
#guard (elected.tracking.currentTerms node1).bindings.any (·.group == 1)
#guard elected.state.network node1 == []
#guard (elected.tracking.queueLengths node1).eval Fin.elim0 == 0

def written : Frame 0 := clientRequestFrame 1 node0 (.literal 0) start
def signed : Frame 0 := signatureFrame 2 node0 written
def sent : Frame 0 := (appendFrames 3 signed node0 node1 1).eval Fin.elim0
def received : Frame 0 := (receiveFrames 4 sent node0 node1).eval Fin.elim0

#guard (received.state.nodes node1).log.length == 1
#guard (received.tracking.logLengths node1).eval Fin.elim0 == 1
#guard (received.tracking.logLengths node1).bindings.any (·.group == 3)
#guard received.state.network node1 == []
#guard (received.state.network node0).length == 1

def staleRetirement : Frame 0 :=
  let state : BoundedTrace.Template 0 := { start.state with retirementCompleted := fun node =>
    if node = node0 then {node1} else ∅ }
  { state, tracking := initialTracking state, pathId := 0 }

def refreshedRetirement : Frame 0 := rememberReceiveRetirement 8 staleRetirement start node0

#guard (refreshedRetirement.tracking.completedMembers node0 node1 false).bindings.any (·.group == 8)
#guard !(refreshedRetirement.tracking.completedMembers node0 node0 false).bindings.any (·.group == 8)

end CCFRaft.ReceiveTraceTests
