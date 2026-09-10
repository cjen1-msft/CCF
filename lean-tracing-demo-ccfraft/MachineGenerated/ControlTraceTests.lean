-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TraceEncodingProofs

set_option autoImplicit false

namespace CCFRaft.ControlTraceTests

open TraceEncoding TraceSmt BoundedTrace

def node0 : Node := ⟨0, by decide⟩
def node1 : Node := ⟨1, by decide⟩

def start : Frame 0 :=
  { state := initialState, tracking := initialTracking initialState, pathId := 0 }

def elected : Frame 0 := controlFrame 1 (.timeout node1) start
def reelected : Frame 0 := controlFrame 2 (.timeout node1) elected

#guard decide (Enabled start.state (.timeout node1))
#guard !decide (Enabled start.state (.timeout node0))
#guard (elected.state.nodes node1).currentTerm == 2
#guard (reelected.state.nodes node1).currentTerm == 3
#guard (reelected.tracking.currentTerms node1).bindings.map (·.group) == [1, 2]
#guard (controlValue reelected.tracking node1 (markerSlot ROLE_SLOT_BASE node1)
  "role" (roleCode (reelected.state.nodes node1).role)).bindings.map (·.group) == [1]

def voted : Frame 0 := controlFrame 3 (.requestVote node1 node0) reelected
def repeatedVote : Frame 0 := controlFrame 4 (.requestVote node1 node0) voted

#guard decide (Enabled reelected.state (.requestVote node1 node0))
#guard (voted.state.network node0).length == 1
#guard (repeatedVote.state.network node0).length == 1
#guard (repeatedVote.tracking.queueLengths node0).eval Fin.elim0 == 1
#guard (repeatedVote.tracking.queueLengths node0).bindings.any (·.group == 3)
#guard (repeatedVote.tracking.queueLengths node0).bindings.any (·.group == 4)
#guard (repeatedVote.tracking.packetTerms
  (.requestVoteRequest (makeRequestVoteRequest reelected.state node1 node0))).bindings.map
    (·.group) == [1, 2, 3]

def written : Frame 0 := clientRequestFrame 1 node0 (.literal 0) start
def signed : Frame 0 := signatureFrame 2 node0 written

#guard (signed.tracking.logPositions node0 2).bindings.map (·.group) == [1, 2]

def frontierState : Template 1 :=
  let state : Template 1 := initialState
  { state with
    nodes := updateNode state.nodes node0
      { state.nodes node0 with
        currentTerm := 2
        log := [{ term := 1, content := .signature }, { term := 2, content := .signature }]
        matchIndex := fun _ => 2 } }

def frontierTracking : Tracking 1 :=
  { initialTracking frontierState with
    currentTerms := Function.update (initialTracking frontierState).currentTerms node0
      (.named 1 (markerSlot TERM_SLOT_BASE node0) "current term" (.unknown ⟨0, by decide⟩)) }

#guard (highestCommittableValue frontierState frontierTracking node0).eval (fun _ => 1) == 1
#guard (highestCommittableValue frontierState frontierTracking node0).eval (fun _ => 2) == 2
#guard (highestCommittableValue frontierState frontierTracking node0).eval (fun _ => 3) == 0
#guard (highestCommittableValue frontierState frontierTracking node0).bindings.any (·.group == 1)

def completedEntry : Frame 0 :=
  let state : Template 0 :=
    { initialState with retirementCompleted := fun node => if node = node0 then {node1} else ∅ }
  { state, tracking := initialTracking state, pathId := 0 }

def recorded : Frame 0 := retiredCommittedFrame 9 node0 completedEntry

#guard decide (Enabled completedEntry.state (.appendRetiredCommitted node0))
#guard (recorded.tracking.completedMembers node0 node1 false).eval Fin.elim0 == 0
#guard (recorded.tracking.completedMembers node0 node1 false).bindings.any (·.group == 9)

def reconfigured : Frame 0 := configurationFrame 7 node0 {node0, node1} start

#guard (latestConfigurationValue reconfigured.state reconfigured.tracking node0
  (fun configuration => decide (configuration.nodes = {node0, node1}))).eval Fin.elim0 == 1
#guard (latestConfigurationValue reconfigured.state reconfigured.tracking node0
  (fun configuration => decide (configuration.nodes = {node0, node1}))).bindings.any (·.group == 7)

def retainedConfigurations :=
  ControlTraceConfigurations.truncate
    (configurationSnapshots reconfigured.state reconfigured.tracking node0)
    (.named 8 (pathSlot 0 1) "next log length" (.literal 0))
    8 (fun index => pathSlot (Nat.pair 0 index) CONFIGURATION_SLOT)

#guard ControlTraceConfigurations.selected Fin.elim0 retainedConfigurations == [implicitConfiguration]
#guard match retainedConfigurations.drop 1 |>.head? with
  | some snapshot =>
      let writers := snapshot.present.bindings.map (·.group)
      writers.contains 7 && writers.contains 8
  | none => false

def shortened : Tracking 0 :=
  nextControlTracking 5 0 voted.state start.state voted.tracking

#guard (shortened.queueLengths node0).bindings.map (·.group) == [3, 5]
#guard (shortened.currentTerms node1).bindings.map (·.group) == [1, 2, 5]
#guard (shortened.queueLengths node0).eval Fin.elim0 == 0
#guard (shortened.currentTerms node1).eval Fin.elim0 == 1

def limits : Bounds :=
  { transactionCount := 2, termCount := 4, indexCount := 4,
    logCapacity := 4, queueCapacity := 1 }

#guard match (encode (holes := 0) limits initialState
    [.timeout node1, .timeout node1, .requestVote node1 node0,
     .observation (.currentTerm node1 3), .observation (.queueLength node0 1)]).prepare with
  | .ok prepared => prepared.groups.length == 7
  | .error _ => false

example (assignment : Fin 0 -> Nat) :
    FrameCorrect assignment repeatedVote := by
  apply controlFrame_correct
  apply controlFrame_correct
  apply controlFrame_correct
  apply controlFrame_correct
  exact initialTracking_correct assignment initialState

end CCFRaft.ControlTraceTests
