module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter
public import CCF.Execution
public import MidTrace.Model

@[expose] public section

namespace Consensus.MidTrace.Properties

open Model.Node
open Replay (Envelope Header Instruction NativeSend Packet ReplayState StateSnapshot Step)
open CCF.MultiNodeTransitionSystem (removeOne)

/-- A send observation identifies the recipient and the native projection of the payload. -/
def SendMatches (header : Header) (send : NativeSend) (envelope : Envelope) : Prop :=
  header.nodeId send.target = .ok envelope.target
  /\ (send.packet == Packet.ofMessage envelope.payload) = true

/-- The observed sends account for every envelope, including multiplicities. -/
def SendsMatch (header : Header) (sends : List NativeSend) (queued : List Envelope)
    : Prop :=
  exists ordered,
    queued.Perm ordered
    /\ sends.length = ordered.length
    /\ forall pair, pair ∈ sends.zip ordered -> SendMatches header pair.1 pair.2

/-- The concrete action corresponding to a source instruction at this state. -/
inductive ActionMatches (header : Header) (state : Model.State)
    : Step -> Model.Action -> Prop
  | local {node : String} {self : NodeID} {input : Input}
    (named : header.nodeId node = .ok self)
    : ActionMatches header state (.local node input) (.local self input)
  | receive {source destination : String} {packet : Packet} {envelope : Envelope}
    (namedSource : header.nodeId source = .ok envelope.source)
    (namedTarget : header.nodeId destination = .ok envelope.target)
    (payload : (packet == Packet.ofMessage envelope.payload) = true)
    : ActionMatches header state (.receive source destination packet) (.deliver envelope)
  | initAsBackup {node : String} {self : NodeID} {index view : Nat}
    {source : NodeID} {localState : NodeState}
    (named : header.nodeId node = .ok self)
    (member : (source, localState) ∈ state.nodes)
    (committed : index <= localState.commitIndex)
    (signature : index = 0 \/ isSignatureAt localState.log index = true)
    (term : termAt localState.log index = view)
    : ActionMatches header state (.initAsBackup node index view)
        (.local self (.initAsBackup (localState.log.take index)))

/-- The network left after consuming the input, before appending this step's sends. -/
def pendingAfter (state : Model.State) : Model.Action -> List Envelope
  | .local .. => state.network
  | .deliver envelope => removeOne envelope state.network

/-- One model action or a checked observation, which contributes no model action. -/
inductive ValidInstruction (header : Header)
    : ReplayState -> Instruction -> List Model.Action -> ReplayState -> Prop
  | action {before : ReplayState} {after : Model.State} {action : Model.Action}
    {step : Step} {origin : Replay.Origin} {sent : List Envelope}
    (resolved : ActionMatches header before.state step action)
    (transition : Model.networkStep header.bootstrap before.state action = some after)
    (network : after.network = pendingAfter before.state action ++ sent)
    : ValidInstruction header before (.action step origin) [action]
        { state := after, queued := before.queued ++ sent }
  | node {before : ReplayState} {node : String} {expected : StateSnapshot}
    {origin : Replay.Origin}
    (observed : Replay.observeState header node expected before = .ok ())
    : ValidInstruction header before (.observeNodeState node expected origin) [] before
  | sends {before : ReplayState} {sends : List NativeSend} {origin : Replay.Origin}
    (observed : SendsMatch header sends before.queued)
    : ValidInstruction header before (.observeSends sends origin) []
        { before with queued := [] }

/-- An instruction-by-instruction execution from the given cut. The action list excludes
observations, but their positions and the send queue at each position are preserved. -/
inductive ValidInstructions (header : Header)
    : ReplayState -> List Instruction -> List Model.Action -> ReplayState -> Prop
  | nil (state : ReplayState) : ValidInstructions header state [] [] state
  | cons {before middle after : ReplayState} {instruction : Instruction}
    {instructions : List Instruction} {actions rest : List Model.Action}
    (first : ValidInstruction header before instruction actions middle)
    (tail : ValidInstructions header middle instructions rest after)
    : ValidInstructions header before (instruction :: instructions) (actions ++ rest)
        after

end Consensus.MidTrace.Properties
