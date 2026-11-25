module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.EventSupport

namespace ConsensusCoverage.DeepSchedules

open Consensus Consensus.Model Consensus.Model.Node FrontierRows

-- Resolve a message by kind as well as route: delayed elections and
-- replication responses can occupy the same route simultaneously.
private inductive Op where
  | input (node : NodeID) (action : Input)
  | msg (source target : NodeID) (kind : EventSupport.Tag)

private def Op.command : Op → Command
  | .input n a => .input n a
  | .msg s t _ => .deliver s t

private structure Script where
  cfg : FullProfile.Configuration
  nodes : List NodeID
  ops : List Op

private def Script.run (s : Script) : Run := ⟨s.cfg, s.nodes, s.ops.map Op.command⟩

private def Script.choices (script : Script) : List (Nat × Nat) := Id.run do
  let mut state := initial script.run
  let mut picks := []
  for (op, i) in script.ops.zipIdx do
    let action ← match op with
      | .input n a => pure (.local n a)
      | .msg n m k =>
        let some j := state.network.findIdx? (fun e =>
          e.source == n && e.target == m && decide (EventSupport.actionTag (.deliver e) = k))
          | return (i, state.network.length) :: picks
        let some e := state.network[j]? | return (i, j) :: picks
        if state.network.find? (fun e => e.source == n && e.target == m) != some e then
          picks := (i, j) :: picks
        pure (.deliver e)
    let some after := (transitionSystem script.cfg script.nodes).step state action | return picks
    state := after
  return picks

private def installLater : Script := ⟨{0, 1}, [0, 1, 2], [
  .input 0 (.append [{content := .signature, flushes := [(1, 2)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 1 0 .appendEntriesResponse,
  .input 0 .nominateSuccessor, .msg 0 1 .proposeRequestVoteRequest,
  .msg 1 0 .requestVoteRequest, .msg 0 1 .requestVoteResponse,
  .input 1 (.append [{content := .signature, flushes := [(0, 3)]}]),
  .msg 1 0 .appendEntriesRequest, .msg 1 0 .appendEntriesRequest,
  .msg 0 1 .appendEntriesResponse, .msg 0 1 .appendEntriesResponse,
  .input 2 (.initAsBackup [
    {term := 2, content := .transaction 0 {configuration := some {0, 1}}},
    {term := 2, content := .signature}, {term := 3, content := .signature}])]⟩

-- Node 2 votes for 1 without advancing the old primary's term. Both voters
-- have the first signature, but neither has learned its commit index.
private def splitLeaders : List Op := [
  .input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .input 0 .nominateSuccessor,
  .input 0 (.append [{content := .signature}]),
  .msg 0 1 .proposeRequestVoteRequest, .msg 1 2 .requestVoteRequest,
  .msg 2 1 .requestVoteResponse]

private def divergent : Script := ⟨{0, 1, 2}, [0, 1, 2], splitLeaders ++ [
  .input 1 (.append [{content := .signature, flushes := [(0, 3)]}]),
  .msg 1 0 .appendEntriesRequest, .msg 1 0 .appendEntriesRequest,
  .input 1 (.append [{content := .signature, flushes := [(0, 4)]}]),
  .msg 1 0 .appendEntriesRequest]⟩

-- Drain the stale success before requesting a reply from the higher-term
-- voter. Node 0 is still primary when the rejection arrives.
private def higherReply : Script := { divergent with ops := splitLeaders ++ [
  .msg 2 0 .appendEntriesResponse, .input 0 (.sendEntries 2 3),
  .msg 0 2 .appendEntriesRequest, .msg 2 0 .appendEntriesResponse] }

-- Node 0's third signature changes from term 2 to term 3, and it then
-- campaigns with the replacement log, granting itself a term-4 vote.
private def lossGrant : Script := { divergent with ops := divergent.ops ++ [
  .msg 0 1 .appendEntriesResponse, .msg 0 1 .appendEntriesResponse,
  .msg 0 1 .appendEntriesResponse, .input 1 .nominateSuccessor,
  .msg 1 0 .proposeRequestVoteRequest] }

-- Deliver the second batch first. The follower rejects its missing prefix,
-- enabling a retry overlapping the still-queued first batch.
private def overlappingBatch : Run := ⟨{0, 1}, [0, 1], [
  .input 0 (.append [{content := .signature, flushes := [(1, 2)]},
    {content := .signature, flushes := [(1, 3)]}]),
  .deliver 0 1, .deliver 1 0, .input 0 (.sendEntries 1 3),
  .deliver 0 1, .deliver 0 1]⟩

-- In term 3, voters 0, 3, 4 see a newer signature before the delayed term-2
-- nomination reaches voter 1. Voter 2 can still grant 1's request.
private def doomed : Script := ⟨{0, 1, 2, 3, 4}, [0, 1, 2, 3, 4], [
  .input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2), (3, 2), (4, 2)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 1 0 .appendEntriesResponse,
  .input 0 .nominateSuccessor,
  .msg 0 2 .appendEntriesRequest, .msg 0 3 .appendEntriesRequest,
  .msg 0 4 .appendEntriesRequest, .msg 4 0 .appendEntriesResponse,
  .input 0 .nominateSuccessor, .msg 0 4 .proposeRequestVoteRequest,
  .msg 4 0 .requestVoteRequest, .msg 0 4 .requestVoteResponse,
  .msg 4 3 .requestVoteRequest, .msg 3 4 .requestVoteResponse,
  .input 4 (.append [{content := .signature, flushes := [(0, 3), (3, 3)]}]),
  .msg 4 0 .appendEntriesRequest, .msg 4 0 .appendEntriesRequest,
  .msg 4 3 .appendEntriesRequest, .msg 4 3 .appendEntriesRequest,
  .msg 0 1 .proposeRequestVoteRequest, .msg 1 2 .requestVoteRequest,
  .msg 2 1 .requestVoteResponse]⟩

-- Teach the lagging nominee its first positive commit but withhold the
-- nomination until the other quorum holds two further signed prefixes.
private def laggingBacked : Script := { doomed with
  ops := doomed.ops.take 8 ++ [
    .input 0 (.sendEntries 1 2), .msg 0 1 .appendEntriesRequest] ++
    ((doomed.ops.drop 8).take 11) ++ [
      .input 4 (.append [{content := .signature, flushes := [(0, 4), (3, 4)]}]),
      .msg 4 0 .appendEntriesRequest, .msg 4 3 .appendEntriesRequest] ++ doomed.ops.drop 19 }

-- Two copies of the old leader's second signature are not a majority of
-- five. The queued third copy reaches 4 after 1 has won with 2 and 3.
private def lateCopy : Script := ⟨{0, 1, 2, 3, 4}, [0, 1, 2, 3, 4], [
  .input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .msg 2 0 .appendEntriesResponse,
  .input 0 (.append [{content := .signature, flushes := [(1, 3), (4, 3)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 1 0 .appendEntriesResponse,
  .input 0 .nominateSuccessor, .msg 0 1 .proposeRequestVoteRequest,
  .msg 1 2 .requestVoteRequest, .msg 2 1 .requestVoteResponse,
  .msg 1 3 .requestVoteRequest, .msg 3 1 .requestVoteResponse,
  .msg 0 4 .appendEntriesRequest]⟩

-- Leave 0 in term 2 when electing 1 in term 3. Elect 2 in term 4 either
-- with 0 (leaving 1 behind) or with 1 (leaving 0 behind).
private def threeTerms (higherBacking : Bool) : Script := ⟨{0, 1, 2}, [0, 1, 2], [
  .input 0 (.append [{content := .signature, flushes := [(1, 2), (2, 2)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .input 0 .nominateSuccessor,
  .input 0 (.sendEntries 2 2), .msg 0 2 .appendEntriesRequest,
  .msg 0 1 .proposeRequestVoteRequest, .msg 1 2 .requestVoteRequest,
  .msg 2 1 .requestVoteResponse,
  .input 1 (.append [{content := .signature, flushes := [(2, 3)]}]),
  .msg 1 2 .appendEntriesRequest, .msg 1 2 .appendEntriesRequest,
  .msg 2 1 .appendEntriesResponse, .msg 2 1 .appendEntriesResponse] ++
  (if higherBacking then [.input 1 (.sendEntries 2 3), .msg 1 2 .appendEntriesRequest] else []) ++
  [.input 1 .nominateSuccessor, .msg 1 2 .proposeRequestVoteRequest,
   .msg 2 (if higherBacking then 1 else 0) .requestVoteRequest,
   .msg (if higherBacking then 1 else 0) 2 .requestVoteResponse]⟩

-- Leave candidate 2's commit at zero. Its term-3 signature strictly
-- outranks term 2's quorum signature without its commit already covering it.
private def rankGap : Script := ⟨{0, 1, 2}, [0, 1, 2], [
  .input 0 (.append [{content := .signature},
    {content := .signature, flushes := [(1, 3), (2, 3)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .input 0 .nominateSuccessor,
  .msg 0 1 .proposeRequestVoteRequest, .msg 1 2 .requestVoteRequest,
  .msg 2 1 .requestVoteResponse,
  .input 1 (.append [{content := .signature, flushes := [(2, 4)]}]),
  .msg 1 2 .appendEntriesRequest, .msg 1 2 .appendEntriesRequest,
  .msg 2 1 .appendEntriesResponse, .msg 2 1 .appendEntriesResponse,
  .input 1 .nominateSuccessor, .msg 1 2 .proposeRequestVoteRequest,
  .msg 2 0 .requestVoteRequest, .msg 0 2 .requestVoteResponse]⟩

-- The old configuration {1, 2} can commit through 5. After that commit,
-- the new configuration {1} can commit the retirement through 7 on append.
private def retireOnAppend : Script := ⟨{0, 1, 2}, [0, 1, 2], [
  .input 0 (.append [{content := .transaction 1 {configuration := some {1, 2}}},
    {content := .signature, flushes := [(1, 3), (2, 3)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .msg 2 0 .appendEntriesResponse,
  .input 0 (.append [{content := .transaction 2 {configuration := some {1}}},
    {content := .signature, flushes := [(2, 5)]},
    {content := .transaction 3 {retirementConfirmations := {0}}},
    {content := .signature, flushes := [(1, 7)]}]),
  .msg 0 1 .appendEntriesRequest, .msg 0 2 .appendEntriesRequest,
  .msg 1 0 .appendEntriesResponse, .msg 2 0 .appendEntriesResponse,
  .input 0 (.append [{content := .transaction 4 {}}])]⟩

-- The same retiring append emits both an ordinary replication message
-- during the batch and a successor nomination during commit advancement.
private def retiringFlush : Script := { retireOnAppend with ops := retireOnAppend.ops.take 10 ++ [
  .input 0 (.append [{content := .transaction 4 {}, flushes := [(1, 8)]}])] }

end ConsensusCoverage.DeepSchedules
