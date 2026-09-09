-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.GuardedReceive
import Lean

set_option autoImplicit false

namespace CCFRaft.GuardedReceive.Tests

open TraceSmt TransactionMapping

private def source : Node := ⟨0, by decide⟩
private def destination : Node := ⟨1, by decide⟩
private def other : Node := ⟨2, by decide⟩
private def absent : Node := ⟨14, by decide⟩
private def old : NatTerm 2 := .unknown 0
private def fresh : NatTerm 2 := .unknown 1
private def aliased : Fin 2 -> Nat := fun _ => 7
private def distinct : Fin 2 -> Nat := fun index => index.val + 7
private def tx (value : NatTerm 2) (term : Nat := 1) : Entry Node (NatTerm 2) :=
  { term, content := .transaction value }
private def signature : Entry Node (NatTerm 2) := { term := 1, content := .signature }

private def follower : NodeState Node (NatTerm 2) :=
  { (freshNodeState : NodeState Node (NatTerm 2)) with
    role := .follower, currentTerm := 1, log := [tx old] }

private def request : AppendEntriesRequest Node (NatTerm 2) :=
  { term := 1, prevLogIndex := 0, prevLogTerm := 0, entries := [tx fresh, signature],
    leaderCommit := 2, source, destination }

private def entry (node : NodeState Node (NatTerm 2))
    (queue : List (Message Node (NatTerm 2))) : State Node (NatTerm 2) :=
  { (initialState : State Node (NatTerm 2)) with
    nodes := updateNode (initialState : State Node (NatTerm 2)).nodes destination node
    network := fun node => if node = destination then queue else []
    submittedTxIds := {old, fresh} }

private def minimal := entry follower [.appendEntriesRequest request]
private def run (state : State Node (NatTerm 2)) (assignment : Fin 2 -> Nat := aliased) :=
  (step state source destination).eval assignment

-- Syntactic prefix inequality is not a valid enabledness test after decoding.
#guard !(decide (Enabled minimal (.receive source destination)))
#guard decide (Enabled (mapState (NatTerm.eval aliased) minimal) (.receive source destination))
#guard !(decide (Enabled (mapState (NatTerm.eval distinct) minimal) (.receive source destination)))
#guard (run minimal).enabled
#guard !(run minimal distinct).enabled
#guard ((run minimal).successor.nodes destination).log == [tx fresh, signature]
#guard ((run minimal).successor.nodes destination).commitIndex == 2
#guard (run minimal).successor.network destination == []
#guard (run minimal distinct).successor.network destination == [.appendEntriesRequest request]
#guard ((run minimal distinct).successor.nodes destination).log == [tx old]
#guard ((next minimal (.receive source destination)).nodes destination).log.length == 1
#guard ((next (mapState (NatTerm.eval aliased) minimal)
  (.receive source destination)).nodes destination).log.length == 2
#guard !((run minimal).successor.nodes.node? absent).isSome
#guard !((run minimal distinct).successor.nodes.node? absent).isSome
#guard (run minimal).successor.submittedTxIds == {old, fresh}
#guard (mapState (NatTerm.eval aliased) (run minimal).successor).submittedTxIds.card == 1

private def ack : Message Node (NatTerm 2) :=
  .appendEntriesResponse
    { term := 1, success := true, lastLogIndex := 2, source := destination,
      destination := source }

#guard (run minimal).successor.network source == [ack]

-- An existing ACK is retained once, even with transaction-bearing packets nearby.
private def ackQueued : State Node (NatTerm 2) :=
  { minimal with network := fun node =>
      if node = source then [.appendEntriesRequest request, ack, .appendEntriesRequest request]
      else minimal.network node }
#guard (run ackQueued).successor.network source ==
  [.appendEntriesRequest request, ack, .appendEntriesRequest request]

private def unrelated : Message Node (NatTerm 2) :=
  .proposeVoteRequest { term := 1, source := other, destination }
private def later : Message Node (NatTerm 2) :=
  .proposeVoteRequest { term := 0, source, destination }
private def filtered := entry follower
  [unrelated, .appendEntriesRequest request, unrelated, later]
#guard (run filtered).enabled
#guard (run filtered).successor.network destination == [unrelated, unrelated, later]
#guard (run filtered distinct).successor.network destination ==
  [unrelated, .appendEntriesRequest request, unrelated, later]
#guard !((step filtered absent destination).eval aliased).enabled
#guard !((step filtered destination source).eval aliased).enabled

-- Candidates step down without consuming or replying to the selected request.
private def candidate := entry { follower with role := .candidate }
  [unrelated, .appendEntriesRequest request, later]
private def preCandidate := entry { follower with role := .preVoteCandidate }
  [.appendEntriesRequest request]
#guard (run candidate distinct).enabled
#guard ((run candidate distinct).successor.nodes destination).role == .follower
#guard ((run candidate distinct).successor.nodes destination).isNewFollower
#guard (run candidate distinct).successor.network destination == candidate.network destination
#guard (run candidate distinct).successor.network source == []
#guard (run preCandidate).enabled
#guard ((run preCandidate).successor.nodes destination).role == .follower
#guard (run preCandidate).successor.network destination == preCandidate.network destination
#guard !(run (run candidate distinct).successor distinct).enabled
#guard (run (run candidate).successor).enabled

-- Rejection, term-only already-done, truncation/retry, and blocked acceptance.
private def stale := entry follower [.appendEntriesRequest { request with term := 0 }]
private def future := entry follower [.appendEntriesRequest { request with term := 2 }]
private def wrongDestination := entry follower
  [.appendEntriesRequest { request with destination := other }, later]
private def done := entry follower
  [.appendEntriesRequest { request with entries := [tx fresh] }]
private def conflict := entry { follower with log := [tx old 2] }
  [.appendEntriesRequest request]
private def blockedConflict := entry { follower with log := [tx old 2], isNewFollower := false }
  [.appendEntriesRequest request]
private def blockedCommit := entry { follower with commitIndex := 1 }
  [.appendEntriesRequest request]
private def badPrevious := entry follower
  [.appendEntriesRequest { request with prevLogIndex := 1, prevLogTerm := 3 }]
private def heartbeat := entry follower [.appendEntriesRequest { request with entries := [] }]
#guard (run stale).enabled
#guard (run stale).successor.network destination == []
#guard ((run stale).successor.nodes destination).log == [tx old]
#guard !(run future).enabled
#guard !(run wrongDestination).enabled
#guard (run wrongDestination).successor.network destination == wrongDestination.network destination
#guard (run done distinct).enabled
#guard ((run done distinct).successor.nodes destination).log == [tx old]
#guard (run conflict distinct).enabled
#guard ((run conflict distinct).successor.nodes destination).log == [tx fresh, signature]
#guard !((run conflict distinct).successor.nodes destination).isNewFollower
#guard !(run blockedConflict).enabled
#guard !(run blockedCommit).enabled
#guard (run badPrevious).enabled
#guard (run badPrevious).successor.network destination == []
#guard (run heartbeat).enabled

private def reconfiguration : Entry Node (NatTerm 2) :=
  { term := 1, content := .reconfiguration {source} }
private def retired : Entry Node (NatTerm 2) :=
  { term := 1, content := .retiredCommitted {destination} }
private def retirement :=
  entry follower [.appendEntriesRequest
    { request with
      entries := [tx fresh, reconfiguration, signature, retired, signature]
      leaderCommit := 5 }]
#guard (run retirement).enabled
#guard ((run retirement).successor.nodes destination).commitIndex == 5
#guard ((run retirement).successor.nodes destination).membershipState == .retiredCommitted
#guard ((run retirement).successor.nodes destination).retirementIndex == some 2
#guard ((run retirement).successor.nodes destination).retirementCommittableIndex == some 3
#guard ((run retirement).successor.nodes destination).retiredCommittedIndex == some 4
#guard !(run retirement distinct).enabled

private def differentContent := entry { follower with log := [signature] }
  [.appendEntriesRequest request]
private def differentConfiguration := entry { follower with log := [reconfiguration] }
  [.appendEntriesRequest { request with entries :=
    [{ reconfiguration with content := .reconfiguration {destination} }, signature] }]
#guard !(run differentContent).enabled
#guard !(run differentConfiguration).enabled

-- Self-replies deduplicate against the remaining queue, after consuming the request.
private def selfAck : Message Node (NatTerm 2) :=
  .appendEntriesResponse
    { term := 1, success := true, lastLogIndex := 2, source := destination, destination }
private def selfRequest := { request with source := destination }
private def selfReceive := entry follower
  [.appendEntriesRequest selfRequest, selfAck, unrelated]
#guard ((step selfReceive destination destination).eval aliased).enabled
#guard ((step selfReceive destination destination).eval aliased).successor.network destination ==
  [selfAck, unrelated]
private def selfEnqueue := entry follower [.appendEntriesRequest selfRequest, unrelated]
#guard ((step selfEnqueue destination destination).eval aliased).successor.network destination ==
  [unrelated, selfAck]

private def response (success : Bool) (term : Nat := 1) (sender : Node := source) :
    Message Node (NatTerm 2) :=
  .appendEntriesResponse { term, success, lastLogIndex := 1, source := sender, destination }
private def leader :=
  { follower with
    role := Role.leader
    sentIndex := fun _ => 2
    matchIndex := fun _ => 0 }
#guard (run (entry leader [response true])).enabled
#guard ((run (entry leader [response true])).successor.nodes destination).matchIndex source == 1
#guard ((run (entry leader [response false])).successor.nodes destination).sentIndex source == 1
#guard !(run (entry leader [response true 2])).enabled
#guard (run (entry leader [response true 0])).enabled
#guard (run (entry follower [response true 2])).enabled

private def voteRequest (term : Nat := 1) : Message Node (NatTerm 2) :=
  .requestVoteRequest
    { term, lastCommittableTerm := 0, lastCommittableIndex := 0, source, destination }
private def preVoteRequest (term : Nat := 1) : Message Node (NatTerm 2) :=
  .requestPreVote
    { term, lastCommittableTerm := 0, lastCommittableIndex := 0, source, destination }
private def voteResponse (term : Nat := 1) (grant : Bool := true) (sender : Node := source) :
    Message Node (NatTerm 2) :=
  .requestVoteResponse { term, voteGranted := grant, source := sender, destination }
private def preVoteResponse (term : Nat := 1) (grant : Bool := true)
    (sender : Node := source) : Message Node (NatTerm 2) :=
  .requestPreVoteResponse { term, voteGranted := grant, source := sender, destination }

#guard (run (entry follower [voteRequest])).enabled
#guard ((run (entry follower [voteRequest])).successor.nodes destination).votedFor == some source
#guard (run (entry follower [voteRequest 0])).enabled
#guard !(run (entry follower [voteRequest 2])).enabled
#guard (run (entry follower [preVoteRequest])).enabled
#guard ((run (entry follower [preVoteRequest])).successor.nodes destination).votedFor == none
#guard (run (entry follower [preVoteRequest 0])).enabled
#guard !(run (entry follower [preVoteRequest 2])).enabled
#guard ((run (entry { follower with role := .candidate } [voteResponse])).successor.nodes
  destination).votesGranted == {source}
#guard ((run (entry { follower with role := .candidate } [voteResponse 1 false])).successor.nodes
  destination).votesGranted == {}
#guard !(run (entry { follower with role := .candidate } [voteResponse 2])).enabled
#guard (run (entry { follower with role := .candidate } [voteResponse 0])).enabled
#guard (run (entry follower [voteResponse 2])).enabled
#guard ((run (entry { follower with role := .preVoteCandidate } [preVoteResponse])).successor.nodes
  destination).preVotesGranted == {source}
#guard !(run (entry { follower with role := .preVoteCandidate } [preVoteResponse 2])).enabled
#guard (run (entry { follower with role := .preVoteCandidate } [preVoteResponse 0])).enabled
#guard (run (entry follower [preVoteResponse 2])).enabled
#guard ((run (entry { follower with role := .preVoteCandidate }
  [preVoteResponse 1 false])).successor.nodes destination).preVotesGranted == {}

private def propose (term : Nat := 1) : Message Node (NatTerm 2) :=
  .proposeVoteRequest { term, source, destination }
#guard (run (entry follower [propose])).enabled
#guard ((run (entry follower [propose])).successor.nodes destination).role == .candidate
#guard ((run (entry follower [propose])).successor.nodes destination).currentTerm == 2
#guard (run (entry leader [propose])).enabled
#guard ((run (entry leader [propose])).successor.nodes destination).role == .leader
#guard (run (entry follower [propose 0])).enabled
#guard !(run (entry follower [propose 2])).enabled

-- Responses from unallocated senders are consumed, not handled.
private def unknownResponses := [response true 2 absent,
  voteResponse 2 true absent, preVoteResponse 2 true absent]
#guard unknownResponses.all fun packet =>
  let result := (step (entry follower [packet]) absent destination).eval aliased
  result.enabled && result.successor.network destination == [] &&
    !((result.successor.nodes.node? absent).isSome)

-- Requests may introduce an unknown sender without allocating its node slot.
private def unknownRequest := entry follower
  [.appendEntriesRequest { request with source := absent }]
#guard ((step unknownRequest absent destination).eval aliased).enabled
#guard !(((step unknownRequest absent destination).eval aliased).successor.nodes.node? absent).isSome
#guard (((step unknownRequest absent destination).eval aliased).successor.network absent).length == 1
#guard !((step minimal source absent).eval aliased).enabled
#guard !(((step minimal source absent).eval aliased).successor.nodes.node? absent).isSome

-- Real next can allocate an absent destination even though Enabled rejects it.
private def absentDestination : State Node (NatTerm 2) :=
  { (initialState : State Node (NatTerm 2)) with network := fun node =>
      if node = absent then [.requestVoteRequest
        { term := 0, lastCommittableTerm := 0, lastCommittableIndex := 0,
          source, destination := absent }] else [] }
#guard !((step absentDestination source absent).eval aliased).enabled
#guard (((step absentDestination source absent).eval aliased).successor.nodes.node? absent).isSome

example (assignment : Fin 2 -> Nat) (state : State Node (NatTerm 2)) (src dst : Node) :
    ((step state src dst).eval assignment).enabledExpr.Holds assignment ↔
      Enabled (mapState (NatTerm.eval assignment) state) (.receive src dst) :=
  step_enabledExpr_correct assignment state src dst

example (assignment : Fin 2 -> Nat) (state : State Node (NatTerm 2)) (src dst : Node) :
    mapState (NatTerm.eval assignment) ((step state src dst).eval assignment).successor =
      next (mapState (NatTerm.eval assignment) state) (.receive src dst) :=
  step_correct assignment state src dst

end CCFRaft.GuardedReceive.Tests

run_cmd do
  for theoremName in [
      ``CCFRaft.GuardedReceive.handle_correct,
      ``CCFRaft.GuardedReceive.step_enabled_correct,
      ``CCFRaft.GuardedReceive.step_enabledExpr_correct,
      ``CCFRaft.GuardedReceive.step_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
