module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model

public section

namespace Consensus.MidTrace.InitInvariant

open Model.Node
open CCF (Finset)

private def ensure (ok : Bool) (reason : String) : Except String Unit :=
  unless ok do throw reason

private def checkNode (bootstrap : Finset NodeID) (self : NodeID) (s : NodeState)
    : Except String Unit := do
  let ck ok clause := ensure ok s!"node {self}: {clause}"
  let log := s.log
  ck
    (s.commitIndex <= log.length
      && (s.commitIndex == 0 || isSignatureAt log s.commitIndex))
    "commit_frontier"
  ck (log.all (·.term <= s.currentTerm)) "terms_bounded"
  ck ((log.zip log.tail).all fun (a, b) => a.term <= b.term) "terms_sorted"
  if s.role != .none && !(s.role == .follower && s.currentTerm == 0 && log.isEmpty) then
    ck (Model.BOOTSTRAP_TERM <= s.currentTerm) "active_term"
  if s.role == .candidate then
    ck
      (3 <= s.currentTerm
        && s.votedFor == some self
        && decide (self ∈ s.votesGranted)
        && log.all (·.term < s.currentTerm))
      "candidate_invariants"
  if s.role == .primary then ck (!log.isEmpty && s.primaryKnown) "leader_invariants"
  if let root :: _ := log then
    let .transaction req metadata := root.content | throw s!"node {self}: rooted_logs"
    ck
      (root.term == Model.BOOTSTRAP_TERM
        && metadata.configuration.isSome
        && metadata.retirementConfirmations == ∅
        && (!decide bootstrap.Nonempty
            || (req == 0 && metadata.configuration == some bootstrap)))
      "rooted_logs"

private def checkMessage (state : Model.State) (e : Model.Envelope)
    : Except String Unit := do
  let some sender := state.nodes.lookup e.source | throw s!"missing sender {e.source}"
  let ck ok := ensure ok s!"message_invariants: {e.source} -> {e.target}"
  ck (e.source != e.target && e.payload.term <= sender.currentTerm)
  match e.payload with
  | .appendEntriesRequest r =>
      ck
        (2 <= r.term
          && r.prevLogTerm <= r.term
          && (r.prevLogIndex != 0 || r.prevLogTerm == 0)
          && r.entries.all
              fun x =>
                r.prevLogTerm <= x.term
                && x.term <= r.term
                && r.entries.head?.all (·.term == x.term))
  | .appendEntriesResponse r => ck (!r.success || 2 <= r.term)
  | .requestVoteRequest r => ck (3 <= r.term && r.lastCommittableTerm < r.term)
  | .requestPreVoteRequest r => ck (2 <= r.term && r.lastCommittableTerm <= r.term)
  | .requestVoteResponse r =>
      if r.voteGranted then
        ck (3 <= r.term && (state.nodes.lookup e.target).any (r.term <= ·.currentTerm))
  | .requestPreVoteResponse _ => pure ()
  | .proposeRequestVoteRequest t => ck (2 <= t)

/-- Check necessary, not sufficient, conditions for a reachable state at the cut. -/
def check (bootstrap : Finset NodeID) (state : Model.State) : Except String Unit := do
  for (i, a) in state.nodes do
    checkNode bootstrap i a
    for (j, b) in state.nodes do
      if i < j then
        ensure
          (!(a.role == .primary && b.role == .primary && a.currentTerm == b.currentTerm))
          s!"nodes {i}, {j}: election_safety"
        let k := min a.commitIndex b.commitIndex
        ensure (a.log.take k == b.log.take k)
          s!"nodes {i}, {j}: committed_logs_comparable"
  state.network.forM (checkMessage state)

end Consensus.MidTrace.InitInvariant
