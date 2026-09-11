-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Shared.SymbolicData
import Shared.BoundedContainer
import Shared.Membership
import MachineGenerated.BoundedStateProofs

set_option autoImplicit false

namespace CCFRaft.SymbolicModel

open Symbolic

abbrev nodeCodec : Codec Node := Codec.fin 14
abbrev nodeSetCodec : Codec (Finset Node) := Codec.finset NODE_COUNT

def roleEquiv : Fin 5 ≃ Role where
  toFun := fun i => match i.val with
    | 0 => .none | 1 => .follower | 2 => .preVoteCandidate | 3 => .candidate | _ => .leader
  invFun := fun r => match r with
    | .none => 0 | .follower => 1 | .preVoteCandidate => 2 | .candidate => 3 | .leader => 4
  left_inv := by intro i; fin_cases i <;> rfl
  right_inv := by intro r; cases r <;> rfl

abbrev roleCodec : Codec Role := (Codec.fin 4).transport roleEquiv

abbrev membershipEquiv : Fin 5 ≃ MembershipState := MembershipState.equiv

abbrev membershipCodec : Codec MembershipState :=
  (Codec.fin 4).transport membershipEquiv

abbrev preVoteCodec : Codec PreVoteStatus :=
  Codec.bool.transport
    { toFun := fun b => if b then .enabled else .capable
      invFun := fun s => match s with | .enabled => true | .capable => false
      left_inv := by intro b; cases b <;> rfl
      right_inv := by intro s; cases s <;> rfl }

abbrev contentCodec : Codec (EntryContent Node Nat) :=
  (Codec.nat.sum (Codec.unit.sum (nodeSetCodec.sum nodeSetCodec))).transport
    { toFun := fun v => match v with
        | .inl tx => .transaction tx
        | .inr (.inl _) => .signature
        | .inr (.inr (.inl ns)) => .reconfiguration ns
        | .inr (.inr (.inr ns)) => .retiredCommitted ns
      invFun := fun v => match v with
        | .transaction tx => .inl tx
        | .signature => .inr (.inl ())
        | .reconfiguration ns => .inr (.inr (.inl ns))
        | .retiredCommitted ns => .inr (.inr (.inr ns))
      left_inv := by
        intro v; rcases v with tx | (_ | (ns | ns)) <;> rfl
      right_inv := by intro v; cases v <;> rfl }

abbrev entryCodec : Codec (Entry Node Nat) :=
  (Codec.nat.prod contentCodec).transport
    { toFun := fun (term, content) => ⟨term, content⟩
      invFun := fun e => (e.term, e.content)
      left_inv := by intro p; cases p; rfl
      right_inv := by intro e; cases e; rfl }

abbrev logCodec : Codec (List (Entry Node Nat)) := entryCodec.list

abbrev appendRequestCodec : Codec (AppendEntriesRequest Node Nat) :=
  (Codec.nat.prod (Codec.nat.prod (Codec.nat.prod
    (logCodec.prod (Codec.nat.prod (nodeCodec.prod nodeCodec)))))).transport
    { toFun := fun (term, prevIndex, prevTerm, entries, commit, source, dest) =>
        ⟨term, prevIndex, prevTerm, entries, commit, source, dest⟩
      invFun := fun r =>
        (r.term, r.prevLogIndex, r.prevLogTerm, r.entries, r.leaderCommit, r.source, r.destination)
      left_inv := by rintro ⟨_, _, _, _, _, _, _⟩; rfl
      right_inv := by intro r; cases r; rfl }

abbrev appendResponseCodec : Codec (AppendEntriesResponse Node) :=
  (Codec.nat.prod (Codec.bool.prod (Codec.nat.prod (nodeCodec.prod nodeCodec)))).transport
    { toFun := fun (term, success, index, source, dest) => ⟨term, success, index, source, dest⟩
      invFun := fun r => (r.term, r.success, r.lastLogIndex, r.source, r.destination)
      left_inv := by rintro ⟨_, _, _, _, _⟩; rfl
      right_inv := by intro r; cases r; rfl }

abbrev voteRequestCodec : Codec (RequestVoteRequest Node) :=
  (Codec.nat.prod (Codec.nat.prod (Codec.nat.prod (nodeCodec.prod nodeCodec)))).transport
    { toFun := fun (term, lastTerm, index, source, dest) => ⟨term, lastTerm, index, source, dest⟩
      invFun := fun r => (r.term, r.lastCommittableTerm, r.lastCommittableIndex, r.source, r.destination)
      left_inv := by rintro ⟨_, _, _, _, _⟩; rfl
      right_inv := by intro r; cases r; rfl }

abbrev voteResponseCodec : Codec (RequestVoteResponse Node) :=
  (Codec.nat.prod (Codec.bool.prod (nodeCodec.prod nodeCodec))).transport
    { toFun := fun (term, granted, source, dest) => ⟨term, granted, source, dest⟩
      invFun := fun r => (r.term, r.voteGranted, r.source, r.destination)
      left_inv := by rintro ⟨_, _, _, _⟩; rfl
      right_inv := by intro r; cases r; rfl }

abbrev preVoteRequestCodec : Codec (RequestPreVote Node) :=
  voteRequestCodec.transport
    { toFun := fun r => ⟨r.term, r.lastCommittableTerm, r.lastCommittableIndex, r.source, r.destination⟩
      invFun := fun r => ⟨r.term, r.lastCommittableTerm, r.lastCommittableIndex, r.source, r.destination⟩
      left_inv := by intro r; cases r; rfl
      right_inv := by intro r; cases r; rfl }

abbrev preVoteResponseCodec : Codec (RequestPreVoteResponse Node) :=
  voteResponseCodec.transport
    { toFun := fun r => ⟨r.term, r.voteGranted, r.source, r.destination⟩
      invFun := fun r => ⟨r.term, r.voteGranted, r.source, r.destination⟩
      left_inv := by intro r; cases r; rfl
      right_inv := by intro r; cases r; rfl }

abbrev proposeCodec : Codec (ProposeVoteRequest Node) :=
  (Codec.nat.prod (nodeCodec.prod nodeCodec)).transport
    { toFun := fun (term, source, dest) => ⟨term, source, dest⟩
      invFun := fun r => (r.term, r.source, r.destination)
      left_inv := by rintro ⟨_, _, _⟩; rfl
      right_inv := by intro r; cases r; rfl }

abbrev messageCodec : Codec (Message Node Nat) :=
  (appendRequestCodec.sum (appendResponseCodec.sum (voteRequestCodec.sum
    (voteResponseCodec.sum (preVoteRequestCodec.sum
      (preVoteResponseCodec.sum proposeCodec)))))).transport
    { toFun := fun v => match v with
        | .inl r => .appendEntriesRequest r
        | .inr (.inl r) => .appendEntriesResponse r
        | .inr (.inr (.inl r)) => .requestVoteRequest r
        | .inr (.inr (.inr (.inl r))) => .requestVoteResponse r
        | .inr (.inr (.inr (.inr (.inl r)))) => .requestPreVote r
        | .inr (.inr (.inr (.inr (.inr (.inl r))))) => .requestPreVoteResponse r
        | .inr (.inr (.inr (.inr (.inr (.inr r))))) => .proposeVoteRequest r
      invFun := fun v => match v with
        | .appendEntriesRequest r => .inl r
        | .appendEntriesResponse r => .inr (.inl r)
        | .requestVoteRequest r => .inr (.inr (.inl r))
        | .requestVoteResponse r => .inr (.inr (.inr (.inl r)))
        | .requestPreVote r => .inr (.inr (.inr (.inr (.inl r))))
        | .requestPreVoteResponse r => .inr (.inr (.inr (.inr (.inr (.inl r)))))
        | .proposeVoteRequest r => .inr (.inr (.inr (.inr (.inr (.inr r)))))
      left_inv := by
        intro v
        rcases v with r | (r | (r | (r | (r | (r | r))))) <;> rfl
      right_inv := by intro v; cases v <;> rfl }

abbrev queueCodec : Codec (List (Message Node Nat)) := messageCodec.list

def nodeTableCodec {α : Type} (c : Codec α) : Codec (BoundedState.NodeTable α) :=
  (c.table NODE_COUNT).transport
    { toFun := Vector.ofFn
      invFun := fun v i => v.get i
      left_inv := by intro f; funext i; simp [BoundedState.NodeTable.get]
      right_inv := by intro v; ext i h; simp [BoundedState.NodeTable.get, Vector.get] }

abbrev localCodec : Codec BoundedState.LocalStateData :=
  (roleCodec.prod (Codec.nat.prod (logCodec.prod (Codec.nat.prod
    ((nodeTableCodec Codec.nat).prod ((nodeTableCodec Codec.nat).prod
      (Codec.bool.prod (nodeCodec.option.prod (nodeSetCodec.prod
        (nodeSetCodec.prod (membershipCodec.prod (Codec.nat.option.prod
          (Codec.nat.option.prod Codec.nat.option))))))))))))).transport
    { toFun := fun (role, term, log, commit, sent, matched, newFollower, voted,
        votes, preVotes, membership, retirement, committable, retired) =>
        ⟨role, term, log, commit, sent, matched, newFollower, voted, votes,
          preVotes, membership, retirement, committable, retired⟩
      invFun := fun s => (s.role, s.currentTerm, s.log, s.commitIndex, s.sentIndex,
        s.matchIndex, s.isNewFollower, s.votedFor, s.votesGranted, s.preVotesGranted,
        s.membershipState, s.retirementIndex, s.retirementCommittableIndex, s.retiredCommittedIndex)
      left_inv := by rintro ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _⟩; rfl
      right_inv := by intro s; cases s; rfl }

theorem entry_equal_correct (ρ : Assignment) (a b : Expr entryCodec.ty) :
    (Expr.eq a b).eval ρ = true ↔ entryCodec.decode ρ a = entryCodec.decode ρ b :=
  entryCodec.equal_correct ρ a b

theorem message_equal_correct (ρ : Assignment) (a b : Expr messageCodec.ty) :
    (Expr.eq a b).eval ρ = true ↔ messageCodec.decode ρ a = messageCodec.decode ρ b :=
  messageCodec.equal_correct ρ a b

end CCFRaft.SymbolicModel
