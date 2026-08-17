-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

/-!
# Static CCF Raft safety core

This file models a certified signed-log safety core of
`tla/consensus/ccfraft.tla`. It deliberately starts above the asynchronous
message layer. Election, commit, and replication certificates are explicit
action guards; proving that the concrete message protocol produces those
certificates is a later refinement layer.

`committed` is ghost state: a common upper bound on every local committed log.
The proofs establish selected safety consequences of `tla/consensus/abs.tla`;
they do not yet establish a refinement theorem.
-/

namespace CCFRaft

inductive Role where
  | follower
  | candidate
  | leader
  deriving DecidableEq, Repr

inductive EntryKind where
  | transaction (id : Nat)
  | signature
  deriving DecidableEq, Repr

structure Entry where
  term : Nat
  kind : EntryKind
  deriving DecidableEq, Repr

structure State (Server : Type) where
  role : Server -> Role
  currentTerm : Server -> Nat
  log : Server -> List Entry
  commitIndex : Server -> Nat
  committed : List Entry

variable {Server : Type}

def update
    [DecidableEq Server]
    {Value : Type}
    (old : Server -> Value)
    (server : Server)
    (value : Value) :
    Server -> Value :=
  fun candidate => if candidate = server then value else old candidate

@[simp]
theorem update_same
    [DecidableEq Server]
    {Value : Type}
    (old : Server -> Value)
    (server : Server)
    (value : Value) :
    update old server value server = value := by
  simp [update]

@[simp]
theorem update_of_ne
    [DecidableEq Server]
    {Value : Type}
    (old : Server -> Value)
    (server candidate : Server)
    (value : Value)
    (different : Not (candidate = server)) :
    update old server value candidate = old candidate := by
  simp [update, different]

def initialState
    [DecidableEq Server]
    (initialLeader : Server) :
    State Server where
  role server := if server = initialLeader then .leader else .follower
  currentTerm _ := 1
  log _ := []
  commitIndex _ := 0
  committed := []

namespace State

def committedLog (state : State Server) (server : Server) : List Entry :=
  (state.log server).take (state.commitIndex server)

def signatureAt
    (state : State Server)
    (server : Server)
    (index : Nat) : Prop :=
  ((state.log server)[index - 1]?).map Entry.kind =
    some EntryKind.signature

def hasLeaderRole (state : State Server) (server : Server) : Prop :=
  state.role server = .leader

end State

def clientRequestNext
    [DecidableEq Server]
    (state : State Server)
    (leader : Server)
    (transaction : Nat) :
    State Server :=
  { state with
    log :=
      update
        state.log
        leader
        (state.log leader ++
          [{ term := state.currentTerm leader
             kind := .transaction transaction }]) }

def signNext
    [DecidableEq Server]
    (state : State Server)
    (leader : Server) :
    State Server :=
  { state with
    log :=
      update
        state.log
        leader
        (state.log leader ++
          [{ term := state.currentTerm leader
             kind := .signature }]) }

def advanceCommitNext
    [DecidableEq Server]
    (state : State Server)
    (leader : Server)
    (index : Nat) :
    State Server :=
  { state with
    commitIndex := update state.commitIndex leader index
    committed := (state.log leader).take index }

def lastSignedPrefix : List Entry -> List Entry
  | [] => []
  | entry :: tail =>
      let signedTail := lastSignedPrefix tail
      if signedTail = [] then
        if entry.kind = .signature then [entry] else []
      else
        entry :: signedTail

def replicateNext
    [DecidableEq Server]
    (state : State Server)
    (leader follower : Server) :
    State Server :=
  { state with
    log := update state.log follower (state.log leader) }

def learnCommitNext
    [DecidableEq Server]
    (state : State Server)
    (_leader follower : Server)
    (index : Nat) :
    State Server :=
  { state with
    commitIndex := update state.commitIndex follower index }

def timeoutNext
    [DecidableEq Server]
    (state : State Server)
    (server : Server) :
    State Server :=
  { state with
    role := update state.role server .candidate
    currentTerm :=
      update state.currentTerm server (state.currentTerm server + 1) }

def becomeLeaderNext
    [DecidableEq Server]
    (state : State Server)
    (server : Server) :
    State Server :=
  { state with
    role := update state.role server .leader
    log := update state.log server (lastSignedPrefix (state.log server)) }

inductive CertifiedStep [DecidableEq Server] :
    State Server -> State Server -> Prop where
  | clientRequest
      (state : State Server)
      (leader : Server)
      (transaction : Nat)
      (isLeader : state.hasLeaderRole leader) :
      CertifiedStep state (clientRequestNext state leader transaction)
  | sign
      (state : State Server)
      (leader : Server)
      (isLeader : state.hasLeaderRole leader)
      (logNotEmpty : Not (state.log leader = [])) :
      CertifiedStep state (signNext state leader)
  | advanceCommit
      (state : State Server)
      (leader : Server)
      (index : Nat)
      (isLeader : state.hasLeaderRole leader)
      (advances : state.commitIndex leader < index)
      (indexExists : index <= (state.log leader).length)
      (isSignature : state.signatureAt leader index)
      (isCurrentTerm :
        ((state.log leader)[index - 1]?).map Entry.term =
          some (state.currentTerm leader))
      (extendsCommitted :
        state.committed <+: (state.log leader).take index)
      (visibleToHigherTermLeaders :
        forall other,
          state.hasLeaderRole other ->
            state.currentTerm leader < state.currentTerm other ->
              (state.log leader).take index <+: state.log other) :
      CertifiedStep state (advanceCommitNext state leader index)
  | replicate
      (state : State Server)
      (leader follower : Server)
      (isLeader : state.hasLeaderRole leader)
      (different : Not (leader = follower))
      (followerIsNotLeader : Not (state.hasLeaderRole follower))
      (leaderHasCommitted : state.committed <+: state.log leader)
      (preservesFollowerCommit :
        state.committedLog follower <+: state.log leader) :
      CertifiedStep state (replicateNext state leader follower)
  | learnCommit
      (state : State Server)
      (leader follower : Server)
      (index : Nat)
      (isLeader : state.hasLeaderRole leader)
      (different : Not (leader = follower))
      (advances : state.commitIndex follower < index)
      (indexExists : index <= (state.log follower).length)
      (isSignature : state.signatureAt follower index)
      (withinLeaderCommit : index <= state.commitIndex leader)
      (logsAgree :
        (state.log follower).take index =
          (state.log leader).take index)
      (visibleToHigherTermLeaders :
        forall other,
          state.hasLeaderRole other ->
            state.currentTerm follower < state.currentTerm other ->
              (state.log follower).take index <+: state.log other) :
      CertifiedStep state (learnCommitNext state leader follower index)
  | timeout
      (state : State Server)
      (server : Server)
      (isNotLeader : Not (state.hasLeaderRole server)) :
      CertifiedStep state (timeoutNext state server)
  | becomeLeader
      (state : State Server)
      (server : Server)
      (isCandidate : state.role server = .candidate)
      (electionCertificate :
        state.committed <+: lastSignedPrefix (state.log server)) :
      CertifiedStep state (becomeLeaderNext state server)

inductive Reachable
    [DecidableEq Server]
    (initialLeader : Server) :
    State Server -> Prop where
  | initial : Reachable initialLeader (initialState initialLeader)
  | step
      {state next : State Server}
      (reachable : Reachable initialLeader state)
      (transition : CertifiedStep state next) :
      Reachable initialLeader next

end CCFRaft
