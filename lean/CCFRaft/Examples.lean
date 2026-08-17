-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs

set_option autoImplicit false

/-!
# CCF Raft safety-core examples

These examples exercise the public transition relation over a concrete
two-server execution. They ensure that the guards used by the safety proofs are
jointly satisfiable.
-/

namespace CCFRaft.Examples

inductive Server where
  | one
  | two
  deriving DecidableEq

abbrev RaftState := State Server

def initial : RaftState :=
  initialState Server.one

def requested : RaftState :=
  clientRequestNext initial Server.one 7

def signed : RaftState :=
  signNext requested Server.one

def committed : RaftState :=
  advanceCommitNext signed Server.one 2

def replicated : RaftState :=
  replicateNext committed Server.one Server.two

def learned : RaftState :=
  learnCommitNext replicated Server.one Server.two 2

def candidate : RaftState :=
  timeoutNext learned Server.two

def elected : RaftState :=
  becomeLeaderNext candidate Server.two

def staleRequested : RaftState :=
  clientRequestNext elected Server.one 8

def staleSigned : RaftState :=
  signNext staleRequested Server.one

theorem requestSignCommitReachable :
    Reachable Server.one committed := by
  have initialReachable : Reachable Server.one initial :=
    Reachable.initial
  have requestedReachable : Reachable Server.one requested := by
    apply Reachable.step initialReachable
    exact
      CertifiedStep.clientRequest initial Server.one 7
        (by simp [State.hasLeaderRole, initial, initialState])
  have signedReachable : Reachable Server.one signed := by
    apply Reachable.step requestedReachable
    exact
      CertifiedStep.sign requested Server.one
        (by simp [
          State.hasLeaderRole,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [requested, clientRequestNext, initial, initialState])
  apply Reachable.step signedReachable
  exact
    CertifiedStep.advanceCommit signed Server.one 2
      (by simp [
        State.hasLeaderRole,
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by simp [
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by simp [signed, signNext, requested, clientRequestNext, initial])
      (by simp [
        State.signatureAt,
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by simp [
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by simp [
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by
        intro other _ higherTerm
        simp [
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ] at higherTerm)

theorem replicatedCommitAndElectionReachable :
    Reachable Server.one elected := by
  have committedReachable := requestSignCommitReachable
  have replicatedReachable : Reachable Server.one replicated := by
    apply Reachable.step committedReachable
    exact
      CertifiedStep.replicate committed Server.one Server.two
        (by simp [
          State.hasLeaderRole,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by decide)
        (by simp [
          State.hasLeaderRole,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          State.committedLog,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
  have learnedReachable : Reachable Server.one learned := by
    apply Reachable.step replicatedReachable
    exact
      CertifiedStep.learnCommit replicated Server.one Server.two 2
        (by simp [
          State.hasLeaderRole,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by decide)
        (by simp [
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          State.signatureAt,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by
          intro other _ higherTerm
          simp [
            replicated,
            replicateNext,
            committed,
            advanceCommitNext,
            signed,
            signNext,
            requested,
            clientRequestNext,
            initial,
            initialState
          ] at higherTerm)
  have candidateReachable : Reachable Server.one candidate := by
    apply Reachable.step learnedReachable
    exact
      CertifiedStep.timeout learned Server.two
        (by simp [
          State.hasLeaderRole,
          learned,
          learnCommitNext,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
  apply Reachable.step candidateReachable
  exact
    CertifiedStep.becomeLeader candidate Server.two
      (by simp [
        candidate,
        timeoutNext,
        learned,
        learnCommitNext,
        replicated,
        replicateNext,
        committed,
        advanceCommitNext,
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
      (by simp [
        candidate,
        timeoutNext,
        learned,
        learnCommitNext,
        replicated,
        replicateNext,
        committed,
        advanceCommitNext,
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState,
        lastSignedPrefix
      ])

theorem electedSatisfiesLeaderCompleteness :
    LeaderCompleteness elected :=
  reachableLeaderCompleteness replicatedCommitAndElectionReachable

theorem electedLeaderContainsOriginalCommit :
    elected.committedLog Server.one <+: elected.log Server.two := by
  apply electedSatisfiesLeaderCompleteness Server.two
  · simp [
      State.hasLeaderRole,
      elected,
      becomeLeaderNext,
      candidate,
      timeoutNext,
      learned,
      learnCommitNext,
      replicated,
      replicateNext,
      committed,
      advanceCommitNext,
      signed,
      signNext,
      requested,
      clientRequestNext,
      initial,
      initialState
    ]
  · decide
  · simp [
      elected,
      becomeLeaderNext,
      candidate,
      timeoutNext,
      learned,
      learnCommitNext,
      replicated,
      replicateNext,
      committed,
      advanceCommitNext,
      signed,
      signNext,
      requested,
      clientRequestNext,
      initial,
      initialState
    ]

theorem electedCommittedLogsHaveNoConflicts :
    CommittedLogsNoConflicts elected :=
  reachableCommittedLogsNoConflicts replicatedCommitAndElectionReachable

theorem staleLeaderPathReachable :
    Reachable Server.one staleSigned := by
  apply Reachable.step
  · apply Reachable.step replicatedCommitAndElectionReachable
    exact
      CertifiedStep.clientRequest elected Server.one 8
        (by simp [
          State.hasLeaderRole,
          elected,
          becomeLeaderNext,
          candidate,
          timeoutNext,
          learned,
          learnCommitNext,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
  · exact
      CertifiedStep.sign staleRequested Server.one
        (by simp [
          State.hasLeaderRole,
          staleRequested,
          clientRequestNext,
          elected,
          becomeLeaderNext,
          candidate,
          timeoutNext,
          learned,
          learnCommitNext,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState
        ])
        (by simp [
          staleRequested,
          clientRequestNext,
          elected,
          becomeLeaderNext,
          candidate,
          timeoutNext,
          learned,
          learnCommitNext,
          replicated,
          replicateNext,
          committed,
          advanceCommitNext,
          signed,
          signNext,
          requested,
          clientRequestNext,
          initial,
          initialState,
          lastSignedPrefix
        ])

theorem staleLeaderCommitVisibilityCertificateFails :
    Not (
      forall other,
        staleSigned.hasLeaderRole other ->
          staleSigned.currentTerm Server.one <
            staleSigned.currentTerm other ->
              (staleSigned.log Server.one).take 4 <+:
                staleSigned.log other) := by
  intro certificate
  have impossible :=
    certificate Server.two
      (by simp [
        State.hasLeaderRole,
        staleSigned,
        signNext,
        staleRequested,
        clientRequestNext,
        elected,
        becomeLeaderNext,
        candidate,
        timeoutNext
      ])
      (by simp [
        staleSigned,
        signNext,
        staleRequested,
        clientRequestNext,
        elected,
        becomeLeaderNext,
        candidate,
        timeoutNext,
        learned,
        learnCommitNext,
        replicated,
        replicateNext,
        committed,
        advanceCommitNext,
        signed,
        signNext,
        requested,
        clientRequestNext,
        initial,
        initialState
      ])
  have impossibleLength := impossible.length_le
  simp [
    staleSigned,
    signNext,
    staleRequested,
    clientRequestNext,
    elected,
    becomeLeaderNext,
    candidate,
    timeoutNext,
    learned,
    learnCommitNext,
    replicated,
    replicateNext,
    committed,
    advanceCommitNext,
    signed,
    signNext,
    requested,
    clientRequestNext,
    initial,
    initialState,
    lastSignedPrefix
  ] at impossibleLength

theorem reachableTransitionsAreAppendOnly
    {state next : RaftState}
    (reachable : Reachable Server.one state)
    (transition : CertifiedStep state next) :
    CommittedLogAppendOnly state next :=
  reachableStepCommittedLogAppendOnly reachable transition

end CCFRaft.Examples
