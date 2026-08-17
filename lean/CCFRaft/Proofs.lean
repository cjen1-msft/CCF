-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties

set_option autoImplicit false

namespace CCFRaft

variable {Server : Type}
variable [DecidableEq Server]

theorem prefixRefl {Alpha : Type} (values : List Alpha) :
    values <+: values :=
  ⟨[], by simp⟩

theorem prefixEqTake
    {Alpha : Type}
    {head values : List Alpha}
    (isPrefix : head <+: values) :
    values.take head.length = head := by
  rcases isPrefix with ⟨suffix, rfl⟩
  exact List.take_left

theorem prefixesComparable
    {Alpha : Type}
    {left right values : List Alpha}
    (leftPrefix : left <+: values)
    (rightPrefix : right <+: values) :
    left <+: right \/ right <+: left := by
  by_cases leftShorter : left.length <= right.length
  · left
    have leftEq : right.take left.length = left := by
      calc
        right.take left.length =
            (values.take right.length).take left.length := by
              rw [prefixEqTake rightPrefix]
        _ = values.take left.length := by
              simp [List.take_take, Nat.min_eq_left leftShorter]
        _ = left := prefixEqTake leftPrefix
    have taken :=
      List.take_prefix left.length right
    rwa [leftEq] at taken
  · right
    have rightShorter : right.length <= left.length := by omega
    have rightEq : left.take right.length = right := by
      calc
        left.take right.length =
            (values.take left.length).take right.length := by
              rw [prefixEqTake leftPrefix]
        _ = values.take right.length := by
              simp [List.take_take, Nat.min_eq_left rightShorter]
        _ = right := prefixEqTake rightPrefix
    have taken :=
      List.take_prefix right.length left
    rwa [rightEq] at taken

theorem initialCore (initialLeader : Server) :
    CoreBundle (initialState initialLeader) := by
  constructor
  · simp [CommitIndicesBounded, initialState]
  · intro server
    exact prefixRefl []
  · intro leader _ server _ _
    exact List.nil_prefix

theorem committedLogClientRequest
    {state : State Server}
    {leader : Server}
    {transaction : Nat}
    (bounded : CommitIndicesBounded state)
    (server : Server) :
    (clientRequestNext state leader transaction).committedLog server =
      state.committedLog server := by
  by_cases serverEq : server = leader
  · subst server
    simp only [
      State.committedLog,
      clientRequestNext,
      update_same
    ]
    exact List.take_append_of_le_length (bounded leader)
  · simp [
      State.committedLog,
      clientRequestNext,
      update,
      serverEq
    ]

theorem committedLogSign
    {state : State Server}
    {leader : Server}
    (bounded : CommitIndicesBounded state)
    (server : Server) :
    (signNext state leader).committedLog server =
      state.committedLog server := by
  by_cases serverEq : server = leader
  · subst server
    simp only [
      State.committedLog,
      signNext,
      update_same
    ]
    exact List.take_append_of_le_length (bounded leader)
  · simp [
      State.committedLog,
      signNext,
      update,
      serverEq
    ]

theorem committedLogReplicateFollower
    {state : State Server}
    {leader follower : Server}
    (bounded : CommitIndicesBounded state)
    (preservesFollowerCommit :
      state.committedLog follower <+: state.log leader) :
    (replicateNext state leader follower).committedLog follower =
      state.committedLog follower := by
  have committedLength :
      (state.committedLog follower).length =
        state.commitIndex follower := by
    simp [
      State.committedLog,
      List.length_take,
      Nat.min_eq_left (bounded follower)
    ]
  have copiedPrefix := prefixEqTake preservesFollowerCommit
  rw [committedLength] at copiedPrefix
  simpa [State.committedLog, replicateNext] using copiedPrefix

theorem committedLogReplicate
    {state : State Server}
    {leader follower : Server}
    (bounded : CommitIndicesBounded state)
    (preservesFollowerCommit :
      state.committedLog follower <+: state.log leader)
    (server : Server) :
    (replicateNext state leader follower).committedLog server =
      state.committedLog server := by
  by_cases serverEq : server = follower
  · subst server
    exact
      committedLogReplicateFollower bounded preservesFollowerCommit
  · simp [
      State.committedLog,
      replicateNext,
      update,
      serverEq
    ]

theorem committedLogBecomeLeader
    {state : State Server}
    {server : Server}
    (core : CoreBundle state)
    (electionCertificate :
      state.committed <+: lastSignedPrefix (state.log server)) :
    (becomeLeaderNext state server).committedLog server =
      state.committedLog server := by
  have preserved :
      state.committedLog server <+:
        lastSignedPrefix (state.log server) :=
    (core.localCommitsWithinGlobal server).trans electionCertificate
  have committedLength :
      (state.committedLog server).length =
        state.commitIndex server := by
    simp [
      State.committedLog,
      List.length_take,
      Nat.min_eq_left (core.commitIndicesBounded server)
    ]
  have copiedPrefix := prefixEqTake preserved
  rw [committedLength] at copiedPrefix
  simpa [State.committedLog, becomeLeaderNext] using copiedPrefix

theorem committedLogBecomeLeaderAt
    {state : State Server}
    {newLeader : Server}
    (core : CoreBundle state)
    (electionCertificate :
      state.committed <+: lastSignedPrefix (state.log newLeader))
    (server : Server) :
    (becomeLeaderNext state newLeader).committedLog server =
      state.committedLog server := by
  by_cases serverEq : server = newLeader
  · subst server
    exact committedLogBecomeLeader core electionCertificate
  · simp [
      State.committedLog,
      becomeLeaderNext,
      update,
      serverEq
    ]

omit [DecidableEq Server] in
theorem coreLeaderCompleteness
    {state : State Server}
    (core : CoreBundle state) :
    LeaderCompleteness state := by
  exact core.leaderCompleteness

omit [DecidableEq Server] in
theorem coreCommittedLogsNoConflicts
    {state : State Server}
    (core : CoreBundle state) :
    CommittedLogsNoConflicts state := by
  intro left right
  exact
    prefixesComparable
      (core.localCommitsWithinGlobal left)
      (core.localCommitsWithinGlobal right)

theorem clientRequestPreservesCore
    {state : State Server}
    {leader : Server}
    {transaction : Nat}
    (core : CoreBundle state) :
    CoreBundle (clientRequestNext state leader transaction) := by
  constructor
  · intro server
    by_cases serverEq : server = leader
    · subst server
      have oldBound := core.commitIndicesBounded leader
      simpa [clientRequestNext] using Nat.le.step oldBound
    · simpa [
        CommitIndicesBounded,
        clientRequestNext,
        update,
        serverEq
      ] using core.commitIndicesBounded server
  · intro server
    rw [committedLogClientRequest core.commitIndicesBounded server]
    exact core.localCommitsWithinGlobal server
  · intro currentLeader isLeader server different higherTerm
    have oldCompleteness :=
      core.leaderCompleteness
        currentLeader
        (by simpa [State.hasLeaderRole, clientRequestNext] using isLeader)
        server
        different
        (by simpa [clientRequestNext] using higherTerm)
    rw [committedLogClientRequest core.commitIndicesBounded server]
    by_cases currentEq : currentLeader = leader
    · subst currentLeader
      simpa [clientRequestNext] using
        oldCompleteness.trans (List.prefix_append _ _)
    · simpa [clientRequestNext, update, currentEq] using oldCompleteness

theorem signPreservesCore
    {state : State Server}
    {leader : Server}
    (core : CoreBundle state) :
    CoreBundle (signNext state leader) := by
  constructor
  · intro server
    by_cases serverEq : server = leader
    · subst server
      have oldBound := core.commitIndicesBounded leader
      simpa [signNext] using Nat.le.step oldBound
    · simpa [
        CommitIndicesBounded,
        signNext,
        update,
        serverEq
      ] using core.commitIndicesBounded server
  · intro server
    rw [committedLogSign core.commitIndicesBounded server]
    exact core.localCommitsWithinGlobal server
  · intro currentLeader isLeader server different higherTerm
    have oldCompleteness :=
      core.leaderCompleteness
        currentLeader
        (by simpa [State.hasLeaderRole, signNext] using isLeader)
        server
        different
        (by simpa [signNext] using higherTerm)
    rw [committedLogSign core.commitIndicesBounded server]
    by_cases currentEq : currentLeader = leader
    · subst currentLeader
      simpa [signNext] using
        oldCompleteness.trans (List.prefix_append _ _)
    · simpa [signNext, update, currentEq] using oldCompleteness

theorem advanceCommitPreservesCore
    {state : State Server}
    {leader : Server}
    {index : Nat}
    (core : CoreBundle state)
    (indexExists : index <= (state.log leader).length)
    (extendsCommitted :
      state.committed <+: (state.log leader).take index)
    (visibleToHigherTermLeaders :
      forall other,
        state.hasLeaderRole other ->
          state.currentTerm leader < state.currentTerm other ->
            (state.log leader).take index <+: state.log other) :
    CoreBundle (advanceCommitNext state leader index) := by
  constructor
  · intro server
    by_cases serverEq : server = leader
    · subst server
      simpa [CommitIndicesBounded, advanceCommitNext] using indexExists
    · simpa [
        CommitIndicesBounded,
        advanceCommitNext,
        update,
        serverEq
      ] using core.commitIndicesBounded server
  · intro server
    by_cases serverEq : server = leader
    · subst server
      simp [State.committedLog, advanceCommitNext]
    · have oldLocal := core.localCommitsWithinGlobal server
      simpa [
        State.committedLog,
        advanceCommitNext,
        update,
        serverEq
      ] using oldLocal.trans extendsCommitted
  · intro currentLeader isLeader server different higherTerm
    have oldLeader :
        state.hasLeaderRole currentLeader := by
      simpa [State.hasLeaderRole, advanceCommitNext] using isLeader
    by_cases serverEq : server = leader
    · subst server
      simpa [State.committedLog, advanceCommitNext] using
        visibleToHigherTermLeaders currentLeader oldLeader higherTerm
    · have oldCompleteness :=
        core.leaderCompleteness
          currentLeader
          oldLeader
          server
          different
          (by simpa [advanceCommitNext] using higherTerm)
      simpa [
        State.committedLog,
        advanceCommitNext,
        update,
        serverEq
      ] using oldCompleteness

theorem replicatePreservesCore
    {state : State Server}
    {leader follower : Server}
    (core : CoreBundle state)
    (followerIsNotLeader : Not (state.hasLeaderRole follower))
    (preservesFollowerCommit :
      state.committedLog follower <+: state.log leader) :
    CoreBundle (replicateNext state leader follower) := by
  have followerCommitUnchanged :=
    committedLogReplicateFollower
      core.commitIndicesBounded
      preservesFollowerCommit
  constructor
  · intro server
    by_cases serverEq : server = follower
    · subst server
      have committedLength :
          (state.committedLog follower).length =
            state.commitIndex follower := by
        simp [
          State.committedLog,
          List.length_take,
          Nat.min_eq_left (core.commitIndicesBounded follower)
        ]
      have copiedBound := preservesFollowerCommit.length_le
      rw [committedLength] at copiedBound
      simpa [replicateNext] using copiedBound
    · simpa [
        CommitIndicesBounded,
        replicateNext,
        update,
        serverEq
      ] using core.commitIndicesBounded server
  · intro server
    by_cases serverEq : server = follower
    · subst server
      rw [followerCommitUnchanged]
      exact core.localCommitsWithinGlobal follower
    · simpa [
        State.committedLog,
        replicateNext,
        update,
        serverEq
      ] using core.localCommitsWithinGlobal server
  · intro currentLeader isLeader server differentServers higherTerm
    have currentLeaderNe : Not (currentLeader = follower) := by
      intro currentEq
      subst currentLeader
      exact followerIsNotLeader isLeader
    have oldCompleteness :=
      core.leaderCompleteness
        currentLeader
        (by
          simpa [
            State.hasLeaderRole,
            replicateNext
          ] using isLeader)
        server
        differentServers
        (by simpa [replicateNext] using higherTerm)
    rw [
      committedLogReplicate
        core.commitIndicesBounded
        preservesFollowerCommit
        server
    ]
    simpa [replicateNext, update, currentLeaderNe] using oldCompleteness

theorem learnCommitPreservesCore
    {state : State Server}
    {leader follower : Server}
    {index : Nat}
    (core : CoreBundle state)
    (indexExists : index <= (state.log follower).length)
    (withinLeaderCommit : index <= state.commitIndex leader)
    (logsAgree :
      (state.log follower).take index =
        (state.log leader).take index)
    (visibleToHigherTermLeaders :
      forall other,
        state.hasLeaderRole other ->
          state.currentTerm follower < state.currentTerm other ->
            (state.log follower).take index <+: state.log other) :
    CoreBundle (learnCommitNext state leader follower index) := by
  constructor
  · intro server
    by_cases serverEq : server = follower
    · subst server
      simpa [CommitIndicesBounded, learnCommitNext] using indexExists
    · simpa [
        CommitIndicesBounded,
        learnCommitNext,
        update,
        serverEq
      ] using core.commitIndicesBounded server
  · intro server
    by_cases serverEq : server = follower
    · subst server
      have prefixLeaderCommit :
          (state.log leader).take index <+:
            state.committedLog leader := by
        have taken :=
          List.take_prefix index
            ((state.log leader).take (state.commitIndex leader))
        simpa [
          State.committedLog,
          List.take_take,
          Nat.min_eq_left withinLeaderCommit
        ] using taken
      simpa [
        State.committedLog,
        learnCommitNext,
        logsAgree
      ] using
        prefixLeaderCommit.trans
          (core.localCommitsWithinGlobal leader)
    · simpa [
        State.committedLog,
        learnCommitNext,
        update,
        serverEq
      ] using core.localCommitsWithinGlobal server
  · intro currentLeader isLeader server differentServers higherTerm
    by_cases serverEq : server = follower
    · subst server
      simpa [State.committedLog, learnCommitNext] using
        visibleToHigherTermLeaders currentLeader isLeader higherTerm
    · have oldCompleteness :=
        core.leaderCompleteness
          currentLeader
          (by
            simpa [
              State.hasLeaderRole,
              learnCommitNext
            ] using isLeader)
          server
          differentServers
          (by simpa [learnCommitNext] using higherTerm)
      simpa [
        State.committedLog,
        learnCommitNext,
        update,
        serverEq
      ] using oldCompleteness

theorem timeoutPreservesCore
    {state : State Server}
    {server : Server}
    (core : CoreBundle state) :
    CoreBundle (timeoutNext state server) := by
  constructor
  · simpa [CommitIndicesBounded, timeoutNext] using
      core.commitIndicesBounded
  · simpa [LocalCommitsWithinGlobal, State.committedLog, timeoutNext] using
      core.localCommitsWithinGlobal
  · intro leader isLeader committedServer differentServers higherTerm
    have leaderNe : Not (leader = server) := by
      intro leaderEq
      subst leader
      simp [State.hasLeaderRole, timeoutNext] at isLeader
    have oldLeader : state.hasLeaderRole leader := by
      simpa [
        State.hasLeaderRole,
        timeoutNext,
        update,
        leaderNe
      ] using isLeader
    by_cases committedEq : committedServer = server
    · subst committedServer
      have newHigher :
          state.currentTerm server + 1 < state.currentTerm leader := by
        simpa [timeoutNext, update, leaderNe] using higherTerm
      have oldHigher :
          state.currentTerm server < state.currentTerm leader := by
        omega
      have oldCompleteness :=
        core.leaderCompleteness
          leader
          oldLeader
          server
          differentServers
          oldHigher
      simpa [State.committedLog, timeoutNext] using oldCompleteness
    · have oldCompleteness :=
        core.leaderCompleteness
          leader
          oldLeader
          committedServer
          differentServers
          (by
            simpa [
              timeoutNext,
              update,
              leaderNe,
              committedEq
            ] using higherTerm)
      simpa [State.committedLog, timeoutNext] using oldCompleteness

theorem becomeLeaderPreservesCore
    {state : State Server}
    {server : Server}
    (core : CoreBundle state)
    (electionCertificate :
      state.committed <+: lastSignedPrefix (state.log server)) :
    CoreBundle (becomeLeaderNext state server) := by
  constructor
  · intro candidate
    by_cases candidateEq : candidate = server
    · subst candidate
      have preserved :=
        (core.localCommitsWithinGlobal server).trans electionCertificate
      have committedLength :
          (state.committedLog server).length =
            state.commitIndex server := by
        simp [
          State.committedLog,
          List.length_take,
          Nat.min_eq_left (core.commitIndicesBounded server)
        ]
      have bound := preserved.length_le
      rw [committedLength] at bound
      simpa [becomeLeaderNext] using bound
    · simpa [
        CommitIndicesBounded,
        becomeLeaderNext,
        update,
        candidateEq
      ] using core.commitIndicesBounded candidate
  · intro candidate
    rw [
      committedLogBecomeLeaderAt
        core
        electionCertificate
        candidate
    ]
    exact core.localCommitsWithinGlobal candidate
  · intro leader isLeader committedServer differentServers higherTerm
    by_cases leaderEq : leader = server
    · subst leader
      rw [
        committedLogBecomeLeaderAt
          core
          electionCertificate
          committedServer
      ]
      simpa [becomeLeaderNext] using
        (core.localCommitsWithinGlobal committedServer).trans
          electionCertificate
    · have oldLeader : state.hasLeaderRole leader := by
        simpa [
          State.hasLeaderRole,
          becomeLeaderNext,
          update,
          leaderEq
        ] using isLeader
      have oldCompleteness :=
        core.leaderCompleteness
          leader
          oldLeader
          committedServer
          differentServers
          (by simpa [becomeLeaderNext] using higherTerm)
      rw [
        committedLogBecomeLeaderAt
          core
          electionCertificate
          committedServer
      ]
      simpa [becomeLeaderNext, update, leaderEq] using oldCompleteness

theorem stepPreservesCore
    {state next : State Server}
    (core : CoreBundle state)
    (transition : CertifiedStep state next) :
    CoreBundle next := by
  cases transition with
  | clientRequest _ _ isLeader =>
      exact clientRequestPreservesCore core
  | sign _ isLeader logNotEmpty =>
      exact signPreservesCore core
  | advanceCommit
      _ _
      isLeader
      advances
      indexExists
      isSignature
      isCurrentTerm
      extendsCommitted
      visibleToHigherTermLeaders =>
      exact
        advanceCommitPreservesCore
          core
          indexExists
          extendsCommitted
          visibleToHigherTermLeaders
  | replicate
      _ _
      isLeader
      different
      followerIsNotLeader
      leaderHasCommitted
      preservesFollowerCommit =>
      exact
        replicatePreservesCore
          core
          followerIsNotLeader
          preservesFollowerCommit
  | learnCommit
      _ _ _
      isLeader
      different
      advances
      indexExists
      isSignature
      withinLeaderCommit
      logsAgree
      visibleToHigherTermLeaders =>
      exact
        learnCommitPreservesCore
          core
          indexExists
          withinLeaderCommit
          logsAgree
          visibleToHigherTermLeaders
  | timeout _ isNotLeader =>
      exact timeoutPreservesCore core
  | becomeLeader _ isCandidate electionCertificate =>
      exact becomeLeaderPreservesCore core electionCertificate

theorem stepCommittedLogAppendOnly
    {state next : State Server}
    (core : CoreBundle state)
    (transition : CertifiedStep state next) :
    CommittedLogAppendOnly state next := by
  intro server
  cases transition with
  | clientRequest _ _ isLeader =>
      rw [committedLogClientRequest core.commitIndicesBounded server]
  | sign _ isLeader logNotEmpty =>
      rw [committedLogSign core.commitIndicesBounded server]
  | advanceCommit
      leader index
      isLeader
      advances
      indexExists
      isSignature
      isCurrentTerm
      extendsCommitted
      visibleToHigherTermLeaders =>
      by_cases serverEq : server = leader
      · subst server
        have extendsLocal :=
          (core.localCommitsWithinGlobal leader).trans extendsCommitted
        simpa [State.committedLog, advanceCommitNext] using extendsLocal
      · simp [
          State.committedLog,
          advanceCommitNext,
          update,
          serverEq
        ]
  | replicate
      leader follower
      isLeader
      different
      followerIsNotLeader
      leaderHasCommitted
      preservesFollowerCommit =>
      rw [
        committedLogReplicate
          core.commitIndicesBounded
          preservesFollowerCommit
          server
      ]
  | learnCommit
      leader follower index
      isLeader
      different
      advances
      indexExists
      isSignature
      withinLeaderCommit
      logsAgree
      visibleToHigherTermLeaders =>
      by_cases serverEq : server = follower
      · subst server
        have taken :=
          List.take_prefix
            (state.commitIndex follower)
            ((state.log follower).take index)
        simpa [
          State.committedLog,
          learnCommitNext,
          List.take_take,
          Nat.min_eq_left (Nat.le_of_lt advances)
        ] using taken
      · simp [
          State.committedLog,
          learnCommitNext,
          update,
          serverEq
        ]
  | timeout timedOut isNotLeader =>
      simp [State.committedLog, timeoutNext]
  | becomeLeader newLeader isCandidate electionCertificate =>
      rw [
        committedLogBecomeLeaderAt
          core
          electionCertificate
          server
      ]

theorem stepGlobalCommitAppendOnly
    {state next : State Server}
    (transition : CertifiedStep state next) :
    GlobalCommitAppendOnly state next := by
  cases transition with
  | advanceCommit
      leader index
      isLeader
      advances
      indexExists
      isSignature
      isCurrentTerm
      extendsCommitted
      visibleToHigherTermLeaders =>
      exact extendsCommitted
  | clientRequest _ _ _ =>
      exact prefixRefl _
  | sign _ _ _ =>
      exact prefixRefl _
  | replicate _ _ _ _ _ _ _ =>
      exact prefixRefl _
  | learnCommit _ _ _ _ _ _ _ _ _ _ _ =>
      exact prefixRefl _
  | timeout _ _ =>
      exact prefixRefl _
  | becomeLeader _ _ _ =>
      exact prefixRefl _

theorem reachableCore
    {initialLeader : Server}
    {state : State Server}
    (reachable : Reachable initialLeader state) :
    CoreBundle state := by
  induction reachable with
  | initial => exact initialCore initialLeader
  | step _ transition core =>
      exact stepPreservesCore core transition

theorem reachableLeaderCompleteness
    {initialLeader : Server}
    {state : State Server}
    (reachable : Reachable initialLeader state) :
    LeaderCompleteness state :=
  coreLeaderCompleteness (reachableCore reachable)

theorem reachableCommittedLogsNoConflicts
    {initialLeader : Server}
    {state : State Server}
    (reachable : Reachable initialLeader state) :
    CommittedLogsNoConflicts state :=
  coreCommittedLogsNoConflicts (reachableCore reachable)

theorem reachableStepCommittedLogAppendOnly
    {initialLeader : Server}
    {state next : State Server}
    (reachable : Reachable initialLeader state)
    (transition : CertifiedStep state next) :
    CommittedLogAppendOnly state next :=
  stepCommittedLogAppendOnly (reachableCore reachable) transition

theorem reachableProved
    {initialLeader : Server}
    {state : State Server}
    (reachable : Reachable initialLeader state) :
    ProvedBundle state := by
  have core := reachableCore reachable
  exact
    { core
      leaderCompleteness := core.leaderCompleteness
      committedLogsNoConflicts :=
        coreCommittedLogsNoConflicts core }

end CCFRaft
