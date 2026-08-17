-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model

set_option autoImplicit false

/-!
# Safety properties for the static CCF Raft core

`LeaderCompleteness` follows the state predicate in `ccfraft.tla`.
`CommittedLogsNoConflicts` is the spatial no-conflicts property of `abs.tla`.
`CommittedLogAppendOnly` is its transition-level append-only property.
-/

namespace CCFRaft

variable {Server : Type}

def CommitIndicesBounded (state : State Server) : Prop :=
  forall server,
    state.commitIndex server <= (state.log server).length

def LocalCommitsWithinGlobal (state : State Server) : Prop :=
  forall server,
    state.committedLog server <+: state.committed

def LeaderCompleteness (state : State Server) : Prop :=
  forall leader,
    state.hasLeaderRole leader ->
      forall server,
        Not (leader = server) ->
          state.currentTerm server < state.currentTerm leader ->
            state.committedLog server <+: state.log leader

structure CoreBundle (state : State Server) : Prop where
  commitIndicesBounded : CommitIndicesBounded state
  localCommitsWithinGlobal : LocalCommitsWithinGlobal state
  leaderCompleteness : LeaderCompleteness state

def CommittedLogsNoConflicts (state : State Server) : Prop :=
  forall left right,
    state.committedLog left <+: state.committedLog right \/
      state.committedLog right <+: state.committedLog left

def CommittedLogAppendOnly
    (before after : State Server) : Prop :=
  forall server,
    before.committedLog server <+: after.committedLog server

def GlobalCommitAppendOnly
    (before after : State Server) : Prop :=
  before.committed <+: after.committed

structure ProvedBundle (state : State Server) : Prop where
  core : CoreBundle state
  leaderCompleteness : LeaderCompleteness state
  committedLogsNoConflicts : CommittedLogsNoConflicts state

end CCFRaft
