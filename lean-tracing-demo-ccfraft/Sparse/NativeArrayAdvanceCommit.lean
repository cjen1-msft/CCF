-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayCommitIndex
import Sparse.NativeArrayRetirement
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayAdvanceCommit

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def commitRow (row : Local N T) (best : Nat)
    (retirement signature retired : Option Nat) : Local N T :=
  NativeArrayRetirement.refresh { row with commit := best } retirement signature retired

theorem commit_row_correct (row : Local N T) (source : N) (best : Nat)
    (retirement signature retired : Option Nat)
    (retirementCorrect : retirementIndexInLog source row.log.decode = retirement)
    (signatureCorrect :
      retirement.bind (retirementCommittableIndexInLog row.log.decode) = signature)
    (retiredCorrect : retiredCommittedIndexInLog source row.log.decode = retired) :
    (commitRow row best retirement signature retired).toModel =
      refreshRetirementState source { row.toModel with commitIndex := best } := by
  exact NativeArrayRetirement.refresh_correct { row with commit := best }
    source retirement signature retired retirementCorrect signatureCorrect retiredCorrect

def enabled (frame : NativeArrayVote.Frame N T) (source : N) (best : Nat)
    (output : Local N T) : Prop :=
  (frame.nodes source).isSome = true /\
    (get frame.nodes source).role = .leader /\
    (get frame.nodes source).commit < best /\
    output.membershipState ≠ .retiredCommitted

def advanceCommit (frame : NativeArrayVote.Frame N T) (source : N)
    (output : Local N T) (completed : Finset N) : NativeArrayVote.Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some output)
    globals :=
      { frame.globals with
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } }

theorem enabled_correct (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (best : Nat) (output : Local N T)
    (bestCorrect : highestCommittableIndex state source = best)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source { (state.nodes source) with commitIndex := best }) :
    enabled frame source best output <-> CCFRaft.Enabled state (.advanceCommitIndex source) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have membership := congrArg NodeState.membershipState rowCorrect
  simp only [Local.toModel] at membership
  simp only [enabled, CCFRaft.Enabled, terminalRetirementCommit, bestCorrect, <- membership]
  simp only [allocated_rep frame.nodes state rep.nodes source, <- fields, Local.toModel]

theorem advance_commit_output_rep (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (output : Local N T) (completed : Finset N)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with commitIndex := highestCommittableIndex state source })
    (completedCorrect : retirementCompletedNodes output.log.decode output.commit = completed)
    (nonterminal : output.membershipState ≠ .retiredCommitted) :
    (advanceCommit frame source output completed).Rep
      (CCFRaft.next state (.advanceCommitIndex source)) := by
  have afterRow : (advanceCommitState state source).nodes source = output.toModel := by
    simp [advanceCommitState, rowCorrect]
  have nextEq : CCFRaft.next state (.advanceCommitIndex source) = advanceCommitState state source := by
    rw [CCFRaft.next, demoteRetiredCommitted, afterRow]
    exact if_neg nonterminal
  rw [nextEq]
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simp [advanceCommit, advanceCommitState, State.node?, updateNode, Local.Rep, rowCorrect]
    · simpa [advanceCommit, advanceCommitState, State.node?, updateNode, same]
        using rep.nodes peer
  · simpa [advanceCommit, advanceCommitState] using rep.queues
  · rw [show (advanceCommit frame source output completed).globals =
      { frame.globals with
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } from rfl,
      rep.globals]
    simp [advanceCommitState, NativeArrayVote.Globals.ofModel, refreshRetirementCompleted,
      <- rowCorrect, Local.toModel, completedCorrect]

end CCFRaft.NativeArrayAdvanceCommit

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayAdvanceCommit).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
