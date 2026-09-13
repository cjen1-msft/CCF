-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayVoteState
import Sparse.NativeArrayLogWrite
import Sparse.NativeArrayRetirement
import Sparse.NativeArrayVotingMajority

set_option autoImplicit false

namespace CCFRaft.NativeArrayBecomeLeader

open NativeArrayCheckQuorum NativeArrayVote

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def prepareRow (row : Local N T) (latest : Nat) : Local N T :=
  let log := NativeArrayLogWrite.take row.log latest
  { row with
    role := .leader
    log
    sentIndex := fun _ => log.length
    matchIndex := fun _ => 0 }

def refreshRow (row : Local N T) (latest : Nat)
    (retirement signature retired : Option Nat) : Local N T :=
  NativeArrayRetirement.refresh (prepareRow row latest) retirement signature retired

def enabled (frame : Frame N T) (source : N) (current : Nat) (output : Local N T) : Prop :=
  let old := get frame.nodes source
  (frame.nodes source).isSome = true /\
    old.role = .candidate /\
    old.membershipState ≠ .retiredCommitted /\
    NativeArrayVotingMajority.Majority old current old.votesGranted /\
    output.membershipState ≠ .retiredCommitted

def becomeLeader (frame : Frame N T) (source : N) (output : Local N T)
    (completed : Finset N) : Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some output)
    globals := { frame.globals with
      retirementCompleted := Function.update frame.globals.retirementCompleted source completed } }

theorem prepare_row_correct (row : Local N T) (latest : Nat) :
    (prepareRow row latest).toModel =
      { row.toModel with
        role := .leader
        log := row.toModel.log.take latest
        sentIndex := fun _ => (row.toModel.log.take latest).length
        matchIndex := fun _ => 0 } := by
  have lengthCorrect :
      (NativeArrayLogWrite.take row.log latest).length =
        (row.log.decode.take latest).length := by
    simpa only [Log.decode_length] using
      congrArg List.length (NativeArrayLogWrite.take_correct row.log latest)
  simp [prepareRow, Local.toModel, NativeArrayLogWrite.take_correct,
    lengthCorrect]

theorem refresh_row_correct (row : Local N T) (source : N) (latest : Nat)
    (retirement signature retired : Option Nat)
    (retirementCorrect :
      retirementIndexInLog source (prepareRow row latest).log.decode =
        retirement)
    (signatureCorrect :
      retirement.bind
        (retirementCommittableIndexInLog
          (prepareRow row latest).log.decode) =
        signature)
    (retiredCorrect :
      retiredCommittedIndexInLog source
        (prepareRow row latest).log.decode =
        retired) :
    (refreshRow row latest retirement signature retired).toModel =
      refreshRetirementState source
        { row.toModel with
          role := .leader
          log := row.toModel.log.take latest
          sentIndex := fun _ => (row.toModel.log.take latest).length
          matchIndex := fun _ => 0 } := by
  rw [refreshRow,
    NativeArrayRetirement.refresh_correct
      (prepareRow row latest) source retirement signature retired
      retirementCorrect signatureCorrect retiredCorrect,
    prepare_row_correct]

theorem become_leader_output_rep
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N)
    (output : Local N T) (completed : Finset N)
    (sourceAllocated : (frame.nodes source).isSome = true)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            role := .leader
            log := (state.nodes source).log.take
              (maxCommittableIndex (state.nodes source).log)
            sentIndex := fun _ =>
              ((state.nodes source).log.take
                (maxCommittableIndex (state.nodes source).log)).length
            matchIndex := fun _ => 0 })
    (completedCorrect :
      retirementCompletedNodes output.log.decode output.commit = completed) :
    (becomeLeader frame source output completed).Rep
      (CCFRaft.next state (.becomeLeader source)) := by
  have modelAllocated : state.allocated source :=
    (allocated_rep frame.nodes state rep.nodes source).mp sourceAllocated
  have sameLog := congrArg NodeState.log rowCorrect
  have sameCommit := congrArg NodeState.commitIndex rowCorrect
  simp only [Local.toModel, refreshRetirementState] at sameLog sameCommit
  have completedState :
      completed =
        retirementCompletedNodes
          ((state.nodes source).log.take
            (maxCommittableIndex (state.nodes source).log))
          (state.nodes source).commitIndex := by
    rw [<- completedCorrect, sameLog, sameCommit]
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simp [becomeLeader, CCFRaft.next, State.node?, updateNode, Local.Rep,
        rowCorrect]
    · simpa [becomeLeader, CCFRaft.next, State.node?, updateNode, same]
        using rep.nodes peer
  · simpa [becomeLeader, CCFRaft.next] using rep.queues
  · rw [show (becomeLeader frame source output completed).globals =
      { frame.globals with
        retirementCompleted :=
          Function.update frame.globals.retirementCompleted source completed } from rfl,
      rep.globals]
    simp [CCFRaft.next, NativeArrayVote.Globals.ofModel,
      refreshRetirementCompleted, completedState]

theorem enabled_correct (frame : NativeArrayVote.Frame N T)
    (state : State N T) (rep : frame.Rep state) (source : N)
    (current latest : Nat) (output : Local N T)
    (currentCorrect :
      CurrentIndex (get frame.nodes source).log
        (get frame.nodes source).commit current)
    (latestCorrect :
      SignatureIndex (get frame.nodes source).log latest)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          (prepareRow (get frame.nodes source) latest).toModel) :
    enabled frame source current output <->
      CCFRaft.Enabled state (.becomeLeader source) := by
  have fields :
      (get frame.nodes source).toModel = state.nodes source :=
    get_rep frame.nodes state rep.nodes source
  have latestValue :
      maxCommittableIndex (get frame.nodes source).toModel.log = latest := by
    simpa only [Local.toModel] using
      (signature_index_correct (get frame.nodes source).log latest).mp
        latestCorrect
  have majority :=
    NativeArrayVotingMajority.election_majority_correct
      (get frame.nodes source) state source current fields.symm currentCorrect
  have outputMembership :
      output.membershipState =
        (refreshRetirementState source
          (prepareRow (get frame.nodes source) latest).toModel).membershipState :=
    congrArg NodeState.membershipState rowCorrect
  have refreshedMembership :
      (refreshRetirementState source
          (prepareRow (get frame.nodes source) latest).toModel).membershipState =
        (refreshRetirementState source
          { (get frame.nodes source).toModel with
            log := (get frame.nodes source).toModel.log.take latest }).membershipState := by
    simp [prepareRow, Local.toModel, NativeArrayLogWrite.take_correct,
      refreshRetirementState]
  simp only [enabled, CCFRaft.Enabled]
  rw [allocated_rep frame.nodes state rep.nodes source, <- fields, latestValue,
    <- majority, outputMembership, refreshedMembership]
  rfl

end CCFRaft.NativeArrayBecomeLeader

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayBecomeLeader).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
