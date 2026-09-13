-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLeaderLogWrite
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArraySignature

open NativeArrayCheckQuorum

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def enabled (frame : NativeArrayVote.Frame N T) (source : N) (output : Local N T) : Prop :=
  let row := get frame.nodes source
  (frame.nodes source).isSome = true /\
    row.role = .leader /\
    row.membershipState ≠ .retiredCommitted /\
    0 < row.log.length /\
    output.membershipState ≠ .retiredCommitted

def sign (frame : NativeArrayVote.Frame N T) (source : N) (output : Local N T)
    (completed : Finset N) : NativeArrayVote.Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some output)
    globals :=
      { frame.globals with
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } }

theorem enabled_correct (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (output : Local N T)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm, content := .signature }] }) :
    enabled frame source output <-> CCFRaft.Enabled state (.signCommittableMessages source) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have membership := congrArg NodeState.membershipState rowCorrect
  simp only [Local.toModel] at membership
  simp only [enabled, CCFRaft.Enabled, <- membership]
  simp only [allocated_rep frame.nodes state rep.nodes source, <- fields, Local.toModel]
  simp only [<- List.length_eq_zero_iff, Log.decode_length, Nat.pos_iff_ne_zero]

theorem sign_output_rep (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (output : Local N T) (completed : Finset N)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm, content := .signature }] })
    (completedCorrect : retirementCompletedNodes output.log.decode output.commit = completed) :
    (sign frame source output completed).Rep
      (CCFRaft.next state (.signCommittableMessages source)) := by
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simp [sign, CCFRaft.next, State.node?, updateNode, Local.Rep, rowCorrect]
    · simpa [sign, CCFRaft.next, State.node?, updateNode, same] using rep.nodes peer
  · simpa [sign, CCFRaft.next] using rep.queues
  · rw [show (sign frame source output completed).globals =
      { frame.globals with
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } from rfl,
      rep.globals]
    simp [CCFRaft.next, NativeArrayVote.Globals.ofModel, refreshRetirementCompleted,
      <- rowCorrect, Local.toModel, completedCorrect]

end CCFRaft.NativeArraySignature

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArraySignature).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
