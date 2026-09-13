-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayClientRequest

set_option autoImplicit false

namespace CCFRaft.NativeArrayClientRequest

open NativeArrayCheckQuorum NativeArrayLeaderLogWrite

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

theorem enabled_correct (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (transaction : T) (output : Local N T)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm,
                 content := .transaction transaction }] }) :
    enabled frame source transaction output <->
      CCFRaft.Enabled state (.clientRequest source transaction) := by
  have fields := get_rep frame.nodes state rep.nodes source
  have membership := congrArg NodeState.membershipState rowCorrect
  simp only [Local.toModel] at membership
  simp only [enabled, CCFRaft.Enabled, <- membership]
  simp [allocated_rep frame.nodes state rep.nodes, <- fields, Local.toModel,
    rep.globals, NativeArrayVote.Globals.ofModel]

theorem request_output_rep (frame : NativeArrayVote.Frame N T)
    (state : State N T) (rep : frame.Rep state) (source : N) (transaction : T)
    (output : Local N T) (completed : Finset N)
    (rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm,
                 content := .transaction transaction }] })
    (completedCorrect :
      retirementCompletedNodes output.log.decode output.commit = completed) :
    (request frame source transaction output completed).Rep
      (CCFRaft.next state (.clientRequest source transaction)) := by
  constructor
  · intro peer
    by_cases same : peer = source
    · subst peer
      simp [request, CCFRaft.next, State.node?, updateNode, Local.Rep, rowCorrect]
    · simpa [request, CCFRaft.next, State.node?, updateNode, same] using rep.nodes peer
  · simpa [request, CCFRaft.next] using rep.queues
  · rw [show (request frame source transaction output completed).globals =
      { frame.globals with
        submittedTxIds := insert transaction frame.globals.submittedTxIds
        retirementCompleted :=
          Function.update frame.globals.retirementCompleted source completed } from rfl,
      rep.globals]
    simp [CCFRaft.next, NativeArrayVote.Globals.ofModel, refreshRetirementCompleted,
      <- rowCorrect, Local.toModel, completedCorrect]

theorem Request.model_correct
    (frame after : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (transaction : T)
    (step : Request frame source transaction after) :
    CCFRaft.Enabled state (.clientRequest source transaction) /\
      after.Rep (CCFRaft.next state (.clientRequest source transaction)) := by
  cases step with
  | submit retirement signature retired completed retirementCorrect signatureCorrect
      retiredCorrect completedCorrect allowed =>
    let row := get frame.nodes source
    let output :=
      refreshRow row (.transaction transaction) retirement signature retired
    have same : state.nodes source = row.toModel :=
      (get_rep frame.nodes state rep.nodes source).symm
    have rowCorrect :
        output.toModel =
          refreshRetirementState source
            { (state.nodes source) with
              log := (state.nodes source).log ++
                [{ term := (state.nodes source).currentTerm,
                   content := .transaction transaction }] } := by
      rw [same]
      exact refresh_row_correct row source (.transaction transaction) retirement signature
        retired retirementCorrect signatureCorrect retiredCorrect
    exact
      ⟨(enabled_correct frame state rep source transaction output rowCorrect).mp allowed,
        request_output_rep frame state rep source transaction output completed rowCorrect
          completedCorrect⟩

theorem Request.exists_of_enabled
    (frame : NativeArrayVote.Frame N T) (state : State N T)
    (rep : frame.Rep state) (source : N) (transaction : T)
    (allowed : CCFRaft.Enabled state (.clientRequest source transaction)) :
    exists after, Request frame source transaction after := by
  let row := get frame.nodes source
  let appended := appendRow row (.transaction transaction)
  let retirement := retirementIndexInLog source appended.log.decode
  let signature := retirement.bind (retirementCommittableIndexInLog appended.log.decode)
  let retired := retiredCommittedIndexInLog source appended.log.decode
  let output :=
    refreshRow row (.transaction transaction) retirement signature retired
  let completed := retirementCompletedNodes output.log.decode output.commit
  have same : state.nodes source = row.toModel :=
    (get_rep frame.nodes state rep.nodes source).symm
  have rowCorrect :
      output.toModel =
        refreshRetirementState source
          { (state.nodes source) with
            log := (state.nodes source).log ++
              [{ term := (state.nodes source).currentTerm,
                 content := .transaction transaction }] } := by
    rw [same]
    exact refresh_row_correct row source (.transaction transaction) retirement signature
      retired rfl rfl rfl
  have nativeAllowed : enabled frame source transaction output :=
    (enabled_correct frame state rep source transaction output rowCorrect).mpr allowed
  exact
    ⟨request frame source transaction output completed,
      .submit retirement signature retired completed rfl rfl rfl rfl nativeAllowed⟩

end CCFRaft.NativeArrayClientRequest

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayClientRequest).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
