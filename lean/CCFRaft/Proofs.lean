import Mathlib.Tactic

import CCFRaft.Properties

/-!
# CCFRaft proofs

The full reachable-state theorem is derived only after proving
`Properties.FullInductivenessObligation`; no assumption is introduced for that
obligation.
-/

set_option autoImplicit false

namespace CCFRaft.Proofs

open Model
open Properties

@[simp]
theorem compactFunction_apply
    {α : Type}
    (f : Node -> α)
    (node : Node) :
    compactFunction f node = f node := by
  simp [compactFunction, Vector.ofFn, Vector.get]

@[simp]
theorem compactFunction₂_apply
    {α : Type}
    (f : Node -> Node -> α)
    (first second : Node) :
    compactFunction₂ f first second = f first second := by
  simp [compactFunction₂]

@[simp]
theorem compactState_currentTerm
    (state : State)
    (node : Node) :
    (compactState state).currentTerm node = state.currentTerm node := by
  simp [compactState]

@[simp]
theorem compactState_commitIndex
    (state : State)
    (node : Node) :
    (compactState state).commitIndex node = state.commitIndex node := by
  simp [compactState]

@[simp]
theorem initial_LogInv (start : Node) :
    LogInv (initialState start) := by
  intro i j
  by_cases hi : i = start <;>
    by_cases hj : j = start <;>
      simp [committed, initialState, hi, hj, isLogPrefix, logPrefix,
        startLog]

@[simp]
theorem initial_MoreThanOneLeaderInv (start : Node) :
    MoreThanOneLeaderInv (initialState start) := by
  intro i j _ hi hj
  simp [initialState] at hi hj
  exact hi.trans hj.symm

@[simp]
theorem initial_SignatureInv (start : Node) :
    SignatureInv (initialState start) := by
  intro node positive
  by_cases h : node = start
  · subst node
    simp [initialState, startLog, entryAt?]
  · simp [initialState, h] at positive

/-- Stage-one reachable theorem: the literal initial state satisfies three public safety invariants. -/
theorem initialSafetyCheckpoint (start : Node) :
    And
      (LogInv (initialState start))
      (And
        (MoreThanOneLeaderInv (initialState start))
        (SignatureInv (initialState start))) := by
  exact
    ⟨initial_LogInv start,
      initial_MoreThanOneLeaderInv start,
      initial_SignatureInv start⟩

theorem functionUpdate_mono
    (values : Node -> Nat)
    (updated : Node)
    (value : Nat)
    (atUpdated : values updated <= value) :
    forall node,
      values node <= Function.update values updated value node := by
  intro node
  by_cases h : node = updated
  · subst node
    simpa using atUpdated
  · simp [Function.update, h]

theorem monotonicTerm_step
    (state : State)
    (action : Action)
    (_enabled : Enabled state action) :
    MonotonicTermProp state (next state action) := by
  intro node
  cases action with
  | timeout candidate =>
      by_cases h : node = candidate
      · subst node
        simp [next, rawNext, nextTimeout]
      · simp [next, rawNext, nextTimeout, h]
  | requestVote source dest =>
      simp [next, rawNext, nextRequestVote]
  | appendEntries source dest =>
      simp [next, rawNext, nextAppendEntries]
  | becomeLeader leader =>
      simp [next, rawNext, nextBecomeLeader]
  | clientRequest leader =>
      simp [next, rawNext, nextClientRequest]
  | signCommittableMessages leader =>
      simp [next, rawNext, nextSignCommittableMessages]
  | changeConfiguration leader configuration =>
      simp [next, rawNext, nextChangeConfiguration]
  | advanceCommitIndex leader =>
      simp [next, rawNext, nextAdvanceCommitIndex]
  | receive dest source kind =>
      cases hmessage : headMessage? state dest source with
      | none =>
          simp [next, rawNext, nextReceive, hmessage]
      | some message =>
          cases kind <;>
            cases hbody : message.body <;>
              simp_all [next, rawNext, nextReceive, Enabled,
                actionEnabled, receiveBranchEnabled, updateTermEnabled,
                nextAppendEntriesAlreadyDone, nextAppendEntriesNoConflict,
                conflictRollback]
          all_goals
            first
            | apply functionUpdate_mono
              have hterm := Nat.le_of_lt _enabled.2
              rw [_enabled.1.1] at hterm
              exact hterm
            | split <;> simp_all

theorem reachable_currentTerm_lowerBound
    (start : Node)
    {state : State}
    (reachable : Reachable start state) :
    forall node,
      (initialState start).currentTerm node <= state.currentTerm node := by
  apply
    ExecutableTransitionSystem.reachableInvariant
      (system start)
      (Invariant := fun current =>
        forall node,
          (initialState start).currentTerm node <=
            current.currentTerm node)
  · intro node
    exact Nat.le_refl _
  · intro current action inductionHypothesis enabled node
    exact
      Nat.le_trans
        (inductionHypothesis node)
        (monotonicTerm_step current action enabled node)
  · exact reachable

/--
Kernel-checked reachable-step theorem for `MonotonicTermProp` over every
enabled selected action.
-/
theorem reachable_MonotonicTermProp
    (start : Node)
    {state : State}
    (_reachable : Reachable start state)
    {action : Action}
    (enabled : Enabled state action) :
    MonotonicTermProp state (next state action) :=
  monotonicTerm_step state action enabled

end CCFRaft.Proofs
