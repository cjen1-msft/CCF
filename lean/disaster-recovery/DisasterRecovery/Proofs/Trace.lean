module

public import CCF.Execution
public import Mathlib.Tactic

@[expose] public section

namespace DisasterRecovery.Proofs.Trace

open CCF

/-- Enabled steps through the listed successor states, from a start state to a final state. -/
inductive Path (system : TransitionSystem)
    : system.State -> List system.State -> system.State -> Prop where
  /-- An empty path starts and ends at the same state. -/
  | nil (state) : Path system state [] state
  /-- Prepend one enabled step and its successor to the remaining path. -/
  | cons {before middle after tail} {action}
    (step : system.step before action = some middle)
    (rest : Path system middle tail after)
    : Path system before (middle :: tail) after

lemma Path.reachable {system : TransitionSystem} {before tail after}
    (path : Path system before tail after) (reachable : system.Reachable before)
    : system.Reachable after := by
  induction path with
  | nil => exact reachable
  | cons step _ ih => exact ih (.step reachable step)

lemma Path.run {system : TransitionSystem} {before tail after}
    (path : Path system before tail after)
    : exists actions, Execution.Run system before actions after := by
  induction path with
  | nil => exact ⟨[], .nil _⟩
  | cons step _ ih =>
      obtain ⟨actions, rest⟩ := ih
      exact ⟨_, .cons step rest⟩

/-- Enabled recorded steps connect every replayed state to every later replayed state. -/
lemma stateAt_path {system : TransitionSystem}
    {trace : Execution.Trace system.State system.Action} (start count : Nat)
    {before after : system.State}
    (first : trace.stateAt system start = some before)
    (last : trace.stateAt system (start + count) = some after)
    : exists tail, Path system before tail after := by
  induction count generalizing start before with
  | zero =>
      cases first.symm.trans last
      exact ⟨[], .nil _⟩
  | succ count ih =>
      obtain ⟨middle, next⟩ := Execution.Trace.exists_stateAt_of_le
        (show start + 1 <= start + (count + 1) by omega) last
      obtain ⟨previous, _, atPrevious, _, step⟩ :=
        Execution.Trace.stateAt_succ_eq_some.mp next
      have same : previous = before := Option.some.inj (atPrevious.symm.trans first)
      subst previous
      obtain ⟨tail, rest⟩ :=
        ih (start + 1) next (by rwa [show start + 1 + count = start + (count + 1) by omega])
      exact ⟨_, .cons step rest⟩

/-- The later of two trace positions is also a trace position. -/
lemma max_isSome {system : TransitionSystem}
    {trace : Execution.Trace system.State system.Action} {first second : Nat}
    (firstIn : (trace.stateAt system first).isSome)
    (secondIn : (trace.stateAt system second).isSome)
    : (trace.stateAt system (max first second)).isSome := by
  rcases le_total first second with le | le
  · rwa [max_eq_right le]
  · rwa [max_eq_left le]

/-- Finitely many trace positions all lie at or before one trace position after `start`. -/
lemma exists_bound {α : Type} {system : TransitionSystem}
    {trace : Execution.Trace system.State system.Action} {P : α -> Nat -> Prop}
    {start : Nat} (startIn : (trace.stateAt system start).isSome) (items : List α)
    (indexed
      : forall item,
          item ∈ items
          -> exists index, (trace.stateAt system index).isSome /\ P item index)
    : exists bound,
        (trace.stateAt system bound).isSome
        /\ start <= bound
        /\ forall item, item ∈ items -> exists index, index <= bound /\ P item index := by
  induction items with
  | nil => exact ⟨start, startIn, le_rfl, by simp⟩
  | cons head tail ih =>
      obtain ⟨headIndex, headIn, headHolds⟩ := indexed head (by simp)
      obtain ⟨bound, boundIn, startLe, bounded⟩ :=
        ih fun item member => indexed item (by simp [member])
      refine ⟨
        max headIndex bound,
        max_isSome headIn boundIn,
        startLe.trans (le_max_right _ _),
        fun item member => ?_
      ⟩
      rcases List.mem_cons.mp member with rfl | member
      · exact ⟨headIndex, le_max_left _ _, headHolds⟩
      · obtain ⟨index, le, holds⟩ := bounded item member
        exact ⟨index, le.trans (le_max_right _ _), holds⟩

/-- Replaying a finite action trace never produces a state past the end of its action list. -/
lemma stateAt_le_length {system : TransitionSystem}
    {initial state : system.State} {actions : List system.Action} {index : Nat}
    (found
      : (Execution.Trace.mk initial (Stream'.Seq.ofList actions)).stateAt system index
        = some state)
    : index <= actions.length := by
  cases index with
  | zero => exact Nat.zero_le _
  | succ index =>
      obtain ⟨_, _, _, recorded, _⟩ := Execution.Trace.stateAt_succ_eq_some.mp found
      simp only [Execution.Trace.actionAt, Stream'.Seq.ofList_get?] at recorded
      exact Nat.succ_le_of_lt (List.getElem?_eq_some_iff.mp recorded).1

/-- A finite action trace is valid if it starts initialized and replays through its last action. -/
lemma valid_of_stateAt_length {system : TransitionSystem}
    {initial final : system.State} {actions : List system.Action}
    (initialized : system.init initial)
    (last
      : (Execution.Trace.mk initial (Stream'.Seq.ofList actions)).stateAt system
          actions.length
        = some final)
    : (Execution.Trace.mk initial (Stream'.Seq.ofList actions)).Valid system := by
  refine ⟨initialized, fun index action recorded => ?_⟩
  have below : index < actions.length := by
    exact (List.getElem?_eq_some_iff.mp (by
      simpa only [Execution.Trace.actionAt, Stream'.Seq.ofList_get?] using recorded)).1
  obtain ⟨after, atAfter⟩ := Execution.Trace.exists_stateAt_of_le
    (show index + 1 <= actions.length by omega) last
  obtain ⟨before, actual, atBefore, atAction, stepped⟩ :=
    Execution.Trace.stateAt_succ_eq_some.mp atAfter
  have same : actual = action := Option.some.inj (atAction.symm.trans recorded)
  exact ⟨before, after, atBefore, same ▸ stepped⟩

end DisasterRecovery.Proofs.Trace
