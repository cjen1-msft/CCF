module

public import CCFRaft.Liveness.Model.Trace

@[expose] public section

/-!
# Recorded traces

Generic facts about a recorded relational trace: a recording is prefix closed,
coherence places each step between the states recorded at its index and the next,
and induction runs over the recorded states from any index.
-/

namespace CCFRaft.Liveness.Trace

variable {W A : Type} {trace : Trace W A}

@[simp] theorem stateAt_zero : trace.stateAt 0 = some trace.initial := rfl

theorem stateAt_succ_of_stepAt {index : Nat} {step : CCF.Execution.Step W A}
    (stepped : trace.stepAt index = some step)
    : trace.stateAt (index + 1) = some step.after := by
  simp [stateAt, stepped]

theorem stateAt_succ_eq_some {index : Nat} {point : W}
    : trace.stateAt (index + 1) = some point
      <-> exists step, trace.stepAt index = some step /\ step.after = point := by
  simp [stateAt]

/-- A step is recorded at every index below a recorded step. -/
theorem stepAt_of_le {earlier later : Nat} (le : earlier <= later)
    {step : CCF.Execution.Step W A} (stepped : trace.stepAt later = some step)
    : exists step', trace.stepAt earlier = some step' := by
  cases found : trace.stepAt earlier with
  | none =>
      have := Stream'.Seq.le_stable trace.steps le found
      simp only [stepAt] at stepped
      rw [this] at stepped
      cases stepped
  | some step' => exact ⟨step', rfl⟩

/-- A state is recorded at every index below a recorded state. -/
theorem stateAt_of_le {earlier later : Nat} (le : earlier <= later) {point : W}
    (found : trace.stateAt later = some point)
    : exists point', trace.stateAt earlier = some point' := by
  cases earlier with
  | zero => exact ⟨trace.initial, rfl⟩
  | succ earlier =>
      cases later with
      | zero => omega
      | succ later =>
          obtain ⟨step, stepped, _⟩ := stateAt_succ_eq_some.mp found
          obtain ⟨step', stepped'⟩ := stepAt_of_le (earlier := earlier) (by omega) stepped
          exact ⟨step'.after, stateAt_succ_of_stepAt stepped'⟩

/-- A recorded step has a recorded state at its index. -/
theorem stateAt_of_stepAt {index : Nat} {step : CCF.Execution.Step W A}
    (stepped : trace.stepAt index = some step)
    : exists point, trace.stateAt index = some point :=
  stateAt_of_le (Nat.le_succ index) (stateAt_succ_of_stepAt stepped)

/-- A recorded state that is not the last one is followed by a recorded step. -/
theorem stepAt_of_stateAt_lt {index later : Nat} (lt : index < later) {point : W}
    (found : trace.stateAt later = some point)
    : exists step, trace.stepAt index = some step := by
  obtain ⟨next, nextFound⟩ := stateAt_of_le lt found
  obtain ⟨step, stepped, _⟩ := stateAt_succ_eq_some.mp nextFound
  exact ⟨step, stepped⟩

/-- Coherence places a step after the state recorded at its index. -/
theorem Coherent.before (coherent : trace.Coherent) {index : Nat}
    {step : CCF.Execution.Step W A} (stepped : trace.stepAt index = some step)
    : trace.stateAt index = some step.before := by
  cases index with
  | zero => exact congrArg some (coherent.1 step stepped).symm
  | succ index =>
      obtain ⟨previous, previousStepped⟩ := stepAt_of_le (Nat.le_succ index) stepped
      rw [stateAt_succ_of_stepAt previousStepped, coherent.2 index previous step previousStepped
        stepped]

/-- Induction over the recorded states from `start`. -/
theorem Coherent.induction (coherent : trace.Coherent) {start : Nat}
    {motive : Nat -> W -> Prop}
    (base : forall point, trace.stateAt start = some point -> motive start point)
    (next
      : forall index step,
          start <= index
          -> trace.stepAt index = some step
          -> motive index step.before
          -> motive (index + 1) step.after)
    : forall index point,
        start <= index -> trace.stateAt index = some point -> motive index point := by
  intro index point le found
  induction index, le using Nat.le_induction generalizing point with
  | base => exact base point found
  | succ index le ih =>
      obtain ⟨step, stepped, rfl⟩ := stateAt_succ_eq_some.mp found
      exact next index step le stepped (ih step.before (coherent.before stepped))

/-- A relation that every step preserves holds between any two recorded states in order. -/
theorem Coherent.chain (coherent : trace.Coherent) {relation : W -> W -> Prop}
    (refl : forall point, relation point point)
    (trans : forall a b c, relation a b -> relation b c -> relation a c)
    (next
      : forall index step,
          trace.stepAt index = some step -> relation step.before step.after)
    {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : relation first last :=
  coherent.induction (start := earlier) (motive := fun _ point => relation first point)
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      exact found ▸ refl first)
    (fun index step _ stepped held => trans _ _ _ held (next index step stepped))
    later last le lastFound

/-- A point-valued measure preserved by each recorded step is monotone between
recorded states, starting at any index. -/
theorem Coherent.measure_mono (coherent : trace.Coherent) {start : Nat}
    {measure : Nat -> W -> Nat}
    (next
      : forall index step,
          start <= index
          -> trace.stepAt index = some step
          -> measure index step.before <= measure (index + 1) step.after)
    {index later : Nat} (afterStart : start <= index) (le : index <= later)
    {first last : W} (firstFound : trace.stateAt index = some first)
    (lastFound : trace.stateAt later = some last)
    : measure index first <= measure later last :=
  coherent.induction (start := index)
    (motive := fun later point => measure index first <= measure later point)
    (fun point found => by
      rw [firstFound, Option.some.injEq] at found
      exact found ▸ Nat.le_refl _)
    (fun later step after stepped held =>
      Nat.le_trans held (next later step (Nat.le_trans afterStart after) stepped))
    later last le lastFound

theorem Valid.init {model : Model W A} (valid : trace.Valid model)
    : model.init trace.initial :=
  valid.1

theorem Valid.next {model : Model W A} (valid : trace.Valid model) {index : Nat}
    {step : CCF.Execution.Step W A} (stepped : trace.stepAt index = some step)
    : model.next step :=
  valid.2 index step stepped

/-- An invariant of a model holds at every recorded state. -/
theorem Valid.invariant {model : Model W A} (valid : trace.Valid model)
    (coherent : trace.Coherent) {invariant : W -> Prop}
    (init : forall point, model.init point -> invariant point)
    (next : forall step, model.next step -> invariant step.before -> invariant step.after)
    {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : invariant point :=
  coherent.induction (start := 0) (motive := fun _ point => invariant point)
    (fun point found => by
      rw [stateAt_zero, Option.some.injEq] at found
      exact found ▸ init _ valid.init)
    (fun _ _ _ stepped held => next _ (valid.next stepped) held)
    index point (Nat.zero_le _) found

/-- A measure that never grows between recorded states from `start` attains its
least value at a recorded state, and keeps it from there on. -/
theorem settles_of_antitone {start : Nat} {first : W}
    (found : trace.stateAt start = some first) {measure : Nat -> W -> Nat}
    (anti
      : forall index later point point',
          start <= index
          -> index <= later
          -> trace.stateAt index = some point
          -> trace.stateAt later = some point'
          -> measure later point' <= measure index point)
    : exists stop point,
        start <= stop
        /\ trace.stateAt stop = some point
        /\ forall index later,
            stop <= index
            -> trace.stateAt index = some later
            -> measure index later = measure stop point := by
  classical
  have attained
      : exists value index point,
          start <= index /\ trace.stateAt index = some point /\ measure index point = value :=
    ⟨_, start, first, le_rfl, found, rfl⟩
  obtain ⟨stop, point, le, stopFound, least⟩ := Nat.find_spec attained
  refine ⟨stop, point, le, stopFound, fun index later after laterFound => ?_⟩
  have below := anti stop index point later le after stopFound laterFound
  have above := Nat.find_min' attained ⟨index, later, Nat.le_trans le after, laterFound, rfl⟩
  omega

/-- A bounded measure that never shrinks between recorded states from `start`
reaches its greatest value at a recorded state, and keeps it from there on. -/
theorem settles_of_monotone {start : Nat} {first : W}
    (found : trace.stateAt start = some first) {measure : Nat -> W -> Nat} {bound : Nat}
    (mono
      : forall index later point point',
          start <= index
          -> index <= later
          -> trace.stateAt index = some point
          -> trace.stateAt later = some point'
          -> measure index point <= measure later point')
    (bounded
      : forall index point,
          start <= index
          -> trace.stateAt index = some point
          -> measure index point <= bound)
    : exists stop point,
        start <= stop
        /\ trace.stateAt stop = some point
        /\ forall index later,
            stop <= index
            -> trace.stateAt index = some later
            -> measure index later = measure stop point := by
  obtain ⟨stop, point, le, stopFound, constant⟩ :=
    settles_of_antitone (measure := fun index point => bound - measure index point) found
      fun index later point point' le after found found' => by
        have := mono index later point point' le after found found'
        omega
  refine ⟨stop, point, le, stopFound, fun index later after laterFound => ?_⟩
  have same := constant index later after laterFound
  have := bounded index later (Nat.le_trans le after) laterFound
  have := bounded stop point le stopFound
  omega

end CCFRaft.Liveness.Trace

namespace CCFRaft.Liveness

variable {W A : Type} {trace : Trace W A}

theorem Eventually.of_found {index : Nat} {point : W} {predicate : Nat -> W -> Prop}
    (found : trace.stateAt index = some point) (holds : predicate index point)
    : Eventually trace index predicate :=
  ⟨index, point, le_rfl, found, holds⟩

theorem Eventually.mono {index : Nat} {predicate other : Nat -> W -> Prop}
    (eventually : Eventually trace index predicate)
    (implies
      : forall later point, index <= later -> predicate later point -> other later point)
    : Eventually trace index other := by
  obtain ⟨later, point, le, found, holds⟩ := eventually
  exact ⟨later, point, le, found, implies later point le holds⟩

end CCFRaft.Liveness
