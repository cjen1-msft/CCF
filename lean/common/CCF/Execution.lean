module

public import CCF.TransitionSystem
public import Mathlib.Data.Seq.Defs

@[expose] public section

namespace CCF.Execution

/-!
Executions of a `TransitionSystem`. `Run` relates a start state, a finite
action list, and an end state.
`Trace` records an initial state and a finite or infinite action sequence.
States are derived by deterministic replay; validity checks every recorded
action, not just the prefix before the first disabled action.
-/

/-- `Run system start actions final`: executing `actions` from `start` reaches `final`. -/
inductive Run {State Action : Type} (system : TransitionSystem State Action)
    : State -> List Action -> State -> Prop where
  /-- An empty action list leaves the state unchanged. -/
  | nil (state : State) : Run system state [] state
  /-- Prepend one enabled action to the rest of an execution. -/
  | cons {before middle after : State} {action : Action} {actions : List Action}
    (step : system.step before action = some middle)
    (rest : Run system middle actions after)
    : Run system before (action :: actions) after

/-- A finite or infinite execution, including an explicit initial state even
when no actions are recorded. -/
structure Trace (State Action : Type) where
  /-- The state before any recorded action. -/
  initial : State
  /-- The recorded actions, in execution order. -/
  actions : Stream'.Seq Action

/-- The recorded action at `index`, or `none` past the end of a finite trace. -/
def Trace.actionAt {State Action : Type} (trace : Trace State Action) (index : Nat)
    : Option Action :=
  trace.actions.get? index

/-- One replay step from a cursor: execute the next recorded action when it is enabled. -/
def replay {State Action : Type} (system : TransitionSystem State Action)
    (cursor : State × Stream'.Seq Action)
    : Option (State × (State × Stream'.Seq Action)) :=
  cursor.2.head.bind
    fun action =>
      (system.step cursor.1 action).map fun after => (after, (after, cursor.2.tail))

/-- The initial state followed by the states produced by successful replay.
A disabled action ends this derived state sequence, but remains recorded in
`actions` and is rejected by `Trace.Valid`. -/
def Trace.states {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action)
    : Stream'.Seq State :=
  Stream'.Seq.cons trace.initial
  <| Stream'.Seq.corec (replay system) (trace.initial, trace.actions)

/-- State after exactly `index` actions; index zero is the initial state.
`none` means the execution ended earlier or a preceding action was disabled. -/
def Trace.stateAt {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action) (index : Nat)
    : Option State :=
  (trace.states system).get? index

/-- A derived transition, rather than additional data stored in a trace. -/
structure Step (State Action : Type) where
  /-- The state the action is applied to. -/
  before : State
  /-- The recorded action. -/
  action : Action
  /-- The state the action produces. -/
  after : State

/-- Replay the action at `index`, returning its endpoints when it is enabled. -/
def Trace.stepAt {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action) (index : Nat)
    : Option (Step State Action) := do
  let before <- trace.stateAt system index
  let action <- trace.actionAt index
  let after <- system.step before action
  return { before, action, after }

/-- The initial state satisfies `system.init`, and every recorded action is
enabled after its recorded prefix. A disabled action anywhere invalidates the
trace, including when its successfully replayed prefix is itself valid. -/
def Trace.Valid {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action)
    : Prop :=
  system.init trace.initial
  /\ forall index action,
      trace.actionAt index = some action
      -> exists before after,
          trace.stateAt system index = some before
          /\ system.step before action = some after

section Replay

variable {State Action : Type} {system : TransitionSystem State Action}

/-- Replay from a cursor produces, at each position, the result of the recorded
action applied to the previously produced state. -/
theorem replay_get? (system : TransitionSystem State Action) (index : Nat)
    : forall (state : State) (actions : Stream'.Seq Action),
        (Stream'.Seq.corec (replay system) (state, actions)).get? index
        = ((Stream'.Seq.cons state
              (Stream'.Seq.corec (replay system) (state, actions))).get?
            index).bind
            fun before => (actions.get? index).bind (system.step before) := by
  induction index with
  | zero =>
      intro state actions
      cases headed : actions.head with
      | none =>
          obtain rfl := Stream'.Seq.head_eq_none headed
          rw [Stream'.Seq.corec_nil _ _ (by simp [replay])]
          simp
      | some action =>
          obtain ⟨remaining, rfl⟩ : exists remaining, actions = Stream'.Seq.cons action remaining :=
            ⟨_, Stream'.Seq.head_eq_some headed⟩
          cases stepped : system.step state action with
          | none =>
              rw [Stream'.Seq.corec_nil _ _ (by simp [replay, stepped])]
              simp [stepped]
          | some after =>
              have moved : replay system (state, Stream'.Seq.cons action remaining)
                  = some (after, (after, remaining)) := by
                simp [replay, stepped]
              rw [Stream'.Seq.corec_cons moved]
              simp [stepped]
  | succ index ih =>
      intro state actions
      cases headed : actions.head with
      | none =>
          obtain rfl := Stream'.Seq.head_eq_none headed
          rw [Stream'.Seq.corec_nil _ _ (by simp [replay])]
          simp
      | some action =>
          obtain ⟨remaining, rfl⟩ : exists remaining, actions = Stream'.Seq.cons action remaining :=
            ⟨_, Stream'.Seq.head_eq_some headed⟩
          cases stepped : system.step state action with
          | none =>
              rw [Stream'.Seq.corec_nil _ _ (by simp [replay, stepped])]
              simp
          | some after =>
              have moved : replay system (state, Stream'.Seq.cons action remaining)
                  = some (after, (after, remaining)) := by
                simp [replay, stepped]
              rw [Stream'.Seq.corec_cons moved]
              simp only [Stream'.Seq.get?_cons_succ]
              exact ih after remaining

/-- Index zero is the initial state. -/
@[simp]
theorem Trace.stateAt_zero (trace : Trace State Action)
    (system : TransitionSystem State Action)
    : trace.stateAt system 0 = some trace.initial :=
  Stream'.Seq.get?_cons_zero _ _

/-- The state after `index + 1` actions is the recorded action at `index`
applied to the state after `index` actions. -/
theorem Trace.stateAt_succ (trace : Trace State Action)
    (system : TransitionSystem State Action) (index : Nat)
    : trace.stateAt system (index + 1)
      = (trace.stateAt system index).bind
          fun before =>
            (trace.actionAt index).bind (system.step before) :=
  replay_get? system index trace.initial trace.actions

/-- A replayed state after `index + 1` actions comes from an enabled recorded action. -/
theorem Trace.stateAt_succ_eq_some {trace : Trace State Action} {index : Nat}
    {after : State}
    : trace.stateAt system (index + 1) = some after
      <-> exists before action,
            trace.stateAt system index = some before
            /\ trace.actionAt index = some action
            /\ system.step before action = some after := by
  rw [Trace.stateAt_succ]
  constructor
  · intro found
    obtain ⟨before, current, found⟩ := Option.bind_eq_some_iff.mp found
    obtain ⟨action, recorded, stepped⟩ := Option.bind_eq_some_iff.mp found
    exact ⟨before, action, current, recorded, stepped⟩
  · rintro ⟨before, action, current, recorded, stepped⟩
    simp [current, recorded, stepped]

/-- `stepAt` packages a replayed state, its recorded action, and the enabled result. -/
theorem Trace.stepAt_eq_some {trace : Trace State Action} {index : Nat}
    {step : Step State Action}
    : trace.stepAt system index = some step
      <-> trace.stateAt system index = some step.before
          /\ trace.actionAt index = some step.action
          /\ system.step step.before step.action = some step.after := by
  obtain ⟨before, action, after⟩ := step
  constructor
  · intro found
    simp only [Trace.stepAt, Option.bind_eq_bind, Option.bind_eq_some_iff] at found
    obtain ⟨before', current, action', recorded, after', stepped, packed⟩ := found
    cases packed
    exact ⟨current, recorded, stepped⟩
  · rintro ⟨current, recorded, stepped⟩
    simp [Trace.stepAt, current, recorded, stepped]

/-- The after-state of a replayed step is the next replayed state. -/
theorem Trace.stateAt_succ_of_stepAt {trace : Trace State Action} {index : Nat}
    {step : Step State Action} (found : trace.stepAt system index = some step)
    : trace.stateAt system (index + 1) = some step.after := by
  obtain ⟨current, recorded, stepped⟩ := Trace.stepAt_eq_some.mp found
  exact Trace.stateAt_succ_eq_some.mpr ⟨_, _, current, recorded, stepped⟩

/-- Replay never resumes after it stops. -/
theorem Trace.stateAt_eq_none_of_le {trace : Trace State Action} {index later : Nat}
    (le : index <= later) (missing : trace.stateAt system index = none)
    : trace.stateAt system later = none :=
  (trace.states system).le_stable le missing

/-- Every index before a replayed state is also replayed. -/
theorem Trace.exists_stateAt_of_le {trace : Trace State Action} {index later : Nat}
    {state : State} (le : index <= later)
    (found : trace.stateAt system later = some state)
    : exists earlier, trace.stateAt system index = some earlier :=
  (trace.states system).ge_stable le found

/-- Membership in the replayed states is replay at some index. -/
theorem Trace.mem_states_iff {trace : Trace State Action} {state : State}
    : state ∈ trace.states system
      <-> exists index, trace.stateAt system index = some state := by
  rw [Stream'.Seq.mem_iff_exists_get?]
  exact exists_congr fun _ => eq_comm

/-- Replay depends only on the initial state and the actions before the index. -/
theorem Trace.stateAt_congr {left right : Trace State Action}
    (initial : left.initial = right.initial) {bound : Nat}
    (actions : forall index, index < bound -> left.actionAt index = right.actionAt index)
    {index : Nat} (le : index <= bound)
    : left.stateAt system index = right.stateAt system index := by
  induction index with
  | zero => rw [Trace.stateAt_zero, Trace.stateAt_zero, initial]
  | succ index ih =>
      rw [Trace.stateAt_succ, Trace.stateAt_succ, ih (by omega), actions index (by omega)]

/-- A valid trace starts in an initial state. -/
theorem Trace.Valid.init {trace : Trace State Action} (valid : trace.Valid system)
    : system.init trace.initial :=
  valid.1

/-- Every recorded action of a valid trace is replayed: it is enabled in the
state before it, and its result is the next replayed state. -/
theorem Trace.Valid.stepAt {trace : Trace State Action} (valid : trace.Valid system)
    {index : Nat} {action : Action} (recorded : trace.actionAt index = some action)
    : exists before after,
        trace.stateAt system index = some before
        /\ system.step before action = some after
        /\ trace.stateAt system (index + 1) = some after := by
  obtain ⟨before, after, current, stepped⟩ := valid.2 index action recorded
  exact ⟨before, after, current, stepped,
    Trace.stateAt_succ_eq_some.mpr ⟨before, action, current, recorded, stepped⟩⟩

/-- Every replayed state of a valid trace is reachable. -/
theorem Trace.Valid.reachable_stateAt {trace : Trace State Action}
    (valid : trace.Valid system) {index : Nat} {state : State}
    (found : trace.stateAt system index = some state)
    : system.Reachable state := by
  induction index generalizing state with
  | zero =>
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      exact .initial valid.init
  | succ index ih =>
      obtain ⟨before, _, current, _, stepped⟩ := Trace.stateAt_succ_eq_some.mp found
      exact .step (ih current) stepped

end Replay

/-- Every state in a valid trace is reachable. -/
theorem Trace.Valid.reachable {State Action : Type}
    {system : TransitionSystem State Action}
    {trace : Trace State Action} (valid : trace.Valid system) {state : State}
    (member : state ∈ trace.states system)
    : system.Reachable state := by
  obtain ⟨_, found⟩ := Trace.mem_states_iff.mp member
  exact valid.reachable_stateAt found

/-- Valid traces cover exactly the reachable states. Every reachable state is the
last state of some valid finite trace. -/
theorem reachable_iff_trace {State Action : Type}
    {system : TransitionSystem State Action} {state : State}
    : system.Reachable state
      <-> exists trace : Trace State Action,
            trace.Valid system /\ state ∈ trace.states system := by
  constructor
  · intro reachable
    suffices finite : exists (initial : State) (actions : List Action),
        (Trace.mk initial (Stream'.Seq.ofList actions)).Valid system
        /\ (Trace.mk initial (Stream'.Seq.ofList actions)).stateAt system actions.length
          = some state by
      obtain ⟨_, _, valid, last⟩ := finite
      exact ⟨_, valid, Trace.mem_states_iff.mpr ⟨_, last⟩⟩
    induction reachable with
    | initial initialized =>
        refine ⟨_, [], ⟨initialized, fun index action recorded => ?_⟩, Trace.stateAt_zero _ _⟩
        simp [Trace.actionAt] at recorded
    | @step before after action _ stepped ih =>
        obtain ⟨initial, actions, valid, last⟩ := ih
        have same : forall index, index <= actions.length
            -> (Trace.mk initial (Stream'.Seq.ofList (actions ++ [action]))).stateAt system index
              = (Trace.mk initial (Stream'.Seq.ofList actions)).stateAt system index :=
          fun _ le => by
            refine Trace.stateAt_congr ?_ (fun _ below => ?_) le
            · rfl
            simp [Trace.actionAt, Stream'.Seq.ofList_get?, List.getElem?_append_left below]
        refine ⟨
          initial,
          actions ++ [action],
          ⟨valid.init, fun index recordedAction recorded => ?_⟩,
          ?_
        ⟩
        · simp only [Trace.actionAt, Stream'.Seq.ofList_get?] at recorded
          by_cases inside : index < actions.length
          · rw [List.getElem?_append_left inside] at recorded
            obtain ⟨pre, post, current, enabled⟩ := valid.2 index recordedAction
              (by simpa [Trace.actionAt, Stream'.Seq.ofList_get?] using recorded)
            exact ⟨pre, post, (same index (Nat.le_of_lt inside)).trans current, enabled⟩
          · have length : index = actions.length := by
              have := (List.getElem?_eq_some_iff.mp recorded).1
              simp at this
              omega
            subst length
            simp at recorded
            subst recorded
            exact ⟨before, after, (same _ le_rfl).trans last, stepped⟩
        · rw [List.length_append, List.length_singleton, Trace.stateAt_succ, same _ le_rfl, last]
          simp [Trace.actionAt, Stream'.Seq.ofList_get?, stepped]
  · rintro ⟨trace, valid, member⟩
    exact valid.reachable member

end CCF.Execution
