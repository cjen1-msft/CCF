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
  initial : State
  actions : Stream'.Seq Action

/-- The recorded action at `index`, or `none` past the end of a finite trace. -/
def Trace.actionAt {State Action : Type} (trace : Trace State Action)
    (index : Nat) : Option Action :=
  trace.actions.get? index

/-- The initial state followed by the states produced by successful replay.
A disabled action ends this derived state sequence, but remains recorded in
`actions` and is rejected by `Trace.Valid`. -/
def Trace.states {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action) : Stream'.Seq State :=
  Stream'.Seq.cons trace.initial <|
    Stream'.Seq.corec (fun (cursor : State × Stream'.Seq Action) => do
      let (action, remaining) <- cursor.2.destruct
      let after <- system.step cursor.1 action
      return (after, (after, remaining))) (trace.initial, trace.actions)

/-- State after exactly `index` actions; index zero is the initial state.
`none` means the execution ended earlier or a preceding action was disabled. -/
def Trace.stateAt {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action) (index : Nat) : Option State :=
  (trace.states system).get? index

/-- A derived transition, rather than additional data stored in a trace. -/
structure Step (State Action : Type) where
  before : State
  action : Action
  after : State

/-- Replay the action at `index`, returning its endpoints when it is enabled. -/
def Trace.stepAt {State Action : Type} (trace : Trace State Action)
    (system : TransitionSystem State Action) (index : Nat) : Option (Step State Action) := do
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

/-- Every state in a valid trace is reachable. -/
theorem Trace.Valid.reachable {State Action : Type}
    {system : TransitionSystem State Action}
    {trace : Trace State Action} (valid : trace.Valid system) {state : State}
    (member : state ∈ trace.states system)
    : system.Reachable state := by
  obtain ⟨index, found⟩ := Stream'.Seq.mem_iff_exists_get?.mp member
  clear member
  induction index generalizing state with
  | zero =>
      obtain ⟨initial, first, initialized⟩ := valid.1
      rw [first] at found
      cases found
      exact .initial initialized
  | succ index ih =>
      cases previous : trace.get? index with
      | none => simp [trace.le_stable (Nat.le_succ index) previous] at found
      | some before =>
          obtain ⟨action, step⟩ := valid.2 index before state previous found.symm
          exact .step (ih previous.symm) step

/-- Valid traces cover exactly the reachable states. Every reachable state is the
last state of some valid finite trace. -/
theorem reachable_iff_trace {State Action : Type}
    {system : TransitionSystem State Action} {state : State}
    : system.Reachable state
      <-> exists trace : Trace State Action,
          trace.Valid system /\ state ∈ trace.states system := by
  constructor
  · intro reachable
    suffices finite : exists states : List State,
        Trace.Valid (Stream'.Seq.ofList (states ++ [state])) system by
      obtain ⟨states, valid⟩ := finite
      exact ⟨_, valid, Stream'.Seq.get?_mem (n := states.length) (by simp [Stream'.Seq.ofList_get?])⟩
    induction reachable with
    | initial initialized =>
        refine ⟨[], ⟨_, rfl, initialized⟩, fun index before after _ next => ?_⟩
        simp at next
    | @step before after action _ step ih =>
        obtain ⟨states, valid⟩ := ih
        refine ⟨states ++ [before], ?_, ?_⟩
        · obtain ⟨initial, first, initialized⟩ := valid.1
          refine ⟨initial, ?_, initialized⟩
          simp only [Stream'.Seq.ofList_get?] at first ⊢
          rw [List.getElem?_append_left (by simp)]
          exact first
        · intro index pre post current next
          simp only [Stream'.Seq.ofList_get?] at current next
          by_cases inside : index + 1 < states.length + 1
          · rw [List.getElem?_append_left (by simp; omega)] at current next
            exact valid.2 index pre post (by simpa [Stream'.Seq.ofList_get?] using current)
              (by simpa [Stream'.Seq.ofList_get?] using next)
          · have length : index = states.length := by
              have := (List.getElem?_eq_some_iff.mp next).1
              simp at this
              omega
            subst length
            simp at current next
            subst current next
            exact ⟨action, step⟩
  · rintro ⟨trace, valid, member⟩
    exact valid.reachable member

end CCF.Execution
