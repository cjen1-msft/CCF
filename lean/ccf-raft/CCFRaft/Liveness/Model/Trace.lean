module

public import CCF.Execution

@[expose] public section

namespace CCFRaft.Liveness

/-- A finite or infinite recording of transition endpoints and actions.
Coherence and validity are separate predicates, not replay procedures. -/
structure Trace (W A : Type) where
  initial : W
  steps : Stream'.Seq (CCF.Execution.Step W A)

/-- The recorded step, or `none` past the end of a finite recording. -/
def Trace.stepAt {W A : Type} (trace : Trace W A) (index : Nat)
    : Option (CCF.Execution.Step W A) :=
  trace.steps.get? index

/-- The recorded action at this position. -/
def Trace.actionAt {W A : Type} (trace : Trace W A) (index : Nat) : Option A :=
  (trace.stepAt index).map fun step => step.action

/-- The initial state at zero, then the preceding step's recorded after-state. -/
def Trace.stateAt {W A : Type} (trace : Trace W A) : Nat -> Option W
  | 0 => some trace.initial
  | index + 1 => (trace.stepAt index).map fun step => step.after

/-- All recorded states, including the final state of a finite execution. -/
def Trace.states {W A : Type} (trace : Trace W A) : Stream'.Seq W :=
  Stream'.Seq.cons trace.initial (trace.steps.map fun step => step.after)

/-- The first step starts at `initial`, and adjacent endpoints agree. -/
def Trace.Coherent {W A : Type} (trace : Trace W A) : Prop :=
  (forall step, trace.stepAt 0 = some step -> step.before = trace.initial)
  /\ forall index previous next,
      trace.stepAt index = some previous
      -> trace.stepAt (index + 1) = some next
      -> previous.after = next.before

/-- A TLA-style initial predicate and action on a recorded step.
Fields left unmentioned are unconstrained; models have no variable ownership. -/
structure Model (W A : Type) where
  init : W -> Prop
  next : CCF.Execution.Step W A -> Prop

/-- Every recorded step satisfies the model, independently of other models. -/
def Trace.Valid {W A : Type} (trace : Trace W A) (model : Model W A) : Prop :=
  model.init trace.initial
  /\ forall index step, trace.stepAt index = some step -> model.next step

/-- Eventually, at or after `index`, an existing recorded state satisfies the predicate. -/
def Eventually {W A : Type} (trace : Trace W A) (index : Nat)
    (predicate : Nat -> W -> Prop)
    : Prop :=
  exists later point,
    index <= later /\ trace.stateAt later = some point /\ predicate later point

end CCFRaft.Liveness
