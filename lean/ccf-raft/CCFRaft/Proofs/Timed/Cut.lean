module

public import CCFRaft.Proofs.Liveness.Delay
public import CCFRaft.Proofs.Leadership.Stable

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Cutting a recording at a window's end

The timed argument runs the untimed replication lemmas, which assume a primary that
stays stable at every later recorded state, on a prefix of the recording that ends
inside the window. The prefix agrees with the recording on every state and step it
keeps, so it is admissible and recorded facts transfer back.
-/

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.Liveness (Admissible)

section Cut

variable {W A : Type}

/-- The recording up to and including the state at `last`. -/
def cut (trace : Trace W A) (last : Nat) : Trace W A :=
  ⟨trace.initial, Stream'.Seq.ofList (trace.steps.take last)⟩

theorem cut_stepAt (trace : Trace W A) (last index : Nat)
    : (cut trace last).stepAt index = if index < last then trace.stepAt index else none := by
  simp only [cut, Trace.stepAt, Stream'.Seq.ofList_get?, Stream'.Seq.getElem?_take]

theorem cut_stepAt_of_lt {trace : Trace W A} {last index : Nat} (lt : index < last)
    : (cut trace last).stepAt index = trace.stepAt index := by
  rw [cut_stepAt, ite_eq_left_iff.mpr fun no => absurd lt no]

theorem cut_stateAt_of_le {trace : Trace W A} {last index : Nat} (le : index <= last)
    : (cut trace last).stateAt index = trace.stateAt index := by
  cases index with
  | zero => rfl
  | succ index =>
      simp only [Trace.stateAt, cut_stepAt_of_lt (Nat.lt_of_succ_le le)]

theorem cut_stateAt_of_lt {trace : Trace W A} {last index : Nat} (lt : last < index)
    : (cut trace last).stateAt index = none := by
  cases index with
  | zero => omega
  | succ index =>
      have : Not (index < last) := by omega
      simp [Trace.stateAt, cut_stepAt, this]

/-- A step of the cut is a step of the recording. -/
theorem stepAt_of_cut {trace : Trace W A} {last index : Nat}
    {step : CCF.Execution.Step W A} (stepped : (cut trace last).stepAt index = some step)
    : index < last /\ trace.stepAt index = some step := by
  rw [cut_stepAt] at stepped
  split at stepped
  · rename_i lt
    exact ⟨lt, stepped⟩
  · cases stepped

/-- A state of the cut is a state of the recording. -/
theorem stateAt_of_cut {trace : Trace W A} {last index : Nat} {point : W}
    (found : (cut trace last).stateAt index = some point)
    : index <= last /\ trace.stateAt index = some point := by
  by_cases le : index <= last
  · rw [cut_stateAt_of_le le] at found
    exact ⟨le, found⟩
  · rw [cut_stateAt_of_lt (Nat.lt_of_not_le le)] at found
    cases found

theorem Coherent.cut {trace : Trace W A} (coherent : trace.Coherent) (last : Nat)
    : (cut trace last).Coherent :=
  ⟨
    fun step stepped => coherent.1 step (stepAt_of_cut stepped).2,
    fun index previous next previousAt nextAt =>
      coherent.2 index previous next (stepAt_of_cut previousAt).2 (stepAt_of_cut nextAt).2
  ⟩

theorem Valid.cut {trace : Trace W A} {model : Model W A} (valid : trace.Valid model)
    (last : Nat)
    : (cut trace last).Valid model :=
  ⟨valid.1, fun index step stepped => valid.2 index step (stepAt_of_cut stepped).2⟩

end Cut

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

theorem cut_nodeAt_of_le {trace : Trace W Liveness.Event} {last index : Nat}
    (le : index <= last) (node : NodeID)
    : (cut trace last).nodeAt index node = trace.nodeAt index node := by
  simp only [Trace.nodeAt, cut_stateAt_of_le le]

theorem cut_sentAt {trace : Trace W Liveness.Event} {last index : Nat} (lt : index < last)
    {packet : Packet}
    : (cut trace last).SentAt index packet <-> trace.SentAt index packet := by
  simp only [Trace.SentAt, cut_stepAt_of_lt lt]

theorem Admissible.cut {system : CCF.TransitionSystem Model.State Model.Action}
    {trace : Trace W Liveness.Event} (admissible : Admissible system trace) (last : Nat)
    : Admissible system (cut trace last) :=
  ⟨
    Coherent.cut admissible.coherent last,
    Valid.cut admissible.protocol last,
    Valid.cut admissible.timing last,
    Valid.cut admissible.crash last,
    Valid.cut admissible.delivery last
  ⟩

end CCFRaft.Proofs.Timed
