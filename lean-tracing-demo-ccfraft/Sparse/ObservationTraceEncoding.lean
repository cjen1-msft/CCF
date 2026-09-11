import Sparse.FrameObservationEncoding
import Sparse.StateFrameInitial

set_option autoImplicit false

namespace CCFRaft.Sparse.ObservationTraceEncoding

open Smt (Assignment)
open ModelTrace (UnknownNatAssignment)
open ModelInputScalarEncoding (SourceRep)

variable {n : Nat}

def frame (n : Nat) : StateFrame.Frame NODE_COUNT 0 :=
  StateFrameInitial.frame n 0 0

theorem source_frame_disjoint (n : Nat) :
    ModelInputScalarEncoding.FrameDisjoint 0 n (frame n) := by
  intro id member
  apply Or.inr
  have owned := StateFrameInitial.symbols_owned n 0 0 (.constant .int id) member
  have bound := (StateFrameInitial.owned_bounds n (.constant .int id) owned).1
  simpa [ModelInputScalarEncoding.highwater, SymbolBounds.symbolId] using bound

def encode (trace : ModelInputSyntax.Trace n) :
    Except FrameObservationEncoding.Rejection SmtScript.Formula :=
  FrameObservationEncoding.encodeChecked 0 (frame n) trace

def render (trace : ModelInputSyntax.Trace n) :
    Except FrameObservationEncoding.Rejection String :=
  (encode trace).map SmtScript.render

private def graph : StateFrame.Graph NODE_COUNT 0 := .empty
private def sampleRoots : StateFrame.Roots NODE_COUNT :=
  fun _ _ => { term := 0, content := .signature }

theorem jointly_representable (original : Assignment) (rho : UnknownNatAssignment)
    (state : StateFrame.ModelState) :
    exists assignment arrays,
      SourceRep assignment 0 n rho /\
      StateFrame.Rep assignment graph arrays state.submittedTxIds (frame n) state := by
  let old : StateFrame.Roots 0 := fun index => Fin.elim0 index
  let initial := StateFrameInitial.install original state n
  let arrays := StateFrameInitial.extendRoots old state
  let assignment := ScalarExtension.install initial 0 (fun index : Fin n => (rho index.val : Int))
  have represented := StateFrameInitial.arbitrary_state_coverage original state n 0 0 old graph
  have preserved := (ModelInputScalarEncoding.install_frame_rep initial 0 n rho graph arrays
    state.submittedTxIds (frame n) state (source_frame_disjoint n)).mpr represented
  exact Exists.intro assignment (Exists.intro arrays
    (And.intro (ModelInputScalarEncoding.install_source_rep initial 0 n rho) preserved))

theorem formula_exists_iff [Bootstrap Node] (trace : ModelInputSyntax.Trace n)
    (observations : List (FrameObservationEncoding.Observation n))
    (accepted : FrameObservationEncoding.checkTrace trace = .ok observations) :
    (exists assignment : Assignment, SmtScript.Holds assignment
      (FrameObservationEncoding.encode 0 (frame n) observations)) <->
    ModelInputSyntax.Satisfiable trace := by
  rw [ModelInputSyntax.satisfiable_iff]
  constructor
  next =>
    intro found
    cases found with
    | intro assignment holds =>
      -- Accepted observations cannot inspect log contents, queues, or submitted IDs.
      have realized := (FrameObservationEncoding.formula_iff assignment 0 (frame n)
        graph sampleRoots (fun _ => []) {} observations).mp holds
      cases realized with
      | intro rho realized =>
        cases realized with
        | intro state facts =>
          refine Exists.intro rho (Exists.intro state ?_)
          rw [<- FrameObservationEncoding.check_trace_preserves trace observations accepted,
            FrameObservationEncoding.observations_follows]
          exact facts.2.2.2
  next =>
    intro found
    cases found with
    | intro rho found =>
      cases found with
      | intro state follows =>
        have realized := jointly_representable (n := n) QueueEncoding.regressionInput rho state
        cases realized with
        | intro assignment realized =>
          cases realized with
          | intro arrays facts =>
            apply Exists.intro assignment
            apply (FrameObservationEncoding.formula_iff assignment 0 (frame n) graph arrays
              state.network state.submittedTxIds observations).mpr
            refine Exists.intro rho (Exists.intro state
              (And.intro facts.1 (And.intro facts.2 (And.intro rfl ?_))))
            rw [<- FrameObservationEncoding.check_trace_preserves trace observations accepted,
              FrameObservationEncoding.observations_follows] at follows
            exact follows

theorem rendered_exists_iff [Bootstrap Node] (trace : ModelInputSyntax.Trace n)
    (text : String) (generated : render trace = .ok text) :
    (exists assignment : Assignment, SmtScriptText.runText assignment text = some true) <->
      ModelInputSyntax.Satisfiable trace := by
  cases accepted : FrameObservationEncoding.checkTrace trace with
  | error reason =>
    simp only [render, encode, FrameObservationEncoding.encodeChecked, accepted] at generated
    cases generated
  | ok observations =>
    have text_eq : SmtScript.render (FrameObservationEncoding.encode 0 (frame n) observations) = text := by
      simp only [render, encode, FrameObservationEncoding.encodeChecked, accepted] at generated
      exact Except.ok.inj generated
    rw [<- text_eq]
    simp only [<- SmtScriptText.formula_text_iff]
    exact formula_exists_iff trace observations accepted

theorem rejects_action (action : ModelInputSyntax.ActionSyntax n)
    (rest : ModelInputSyntax.Trace n) :
    render (.action action :: rest) = .error .action := rfl

end CCFRaft.Sparse.ObservationTraceEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ObservationTraceEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit ObservationTraceEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ObservationTraceEncoding: {checked} declarations passed the transitive axiom gate."
