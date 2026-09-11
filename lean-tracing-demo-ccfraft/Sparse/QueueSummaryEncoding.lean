import Sparse.QueueTraceEncoding
import Sparse.QueuePresence

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueSummaryEncoding

open Smt (Assignment)
open QueueEncoding (InputInt)
open QueueScalarEncoding (evalTrace)
open QueueStream (Event concreteFollows)

def different : InputInt -> InputInt -> Bool
  | .literal left, .literal right => left != right
  | _, _ => false

theorem differences_sound (assignment : Assignment) :
    QueuePresence.SoundDifferences (InputInt.eval assignment) different := by
  intro left right distinct
  cases left <;> cases right <;> simp [different, InputInt.eval] at *
  assumption

def normalize (trace : List (Event InputInt)) : List (Event InputInt) :=
  QueuePresence.normalize different {} trace

theorem realize_eq_eval (assignment : Assignment) (trace : List (Event InputInt)) :
    QueuePresence.realize (InputInt.eval assignment) trace = evalTrace assignment trace := by
  apply List.map_congr_left
  intro event _
  cases event <;> rfl

theorem normalize_correct (assignment : Assignment) (queue : List Int)
    (trace : List (Event InputInt)) :
    concreteFollows queue (evalTrace assignment (normalize trace)) <->
      concreteFollows queue (evalTrace assignment trace) := by
  simpa only [normalize, realize_eq_eval] using
    QueuePresence.normalize_from_unknown_correct (InputInt.eval assignment) different
      (differences_sound assignment) trace queue

def encode (input : SmtScript.Formula) (trace : List (Event InputInt))
    (length : InputInt) : SmtScript.Formula :=
  QueueInitialEncoding.encode input (normalize trace) length

def render (input : SmtScript.Formula) (trace : List (Event InputInt))
    (length : InputInt) : String :=
  SmtScript.render (encode input trace length)

theorem encode_exists_iff (input : SmtScript.Formula) (trace : List (Event InputInt))
    (length : InputInt) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input trace length)) <->
    (exists original : Assignment, exists queue : List Int,
      SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
        concreteFollows queue (evalTrace original trace)) := by
  rw [encode, QueueTraceEncoding.encode_exists_iff]
  apply exists_congr
  intro original
  apply exists_congr
  intro queue
  rw [normalize_correct]

theorem rendered_exists_iff (input : SmtScript.Formula) (trace : List (Event InputInt))
    (length : InputInt) :
    (exists assignment : Assignment,
      SmtScriptText.runText assignment (render input trace length) = some true) <->
    (exists original : Assignment, exists queue : List Int,
      SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
        concreteFollows queue (evalTrace original trace)) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  exact encode_exists_iff input trace length

theorem encode_complete (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (queue : List Int)
    (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (evalTrace original trace)) :
    exists assignment : Assignment,
      SmtScript.Holds assignment (encode input trace length) /\
      assignment.constant = original.constant /\
      forall domain result id, Membership.mem (SmtScript.symbols input) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id :=
  QueueTraceEncoding.encode_complete original input (normalize trace) length queue input_holds
    queue_length ((normalize_correct original queue trace).mpr follows)

theorem repeated_symbolic_send_regression :
    normalize [.send (.symbolic 0), .send (.symbolic 1), .send (.symbolic 0), .length 2] =
      [.send (.symbolic 0), .send (.symbolic 1), .length 2] := by
  rfl

theorem aliased_pop_retains_send_regression :
    normalize [.send (.symbolic 0), .pop (.symbolic 1), .send (.symbolic 0), .length 1] =
      [.send (.symbolic 0), .pop (.symbolic 1), .send (.symbolic 0), .length 1] := by
  rfl

theorem literal_difference_retains_presence_regression :
    normalize [.send (.literal 0), .pop (.literal 1), .send (.literal 0), .length 1] =
      [.send (.literal 0), .pop (.literal 1), .length 1] := by
  rfl

theorem observations_retained_regression :
    normalize [.send (.literal 0), .peek (.literal 0), .length 1,
      .send (.literal 0), .length 2] =
      [.send (.literal 0), .peek (.literal 0), .length 1, .length 2] := by
  rfl

end CCFRaft.Sparse.QueueSummaryEncoding

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueSummaryEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueSummaryEncoding: allowed-axiom gate passed."
