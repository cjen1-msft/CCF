import Sparse.QueueEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueScalarEncoding

open Smt (Assignment Term)
open QueueEncoding (InputInt)
open QueueStream (Event)
open QueueClause (Clause Heap)
open QueueReadback (ScalarHolds scalarFields writeCount)
open SignedQueue (SignedWindow)

def evalEvent (assignment : Assignment) : Event InputInt -> Event Int
  | .send key => .send (key.eval assignment)
  | .pop key => .pop (key.eval assignment)
  | .peek key => .peek (key.eval assignment)
  | .length length => .length length

def evalTrace (assignment : Assignment) (trace : List (Event InputInt)) : List (Event Int) :=
  trace.map (evalEvent assignment)

def evalClause (assignment : Assignment) (clause : Clause InputInt) : Clause Int :=
  { event := evalEvent assignment clause.event, source := clause.source, target := clause.target }

theorem compile_eval (assignment : Assignment) (trace : List (Event InputInt)) (current fresh : Nat) :
    (QueueClause.compile current fresh trace).map (evalClause assignment) =
      QueueClause.compile current fresh (evalTrace assignment trace) := by
  induction trace generalizing current fresh with
  | nil => rfl
  | cons event rest ih =>
    cases event <;> simp [QueueClause.compile, QueueClause.writes, evalTrace, evalEvent, evalClause, ih]

theorem write_count_eval (assignment : Assignment) (trace : List (Event InputInt)) :
    writeCount (evalTrace assignment trace) = writeCount trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    cases event <;> simp_all [writeCount, evalTrace, evalEvent, QueueClause.writes]

def headRef (base index : Nat) : Term .int :=
  .app .int .int base (.integer (index : Int))

def tailRef (base index : Nat) : Term .int :=
  .app .int .int (base + 1) (.integer (index : Int))

def orderRef (base : Nat) (position : Term .int) : Term .int :=
  .app .int .int (base + 2) position

def windows (assignment : Assignment) (base index : Nat) : SignedWindow :=
  { head := assignment.unary .int .int base (index : Int)
    tail := assignment.unary .int .int (base + 1) (index : Int) }

def order (assignment : Assignment) (base : Nat) : Int -> Int :=
  assignment.unary .int .int (base + 2)

def rawHeap (assignment : Assignment) (countBase scalarBase : Nat) : Heap Int :=
  fun index =>
    { counts := assignment.unary .int .int (countBase + index)
      window := windows assignment scalarBase index }

def guardTerm (countBase scalarBase : Nat) (clause : Clause InputInt) : Term .bool :=
  let head := headRef scalarBase clause.source
  let tail := tailRef scalarBase clause.source
  match clause.event with
  | .send key =>
    .implies (.equal (QueueEncoding.readRef countBase clause.source key) (.integer 0))
      (.equal (orderRef scalarBase tail) key.term)
  | .pop key =>
    .and (.not (.le tail head))
      (.and (.equal (orderRef scalarBase head) key.term)
        (.not (.le (QueueEncoding.readRef countBase clause.source key) (.integer 0))))
  | .peek key =>
    .and (.not (.le tail head)) (.equal (orderRef scalarBase head) key.term)
  | .length length => .equal (.sub tail head) (.integer (length : Int))

def fieldsTerm (countBase scalarBase : Nat) (clause : Clause InputInt) : Term .bool :=
  let head := headRef scalarBase clause.source
  let tail := tailRef scalarBase clause.source
  let nextHead := headRef scalarBase clause.target
  let nextTail := tailRef scalarBase clause.target
  match clause.event with
  | .send key =>
    .and (.equal nextHead head)
      (.equal nextTail (.add tail
        (.ite (.equal (QueueEncoding.readRef countBase clause.source key) (.integer 0))
          (.integer 1) (.integer 0))))
  | .pop _ => .and (.equal nextHead (.add head (.integer 1))) (.equal nextTail tail)
  | .peek _ | .length _ => .and (.equal nextHead head) (.equal nextTail tail)

def clauseFormula (countBase scalarBase : Nat) (clause : Clause InputInt) : SmtScript.Formula :=
  [guardTerm countBase scalarBase clause, fieldsTerm countBase scalarBase clause]

def scalarBlock (countBase scalarBase : Nat) (trace : List (Event InputInt)) : SmtScript.Formula :=
  (QueueClause.compile 0 1 trace).flatMap (clauseFormula countBase scalarBase)

def initialBlock (scalarBase : Nat) (length : InputInt) : SmtScript.Formula :=
  [.le (.integer 0) length.term,
   .equal (headRef scalarBase 0) (.integer 0),
   .equal (tailRef scalarBase 0) length.term]

theorem guard_correct (assignment : Assignment) (countBase scalarBase : Nat)
    (clause : Clause InputInt) :
    (guardTerm countBase scalarBase clause).eval assignment = true <->
      QueueClause.guard (order assignment scalarBase)
        (rawHeap assignment countBase scalarBase clause.source) (evalEvent assignment clause.event) := by
  cases clause with
  | mk event source target =>
    cases event <;>
      simp [guardTerm, Term.eval, QueueClause.guard, rawHeap, windows, order, evalEvent,
        headRef, tailRef, orderRef, QueueEncoding.readRef, InputInt.eval]
    all_goals tauto

theorem fields_correct (assignment : Assignment) (countBase scalarBase : Nat)
    (clause : Clause InputInt) :
    (fieldsTerm countBase scalarBase clause).eval assignment = true <->
      scalarFields (rawHeap assignment countBase scalarBase clause.source)
        (rawHeap assignment countBase scalarBase clause.target) (evalEvent assignment clause.event) := by
  cases clause with
  | mk event source target =>
    cases event with
    | send key =>
      by_cases zero : assignment.unary .int .int (countBase + source) (key.eval assignment) = 0 <;>
        simp_all [fieldsTerm, Term.eval, scalarFields, QueueClause.advance, rawHeap, windows, evalEvent,
          headRef, tailRef, QueueEncoding.readRef, InputInt.eval, SignedWindow.append]
    | pop key =>
      simp [fieldsTerm, Term.eval, scalarFields, QueueClause.advance, rawHeap, windows, evalEvent,
        headRef, tailRef, SignedWindow.pop]
    | peek key =>
      simp [fieldsTerm, Term.eval, scalarFields, QueueClause.advance, rawHeap, windows, evalEvent,
        headRef, tailRef]
    | length length =>
      simp [fieldsTerm, Term.eval, scalarFields, QueueClause.advance, rawHeap, windows, evalEvent,
        headRef, tailRef]

theorem clauses_correct (assignment : Assignment) (countBase scalarBase : Nat)
    (clauses : List (Clause InputInt)) :
    SmtScript.Holds assignment (clauses.flatMap (clauseFormula countBase scalarBase)) <->
      ScalarHolds (order assignment scalarBase) (rawHeap assignment countBase scalarBase)
        (clauses.map (evalClause assignment)) := by
  induction clauses with
  | nil => simp [SmtScript.Holds, ScalarHolds]
  | cons clause rest ih =>
    rw [List.flatMap_cons, QueueEncoding.holds_append, ih]
    have here :
        SmtScript.Holds assignment (clauseFormula countBase scalarBase clause) <->
          QueueClause.guard (order assignment scalarBase)
            (rawHeap assignment countBase scalarBase clause.source) (evalEvent assignment clause.event) /\
          scalarFields (rawHeap assignment countBase scalarBase clause.source)
            (rawHeap assignment countBase scalarBase clause.target) (evalEvent assignment clause.event) := by
      simp only [clauseFormula, SmtScript.Holds, List.mem_cons, List.not_mem_nil, or_false,
        forall_eq_or_imp, forall_eq]
      exact and_congr (guard_correct assignment countBase scalarBase clause)
        (fields_correct assignment countBase scalarBase clause)
    exact and_congr here Iff.rfl

theorem scalar_block_correct_total (assignment : Assignment) (countBase scalarBase : Nat)
    (trace : List (Event InputInt)) :
    SmtScript.Holds assignment (scalarBlock countBase scalarBase trace) <->
      ScalarHolds (order assignment scalarBase) (rawHeap assignment countBase scalarBase)
        (QueueClause.compile 0 1 (evalTrace assignment trace)) := by
  rw [scalarBlock, clauses_correct, compile_eval]

theorem scalar_congr (order : Int -> Int) (left right : Heap Int) (clauses : List (Clause Int))
    (same : forall clause, Membership.mem clauses clause ->
      left clause.source = right clause.source /\ left clause.target = right clause.target) :
    ScalarHolds order left clauses <-> ScalarHolds order right clauses := by
  induction clauses with
  | nil => rfl
  | cons clause rest ih =>
    have here := same clause (by simp)
    exact and_congr (by rw [here.1, here.2])
      (ih (fun later member => same later (List.mem_cons_of_mem clause member)))

theorem finite_heap_at (assignment : Assignment) (countBase scalarBase : Nat)
    (trace : List (Event InputInt)) (index : Nat) (bound : index <= writeCount trace) :
    QueueReadback.heap (QueueEncoding.values (size := writeCount trace) assignment countBase)
        (windows assignment scalarBase) index =
      rawHeap assignment countBase scalarBase index := by
  exact QueueReadback.heap_at _ _ (Fin.mk index (Nat.lt_succ_of_le bound))

theorem scalar_block_correct (assignment : Assignment) (countBase scalarBase : Nat)
    (trace : List (Event InputInt)) :
    SmtScript.Holds assignment (scalarBlock countBase scalarBase trace) <->
      ScalarHolds (order assignment scalarBase)
        (QueueReadback.heap (QueueEncoding.values (size := writeCount trace) assignment countBase)
          (windows assignment scalarBase))
        (QueueClause.compile 0 1 (evalTrace assignment trace)) := by
  rw [scalar_block_correct_total]
  apply scalar_congr
  intro clause member
  have bounds := QueuePlan.compile_bounds (evalTrace assignment trace) 0 clause member
  simp only [Nat.zero_add, write_count_eval] at bounds
  exact And.intro (finite_heap_at assignment countBase scalarBase trace clause.source bounds.1).symm
    (finite_heap_at assignment countBase scalarBase trace clause.target bounds.2).symm

theorem initial_correct (assignment : Assignment) (scalarBase : Nat) (length : InputInt) :
    SmtScript.Holds assignment (initialBlock scalarBase length) <->
      0 <= length.eval assignment /\
        windows assignment scalarBase 0 = { head := 0, tail := length.eval assignment } := by
  simp [initialBlock, SmtScript.Holds, Term.eval, headRef, tailRef, windows,
    InputInt.eval, SignedWindow.mk.injEq]

def Semantics (assignment : Assignment) (countBase : Nat) (length : InputInt)
    (trace : List (Event InputInt)) (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) : Prop :=
  0 <= length.eval assignment /\
    windowValues 0 = { head := 0, tail := length.eval assignment } /\
    ScalarHolds orderValues
      (QueueReadback.heap (QueueEncoding.values (size := writeCount trace) assignment countBase) windowValues)
      (QueueClause.compile 0 1 (evalTrace assignment trace))

theorem blocks_correct (assignment : Assignment) (countBase scalarBase : Nat)
    (length : InputInt) (trace : List (Event InputInt)) :
    SmtScript.Holds assignment (initialBlock scalarBase length ++ scalarBlock countBase scalarBase trace) <->
      Semantics assignment countBase length trace (windows assignment scalarBase) (order assignment scalarBase) := by
  rw [QueueEncoding.holds_append, initial_correct, scalar_block_correct]
  exact and_assoc

def scalarBase (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) : Nat :=
  max (QueueEncoding.freshBase (QueueEncoding.encode input keys trace observations))
    (QueueEncoding.freshBase input + writeCount trace + 1)

def nextBase (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) : Nat :=
  scalarBase input keys trace observations + 3

theorem count_range_before_scalar (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) :
    QueueEncoding.freshBase input + writeCount trace + 1 <= scalarBase input keys trace observations :=
  Nat.le_max_right _ _

theorem scalar_symbol_fresh (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (slot : Nat) :
    Not (Membership.mem (SmtScript.symbols (QueueEncoding.encode input keys trace observations))
      (.unary .int .int (scalarBase input keys trace observations + slot))) := by
  intro member
  have bound := QueueEncoding.input_symbol_bound _ _ member
  have lower : QueueEncoding.freshBase (QueueEncoding.encode input keys trace observations) <=
      scalarBase input keys trace observations := Nat.le_max_left _ _
  change scalarBase input keys trace observations + slot <
    QueueEncoding.freshBase (QueueEncoding.encode input keys trace observations) at bound
  omega

def encode (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace))
    (length : InputInt) : SmtScript.Formula :=
  QueueEncoding.encode input keys trace observations ++
    (initialBlock (scalarBase input keys trace observations) length ++
      scalarBlock (QueueEncoding.freshBase input) (scalarBase input keys trace observations) trace)

def render (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace))
    (length : InputInt) : String :=
  SmtScript.render (encode input keys trace observations length)

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (length : InputInt) :
    SmtScript.Holds assignment (encode input keys trace observations length) <->
      SmtScript.Holds assignment input /\
      QueueEncoding.CountSemantics assignment keys trace observations
        (QueueEncoding.values assignment (QueueEncoding.freshBase input)) /\
      Semantics assignment (QueueEncoding.freshBase input) length trace
        (windows assignment (scalarBase input keys trace observations))
        (order assignment (scalarBase input keys trace observations)) := by
  rw [encode, QueueEncoding.holds_append, QueueEncoding.encode_correct, blocks_correct]
  exact and_assoc

def scalarFunctions (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    Fin 3 -> Int -> Int :=
  fun slot argument =>
    if slot.val = 0 then (windowValues argument.toNat).head
    else if slot.val = 1 then (windowValues argument.toNat).tail
    else orderValues argument

def installScalars (original : Assignment) (base : Nat)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) : Assignment :=
  QueueEncoding.installCounts original base (scalarFunctions windowValues orderValues)

@[simp] theorem install_windows (original : Assignment) (base : Nat)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    windows (installScalars original base windowValues orderValues) base = windowValues := by
  have head_rule : (installScalars original base windowValues orderValues).unary .int .int base =
      (fun argument => (windowValues argument.toNat).head) := by
    simpa [installScalars, scalarFunctions] using
      QueueEncoding.install_at original base (scalarFunctions windowValues orderValues) (0 : Fin 3)
  have tail_rule : (installScalars original base windowValues orderValues).unary .int .int (base + 1) =
      (fun argument => (windowValues argument.toNat).tail) := by
    simpa [installScalars, scalarFunctions] using
      QueueEncoding.install_at original base (scalarFunctions windowValues orderValues) (1 : Fin 3)
  funext index
  simp [windows, head_rule, tail_rule]

@[simp] theorem install_order (original : Assignment) (base : Nat)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    order (installScalars original base windowValues orderValues) base = orderValues := by
  simpa [order, installScalars, scalarFunctions] using
    QueueEncoding.install_at original base (scalarFunctions windowValues orderValues) (2 : Fin 3)

theorem install_outside (original : Assignment) (base : Nat)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int)
    (domain result : Smt.Ty) (id : Nat) (outside : id < base \/ base + 3 <= id) :
    (installScalars original base windowValues orderValues).unary domain result id =
      original.unary domain result id :=
  QueueEncoding.install_outside original base (scalarFunctions windowValues orderValues)
    domain result id outside

theorem install_count_values (original : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace))
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    QueueEncoding.values (size := writeCount trace)
        (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
        (QueueEncoding.freshBase input) =
      QueueEncoding.values original (QueueEncoding.freshBase input) := by
  funext version
  have before := count_range_before_scalar input keys trace observations
  have bound := version.isLt
  exact install_outside original (scalarBase input keys trace observations) windowValues orderValues
    .int .int (QueueEncoding.freshBase input + version.val) (Or.inl (by omega))

theorem eval_trace_install (original : Assignment) (base : Nat)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) (trace : List (Event InputInt)) :
    evalTrace (installScalars original base windowValues orderValues) trace = evalTrace original trace := by
  unfold evalTrace
  congr 1
  funext event
  cases event <;> simp [evalEvent, installScalars]

theorem count_block_preserved (original : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace))
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    SmtScript.Holds
        (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
        (QueueEncoding.encode input keys trace observations) <->
      SmtScript.Holds original (QueueEncoding.encode input keys trace observations) := by
  have preserved (term : Term .bool)
      (present : Membership.mem (QueueEncoding.encode input keys trace observations) term) :
      term.eval (installScalars original (scalarBase input keys trace observations) windowValues orderValues) =
        term.eval original := by
    apply QueueEncoding.eval_install
    intro symbol member
    have declared := (SmtScript.symbol_coverage (QueueEncoding.encode input keys trace observations) symbol).mpr
      (Exists.intro term (And.intro present (by simpa only [SmtScript.lower_symbols] using member)))
    have bound := QueueEncoding.input_symbol_bound _ symbol declared
    exact Nat.lt_of_lt_of_le bound (Nat.le_max_left _ _)
  constructor
  next =>
    intro holds term present
    rw [Eq.symm (preserved term present)]
    exact holds term present
  next =>
    intro holds term present
    rw [preserved term present]
    exact holds term present

theorem semantics_install (original : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (length : InputInt)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int) :
    Semantics (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
      (QueueEncoding.freshBase input) length trace
      (windows (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
        (scalarBase input keys trace observations))
      (order (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
        (scalarBase input keys trace observations)) <->
    Semantics original (QueueEncoding.freshBase input) length trace windowValues orderValues := by
  have length_eq : length.eval
      (installScalars original (scalarBase input keys trace observations) windowValues orderValues) =
      length.eval original :=
    QueueEncoding.input_install original _ (scalarFunctions windowValues orderValues) length
  simp only [Semantics, length_eq, install_windows, install_order, install_count_values, eval_trace_install]

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (length : InputInt)
    (windowValues : Nat -> SignedWindow) (orderValues : Int -> Int)
    (counts_hold : SmtScript.Holds original (QueueEncoding.encode input keys trace observations))
    (semantics : Semantics original (QueueEncoding.freshBase input) length trace windowValues orderValues) :
    SmtScript.Holds
      (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
      (encode input keys trace observations length) := by
  rw [encode, QueueEncoding.holds_append, blocks_correct]
  exact And.intro
    ((count_block_preserved original input keys trace observations windowValues orderValues).mpr counts_hold)
    ((semantics_install original input keys trace observations length windowValues orderValues).mpr semantics)

theorem encode_exists_iff (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (length : InputInt) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input keys trace observations length)) <->
    (exists original : Assignment,
      SmtScript.Holds original (QueueEncoding.encode input keys trace observations) /\
      exists windowValues : Nat -> SignedWindow, exists orderValues : Int -> Int,
        Semantics original (QueueEncoding.freshBase input) length trace windowValues orderValues) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      rw [encode, QueueEncoding.holds_append, blocks_correct] at holds
      exact Exists.intro assignment (And.intro holds.1
        (Exists.intro (windows assignment (scalarBase input keys trace observations))
        (Exists.intro (order assignment (scalarBase input keys trace observations)) holds.2)))
  next =>
    intro witness
    cases witness with
    | intro original spec =>
      cases spec.2 with
      | intro windowValues witness =>
        cases witness with
        | intro orderValues semantics =>
          exact Exists.intro
            (installScalars original (scalarBase input keys trace observations) windowValues orderValues)
            (install_satisfies original input keys trace observations length windowValues orderValues
              spec.1 semantics)

theorem commands_correct (assignment : Assignment) (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (QueueEncoding.Observation trace)) (length : InputInt) :
    SmtScript.run assignment (SmtScript.compile (encode input keys trace observations length)) = some true <->
      SmtScript.Holds assignment input /\
      QueueEncoding.CountSemantics assignment keys trace observations
        (QueueEncoding.values assignment (QueueEncoding.freshBase input)) /\
      Semantics assignment (QueueEncoding.freshBase input) length trace
        (windows assignment (scalarBase input keys trace observations))
        (order assignment (scalarBase input keys trace observations)) :=
  (SmtScript.formula_holds_iff assignment (encode input keys trace observations length)).symm.trans
    (encode_correct assignment input keys trace observations length)

theorem nonpositive_pop_rejected (assignment : Assignment) (countBase scalarBase source target : Nat)
    (key : InputInt)
    (nonpositive : assignment.unary .int .int (countBase + source) (key.eval assignment) <= 0) :
    (guardTerm countBase scalarBase { event := .pop key, source := source, target := target }).eval assignment =
      false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  have selected := (guard_correct assignment countBase scalarBase _).mp accepted
  have positive := selected.2.2
  change 0 < assignment.unary .int .int (countBase + source) (key.eval assignment) at positive
  exact (not_lt_of_ge nonpositive) positive

theorem empty_peek_rejected (assignment : Assignment) (countBase scalarBase source target : Nat)
    (key : InputInt)
    (empty : (windows assignment scalarBase source).tail <= (windows assignment scalarBase source).head) :
    (guardTerm countBase scalarBase { event := .peek key, source := source, target := target }).eval assignment =
      false := by
  apply Bool.eq_false_iff.mpr
  intro accepted
  have selected := (guard_correct assignment countBase scalarBase _).mp accepted
  have present : (windows assignment scalarBase source).head < (windows assignment scalarBase source).tail :=
    selected.1
  omega

theorem repeated_peeks_agree (assignment : Assignment) (countBase scalarBase source : Nat)
    (left right : InputInt)
    (first : (guardTerm countBase scalarBase
      { event := .peek left, source := source, target := source }).eval assignment = true)
    (second : (guardTerm countBase scalarBase
      { event := .peek right, source := source, target := source }).eval assignment = true) :
    left.eval assignment = right.eval assignment := by
  have selected_left := (guard_correct assignment countBase scalarBase _).mp first
  have selected_right := (guard_correct assignment countBase scalarBase _).mp second
  exact selected_left.2.symm.trans selected_right.2

def regressionWindows (index : Nat) : SignedWindow :=
  { head := if index = 3 then 1 else 0, tail := if index = 0 then 0 else 1 }

def regressionAssignment : Assignment :=
  installScalars
    (QueueEncoding.installCounts QueueEncoding.regressionInput (QueueEncoding.freshBase [])
      QueueEncoding.regressionCounts)
    (scalarBase [] [.literal (-2)] QueueEncoding.regressionTrace QueueEncoding.regressionObservations)
    regressionWindows (fun _ => -2)

theorem combined_unknown_length_regression :
    SmtScript.run regressionAssignment
      (SmtScript.compile
        (encode [] [.literal (-2)] QueueEncoding.regressionTrace QueueEncoding.regressionObservations
          (.symbolic 7))) = some true := by
  apply (SmtScript.formula_holds_iff _ _).mp
  apply install_satisfies
  next => exact (SmtScript.formula_holds_iff _ _).mpr QueueEncoding.duplicate_send_regression
  next =>
    simp [Semantics, evalTrace, evalEvent, QueueEncoding.regressionTrace, QueueEncoding.regressionCounts,
      QueueEncoding.regressionInput, InputInt.eval, InputInt.term, Term.eval, regressionWindows,
      ScalarHolds, scalarFields, QueueReadback.heap, writeCount, QueueClause.compile, QueueClause.writes,
      QueueClause.guard, QueueClause.advance, SignedWindow.append, SignedWindow.pop]
    simp [QueueEncoding.installCounts]

end CCFRaft.Sparse.QueueScalarEncoding

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueScalarEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueScalarEncoding: allowed-axiom gate passed."
