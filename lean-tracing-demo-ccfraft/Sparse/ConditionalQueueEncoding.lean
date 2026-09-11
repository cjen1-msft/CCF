import Sparse.QueueInitialEncoding
import Sparse.ConditionalQueueAccounting

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueEncoding

open Smt (Assignment Term Symbol Ty)
open QueueEncoding (InputInt)
open QueueStream (Event)
open QueueClause (Clause Cursor)
open SignedQueue (SignedWindow)

def guardBase (input guards : SmtScript.Formula) : Nat :=
  QueueEncoding.freshBase (input ++ guards)

def countBase (input guards : SmtScript.Formula) : Nat := guardBase input guards + 1

def scalarBase (input guards : SmtScript.Formula) (size : Nat) : Nat :=
  countBase input guards + size + 1

def nextBase (input guards : SmtScript.Formula) (size : Nat) : Nat :=
  scalarBase input guards size + 3

def guardValue (base eventIndex : Nat) : Term .int :=
  .app .int .int base (.integer (eventIndex : Int))

def guardRef (base eventIndex : Nat) : Term .bool :=
  .equal (guardValue base eventIndex) (.integer 1)

def guardEquation (base : Nat) (guards : SmtScript.Formula)
    (eventIndex : Fin guards.length) : Term .bool :=
  .equal (guardValue base eventIndex.val)
    (.ite guards[eventIndex.val] (.integer 1) (.integer 0))

def guardBindings (base : Nat) (guards : SmtScript.Formula) : SmtScript.Formula :=
  List.ofFn (guardEquation base guards)

theorem bindings_correct (assignment : Assignment) (base : Nat) (guards : SmtScript.Formula) :
    SmtScript.Holds assignment (guardBindings base guards) <->
      forall index : Fin guards.length,
        (guardValue base index.val).eval assignment =
          if guards[index.val].eval assignment then (1 : Int) else 0 := by
  rw [guardBindings, QueueInitialEncoding.ofFn_holds]
  apply forall_congr'
  intro index
  simp [guardEquation, Term.eval]

theorem bound_guard_ref (assignment : Assignment) (base : Nat) (guards : SmtScript.Formula)
    (bindings : SmtScript.Holds assignment (guardBindings base guards)) (index : Fin guards.length) :
    (guardRef base index.val).eval assignment = guards[index.val].eval assignment := by
  have value := (bindings_correct assignment base guards).mp bindings index
  simp only [guardRef, Term.eval, value]
  cases guards[index.val].eval assignment <;> rfl

def guardFunction (original : Assignment) (guards : SmtScript.Formula) (argument : Int) : Int :=
  if within : 0 <= argument /\ argument < (guards.length : Int) then
    if guards[argument.toNat]'(by omega) |>.eval original then 1 else 0
  else 0

theorem guard_function_at (original : Assignment) (guards : SmtScript.Formula)
    (index : Fin guards.length) :
    guardFunction original guards (index.val : Int) =
      if guards[index.val].eval original then (1 : Int) else 0 := by
  have within : 0 <= (index.val : Int) /\ (index.val : Int) < (guards.length : Int) := by
    have bound := index.isLt
    omega
  simp [guardFunction, within]

def installGuards (original : Assignment) (input guards : SmtScript.Formula) : Assignment :=
  QueueEncoding.installCounts (size := 0) original (guardBase input guards)
    (fun _ => guardFunction original guards)

def install {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow)
    (order : Int -> Int) : Assignment :=
  QueueScalarEncoding.installScalars
    (QueueEncoding.installCounts (installGuards original input guards) (countBase input guards) counts)
    (scalarBase input guards size) windows order

theorem install_constants {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    (install original input guards counts windows order).constant = original.constant := rfl

theorem install_below {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (domain result : Ty) (id : Nat) (below : id < guardBase input guards) :
    (install original input guards counts windows order).unary domain result id =
      original.unary domain result id := by
  have before_count : id < countBase input guards := by unfold countBase; omega
  have before_scalar : id < scalarBase input guards size := by unfold scalarBase; omega
  unfold install
  rw [QueueScalarEncoding.install_outside _ _ _ _ domain result id (Or.inl before_scalar),
    QueueEncoding.install_outside _ _ _ domain result id (Or.inl before_count)]
  exact QueueEncoding.install_outside original _ _ domain result id (Or.inl below)

theorem install_external {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (domain result : Ty) (id : Nat)
    (member : Membership.mem (SmtScript.symbols (input ++ guards)) (.unary domain result id)) :
    (install original input guards counts windows order).unary domain result id =
      original.unary domain result id :=
  install_below original input guards counts windows order domain result id
    (QueueEncoding.input_symbol_bound (input ++ guards) _ member)

theorem reserved_eval {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (base : Nat) (values : Fin (size + 1) -> Int -> Int) (after_source : guardBase input guards <= base)
    (term : Term .bool) (member : Membership.mem (input ++ guards) term) :
    term.eval (QueueEncoding.installCounts original base values) = term.eval original := by
  apply QueueEncoding.eval_install
  intro symbol present
  apply Nat.lt_of_lt_of_le _ after_source
  apply QueueEncoding.input_symbol_bound (input ++ guards)
  apply (SmtScript.symbol_coverage (input ++ guards) symbol).mpr
  exact Exists.intro term (And.intro member
    (by simpa only [SmtScript.lower_symbols] using present))

theorem install_source_term {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (term : Term .bool) (member : Membership.mem (input ++ guards) term) :
    term.eval (install original input guards counts windows order) = term.eval original := by
  have count_after : guardBase input guards <= countBase input guards := by unfold countBase; omega
  have scalar_after : guardBase input guards <= scalarBase input guards size := by unfold scalarBase; omega
  unfold install QueueScalarEncoding.installScalars
  rw [reserved_eval _ input guards _ _ scalar_after term member,
    reserved_eval _ input guards _ _ count_after term member]
  exact reserved_eval original input guards _ _ (Nat.le_refl _) term member

theorem install_input {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    SmtScript.Holds (install original input guards counts windows order) input <->
      SmtScript.Holds original input := by
  unfold SmtScript.Holds
  apply forall_congr'
  intro term
  apply forall_congr'
  intro member
  rw [install_source_term original input guards counts windows order term (List.mem_append_left guards member)]

theorem install_guard_function {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    (install original input guards counts windows order).unary .int .int (guardBase input guards) =
      guardFunction original guards := by
  have before_count : guardBase input guards < countBase input guards := by unfold countBase; omega
  have before_scalar : guardBase input guards < scalarBase input guards size := by unfold scalarBase; omega
  unfold install
  rw [QueueScalarEncoding.install_outside _ _ _ _ .int .int _ (Or.inl before_scalar),
    QueueEncoding.install_outside _ _ _ .int .int _ (Or.inl before_count)]
  simpa only [installGuards, Nat.add_zero] using
    QueueEncoding.install_at original (guardBase input guards)
      (fun _ : Fin 1 => guardFunction original guards) 0

theorem install_guard_value {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (index : Fin guards.length) :
    (guardValue (guardBase input guards) index.val).eval (install original input guards counts windows order) =
      if guards[index.val].eval original then (1 : Int) else 0 := by
  simp only [guardValue, Term.eval, install_guard_function, guard_function_at]

theorem install_guard_ref {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (index : Fin guards.length) :
    (guardRef (guardBase input guards) index.val).eval (install original input guards counts windows order) =
      guards[index.val].eval original := by
  simp only [guardRef, Term.eval, install_guard_value]
  cases guards[index.val].eval original <;> rfl

theorem install_bindings {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    SmtScript.Holds (install original input guards counts windows order) (guardBindings (guardBase input guards) guards) := by
  apply (bindings_correct _ _ _).mpr
  intro index
  rw [install_guard_value, install_source_term original input guards counts windows order _]
  exact List.mem_append_right input (List.getElem_mem index.isLt)

theorem install_counts {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (index : Fin (size + 1)) :
    (install original input guards counts windows order).unary .int .int (countBase input guards + index.val) =
      counts index := by
  have below : countBase input guards + index.val < scalarBase input guards size := by
    have bound := index.isLt
    unfold scalarBase
    omega
  unfold install
  rw [QueueScalarEncoding.install_outside _ _ _ _ .int .int _ (Or.inl below),
    QueueEncoding.install_at]

theorem install_windows {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    QueueScalarEncoding.windows (install original input guards counts windows order)
      (scalarBase input guards size) = windows :=
  QueueScalarEncoding.install_windows _ _ windows order

theorem install_order {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    QueueScalarEncoding.order (install original input guards counts windows order)
      (scalarBase input guards size) = order :=
  QueueScalarEncoding.install_order _ _ windows order

theorem install_heap {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (index : Fin (size + 1)) :
    QueueScalarEncoding.rawHeap (install original input guards counts windows order)
      (countBase input guards) (scalarBase input guards size) index.val =
        { counts := counts index, window := windows index.val } := by
  simp only [QueueScalarEncoding.rawHeap, install_counts, install_windows]

theorem install_after {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (domain result : Ty) (id : Nat) (after_range : nextBase input guards size <= id) :
    (install original input guards counts windows order).unary domain result id =
      original.unary domain result id := by
  have after_scalar : scalarBase input guards size + 3 <= id := after_range
  have after_count : countBase input guards + size + 1 <= id := by
    unfold nextBase scalarBase at after_range
    omega
  have after_guard : guardBase input guards + 1 <= id := by
    unfold scalarBase countBase at after_count
    omega
  unfold install
  rw [QueueScalarEncoding.install_outside _ _ _ _ domain result id (Or.inr after_scalar),
    QueueEncoding.install_outside _ _ _ domain result id (Or.inr after_count)]
  exact QueueEncoding.install_outside original _ _ domain result id (Or.inr after_guard)

theorem installed_header_correct {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    SmtScript.Holds (install original input guards counts windows order)
      (input ++ guardBindings (guardBase input guards) guards) <-> SmtScript.Holds original input := by
  rw [QueueEncoding.holds_append, install_input]
  simp only [install_bindings, and_true]

def clauseFor (source : Nat) (event : Event InputInt) : Clause InputInt :=
  { event, source, target := if QueueClause.writes event then source + 1 else source }

def activeCount (base source : Nat) (event : Event InputInt) (key : InputInt) : Term .bool :=
  match event with
  | .send message =>
    QueueEncoding.readEquationFrom (fun _ : Fin 1 => QueuePlan.StoreOp.send message)
      (base + source) (1, key)
  | .pop message =>
    QueueEncoding.readEquationFrom (fun _ : Fin 1 => QueuePlan.StoreOp.pop message)
      (base + source) (1, key)
  | .peek _ | .length _ => .equal (QueueEncoding.readRef base source key) (QueueEncoding.readRef base source key)

def countEquation (guardsBase countsBase eventIndex source : Nat)
    (event : Event InputInt) (key : InputInt) : Term .bool :=
  .ite (guardRef guardsBase eventIndex) (activeCount countsBase source event key)
    (.equal (QueueEncoding.readRef countsBase (clauseFor source event).target key)
      (QueueEncoding.readRef countsBase source key))

def identityFields (base : Nat) (clause : Clause InputInt) : Term .bool :=
  .and (.equal (QueueScalarEncoding.headRef base clause.target) (QueueScalarEncoding.headRef base clause.source))
    (.equal (QueueScalarEncoding.tailRef base clause.target) (QueueScalarEncoding.tailRef base clause.source))

def scalarFormula (guardsBase countsBase fieldsBase eventIndex source : Nat)
    (event : Event InputInt) : SmtScript.Formula :=
  let clause := clauseFor source event
  [.implies (guardRef guardsBase eventIndex) (QueueScalarEncoding.guardTerm countsBase fieldsBase clause),
   .ite (guardRef guardsBase eventIndex) (QueueScalarEncoding.fieldsTerm countsBase fieldsBase clause)
     (identityFields fieldsBase clause)]

def clauseFormula (guardsBase countsBase fieldsBase eventIndex source : Nat)
    (event : Event InputInt) (keys : List InputInt) : SmtScript.Formula :=
  keys.map (countEquation guardsBase countsBase eventIndex source event) ++
    scalarFormula guardsBase countsBase fieldsBase eventIndex source event

theorem active_count_correct (assignment : Assignment) (countsBase fieldsBase source : Nat)
    (event : Event InputInt) (key : InputInt) :
    (activeCount countsBase source event key).eval assignment = true <->
      (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase (clauseFor source event).target).counts
        (key.eval assignment) =
      (QueueClause.advance (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase source)
        (QueueScalarEncoding.evalEvent assignment event)).counts (key.eval assignment) := by
  cases event with
  | send message =>
    change (QueueEncoding.readEquation [.send message] (countsBase + source)
      ((0 : Fin 1).succ, key)).eval assignment = true <-> _
    rw [QueueEncoding.read_successor]
    by_cases zero : assignment.unary .int .int (countsBase + source) (message.eval assignment) = 0 <;>
      by_cases same : key.eval assignment = message.eval assignment <;>
      simp [QueueEncoding.values, QueuePlan.operation, QueuePlan.operations, QueuePlan.StoreOp.key,
        QueuePlan.StoreOp.event, QueueReadback.storeValue, QueueScalarEncoding.rawHeap,
        QueueClause.advance, QueueScalarEncoding.evalEvent, clauseFor, QueueClause.writes,
        QueueReadback.writeCount, zero, same, Nat.add_assoc]
  | pop message =>
    change (QueueEncoding.readEquation [.pop message] (countsBase + source)
      ((0 : Fin 1).succ, key)).eval assignment = true <-> _
    rw [QueueEncoding.read_successor]
    by_cases same : key.eval assignment = message.eval assignment <;>
      simp [QueueEncoding.values, QueuePlan.operation, QueuePlan.operations, QueuePlan.StoreOp.key,
        QueuePlan.StoreOp.event, QueueReadback.storeValue, QueueScalarEncoding.rawHeap,
        QueueClause.advance, QueueScalarEncoding.evalEvent, clauseFor, QueueClause.writes,
        QueueReadback.writeCount, same, Nat.add_assoc]
  | peek message =>
    simp [activeCount, Term.eval, clauseFor, QueueClause.writes, QueueClause.advance,
      QueueScalarEncoding.evalEvent]
  | length length =>
    simp [activeCount, Term.eval, clauseFor, QueueClause.writes, QueueClause.advance,
      QueueScalarEncoding.evalEvent]

theorem count_equation_correct (assignment : Assignment)
    (guardsBase countsBase fieldsBase eventIndex source : Nat) (event : Event InputInt) (key : InputInt) :
    (countEquation guardsBase countsBase eventIndex source event key).eval assignment = true <->
      (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase (clauseFor source event).target).counts
        (key.eval assignment) =
      (if (guardRef guardsBase eventIndex).eval assignment then
        QueueClause.advance (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase source)
          (QueueScalarEncoding.evalEvent assignment event)
       else QueueScalarEncoding.rawHeap assignment countsBase fieldsBase source).counts (key.eval assignment) := by
  cases flag : (guardRef guardsBase eventIndex).eval assignment <;>
    simp [countEquation, Term.eval, flag, active_count_correct assignment countsBase fieldsBase,
      QueueEncoding.readRef, QueueScalarEncoding.rawHeap, InputInt.eval]

theorem identity_fields_correct (assignment : Assignment) (base : Nat) (clause : Clause InputInt) :
    (identityFields base clause).eval assignment = true <->
      (QueueScalarEncoding.windows assignment base clause.target).head =
        (QueueScalarEncoding.windows assignment base clause.source).head /\
      (QueueScalarEncoding.windows assignment base clause.target).tail =
        (QueueScalarEncoding.windows assignment base clause.source).tail := by
  simp [identityFields, QueueScalarEncoding.headRef, QueueScalarEncoding.tailRef,
    QueueScalarEncoding.windows, Term.eval]

theorem scalar_formula_correct (assignment : Assignment)
    (guardsBase countsBase fieldsBase eventIndex source : Nat) (event : Event InputInt) :
    SmtScript.Holds assignment (scalarFormula guardsBase countsBase fieldsBase eventIndex source event) <->
      if (guardRef guardsBase eventIndex).eval assignment then
        QueueClause.guard (QueueScalarEncoding.order assignment fieldsBase)
          (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase source)
          (QueueScalarEncoding.evalEvent assignment event) /\
        QueueReadback.scalarFields (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase source)
          (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase (clauseFor source event).target)
          (QueueScalarEncoding.evalEvent assignment event)
      else
        (QueueScalarEncoding.windows assignment fieldsBase (clauseFor source event).target).head =
          (QueueScalarEncoding.windows assignment fieldsBase source).head /\
        (QueueScalarEncoding.windows assignment fieldsBase (clauseFor source event).target).tail =
          (QueueScalarEncoding.windows assignment fieldsBase source).tail := by
  cases flag : (guardRef guardsBase eventIndex).eval assignment with
  | false =>
    simp [scalarFormula, SmtScript.Holds, Term.eval, flag]
    exact identity_fields_correct assignment fieldsBase (clauseFor source event)
  | true =>
    simp [scalarFormula, SmtScript.Holds, Term.eval, flag]
    exact and_congr
      (QueueScalarEncoding.guard_correct assignment countsBase fieldsBase (clauseFor source event))
      (QueueScalarEncoding.fields_correct assignment countsBase fieldsBase (clauseFor source event))

def ClauseFacts (inputs generated : Assignment) (active : Bool)
    (countsBase fieldsBase source : Nat) (event : Event InputInt) (keys : List InputInt) : Prop :=
  let before := QueueScalarEncoding.rawHeap generated countsBase fieldsBase source
  let after := QueueScalarEncoding.rawHeap generated countsBase fieldsBase (clauseFor source event).target
  let interpreted := QueueScalarEncoding.evalEvent inputs event
  (forall key, Membership.mem keys key ->
    after.counts (key.eval inputs) =
      (if active then QueueClause.advance before interpreted else before).counts (key.eval inputs)) /\
  (if active then
    QueueClause.guard (QueueScalarEncoding.order generated fieldsBase) before interpreted /\
      QueueReadback.scalarFields before after interpreted
  else after.window.head = before.window.head /\ after.window.tail = before.window.tail)

theorem clause_correct (assignment : Assignment) (guardsBase countsBase fieldsBase eventIndex source : Nat)
    (event : Event InputInt) (keys : List InputInt) :
    SmtScript.Holds assignment (clauseFormula guardsBase countsBase fieldsBase eventIndex source event keys) <->
      ClauseFacts assignment assignment ((guardRef guardsBase eventIndex).eval assignment)
        countsBase fieldsBase source event keys := by
  rw [clauseFormula, QueueEncoding.holds_append, scalar_formula_correct]
  apply and_congr _ Iff.rfl
  constructor
  next =>
    intro holds key member
    exact (count_equation_correct assignment guardsBase countsBase fieldsBase eventIndex source event key).mp
      (holds _ (List.mem_map.mpr (Exists.intro key (And.intro member rfl))))
  next =>
    intro correct term member
    cases List.mem_map.mp member with
    | intro key spec =>
      rw [Eq.symm spec.2]
      exact (count_equation_correct assignment guardsBase countsBase fieldsBase eventIndex source event key).mpr
        (correct key spec.1)

theorem bound_clause_correct (assignment : Assignment) (guardsBase countsBase fieldsBase source : Nat)
    (guards : SmtScript.Formula) (eventIndex : Fin guards.length)
    (event : Event InputInt) (keys : List InputInt) :
    SmtScript.Holds assignment (guardBindings guardsBase guards ++
      clauseFormula guardsBase countsBase fieldsBase eventIndex.val source event keys) <->
      SmtScript.Holds assignment (guardBindings guardsBase guards) /\
        ClauseFacts assignment assignment (guards[eventIndex.val].eval assignment)
          countsBase fieldsBase source event keys := by
  rw [QueueEncoding.holds_append, clause_correct]
  apply and_congr_right
  intro bindings
  rw [bound_guard_ref assignment guardsBase guards bindings eventIndex]

theorem install_key {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (key : InputInt) :
    key.eval (install original input guards counts windows order) = key.eval original := by
  cases key <;> rfl

theorem install_event {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (event : Event InputInt) :
    QueueScalarEncoding.evalEvent (install original input guards counts windows order) event =
      QueueScalarEncoding.evalEvent original event := by
  cases event <;> simp [QueueScalarEncoding.evalEvent, install_key]

theorem installed_clause_correct {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (eventIndex : Fin guards.length) (source : Nat) (event : Event InputInt) (keys : List InputInt) :
    SmtScript.Holds (install original input guards counts windows order)
      (clauseFormula (guardBase input guards) (countBase input guards) (scalarBase input guards size)
        eventIndex.val source event keys) <->
      ClauseFacts original (install original input guards counts windows order)
        (guards[eventIndex.val].eval original) (countBase input guards) (scalarBase input guards size)
        source event keys := by
  rw [clause_correct]
  simp only [ClauseFacts, install_guard_ref, install_event, install_key]

theorem installed_unit_correct {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (eventIndex : Fin guards.length) (source : Nat) (event : Event InputInt) (keys : List InputInt) :
    SmtScript.Holds (install original input guards counts windows order)
      ((input ++ guardBindings (guardBase input guards) guards) ++
        clauseFormula (guardBase input guards) (countBase input guards) (scalarBase input guards size)
          eventIndex.val source event keys) <->
      SmtScript.Holds original input /\
        ClauseFacts original (install original input guards counts windows order)
          (guards[eventIndex.val].eval original) (countBase input guards) (scalarBase input guards size)
          source event keys := by
  rw [QueueEncoding.holds_append, installed_header_correct, installed_clause_correct]

theorem allocated_clause_correct {size : Nat} (original : Assignment) (input guards : SmtScript.Formula)
    (counts : Fin (size + 1) -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (eventIndex : Fin guards.length) (source : Fin (size + 1))
    (event : Event InputInt) (keys : List InputInt)
    (target_bound : (clauseFor source.val event).target < size + 1) :
    let before : Cursor Int := { counts := counts source, window := windows source.val }
    let after : Cursor Int :=
      { counts := counts (Fin.mk (clauseFor source.val event).target target_bound)
        window := windows (clauseFor source.val event).target }
    let active := guards[eventIndex.val].eval original
    let interpreted := QueueScalarEncoding.evalEvent original event
    SmtScript.Holds (install original input guards counts windows order)
      ((input ++ guardBindings (guardBase input guards) guards) ++
        clauseFormula (guardBase input guards) (countBase input guards) (scalarBase input guards size)
          eventIndex.val source.val event keys) <->
      SmtScript.Holds original input /\
        (forall key, Membership.mem keys key ->
          after.counts (key.eval original) =
            (if active then QueueClause.advance before interpreted else before).counts (key.eval original)) /\
        (if active then QueueClause.guard order before interpreted /\
          QueueReadback.scalarFields before after interpreted
         else after.window.head = before.window.head /\ after.window.tail = before.window.tail) := by
  dsimp only
  rw [installed_unit_correct]
  simp only [ClauseFacts, install_order,
    install_heap original input guards counts windows order source,
    install_heap original input guards counts windows order
      (Fin.mk (clauseFor source.val event).target target_bound)]

namespace Regression

def original : Assignment where
  constant := QueueEncoding.regressionInput.constant
  unary domain result id :=
    match domain, result with
    | .int, .int => fun _ => if id = 1 then 1 else 0
    | domain, result => QueueEncoding.regressionInput.unary domain result id

def ufGuard : Term .bool := .equal (.app .int .int 1 (.integer 0)) (.integer 1)

def guards : SmtScript.Formula := [.boolean false, ufGuard]

def zeroCounts : Fin 2 -> Int -> Int := fun _ _ => 0

def emptyWindows : Nat -> SignedWindow := fun _ => { head := 0, tail := 0 }

def model (counts : Fin 2 -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int) :
    Assignment := install original [] guards counts windows order

def check (counts : Fin 2 -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (eventIndex : Fin 2) (event : Event InputInt) (keys : List InputInt) : Bool :=
  (clauseFormula (guardBase [] guards) (countBase [] guards) (scalarBase [] guards 1)
    eventIndex.val 0 event keys).all (fun term => term.eval (model counts windows order))

theorem check_correct (counts : Fin 2 -> Int -> Int) (windows : Nat -> SignedWindow) (order : Int -> Int)
    (eventIndex : Fin 2) (event : Event InputInt) (keys : List InputInt) :
    check counts windows order eventIndex event keys = true <->
      SmtScript.Holds (model counts windows order)
        (clauseFormula (guardBase [] guards) (countBase [] guards) (scalarBase [] guards 1)
          eventIndex.val 0 event keys) := by
  simp [check, SmtScript.Holds, List.all_eq_true]

theorem false_guard_bound :
    (guardBindings (guardBase [] guards) guards).all
      (fun term => term.eval (model zeroCounts emptyWindows (fun _ => 77))) = true /\
    (guardRef (guardBase [] guards) 0).eval (model zeroCounts emptyWindows (fun _ => 77)) = false /\
    (guardRef (guardBase [] guards) 1).eval (model zeroCounts emptyWindows (fun _ => 77)) = true := by decide

theorem guard_only_uf_collision :
    ufGuard.eval original = true /\
    ufGuard.eval (QueueEncoding.installCounts (size := 0) original (QueueEncoding.freshBase [])
      (fun _ _ => 0)) = false /\
    ufGuard.eval (model zeroCounts emptyWindows (fun _ => 77)) = true := by decide

theorem guard_uf_preserved_as_function :
    (model zeroCounts emptyWindows (fun _ => 77)).unary .int .int 1 = original.unary .int .int 1 := by
  apply install_below
  decide

def nativeGuard : Term .bool :=
  .equal (.app .nodes .entry 11 (.nodes 0)) (.entry (.integer 0) .signature)

theorem native_source_function_preserved :
    (install original [] [nativeGuard] zeroCounts emptyWindows (fun _ => 0)).unary .nodes .entry 11 =
      original.unary .nodes .entry 11 := by
  apply install_below
  decide

theorem inactive_events :
    ([Event.send (.literal 0), .pop (.literal 0), .peek (.literal 0), .length 99]).all
      (fun event => check zeroCounts emptyWindows (fun _ => 77) 0 event [.literal 0]) = true := by decide

theorem active_send :
    check (fun index key => if index.val = 1 /\ key = 0 then 1 else 0)
      (fun index => { head := 0, tail := index }) (fun _ => 0)
      1 (.send (.literal 0)) [.literal 0, .literal 1] = true := by decide

theorem duplicate_send :
    check (fun _ key => if key = 0 then 2 else 0)
      (fun _ => { head := 0, tail := 2 }) (fun _ => 77)
      1 (.send (.literal 0)) [.literal 0, .literal 1] = true := by decide

theorem active_pop_alias :
    check (fun index key => if key = 0 then 2 - (index.val : Int) else 0)
      (fun index => { head := index, tail := 2 }) (fun _ => 0)
      1 (.pop (.literal 0)) [.literal 0, .symbolic 7, .literal 1] = true := by decide

theorem active_readonly :
    check zeroCounts (fun _ => { head := 0, tail := 2 }) (fun _ => 0)
      1 (.peek (.literal 0)) [.literal 0] = true /\
    check zeroCounts (fun _ => { head := 0, tail := 2 }) (fun _ => 0)
      1 (.length 2) [.literal 0] = true := by decide

theorem nonpositive_pop_rejected :
    check (fun index key => if key = 0 then -(index.val : Int) else 0)
      (fun index => { head := index, tail := 1 }) (fun _ => 0)
      1 (.pop (.literal 0)) [.literal 0] = false := by decide

theorem empty_peek_rejected :
    check zeroCounts emptyWindows (fun _ => 0) 1 (.peek (.literal 0)) [.literal 0] = false := by decide

theorem wrong_length_rejected :
    check zeroCounts emptyWindows (fun _ => 0) 1 (.length 1) [] = false := by decide

def changedOutside (index : Fin 2) (key : Int) : Int :=
  if index.val = 1 /\ key = 99 then 7 else 0

theorem untracked_counts_unrestricted :
    check changedOutside emptyWindows (fun _ => 77) 0 (.send (.literal 0)) [.literal 0] = true /\
      Not (changedOutside 0 = changedOutside 1) := by
  refine And.intro (by decide) ?_
  intro same
  have at_untracked := congrFun same 99
  norm_num [changedOutside] at at_untracked

end Regression

abbrev Entry := Prod (Term .bool) (Event InputInt)

structure Row where
  eventIndex : Nat
  source : Nat
  entry : Entry

def Row.clause (row : Row) : Clause InputInt := clauseFor row.source row.entry.2

def annotate (eventIndex source : Nat) : List Entry -> List Row
  | [] => []
  | entry :: rest =>
    { eventIndex, source, entry } ::
      annotate (eventIndex + 1) (clauseFor source entry.2).target rest

theorem annotate_length (eventIndex source : Nat) (entries : List Entry) :
    (annotate eventIndex source entries).length = entries.length := by
  induction entries generalizing eventIndex source with
  | nil => rfl
  | cons entry rest ih => simp [annotate, ih]

theorem annotate_entries (eventIndex source : Nat) (entries : List Entry) :
    (annotate eventIndex source entries).map Row.entry = entries := by
  induction entries generalizing eventIndex source with
  | nil => rfl
  | cons entry rest ih => simp [annotate, ih]

theorem annotate_clauses (eventIndex source : Nat) (entries : List Entry) :
    (annotate eventIndex source entries).map Row.clause =
      QueueClause.compile source (source + 1) (entries.map Prod.snd) := by
  induction entries generalizing eventIndex source with
  | nil => rfl
  | cons entry rest ih =>
    cases entry with
    | mk guard event =>
      cases event <;> simp [annotate, Row.clause, clauseFor, QueueClause.compile, QueueClause.writes, ih]

theorem annotate_at (eventIndex source : Nat) (entries : List Entry) (index : Fin entries.length) :
    let row := (annotate eventIndex source entries)[index.val]'(by rw [annotate_length]; exact index.isLt)
    row.eventIndex = eventIndex + index.val /\ row.entry = entries[index.val] := by
  induction entries generalizing eventIndex source with
  | nil => exact Fin.elim0 index
  | cons entry rest ih =>
    cases index using Fin.cases with
    | zero => simp [annotate]
    | succ index =>
      simpa [annotate, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using
        ih (eventIndex + 1) (clauseFor source entry.2).target index

theorem row_index (entries : List Entry) (row : Row) (member : Membership.mem (annotate 0 0 entries) row) :
    exists index : Fin entries.length, row.eventIndex = index.val /\ row.entry = entries[index.val] := by
  cases List.mem_iff_getElem.mp member with
  | intro index witness =>
    cases witness with
    | intro bound selected =>
      have inside : index < entries.length := by simpa [annotate_length] using bound
      refine Exists.intro (Fin.mk index inside) ?_
      have at_index := annotate_at 0 0 entries (Fin.mk index inside)
      simpa only [Nat.zero_add, selected] using at_index

def writeRows (entries : List Entry) : List Row :=
  (annotate 0 0 entries).filter (fun row => QueueClause.writes row.entry.2)

theorem write_rows_clauses (entries : List Entry) :
    (writeRows entries).map Row.clause =
      (QueuePlan.operations (entries.map Prod.snd)).mapIdx (QueuePlan.writeClause 0) := by
  have filtered :
      ((annotate 0 0 entries).filter (fun row => QueueClause.writes row.entry.2)).map Row.clause =
        ((annotate 0 0 entries).map Row.clause).filter (fun clause => QueueClause.writes clause.event) := by
    simp only [List.filter_map, Function.comp_def, Row.clause, clauseFor]
  rw [writeRows, filtered, annotate_clauses, QueuePlan.compile_writes]

theorem write_rows_length (entries : List Entry) :
    (writeRows entries).length = QueueReadback.writeCount (entries.map Prod.snd) := by
  have length := congrArg List.length (write_rows_clauses entries)
  simpa [QueuePlan.operations_length] using length

theorem write_row_at (entries : List Entry) (index : Fin (writeRows entries).length) :
    let row := (writeRows entries)[index.val]
    row.source = index.val /\ row.clause.target = index.val + 1 /\
      row.entry.2 = (QueuePlan.operation (entries.map Prod.snd)
        (Fin.mk index.val (by rw [Eq.symm (write_rows_length entries)]; exact index.isLt))).event := by
  have equal := congrArg (fun rows => rows[index.val]?) (write_rows_clauses entries)
  have operation_bound : index.val < (QueuePlan.operations (entries.map Prod.snd)).length := by
    simp [QueuePlan.operations_length, Eq.symm (write_rows_length entries)]
  simp only [List.getElem?_map, List.getElem?_eq_getElem index.isLt,
    List.getElem?_mapIdx, List.getElem?_eq_getElem operation_bound, Option.map_some,
    Option.some.injEq] at equal
  have source := congrArg Clause.source equal
  have target := congrArg Clause.target equal
  have event := congrArg Clause.event equal
  exact And.intro (by simpa [Row.clause, clauseFor, QueuePlan.writeClause] using source)
    (And.intro (by simpa [QueuePlan.writeClause] using target)
      (by simpa [Row.clause, clauseFor, QueuePlan.writeClause, QueuePlan.operation] using event))

theorem write_operation_table (entries : List Entry) (index : Fin (writeRows entries).length) :
    ((writeRows entries)[index.val]).entry.2 =
      ((QueueEncoding.operationArray (entries.map Prod.snd))[index.val]'(by
        rw [QueueEncoding.operation_array_size, Eq.symm (write_rows_length entries)]
        exact index.isLt)).event := by
  rw [QueueEncoding.operation_array_lookup (entries.map Prod.snd)
    (Fin.mk index.val (by rw [Eq.symm (write_rows_length entries)]; exact index.isLt))]
  exact (write_row_at entries index).2.2

def keysOf (entries : List Entry) : List InputInt := QueueInitialEncoding.eventKeys (entries.map Prod.snd)

def countGrid (guardsBase countsBase : Nat) (entries : List Entry) : SmtScript.Formula :=
  let keys := keysOf entries
  (writeRows entries).flatMap fun row =>
    keys.map (countEquation guardsBase countsBase row.eventIndex row.source row.entry.2)

theorem count_grid_length (guardsBase countsBase : Nat) (entries : List Entry) :
    (countGrid guardsBase countsBase entries).length =
      QueueReadback.writeCount (entries.map Prod.snd) * (keysOf entries).length := by
  rw [Eq.symm (write_rows_length entries)]
  unfold countGrid
  generalize writeRows entries = rows
  induction rows with
  | nil => simp
  | cons row rest ih => simp [ih, Nat.add_mul, Nat.add_comm]

def scalarRows (guardsBase countsBase fieldsBase : Nat) (entries : List Entry) : SmtScript.Formula :=
  (annotate 0 0 entries).flatMap fun row =>
    scalarFormula guardsBase countsBase fieldsBase row.eventIndex row.source row.entry.2

def traceBlock (guardsBase countsBase fieldsBase : Nat) (entries : List Entry) : SmtScript.Formula :=
  guardBindings guardsBase (entries.map Prod.fst) ++
    (countGrid guardsBase countsBase entries ++ scalarRows guardsBase countsBase fieldsBase entries)

theorem holds_flatMap (assignment : Assignment) {T : Type} (items : List T)
    (formulas : T -> SmtScript.Formula) :
    SmtScript.Holds assignment (items.flatMap formulas) <->
      forall item, Membership.mem items item -> SmtScript.Holds assignment (formulas item) := by
  constructor
  next =>
    intro holds item member term present
    exact holds term (List.mem_flatMap.mpr (Exists.intro item (And.intro member present)))
  next =>
    intro holds term member
    cases List.mem_flatMap.mp member with
    | intro item spec => exact holds item spec.1 term spec.2

theorem readonly_count (assignment : Assignment) (guardsBase countsBase eventIndex source : Nat)
    (event : Event InputInt) (readonly : QueueClause.writes event = false) (key : InputInt) :
    (countEquation guardsBase countsBase eventIndex source event key).eval assignment = true := by
  cases event <;> simp_all [QueueClause.writes, countEquation, clauseFor, activeCount, Term.eval]

theorem trace_block_facts (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) (holds : SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries))
    (row : Row) (member : Membership.mem (annotate 0 0 entries) row) :
    ClauseFacts assignment assignment (row.entry.1.eval assignment)
      countsBase fieldsBase row.source row.entry.2 (keysOf entries) := by
  have blocks := (QueueEncoding.holds_append _ _ _).mp holds
  have components := (QueueEncoding.holds_append _ _ _).mp blocks.2
  have scalar := (holds_flatMap _ _ _).mp components.2 row member
  have counts : SmtScript.Holds assignment
      ((keysOf entries).map (countEquation guardsBase countsBase row.eventIndex row.source row.entry.2)) := by
    by_cases writing : QueueClause.writes row.entry.2 = true
    next =>
      exact (holds_flatMap _ _ _).mp components.1 row (List.mem_filter.mpr (And.intro member writing))
    next =>
      intro term present
      cases List.mem_map.mp present with
      | intro key spec =>
        rw [Eq.symm spec.2]
        exact readonly_count assignment guardsBase countsBase row.eventIndex row.source row.entry.2
          (by cases flag : QueueClause.writes row.entry.2 <;> simp_all) key
  have fact := (clause_correct assignment guardsBase countsBase fieldsBase row.eventIndex row.source
    row.entry.2 (keysOf entries)).mp ((QueueEncoding.holds_append _ _ _).mpr (And.intro counts scalar))
  cases row_index entries row member with
  | intro index spec =>
    have bound := bound_guard_ref assignment guardsBase (entries.map Prod.fst) blocks.1
      (Fin.mk index.val (by simpa only [List.length_map] using index.isLt))
    simp only [List.getElem_map] at bound
    rw [spec.1, bound] at fact
    simpa only [spec.2] using fact

theorem trace_block_correct (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) :
    SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries) <->
      SmtScript.Holds assignment (guardBindings guardsBase (entries.map Prod.fst)) /\
        forall row, Membership.mem (annotate 0 0 entries) row ->
          ClauseFacts assignment assignment (row.entry.1.eval assignment)
            countsBase fieldsBase row.source row.entry.2 (keysOf entries) := by
  constructor
  next =>
    intro holds
    exact And.intro ((QueueEncoding.holds_append _ _ _).mp holds).1
      (trace_block_facts assignment guardsBase countsBase fieldsBase entries holds)
  next =>
    intro spec
    have each : forall row, Membership.mem (annotate 0 0 entries) row ->
        SmtScript.Holds assignment
          (clauseFormula guardsBase countsBase fieldsBase row.eventIndex row.source row.entry.2 (keysOf entries)) := by
      intro row member
      rw [clause_correct]
      cases row_index entries row member with
      | intro index ids =>
        have guard := bound_guard_ref assignment guardsBase (entries.map Prod.fst) spec.1
          (Fin.mk index.val (by simpa only [List.length_map] using index.isLt))
        rw [ids.1, guard]
        simpa only [List.getElem_map, ids.2] using spec.2 row member
    apply (QueueEncoding.holds_append _ _ _).mpr
    refine And.intro spec.1 ((QueueEncoding.holds_append _ _ _).mpr (And.intro ?_ ?_))
    next =>
      apply (holds_flatMap _ _ _).mpr
      intro row member
      exact ((QueueEncoding.holds_append _ _ _).mp (each row (List.mem_filter.mp member).1)).1
    next =>
      apply (holds_flatMap _ _ _).mpr
      intro row member
      exact ((QueueEncoding.holds_append _ _ _).mp (each row member)).2

def countStep (counts : Int -> Int) (event : Event Int) : Int -> Int :=
  (QueueClause.advance { counts, window := { head := 0, tail := 0 } } event).counts

theorem advance_counts (cursor : Cursor Int) (event : Event Int) :
    (QueueClause.advance cursor event).counts = countStep cursor.counts event := by
  cases event with
  | send key => by_cases zero : cursor.counts key = 0 <;> simp [countStep, QueueClause.advance, zero]
  | pop key => rfl
  | peek key => rfl
  | length length => rfl

theorem advance_counts_agree (assignment : Assignment) (keys : List InputInt)
    (left right : Cursor Int) (event : Event InputInt)
    (used : CountedQueue.Uses keys.toFinset [event])
    (agree : forall key, Membership.mem keys key -> left.counts (key.eval assignment) = right.counts (key.eval assignment))
    (query : InputInt) (member : Membership.mem keys query) :
    (QueueClause.advance left (QueueScalarEncoding.evalEvent assignment event)).counts (query.eval assignment) =
      (QueueClause.advance right (QueueScalarEncoding.evalEvent assignment event)).counts (query.eval assignment) := by
  cases event with
  | send key =>
    have same := agree key (List.mem_toFinset.mp used.1)
    by_cases zero : right.counts (key.eval assignment) = 0 <;>
      simp [QueueScalarEncoding.evalEvent, QueueClause.advance, same, zero, Function.update_apply, agree query member]
  | pop key =>
    have same := agree key (List.mem_toFinset.mp used.1)
    simp [QueueScalarEncoding.evalEvent, QueueClause.advance, Function.update_apply, same, agree query member]
  | peek key => exact agree query member
  | length length => exact agree query member

theorem guard_windows_agree (assignment : Assignment) (keys : List InputInt)
    (order : Int -> Int) (left right : Cursor Int) (event : Event InputInt)
    (used : CountedQueue.Uses keys.toFinset [event]) (window : left.window = right.window)
    (agree : forall key, Membership.mem keys key -> left.counts (key.eval assignment) = right.counts (key.eval assignment)) :
    (QueueClause.guard order left (QueueScalarEncoding.evalEvent assignment event) <->
      QueueClause.guard order right (QueueScalarEncoding.evalEvent assignment event)) /\
    (QueueClause.advance left (QueueScalarEncoding.evalEvent assignment event)).window =
      (QueueClause.advance right (QueueScalarEncoding.evalEvent assignment event)).window := by
  cases event with
  | send key =>
    have same := agree key (List.mem_toFinset.mp used.1)
    by_cases zero : right.counts (key.eval assignment) = 0 <;>
      simp [QueueScalarEncoding.evalEvent, QueueClause.guard, QueueClause.advance, same, zero, window]
  | pop key =>
    have same := agree key (List.mem_toFinset.mp used.1)
    simp [QueueScalarEncoding.evalEvent, QueueClause.guard, QueueClause.advance, same, window]
  | peek key => simp [QueueScalarEncoding.evalEvent, QueueClause.guard, QueueClause.advance, window]
  | length length => simp [QueueScalarEncoding.evalEvent, QueueClause.guard, QueueClause.advance, window]

theorem row_covered (entries : List Entry) (row : Row) (member : Membership.mem (annotate 0 0 entries) row) :
    CountedQueue.Uses (keysOf entries).toFinset [row.entry.2] := by
  have entry_member : Membership.mem entries row.entry := by
    rw [Eq.symm (annotate_entries 0 0 entries)]
    exact List.mem_map.mpr (Exists.intro row (And.intro member rfl))
  have event_member : Membership.mem (entries.map Prod.snd) row.entry.2 :=
    List.mem_map.mpr (Exists.intro row.entry (And.intro entry_member rfl))
  cases event : row.entry.2 with
  | send key | pop key | peek key =>
    have tracked : Membership.mem (keysOf entries) key := by
      rw [keysOf, QueueInitialEncoding.event_keys_mem]
      simp only [event] at event_member
      tauto
    simp [CountedQueue.Uses, tracked]
  | length length => simp [CountedQueue.Uses]

-- A semantic total family. Emitted equations never expand this recursion.
def canonicalFamily (assignment : Assignment) (root : Int -> Int) (rows : List Row) : Nat -> Int -> Int
  | 0 => root
  | index + 1 =>
    let prior := canonicalFamily assignment root rows index
    match rows[index]? with
    | none => prior
    | some row =>
      if row.entry.1.eval assignment then countStep prior (QueueScalarEncoding.evalEvent assignment row.entry.2)
      else prior

theorem canonical_step (assignment : Assignment) (root : Int -> Int) (rows : List Row)
    (index : Fin rows.length) :
    canonicalFamily assignment root rows (index.val + 1) =
      if rows[index.val].entry.1.eval assignment then
        countStep (canonicalFamily assignment root rows index.val)
          (QueueScalarEncoding.evalEvent assignment rows[index.val].entry.2)
      else canonicalFamily assignment root rows index.val := by
  simp only [canonicalFamily, List.getElem?_eq_getElem index.isLt]

theorem canonical_row_step (assignment : Assignment) (root : Int -> Int)
    (entries : List Entry) (row : Row) (member : Membership.mem (annotate 0 0 entries) row) :
    canonicalFamily assignment root (writeRows entries) row.clause.target =
      if row.entry.1.eval assignment then
        countStep (canonicalFamily assignment root (writeRows entries) row.source)
          (QueueScalarEncoding.evalEvent assignment row.entry.2)
      else canonicalFamily assignment root (writeRows entries) row.source := by
  by_cases writing : QueueClause.writes row.entry.2 = true
  next =>
    have present : Membership.mem (writeRows entries) row := List.mem_filter.mpr (And.intro member writing)
    cases List.mem_iff_getElem.mp present with
    | intro index witness =>
      cases witness with
      | intro bound selected =>
        have ids := write_row_at entries (Fin.mk index bound)
        have step := canonical_step assignment root (writeRows entries) (Fin.mk index bound)
        simp only [selected] at ids step
        rw [ids.1, ids.2.1]
        exact step
  next =>
    cases event : row.entry.2 <;>
      simp_all [QueueClause.writes, Row.clause, clauseFor, countStep,
        QueueScalarEncoding.evalEvent, QueueClause.advance]

theorem canonical_agrees (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) (holds : SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries))
    (version : Nat) (bound : version <= (writeRows entries).length)
    (key : InputInt) (tracked : Membership.mem (keysOf entries) key) :
    canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version
      (key.eval assignment) =
        assignment.unary .int .int (countsBase + version) (key.eval assignment) := by
  induction version generalizing key with
  | zero => simp [canonicalFamily]
  | succ version ih =>
    have inside : version < (writeRows entries).length := by omega
    let index : Fin (writeRows entries).length := Fin.mk version inside
    let row := (writeRows entries)[version]
    have member : Membership.mem (annotate 0 0 entries) row :=
      (List.mem_filter.mp (List.getElem_mem inside)).1
    have ids := write_row_at entries index
    change row.source = version /\ row.clause.target = version + 1 /\ _ at ids
    have facts := trace_block_facts assignment guardsBase countsBase fieldsBase entries holds row member
    have agreement :
        forall query, Membership.mem (keysOf entries) query ->
          (canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version)
              (query.eval assignment) =
            assignment.unary .int .int (countsBase + version) (query.eval assignment) := by
      intro query present
      exact ih (by omega) query present
    have transfer := advance_counts_agree assignment (keysOf entries)
      { counts := canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version
        window := { head := 0, tail := 0 } }
      (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase row.source) row.entry.2
      (row_covered entries row member) (by simpa [QueueScalarEncoding.rawHeap, ids.1] using agreement) key tracked
    have equation := facts.1 key tracked
    have target : (clauseFor row.source row.entry.2).target = version + 1 := ids.2.1
    simp only [target] at equation
    have step := canonical_step assignment (assignment.unary .int .int countsBase) (writeRows entries) index
    change canonicalFamily assignment _ _ (version + 1) = _ at step
    rw [step]
    change ((if row.entry.1.eval assignment then
      countStep (canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version)
        (QueueScalarEncoding.evalEvent assignment row.entry.2)
      else canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version) :
      Int -> Int) (key.eval assignment) = _
    cases active : row.entry.1.eval assignment with
    | false =>
      simp only [active, Bool.false_eq_true, ite_false] at equation
      simp only [Bool.false_eq_true, ite_false]
      rw [agreement key tracked]
      simpa [QueueScalarEncoding.rawHeap, ids.1] using equation.symm
    | true =>
      simp only [active, ite_true] at equation
      simp only [ite_true]
      unfold countStep
      rw [transfer]
      simpa [QueueScalarEncoding.rawHeap, ids.1] using equation.symm

theorem canonical_actual_agrees (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) (holds : SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries))
    (version : Nat) (bound : version <= (writeRows entries).length) (value : Int)
    (tracked : Membership.mem ((keysOf entries).map (InputInt.eval assignment)).toFinset value) :
    canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version value =
      assignment.unary .int .int (countsBase + version) value := by
  cases List.mem_map.mp (List.mem_toFinset.mp tracked) with
  | intro key spec =>
    rw [Eq.symm spec.2]
    exact canonical_agrees assignment guardsBase countsBase fieldsBase entries holds version bound key spec.1

theorem annotation_bounds (entries : List Entry) (row : Row)
    (member : Membership.mem (annotate 0 0 entries) row) :
    row.source <= (writeRows entries).length /\ row.clause.target <= (writeRows entries).length := by
  have compiled : Membership.mem (QueueClause.compile 0 1 (entries.map Prod.snd)) row.clause := by
    rw [Eq.symm (annotate_clauses 0 0 entries)]
    exact List.mem_map.mpr (Exists.intro row (And.intro member rfl))
  simpa [Row.clause, clauseFor, write_rows_length] using
    QueuePlan.compile_bounds (entries.map Prod.snd) 0 row.clause compiled

def coherentHeap (assignment : Assignment) (countsBase fieldsBase : Nat)
    (entries : List Entry) : QueueClause.Heap Int :=
  fun version =>
    { counts := canonicalFamily assignment (assignment.unary .int .int countsBase) (writeRows entries) version
      window := QueueScalarEncoding.windows assignment fieldsBase version }

def RowHolds (assignment : Assignment) (order : Int -> Int) (heap : QueueClause.Heap Int) (row : Row) : Prop :=
  if row.entry.1.eval assignment then
    QueueClause.guard order (heap row.source) (QueueScalarEncoding.evalEvent assignment row.entry.2) /\
      heap row.clause.target = QueueClause.advance (heap row.source) (QueueScalarEncoding.evalEvent assignment row.entry.2)
  else heap row.clause.target = heap row.source

theorem coherent_row (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) (holds : SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries))
    (row : Row) (member : Membership.mem (annotate 0 0 entries) row) :
    RowHolds assignment (QueueScalarEncoding.order assignment fieldsBase)
      (coherentHeap assignment countsBase fieldsBase entries) row := by
  have bounds := annotation_bounds entries row member
  have facts := trace_block_facts assignment guardsBase countsBase fieldsBase entries holds row member
  have agreement :
      forall key, Membership.mem (keysOf entries) key ->
        (coherentHeap assignment countsBase fieldsBase entries row.source).counts (key.eval assignment) =
          (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase row.source).counts (key.eval assignment) := by
    intro key tracked
    exact canonical_agrees assignment guardsBase countsBase fieldsBase entries holds row.source bounds.1 key tracked
  have transfer := guard_windows_agree assignment (keysOf entries) (QueueScalarEncoding.order assignment fieldsBase)
    (coherentHeap assignment countsBase fieldsBase entries row.source)
    (QueueScalarEncoding.rawHeap assignment countsBase fieldsBase row.source)
    row.entry.2 (row_covered entries row member) rfl agreement
  have counts := canonical_row_step assignment (assignment.unary .int .int countsBase) entries row member
  unfold RowHolds
  cases active : row.entry.1.eval assignment with
  | false =>
    simp only [ClauseFacts, active, Bool.false_eq_true, ite_false] at facts
    simp only [active, Bool.false_eq_true, ite_false] at counts
    simp only [Bool.false_eq_true, ite_false]
    apply (QueueClause.cursor_eq_iff _ _).mpr
    exact And.intro facts.2.1 (And.intro facts.2.2 counts)
  | true =>
    simp only [ClauseFacts, active, ite_true] at facts
    simp only [active, ite_true] at counts
    simp only [ite_true]
    refine And.intro (transfer.1.mpr facts.2.1) ?_
    apply (QueueClause.cursor_eq_iff _ _).mpr
    exact And.intro (facts.2.2.1.trans (congrArg SignedWindow.head transfer.2).symm)
      (And.intro (facts.2.2.2.trans (congrArg SignedWindow.tail transfer.2).symm)
        (counts.trans (advance_counts (coherentHeap assignment countsBase fieldsBase entries row.source)
          (QueueScalarEncoding.evalEvent assignment row.entry.2)).symm))

def evaluate (assignment : Assignment) (entries : List Entry) :
    List (ConditionalQueueAccounting.GuardedEvent Int) :=
  entries.map fun entry => (entry.1.eval assignment, QueueScalarEncoding.evalEvent assignment entry.2)

theorem annotated_replay (assignment : Assignment) (order : Int -> Int) (heap : QueueClause.Heap Int)
    (entries : List Entry) (eventIndex source : Nat)
    (holds : forall row, Membership.mem (annotate eventIndex source entries) row -> RowHolds assignment order heap row) :
    ConditionalQueueAccounting.replay order (heap source) (evaluate assignment entries) := by
  induction entries generalizing eventIndex source with
  | nil => trivial
  | cons entry rest ih =>
    have first := holds { eventIndex, source, entry } (by simp [annotate])
    have tail := ih (eventIndex + 1) (clauseFor source entry.2).target
      (fun row member => holds row (List.mem_cons_of_mem _ member))
    simp only [RowHolds, Row.clause] at first
    cases active : entry.1.eval assignment with
    | false =>
      simp only [active, Bool.false_eq_true, ite_false] at first
      simpa only [evaluate, List.map_cons, active, ConditionalQueueAccounting.replay, first] using tail
    | true =>
      simp only [active, ite_true] at first
      simp only [evaluate, List.map_cons, active, ConditionalQueueAccounting.replay]
      change QueueClause.guard order (heap source) (QueueScalarEncoding.evalEvent assignment entry.2) /\
        ConditionalQueueAccounting.replay order
          (QueueClause.advance (heap source) (QueueScalarEncoding.evalEvent assignment entry.2))
          (evaluate assignment rest)
      exact And.intro first.1 (by simpa only [first.2] using tail)

theorem trace_block_coherent_replay (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (entries : List Entry) (holds : SmtScript.Holds assignment (traceBlock guardsBase countsBase fieldsBase entries)) :
    (forall version, version <= QueueReadback.writeCount (entries.map Prod.snd) ->
      forall key, Membership.mem (keysOf entries) key ->
        (coherentHeap assignment countsBase fieldsBase entries version).counts (key.eval assignment) =
          assignment.unary .int .int (countsBase + version) (key.eval assignment)) /\
    ConditionalQueueAccounting.replay (QueueScalarEncoding.order assignment fieldsBase)
      { counts := assignment.unary .int .int countsBase
        window := QueueScalarEncoding.windows assignment fieldsBase 0 }
      (evaluate assignment entries) := by
  constructor
  next =>
    intro version bound key tracked
    exact canonical_agrees assignment guardsBase countsBase fieldsBase entries holds version
      (by simpa [write_rows_length] using bound) key tracked
  next =>
    have follows := annotated_replay assignment (QueueScalarEncoding.order assignment fieldsBase)
      (coherentHeap assignment countsBase fieldsBase entries) entries 0 0
      (coherent_row assignment guardsBase countsBase fieldsBase entries holds)
    simpa only [coherentHeap, canonicalFamily] using follows

theorem evaluate_installed {size : Nat} (original : Assignment) (input : SmtScript.Formula)
    (entries : List Entry) (counts : Fin (size + 1) -> Int -> Int)
    (windows : Nat -> SignedWindow) (order : Int -> Int) :
    evaluate (install original input (entries.map Prod.fst) counts windows order) entries =
      evaluate original entries := by
  unfold evaluate
  apply List.map_congr_left
  intro entry member
  rw [install_event, install_source_term original input (entries.map Prod.fst) counts windows order _]
  exact List.mem_append_right input (List.mem_map.mpr (Exists.intro entry (And.intro member rfl)))

theorem installed_trace_replay (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (counts : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) -> Int -> Int)
    (windows : Nat -> SignedWindow) (order : Int -> Int)
    (holds : SmtScript.Holds (install original input (entries.map Prod.fst) counts windows order)
      (input ++ traceBlock (guardBase input (entries.map Prod.fst)) (countBase input (entries.map Prod.fst))
        (scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))) entries)) :
    SmtScript.Holds original input /\
      ConditionalQueueAccounting.replay order { counts := counts 0, window := windows 0 } (evaluate original entries) := by
  have parts := (QueueEncoding.holds_append _ _ _).mp holds
  refine And.intro ((install_input _ _ _ _ _ _).mp parts.1) ?_
  have follows := (trace_block_coherent_replay _ _ _ _ entries parts.2).2
  have root :
      (install original input (entries.map Prod.fst) counts windows order).unary .int .int
        (countBase input (entries.map Prod.fst)) = counts 0 := by
    simpa only [Nat.add_zero] using install_counts original input (entries.map Prod.fst) counts windows order 0
  simpa only [root, install_order, install_windows, evaluate_installed] using follows

namespace ReplayRegression

def original (aliases : Bool) : Assignment where
  constant ty id :=
    match ty with
    | .int => if id = 1 && !aliases then 1 else 0
    | ty => Regression.original.constant ty id
  unary := Regression.original.unary

def entries (mask : Nat) : List Entry :=
  [(.boolean (mask.testBit 0), .send (.symbolic 0)),
   (.boolean (mask.testBit 1), .peek (.symbolic 0)),
   (.boolean (mask.testBit 2), .pop (.symbolic 1)),
   (.boolean (mask.testBit 3), .peek (.symbolic 0)),
   (.boolean (mask.testBit 4), .pop (.symbolic 0))]

theorem static_indices :
    (annotate 0 0 (entries 31)).map (fun row => (row.eventIndex, row.source, row.clause.target)) =
      [(0, 0, 1), (1, 1, 1), (2, 1, 2), (3, 2, 2), (4, 2, 3)] /\
    (writeRows (entries 31)).map Row.eventIndex = [0, 2, 4] := by decide

def initialCursor (queue : List Int) : Cursor Int :=
  { counts := fun key => queue.count key, window := { head := 0, tail := queue.length } }

def snapshots (assignment : Assignment) (queue : List Int) (items : List Entry) : List (Cursor Int) :=
  (writeRows items).scanl (fun cursor row =>
    if row.entry.1.eval assignment then QueueClause.advance cursor (QueueScalarEncoding.evalEvent assignment row.entry.2)
    else cursor) (initialCursor queue)

theorem snapshots_length (assignment : Assignment) (queue : List Int) (items : List Entry) :
    (snapshots assignment queue items).length = QueueReadback.writeCount (items.map Prod.snd) + 1 := by
  simp [snapshots, write_rows_length]

def orderFor (assignment : Assignment) (queue : List Int) (items : List Entry) : Int -> Int :=
  let state := items.foldl (fun state entry =>
    if entry.1.eval assignment then
      let event := QueueScalarEncoding.evalEvent assignment entry.2
      let cells := match event with
        | .send key => if state.1.counts key = 0 then state.2 ++ [key] else state.2
        | _ => state.2
      (QueueClause.advance state.1 event, cells)
    else state) (initialCursor queue, queue)
  fun position => if position < 0 then 99 else state.2[position.toNat]?.getD 99

def fixture (assignment : Assignment) (queue : List Int) (items : List Entry) : Assignment :=
  let states := snapshots assignment queue items
  let counts (index : Fin (QueueReadback.writeCount (items.map Prod.snd) + 1)) :=
    (states[index.val]'(by rw [snapshots_length]; exact index.isLt)).counts
  let windows := fun index => (states[index]?.getD (initialCursor queue)).window
  install assignment [] (items.map Prod.fst) counts windows (orderFor assignment queue items)

def guardDecision (order : Int -> Int) (cursor : Cursor Int) (event : Event Int) :
    Decidable (QueueClause.guard order cursor event) := by
  cases event <;> unfold QueueClause.guard <;> infer_instance

def replayDecision (order : Int -> Int) : (cursor : Cursor Int) ->
    (trace : List (ConditionalQueueAccounting.GuardedEvent Int)) ->
      Decidable (ConditionalQueueAccounting.replay order cursor trace)
  | _, [] => isTrue True.intro
  | cursor, (false, _) :: rest => replayDecision order cursor rest
  | cursor, (true, event) :: rest =>
    letI := guardDecision order cursor event
    letI := replayDecision order (QueueClause.advance cursor event) rest
    show Decidable (QueueClause.guard order cursor event /\
      ConditionalQueueAccounting.replay order (QueueClause.advance cursor event) rest) from inferInstance

def agrees (aliases : Bool) (queue : List Int) (mask : Nat) : Bool :=
  let assignment := original aliases
  let items := entries mask
  let actual := (traceBlock (guardBase [] (items.map Prod.fst)) (countBase [] (items.map Prod.fst))
    (scalarBase [] (items.map Prod.fst) (QueueReadback.writeCount (items.map Prod.snd))) items).all
      (fun term => term.eval (fixture assignment queue items))
  let expected := @decide
    (ConditionalQueueAccounting.replay (orderFor assignment queue items) (initialCursor queue) (evaluate assignment items))
    (replayDecision (orderFor assignment queue items) (initialCursor queue) (evaluate assignment items))
  actual == expected

theorem finite_oracle :
    [false, true].all (fun aliases =>
      ([[], [0], [0, 0], [1], [2]] : List (List Int)).all (fun queue =>
        (List.range 32).all (fun mask => agrees aliases queue mask))) = true := by decide +kernel

theorem inactive_write_identity :
    canonicalFamily (original true) (fun _ => 0) (writeRows (entries 27)) 2 =
      canonicalFamily (original true) (fun _ => 0) (writeRows (entries 27)) 1 := by
  funext key
  rfl

def offGridEntries : List Entry := [(.boolean false, .send (.literal 0))]

def offGridModel : Assignment :=
  install Regression.original [] (offGridEntries.map Prod.fst) Regression.changedOutside
    Regression.emptyWindows (fun _ => 77)

theorem off_grid_raw_disagreement :
    (traceBlock (guardBase [] (offGridEntries.map Prod.fst))
      (countBase [] (offGridEntries.map Prod.fst)) (scalarBase [] (offGridEntries.map Prod.fst) 1)
      offGridEntries).all (fun term => term.eval offGridModel) = true /\
    offGridModel.unary .int .int (countBase [] (offGridEntries.map Prod.fst)) 99 = 0 /\
    offGridModel.unary .int .int (countBase [] (offGridEntries.map Prod.fst) + 1) 99 = 7 /\
    canonicalFamily offGridModel (offGridModel.unary .int .int (countBase [] (offGridEntries.map Prod.fst)))
      (writeRows offGridEntries) 1 99 = 0 := by decide

end ReplayRegression

end CCFRaft.Sparse.ConditionalQueueEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if name.toString.startsWith "CCFRaft.Sparse.ConditionalQueueEncoding." then
      for axiomName in (<- Lean.collectAxioms name) do
        unless [``propext, ``Classical.choice, ``Quot.sound].contains axiomName do
          throwError "disallowed axiom {axiomName} in {name}"
      checked := checked + 1
  Lean.logInfo m!"ConditionalQueueEncoding: {checked} declarations passed the transitive axiom gate"
