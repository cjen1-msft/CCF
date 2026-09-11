import Sparse.QueueInitialEncoding

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
