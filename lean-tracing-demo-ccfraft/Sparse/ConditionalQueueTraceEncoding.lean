import Sparse.ConditionalQueueEncoding
import Sparse.QueueTraceEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueTraceEncoding

open Smt (Assignment Term Ty)
open QueueEncoding (InputInt)
open QueueClause (Cursor Heap)
open SignedQueue (SignedWindow)
open QueueStream (Event)
open ConditionalQueueEncoding (Row)

abbrev Entry := ConditionalQueueEncoding.Entry

def summaryStep (assignment : Assignment) (length : Int) (state : ConditionalQueueAccounting.Summary Int)
    (entry : Entry) : ConditionalQueueAccounting.Summary Int :=
  if entry.1.eval assignment then
    ConditionalQueueAccounting.advanceRead length state (QueueScalarEncoding.evalEvent assignment entry.2)
  else state

theorem summarize_fold (assignment : Assignment) (length : Int) (entries : List Entry) :
    entries.foldl (summaryStep assignment length) ConditionalQueueAccounting.initial =
      ConditionalQueueAccounting.summarize length (ConditionalQueueEncoding.evaluate assignment entries) := by
  simp only [ConditionalQueueAccounting.summarize, ConditionalQueueEncoding.evaluate, List.foldl_map]
  rfl

def isPop (row : Row) : Bool :=
  match row.entry.2 with | .pop _ => true | _ => false

def popRows (entries : List Entry) : List Row := (ConditionalQueueEncoding.annotate 0 0 entries).filter isPop

def histogramStep (assignment : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (row : Row) (histogram : Int -> Int) : Int -> Int :=
  match row.entry.2 with
  | .pop key => fun query => histogram query +
      if row.entry.1.eval assignment = true /\ (windows row.source).head < length /\
        query = key.eval assignment then 1 else 0
  | _ => histogram

def histogram (assignment : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (rows : List Row) (index : Nat) : Int -> Int :=
  (rows.take index).foldl (fun values row => histogramStep assignment length windows row values) (fun _ => 0)

theorem histogram_step (assignment : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (rows : List Row) (index : Nat) (bound : index < rows.length) :
    histogram assignment length windows rows (index + 1) =
      histogramStep assignment length windows rows[index] (histogram assignment length windows rows index) := by
  unfold histogram
  rw [QueueInitialEncoding.take_step rows index bound, List.foldl_append]
  rfl

theorem histogram_filter (assignment : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (rows : List Row) (start : Int -> Int) :
    (rows.filter isPop).foldl (fun values row => histogramStep assignment length windows row values) start =
      rows.foldl (fun values row => histogramStep assignment length windows row values) start := by
  induction rows generalizing start with
  | nil => rfl
  | cons row rest ih =>
    cases event : row.entry.2 <;>
      simp only [List.filter_cons, isPop, event, ite_true,
        Bool.false_eq_true, ite_false, List.foldl_cons]
    all_goals rw [ih]
    all_goals simp only [histogramStep, event]

def pendingStep (assignment : Assignment) (value : Int) (entry : Entry) : Int :=
  if entry.1.eval assignment then
    match entry.2 with | .pop _ => 0 | .peek _ => 1 | _ => value
  else value

def pending (assignment : Assignment) (entries : List Entry) (index : Nat) : Int :=
  (entries.take index).foldl (pendingStep assignment) 0

theorem pending_step (assignment : Assignment) (entries : List Entry) (index : Nat)
    (bound : index < entries.length) :
    pending assignment entries (index + 1) =
      pendingStep assignment (pending assignment entries index) entries[index] := by
  unfold pending
  rw [QueueInitialEncoding.take_step entries index bound, List.foldl_append]
  rfl

theorem pending_fold (assignment : Assignment) (length : Int) (entries : List Entry)
    (state : ConditionalQueueAccounting.Summary Int) :
    entries.foldl (pendingStep assignment) (if state.pending then 1 else 0) =
      if (entries.foldl (summaryStep assignment length) state).pending then 1 else 0 := by
  induction entries generalizing state with
  | nil => rfl
  | cons entry rest ih =>
    simp only [List.foldl_cons]
    have step : pendingStep assignment (if state.pending then 1 else 0) entry =
        if (summaryStep assignment length state entry).pending then 1 else 0 := by
      cases active : entry.1.eval assignment <;> cases event : entry.2 <;>
        simp [pendingStep, summaryStep, ConditionalQueueAccounting.advanceRead, QueueScalarEncoding.evalEvent, active, event]
    rw [step, ih]

theorem pending_final (assignment : Assignment) (length : Int) (entries : List Entry) :
    pending assignment entries entries.length =
      if (ConditionalQueueAccounting.summarize length (ConditionalQueueEncoding.evaluate assignment entries)).pending then 1 else 0 := by
  simp only [pending, List.take_length]
  rw [Eq.symm (summarize_fold assignment length entries)]
  exact pending_fold assignment length entries ConditionalQueueAccounting.initial

theorem histogram_step_summary (assignment : Assignment) (length : Int) (heap : Heap Int)
    (row : Row) (state : ConditionalQueueAccounting.Summary Int)
    (head : (heap row.source).window.head = (state.head : Int)) :
    histogramStep assignment length (fun index => (heap index).window) row state.histogram =
      (summaryStep assignment length state row.entry).histogram := by
  funext query
  cases event : row.entry.2 with
  | send key | peek key | length observed =>
    cases active : row.entry.1.eval assignment <;>
      simp [histogramStep, summaryStep, event, active, ConditionalQueueAccounting.advanceRead, QueueScalarEncoding.evalEvent]
  | pop key =>
    cases active : row.entry.1.eval assignment <;>
      by_cases within : (state.head : Int) < length <;>
      by_cases same : query = key.eval assignment <;>
      simp [histogramStep, summaryStep, event, active, head, ConditionalQueueAccounting.advanceRead,
        QueueScalarEncoding.evalEvent, within, same]

theorem next_summary_head (assignment : Assignment) (length : Int) (order : Int -> Int)
    (heap : Heap Int) (row : Row) (state : ConditionalQueueAccounting.Summary Int)
    (head : (heap row.source).window.head = (state.head : Int))
    (holds : ConditionalQueueEncoding.RowHolds assignment order heap row) :
    (heap row.clause.target).window.head = ((summaryStep assignment length state row.entry).head : Int) := by
  cases active : row.entry.1.eval assignment with
  | false =>
    simp only [ConditionalQueueEncoding.RowHolds, active, Bool.false_eq_true, ite_false] at holds
    simpa [summaryStep, active, holds] using head
  | true =>
    simp only [ConditionalQueueEncoding.RowHolds, active, ite_true] at holds
    rw [holds.2]
    cases event : row.entry.2 with
    | send key =>
      by_cases zero : (heap row.source).counts (key.eval assignment) = 0 <;>
        simp [summaryStep, active, event, ConditionalQueueAccounting.advanceRead, QueueScalarEncoding.evalEvent,
          QueueClause.advance, zero, SignedWindow.append, head]
    | pop key =>
      simp [summaryStep, active, event, ConditionalQueueAccounting.advanceRead, QueueScalarEncoding.evalEvent,
        QueueClause.advance, SignedWindow.pop, head]
    | peek key | length observed =>
      simp [summaryStep, active, event, ConditionalQueueAccounting.advanceRead, QueueScalarEncoding.evalEvent,
        QueueClause.advance, head]

theorem histogram_rows_summary (assignment : Assignment) (length : Int) (order : Int -> Int)
    (heap : Heap Int) (entries : List Entry) (eventIndex source : Nat) (state : ConditionalQueueAccounting.Summary Int)
    (head : (heap source).window.head = (state.head : Int))
    (holds : forall row, Membership.mem (ConditionalQueueEncoding.annotate eventIndex source entries) row ->
      ConditionalQueueEncoding.RowHolds assignment order heap row) :
    (ConditionalQueueEncoding.annotate eventIndex source entries).foldl
      (fun values row => histogramStep assignment length (fun index => (heap index).window) row values)
      state.histogram = (entries.foldl (summaryStep assignment length) state).histogram := by
  induction entries generalizing eventIndex source state with
  | nil => rfl
  | cons entry rest ih =>
    let row : Row := { eventIndex, source, entry }
    have first := holds row (by simp [ConditionalQueueEncoding.annotate, row])
    have next_head := next_summary_head assignment length order heap row state head first
    simp only [ConditionalQueueEncoding.annotate, List.foldl_cons]
    rw [histogram_step_summary assignment length heap row state head]
    exact ih (eventIndex + 1) (ConditionalQueueEncoding.clauseFor source entry.2).target
      (summaryStep assignment length state entry) next_head
      (fun later member => holds later (List.mem_cons_of_mem _ member))

theorem histogram_final (assignment : Assignment) (length : Int) (order : Int -> Int)
    (heap : Heap Int) (entries : List Entry) (head : (heap 0).window.head = 0)
    (holds : forall row, Membership.mem (ConditionalQueueEncoding.annotate 0 0 entries) row ->
      ConditionalQueueEncoding.RowHolds assignment order heap row) :
    histogram assignment length (fun index => (heap index).window) (popRows entries) (popRows entries).length =
      (ConditionalQueueAccounting.summarize length (ConditionalQueueEncoding.evaluate assignment entries)).histogram := by
  simp only [histogram, List.take_length, popRows]
  rw [histogram_filter]
  exact (histogram_rows_summary assignment length order heap entries 0 0 ConditionalQueueAccounting.initial head holds).trans
    (congrArg ConditionalQueueAccounting.Summary.histogram (summarize_fold assignment length entries))

theorem annotated_final (assignment : Assignment) (order : Int -> Int) (heap : Heap Int)
    (entries : List Entry) (eventIndex source : Nat)
    (holds : forall row, Membership.mem (ConditionalQueueEncoding.annotate eventIndex source entries) row ->
      ConditionalQueueEncoding.RowHolds assignment order heap row) :
    heap (source + QueueReadback.writeCount (entries.map Prod.snd)) =
      ConditionalQueueAccounting.cursorAfter (heap source) (ConditionalQueueEncoding.evaluate assignment entries) := by
  induction entries generalizing eventIndex source with
  | nil => simp [QueueReadback.writeCount, ConditionalQueueAccounting.cursorAfter, ConditionalQueueEncoding.evaluate]
  | cons entry rest ih =>
    have first := holds { eventIndex, source, entry } (by simp [ConditionalQueueEncoding.annotate])
    have tail := ih (eventIndex + 1) (ConditionalQueueEncoding.clauseFor source entry.2).target
      (fun row member => holds row (List.mem_cons_of_mem _ member))
    have index_eq :
        source + QueueReadback.writeCount ((entry :: rest).map Prod.snd) =
          (ConditionalQueueEncoding.clauseFor source entry.2).target + QueueReadback.writeCount (rest.map Prod.snd) := by
      cases event : entry.2 <;> simp [event, ConditionalQueueEncoding.clauseFor, QueueReadback.writeCount, QueueClause.writes,
        Nat.add_assoc, Nat.add_comm]
    rw [index_eq, tail]
    cases active : entry.1.eval assignment <;>
      simp only [ConditionalQueueEncoding.RowHolds, ConditionalQueueEncoding.Row.clause, active, Bool.false_eq_true, ite_false, ite_true] at first
    next =>
      simp [ConditionalQueueAccounting.cursorAfter, ConditionalQueueEncoding.evaluate, active, first]
    next =>
      simp [ConditionalQueueAccounting.cursorAfter, ConditionalQueueEncoding.evaluate, active, first.2]

def pendingRef (base index : Nat) : Term .int := ConditionalQueueEncoding.guardValue base index

def pendingEquation (guardsBase pendingBase : Nat) (entries : List Entry) :
    Fin (entries.length + 1) -> Term .bool
  | Fin.mk 0 _ => .equal (pendingRef pendingBase 0) (.integer 0)
  | Fin.mk (index + 1) bound =>
    let prior := pendingRef pendingBase index
    let active := match entries[index].2 with
      | .pop _ => .integer 0 | .peek _ => .integer 1 | _ => prior
    .equal (pendingRef pendingBase (index + 1)) (.ite (ConditionalQueueEncoding.guardRef guardsBase index) active prior)

def histogramEquation {size : Nat} (guardsBase fieldsBase histBase : Nat)
    (length : InputInt) (lookup : Fin size -> Row) : Fin (size + 1) -> InputInt -> Term .bool
  | Fin.mk 0 _, key => .equal (QueueEncoding.readRef histBase 0 key) (.integer 0)
  | Fin.mk (index + 1) bound, key =>
    let row := lookup (Fin.mk index (Nat.lt_of_succ_lt_succ bound))
    let keyMatches := match row.entry.2 with
      | .pop message => .equal key.term message.term | _ => .boolean false
    .equal (QueueEncoding.readRef histBase (index + 1) key)
      (.add (QueueEncoding.readRef histBase index key)
        (.ite (.and (ConditionalQueueEncoding.guardRef guardsBase row.eventIndex)
          (.and (.not (.le length.term (QueueScalarEncoding.headRef fieldsBase row.source))) keyMatches))
          (.integer 1) (.integer 0)))

def PendingCorrect (assignment : Assignment) (pendingBase : Nat) (entries : List Entry) : Prop :=
  forall index : Fin (entries.length + 1),
    (pendingRef pendingBase index.val).eval assignment = pending assignment entries index.val

def HistogramCorrect (assignment : Assignment) (fieldsBase histBase : Nat)
    (length : InputInt) (entries : List Entry) : Prop :=
  forall index : Fin ((popRows entries).length + 1), forall key, Membership.mem (ConditionalQueueEncoding.keysOf entries) key ->
    (QueueEncoding.readRef histBase index.val key).eval assignment =
      histogram assignment (length.eval assignment) (QueueScalarEncoding.windows assignment fieldsBase)
        (popRows entries) index.val (key.eval assignment)

theorem guard_row (assignment : Assignment) (guardsBase : Nat) (entries : List Entry)
    (bindings : SmtScript.Holds assignment
      (ConditionalQueueEncoding.guardBindings guardsBase (entries.map Prod.fst)))
    (row : Row) (member : Membership.mem (ConditionalQueueEncoding.annotate 0 0 entries) row) :
    (ConditionalQueueEncoding.guardRef guardsBase row.eventIndex).eval assignment = row.entry.1.eval assignment := by
  cases ConditionalQueueEncoding.row_index entries row member with
  | intro index spec =>
    have rule := ConditionalQueueEncoding.bound_guard_ref assignment guardsBase (entries.map Prod.fst) bindings
      (Fin.mk index.val (by simpa only [List.length_map] using index.isLt))
    simpa only [spec.1, spec.2, List.getElem_map] using rule

theorem pending_equation_zero (assignment : Assignment) (guardsBase pendingBase : Nat) (entries : List Entry) :
    (pendingEquation guardsBase pendingBase entries 0).eval assignment = true <->
      (pendingRef pendingBase 0).eval assignment = 0 := by
  change (Term.equal (pendingRef pendingBase 0) (.integer 0)).eval assignment = true <-> _
  simp only [Term.eval, decide_eq_true_eq]

theorem pending_equation_step (assignment : Assignment) (guardsBase pendingBase : Nat) (entries : List Entry)
    (bindings : SmtScript.Holds assignment
      (ConditionalQueueEncoding.guardBindings guardsBase (entries.map Prod.fst))) (index : Fin entries.length) :
    (pendingEquation guardsBase pendingBase entries index.succ).eval assignment = true <->
      (pendingRef pendingBase (index.val + 1)).eval assignment =
        pendingStep assignment ((pendingRef pendingBase index.val).eval assignment) entries[index.val] := by
  have rule := ConditionalQueueEncoding.bound_guard_ref assignment guardsBase (entries.map Prod.fst) bindings
    (Fin.mk index.val (by simpa only [List.length_map] using index.isLt))
  simp only [List.getElem_map] at rule
  cases event : entries[index.val].2 <;>
    simp [pendingEquation, Fin.succ, Term.eval, rule, pendingStep, event]

theorem pending_definitions_correct (assignment : Assignment) (guardsBase pendingBase : Nat)
    (entries : List Entry) (bindings : SmtScript.Holds assignment
      (ConditionalQueueEncoding.guardBindings guardsBase (entries.map Prod.fst))) :
    SmtScript.Holds assignment (List.ofFn (pendingEquation guardsBase pendingBase entries)) <->
      PendingCorrect assignment pendingBase entries := by
  rw [QueueInitialEncoding.ofFn_holds]
  constructor
  next =>
    intro every index
    induction index using Fin.induction with
    | zero => simpa [pending] using (pending_equation_zero assignment guardsBase pendingBase entries).mp (every 0)
    | succ index ih =>
      have step := (pending_equation_step assignment guardsBase pendingBase entries bindings index).mp (every index.succ)
      simp only [Fin.val_castSucc] at ih
      simp only [Fin.val_succ]
      rw [ih] at step
      simpa only [pending_step assignment entries index.val index.isLt] using step
  next =>
    intro correct index
    cases index using Fin.cases with
    | zero =>
      apply (pending_equation_zero assignment guardsBase pendingBase entries).mpr
      simpa [pending] using correct 0
    | succ index =>
      apply (pending_equation_step assignment guardsBase pendingBase entries bindings index).mpr
      have current := correct index.succ
      have previous := correct index.castSucc
      simp only [Fin.val_succ] at current
      simp only [Fin.val_castSucc] at previous
      rw [current, previous, pending_step assignment entries index.val index.isLt]

theorem histogram_equation_zero {size : Nat} (assignment : Assignment)
    (guardsBase fieldsBase histBase : Nat) (length : InputInt) (lookup : Fin size -> Row) (key : InputInt) :
    (histogramEquation guardsBase fieldsBase histBase length lookup 0 key).eval assignment = true <->
      (QueueEncoding.readRef histBase 0 key).eval assignment = 0 := by
  change (Term.equal (QueueEncoding.readRef histBase 0 key) (.integer 0)).eval assignment = true <-> _
  simp only [Term.eval, decide_eq_true_eq]

theorem histogram_equation_step {size : Nat} (assignment : Assignment)
    (guardsBase fieldsBase histBase : Nat) (length : InputInt) (lookup : Fin size -> Row)
    (index : Fin size) (key : InputInt)
    (guard : (ConditionalQueueEncoding.guardRef guardsBase (lookup index).eventIndex).eval assignment =
      (lookup index).entry.1.eval assignment) :
    (histogramEquation guardsBase fieldsBase histBase length lookup index.succ key).eval assignment = true <->
      (QueueEncoding.readRef histBase (index.val + 1) key).eval assignment =
        histogramStep assignment (length.eval assignment) (QueueScalarEncoding.windows assignment fieldsBase)
          (lookup index) (assignment.unary .int .int (histBase + index.val)) (key.eval assignment) := by
  cases event : (lookup index).entry.2 <;>
    simp [histogramEquation, Fin.succ, Term.eval, guard, event, histogramStep, QueueEncoding.readRef,
      QueueScalarEncoding.windows, QueueScalarEncoding.headRef, InputInt.eval]

theorem histogram_step_congr (assignment : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (row : Row) (left right : Int -> Int) (key : Int) (same : left key = right key) :
    histogramStep assignment length windows row left key = histogramStep assignment length windows row right key := by
  cases event : row.entry.2 <;> simp [histogramStep, event, same]

def histogramDefinitions (guardsBase fieldsBase histBase : Nat) (length : InputInt) (entries : List Entry) :
    SmtScript.Formula :=
  let rows := popRows entries
  let cached := rows.toArray
  QueueInitialEncoding.grid rows.length (ConditionalQueueEncoding.keysOf entries)
    (histogramEquation guardsBase fieldsBase histBase length
      (fun index : Fin rows.length => cached[index.val]'(by simp [cached])))

theorem histogram_definitions_correct (assignment : Assignment) (guardsBase fieldsBase histBase : Nat)
    (length : InputInt) (entries : List Entry) (bindings : SmtScript.Holds assignment
      (ConditionalQueueEncoding.guardBindings guardsBase (entries.map Prod.fst))) :
    SmtScript.Holds assignment (histogramDefinitions guardsBase fieldsBase histBase length entries) <->
      HistogramCorrect assignment fieldsBase histBase length entries := by
  let lookup := fun index : Fin (popRows entries).length => (popRows entries)[index.val]
  have rules (index : Fin (popRows entries).length) :
      (ConditionalQueueEncoding.guardRef guardsBase (lookup index).eventIndex).eval assignment =
        (lookup index).entry.1.eval assignment := by
    apply guard_row assignment guardsBase entries bindings
    exact (List.mem_filter.mp (List.getElem_mem index.isLt)).1
  change SmtScript.Holds assignment
    (QueueInitialEncoding.grid (popRows entries).length (ConditionalQueueEncoding.keysOf entries)
      (histogramEquation guardsBase fieldsBase histBase length _)) <-> _
  simp only [List.getElem_toArray]
  rw [QueueInitialEncoding.grid_holds]
  constructor
  next =>
    intro every index
    induction index using Fin.induction with
    | zero =>
      intro key member
      simpa [histogram] using
        (histogram_equation_zero assignment guardsBase fieldsBase histBase length lookup key).mp (every 0 key member)
    | succ index ih =>
      intro key member
      have equation := (histogram_equation_step assignment guardsBase fieldsBase histBase length lookup index key
        (rules index)).mp (every index.succ key member)
      have old := ih key member
      simp only [Fin.val_castSucc] at old
      change assignment.unary .int .int (histBase + index.val) (key.eval assignment) = _ at old
      rw [histogram_step_congr _ _ _ _ _ _ _ old] at equation
      simpa only [Fin.val_succ, histogram_step assignment _ _ (popRows entries) index.val index.isLt] using equation
  next =>
    intro correct index key member
    cases index using Fin.cases with
    | zero =>
      apply (histogram_equation_zero assignment guardsBase fieldsBase histBase length lookup key).mpr
      simpa [histogram] using correct 0 key member
    | succ index =>
      apply (histogram_equation_step assignment guardsBase fieldsBase histBase length lookup index key (rules index)).mpr
      have current := correct index.succ key member
      have previous := correct index.castSucc key member
      simp only [Fin.val_castSucc] at previous
      change assignment.unary .int .int (histBase + index.val) (key.eval assignment) = _ at previous
      rw [histogram_step_congr _ _ _ _ _ _ _ previous]
      simpa only [Fin.val_succ, histogram_step assignment _ _ (popRows entries) index.val index.isLt] using current

def finalHistogram (fieldsBase pendingBase histBase : Nat) (length : InputInt)
    (entries : List Entry) (key : InputInt) : Term .int :=
  let head := QueueScalarEncoding.headRef fieldsBase (QueueReadback.writeCount (entries.map Prod.snd))
  .add (QueueEncoding.readRef histBase (popRows entries).length key)
    (.ite (.and (.equal (pendingRef pendingBase entries.length) (.integer 1))
      (.and (.not (.le length.term head)) (.equal (QueueScalarEncoding.orderRef fieldsBase head) key.term)))
      (.integer 1) (.integer 0))

theorem final_head (assignment : Assignment) (guardsBase countsBase fieldsBase : Nat)
    (length : Int) (entries : List Entry)
    (trace : SmtScript.Holds assignment (ConditionalQueueEncoding.traceBlock guardsBase countsBase fieldsBase entries))
    (head : (QueueScalarEncoding.windows assignment fieldsBase 0).head = 0) :
    (QueueScalarEncoding.headRef fieldsBase (QueueReadback.writeCount (entries.map Prod.snd))).eval assignment =
      ((ConditionalQueueAccounting.summarize length (ConditionalQueueEncoding.evaluate assignment entries)).head : Int) := by
  let heap := ConditionalQueueEncoding.coherentHeap assignment countsBase fieldsBase entries
  have final := annotated_final assignment (QueueScalarEncoding.order assignment fieldsBase) heap entries 0 0
    (ConditionalQueueEncoding.coherent_row assignment guardsBase countsBase fieldsBase entries trace)
  have counted := ConditionalQueueAccounting.head_count length (heap 0)
    (ConditionalQueueEncoding.evaluate assignment entries) head
  rw [Eq.symm final] at counted
  simpa [heap, ConditionalQueueEncoding.coherentHeap, QueueScalarEncoding.headRef,
    QueueScalarEncoding.windows, Term.eval] using counted

theorem final_histogram_correct (assignment : Assignment)
    (guardsBase countsBase fieldsBase pendingBase histBase : Nat) (length : InputInt) (entries : List Entry)
    (trace : SmtScript.Holds assignment (ConditionalQueueEncoding.traceBlock guardsBase countsBase fieldsBase entries))
    (head : (QueueScalarEncoding.windows assignment fieldsBase 0).head = 0)
    (flags : PendingCorrect assignment pendingBase entries)
    (hist : HistogramCorrect assignment fieldsBase histBase length entries)
    (key : InputInt) (tracked : Membership.mem (ConditionalQueueEncoding.keysOf entries) key) :
    (finalHistogram fieldsBase pendingBase histBase length entries key).eval assignment =
      ConditionalQueueAccounting.initialHistogram (length.eval assignment) (QueueScalarEncoding.order assignment fieldsBase)
        (ConditionalQueueEncoding.evaluate assignment entries) (key.eval assignment) := by
  let heap := ConditionalQueueEncoding.coherentHeap assignment countsBase fieldsBase entries
  have folded := histogram_final assignment (length.eval assignment) (QueueScalarEncoding.order assignment fieldsBase)
    heap entries head (ConditionalQueueEncoding.coherent_row assignment guardsBase countsBase fieldsBase entries trace)
  have counted := hist (Fin.mk (popRows entries).length (Nat.lt_succ_self _)) key tracked
  change (QueueEncoding.readRef histBase (popRows entries).length key).eval assignment = _ at counted
  rw [show QueueScalarEncoding.windows assignment fieldsBase = (fun index => (heap index).window) from rfl,
    folded] at counted
  have flag := flags (Fin.mk entries.length (Nat.lt_succ_self _))
  change (pendingRef pendingBase entries.length).eval assignment = _ at flag
  rw [pending_final assignment (length.eval assignment) entries] at flag
  have position := final_head assignment guardsBase countsBase fieldsBase (length.eval assignment) entries trace head
  simp only [finalHistogram, Term.eval, counted, flag, position, QueueScalarEncoding.orderRef,
    ConditionalQueueAccounting.initialHistogram]
  cases (ConditionalQueueAccounting.summarize (length.eval assignment)
    (ConditionalQueueEncoding.evaluate assignment entries)).pending <;>
    simp [QueueScalarEncoding.order, InputInt.eval]

def definitions (guardsBase fieldsBase pendingBase histBase : Nat) (length : InputInt)
    (entries : List Entry) : SmtScript.Formula :=
  List.ofFn (pendingEquation guardsBase pendingBase entries) ++
    histogramDefinitions guardsBase fieldsBase histBase length entries

def checks (countsBase fieldsBase pendingBase histBase : Nat) (length : InputInt)
    (entries : List Entry) : SmtScript.Formula :=
  (ConditionalQueueEncoding.keysOf entries).map fun key =>
    .le (finalHistogram fieldsBase pendingBase histBase length entries key) (QueueEncoding.readRef countsBase 0 key)

def accountingBlock (guardsBase countsBase fieldsBase pendingBase histBase budgetBase : Nat)
    (length : InputInt) (entries : List Entry) : SmtScript.Formula :=
  definitions guardsBase fieldsBase pendingBase histBase length entries ++
    (checks countsBase fieldsBase pendingBase histBase length entries ++
      QueueInitialEncoding.initialBlock countsBase budgetBase length [] (ConditionalQueueEncoding.keysOf entries))

theorem definitions_correct (assignment : Assignment) (guardsBase fieldsBase pendingBase histBase : Nat)
    (length : InputInt) (entries : List Entry) (bindings : SmtScript.Holds assignment
      (ConditionalQueueEncoding.guardBindings guardsBase (entries.map Prod.fst))) :
    SmtScript.Holds assignment (definitions guardsBase fieldsBase pendingBase histBase length entries) <->
      PendingCorrect assignment pendingBase entries /\ HistogramCorrect assignment fieldsBase histBase length entries := by
  rw [definitions, QueueEncoding.holds_append, pending_definitions_correct _ _ _ _ bindings,
    histogram_definitions_correct _ _ _ _ _ _ bindings]

theorem checks_correct (assignment : Assignment) (guardsBase countsBase fieldsBase pendingBase histBase : Nat)
    (length : InputInt) (entries : List Entry)
    (trace : SmtScript.Holds assignment (ConditionalQueueEncoding.traceBlock guardsBase countsBase fieldsBase entries))
    (head : (QueueScalarEncoding.windows assignment fieldsBase 0).head = 0)
    (nonnegative : 0 <= length.eval assignment) (flags : PendingCorrect assignment pendingBase entries)
    (hist : HistogramCorrect assignment fieldsBase histBase length entries) :
    SmtScript.Holds assignment (checks countsBase fieldsBase pendingBase histBase length entries) <->
      forall key, Membership.mem (ConditionalQueueEncoding.keysOf entries) key ->
        (((CountedQueue.readHeads (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries))).take
          (length.eval assignment).toNat).count (key.eval assignment) : Int) <=
            QueueInitialEncoding.rootCounts assignment countsBase (key.eval assignment) := by
  have replay := (ConditionalQueueEncoding.trace_block_coherent_replay assignment guardsBase countsBase fieldsBase entries trace).2
  have term_rule (key : InputInt) (member : Membership.mem (ConditionalQueueEncoding.keysOf entries) key) :
      (Term.le (finalHistogram fieldsBase pendingBase histBase length entries key)
        (QueueEncoding.readRef countsBase 0 key)).eval assignment = true <->
      (((CountedQueue.readHeads (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries))).take
        (length.eval assignment).toNat).count (key.eval assignment) : Int) <=
          QueueInitialEncoding.rootCounts assignment countsBase (key.eval assignment) := by
    simp only [Term.eval, decide_eq_true_eq]
    rw [final_histogram_correct assignment guardsBase countsBase fieldsBase pendingBase histBase length entries
      trace head flags hist key member,
      ConditionalQueueAccounting.replay_initial_histogram_exact (length.eval assignment) nonnegative
        (QueueScalarEncoding.order assignment fieldsBase) _ _ head replay]
    rfl
  constructor
  next =>
    intro holds key member
    exact (term_rule key member).mp (holds _ (List.mem_map.mpr (Exists.intro key (And.intro member rfl))))
  next =>
    intro every term member
    cases List.mem_map.mp member with
    | intro key spec =>
      rw [Eq.symm spec.2]
      exact (term_rule key spec.1).mpr (every key spec.1)

theorem accounting_block_correct (assignment : Assignment)
    (guardsBase countsBase fieldsBase pendingBase histBase budgetBase : Nat) (length : InputInt) (entries : List Entry)
    (trace : SmtScript.Holds assignment (ConditionalQueueEncoding.traceBlock guardsBase countsBase fieldsBase entries))
    (head : (QueueScalarEncoding.windows assignment fieldsBase 0).head = 0) :
    SmtScript.Holds assignment (accountingBlock guardsBase countsBase fieldsBase pendingBase histBase budgetBase length entries) <->
      (PendingCorrect assignment pendingBase entries /\ HistogramCorrect assignment fieldsBase histBase length entries) /\
      QueueInitialEncoding.AuxCorrect assignment countsBase budgetBase length [] (ConditionalQueueEncoding.keysOf entries) /\
      0 <= length.eval assignment /\
      IntegerQueue.RawInitialFacts ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval assignment)).toFinset
        (QueueInitialEncoding.rootCounts assignment countsBase) (length.eval assignment).toNat
        (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries)) := by
  have bindings := ((ConditionalQueueEncoding.trace_block_correct assignment guardsBase countsBase fieldsBase entries).mp trace).1
  have budget := QueueInitialEncoding.initial_block_correct assignment countsBase budgetBase length []
    (ConditionalQueueEncoding.keysOf entries)
  simp only [CountedQueue.readHeads] at budget
  rw [accountingBlock, QueueEncoding.holds_append, QueueEncoding.holds_append,
    definitions_correct _ _ _ _ _ _ _ bindings, budget]
  constructor
  next =>
    intro spec
    have lower := (checks_correct assignment guardsBase countsBase fieldsBase pendingBase histBase length entries
      trace head spec.2.2.2.1 spec.1.1 spec.1.2).mp spec.2.1
    refine And.intro spec.1 (And.intro spec.2.2.1 (And.intro spec.2.2.2.1 (And.intro ?_ spec.2.2.2.2.2)))
    intro value member
    cases List.mem_map.mp (List.mem_toFinset.mp member) with
    | intro key chosen => simpa only [chosen.2] using lower key chosen.1
  next =>
    intro spec
    refine And.intro spec.1 (And.intro ?_ (And.intro spec.2.1 (And.intro spec.2.2.1 (And.intro ?_ spec.2.2.2.2))))
    next =>
      apply (checks_correct assignment guardsBase countsBase fieldsBase pendingBase histBase length entries
        trace head spec.2.2.1 spec.1.1 spec.1.2).mpr
      intro key member
      exact spec.2.2.2.1 (key.eval assignment)
        (List.mem_toFinset.mpr (List.mem_map.mpr (Exists.intro key (And.intro member rfl))))
    next =>
      intro key member
      have lower := spec.2.2.2.1 key member
      simpa [QueueScalarEncoding.evalTrace, CountedQueue.readHeads] using (Int.natCast_nonneg _).trans lower

theorem fold_congr {A S : Type} (items : List A) (left right : S -> A -> S) (start : S)
    (same : forall item, Membership.mem items item -> forall state, left state item = right state item) :
    items.foldl left start = items.foldl right start := by
  induction items generalizing start with
  | nil => rfl
  | cons item rest ih =>
    simp only [List.foldl_cons]
    rw [same item (by simp)]
    exact ih _ (fun other member state => same other (List.mem_cons_of_mem _ member) state)

theorem pending_congr (left right : Assignment) (entries : List Entry)
    (same : forall entry, Membership.mem entries entry -> entry.1.eval left = entry.1.eval right) (index : Nat) :
    pending left entries index = pending right entries index := by
  unfold pending
  apply fold_congr
  intro entry member state
  simp only [pendingStep, same entry (List.mem_of_mem_take member)]

theorem histogram_congr (left right : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (entries : List Entry) (index : Nat)
    (guards : forall entry, Membership.mem entries entry -> entry.1.eval left = entry.1.eval right)
    (keys : InputInt.eval left = InputInt.eval right) :
    histogram left length windows (popRows entries) index =
      histogram right length windows (popRows entries) index := by
  unfold histogram
  apply fold_congr
  intro row member state
  have annotated := (List.mem_filter.mp (List.mem_of_mem_take member)).1
  have entry_member : Membership.mem entries row.entry := by
    rw [Eq.symm (ConditionalQueueEncoding.annotate_entries 0 0 entries)]
    exact List.mem_map.mpr (Exists.intro row (And.intro annotated rfl))
  funext query
  cases event : row.entry.2 <;> simp [histogramStep, event, guards row.entry entry_member, keys]

def pendingBase (input : SmtScript.Formula) (entries : List Entry) : Nat :=
  ConditionalQueueEncoding.nextBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))

def histogramBase (input : SmtScript.Formula) (entries : List Entry) : Nat := pendingBase input entries + 1

def budgetBase (input : SmtScript.Formula) (entries : List Entry) : Nat :=
  pendingBase input entries + (popRows entries).length + 2

def nextBase (input : SmtScript.Formula) (entries : List Entry) : Nat :=
  budgetBase input entries + (ConditionalQueueEncoding.keysOf entries).length + 3

def auxiliaryFunctions (original : Assignment) (length : Int) (windows : Nat -> SignedWindow)
    (entries : List Entry) : Fin ((popRows entries).length + 2) -> Int -> Int :=
  fun slot argument =>
    if slot.val = 0 then pending original entries argument.toNat
    else histogram original length windows (popRows entries) (slot.val - 1) argument

def installWitness (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) : Assignment :=
  let core := ConditionalQueueEncoding.install original input (entries.map Prod.fst)
    (fun index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) => (heap index.val).counts)
    (fun index => (heap index).window) order
  let stats := QueueEncoding.installCounts core (pendingBase input entries)
    (auxiliaryFunctions original (length.eval original) (fun index => (heap index).window) entries)
  QueueInitialEncoding.installInitial stats (ConditionalQueueEncoding.countBase input (entries.map Prod.fst))
    (budgetBase input entries) length [] (ConditionalQueueEncoding.keysOf entries)

theorem witness_constants (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    (installWitness original input entries length heap order).constant = original.constant := rfl

theorem witness_before (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (domain result : Ty) (id : Nat)
    (before : id < pendingBase input entries) :
    (installWitness original input entries length heap order).unary domain result id =
      (ConditionalQueueEncoding.install original input (entries.map Prod.fst)
        (fun index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) => (heap index.val).counts)
        (fun index => (heap index).window) order).unary domain result id := by
  have below_budget : id < budgetBase input entries := by unfold budgetBase; omega
  unfold installWitness
  rw [QueueInitialEncoding.install_before _ _ _ _ _ _ domain result id below_budget,
    QueueEncoding.install_outside _ _ _ domain result id (Or.inl before)]

theorem witness_external (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (domain result : Ty) (id : Nat)
    (member : Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id)) :
    (installWitness original input entries length heap order).unary domain result id = original.unary domain result id := by
  have source := QueueEncoding.input_symbol_bound (input ++ entries.map Prod.fst) _ member
  change id < QueueEncoding.freshBase (input ++ entries.map Prod.fst) at source
  have before : id < pendingBase input entries := by
    unfold pendingBase ConditionalQueueEncoding.nextBase ConditionalQueueEncoding.scalarBase
      ConditionalQueueEncoding.countBase ConditionalQueueEncoding.guardBase
    omega
  rw [witness_before original input entries length heap order domain result id before]
  exact ConditionalQueueEncoding.install_external _ _ _ _ _ _ domain result id member

theorem witness_after (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (domain result : Ty) (id : Nat)
    (after : nextBase input entries <= id) :
    (installWitness original input entries length heap order).unary domain result id = original.unary domain result id := by
  have after_budget : budgetBase input entries + (ConditionalQueueEncoding.keysOf entries).length + 3 <= id := after
  have after_stats : pendingBase input entries + (popRows entries).length + 2 <= id := by
    unfold budgetBase at after_budget
    omega
  have after_core : pendingBase input entries <= id := by omega
  unfold installWitness QueueInitialEncoding.installInitial
  rw [QueueEncoding.install_outside _ _ _ domain result id (Or.inr (by simpa using after_budget)),
    QueueEncoding.install_outside _ _ _ domain result id (Or.inr (by omega))]
  exact ConditionalQueueEncoding.install_after _ _ _ _ _ _ domain result id after_core

theorem witness_source_term (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (term : Term .bool)
    (member : Membership.mem (input ++ entries.map Prod.fst) term) :
    term.eval (installWitness original input entries length heap order) = term.eval original := by
  have after_source : ConditionalQueueEncoding.guardBase input (entries.map Prod.fst) <= pendingBase input entries := by
    unfold pendingBase ConditionalQueueEncoding.nextBase ConditionalQueueEncoding.scalarBase ConditionalQueueEncoding.countBase
    omega
  have budget_after : ConditionalQueueEncoding.guardBase input (entries.map Prod.fst) <= budgetBase input entries := by
    unfold budgetBase
    omega
  unfold installWitness QueueInitialEncoding.installInitial
  rw [ConditionalQueueEncoding.reserved_eval _ input (entries.map Prod.fst) _ _ budget_after term member,
    ConditionalQueueEncoding.reserved_eval _ input (entries.map Prod.fst) _ _ after_source term member]
  exact ConditionalQueueEncoding.install_source_term _ _ _ _ _ _ term member

theorem witness_inputs (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    InputInt.eval (installWitness original input entries length heap order) = InputInt.eval original := by
  funext key
  cases key <;> rfl

theorem witness_guards (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (entry : Entry) (member : Membership.mem entries entry) :
    entry.1.eval (installWitness original input entries length heap order) = entry.1.eval original :=
  witness_source_term original input entries length heap order entry.1
    (List.mem_append_right input (List.mem_map.mpr (Exists.intro entry (And.intro member rfl))))

theorem witness_evaluate (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    ConditionalQueueEncoding.evaluate (installWitness original input entries length heap order) entries =
      ConditionalQueueEncoding.evaluate original entries := by
  unfold ConditionalQueueEncoding.evaluate
  apply List.map_congr_left
  intro entry member
  rw [witness_guards original input entries length heap order entry member]
  congr 1
  cases entry.2 <;> simp [QueueScalarEncoding.evalEvent, witness_inputs]

theorem witness_windows (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    QueueScalarEncoding.windows (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))) =
        (fun index => (heap index).window) := by
  let base := ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))
  have head := witness_before original input entries length heap order .int .int base (by
    change base < base + 3
    omega)
  have tail := witness_before original input entries length heap order .int .int (base + 1) (by
    change base + 1 < base + 3
    omega)
  dsimp only [base] at head tail
  funext index
  simp only [QueueScalarEncoding.windows, head, tail]
  exact congrFun (ConditionalQueueEncoding.install_windows original input (entries.map Prod.fst)
    (fun index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) => (heap index.val).counts)
    (fun index => (heap index).window) order) index

theorem witness_order (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    QueueScalarEncoding.order (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))) = order := by
  unfold QueueScalarEncoding.order
  rw [witness_before original input entries length heap order .int .int _ (by
    unfold pendingBase ConditionalQueueEncoding.nextBase
    omega)]
  exact ConditionalQueueEncoding.install_order _ _ _ _ _ _

theorem witness_counts (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int)
    (index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1)) :
    (installWitness original input entries length heap order).unary .int .int
      (ConditionalQueueEncoding.countBase input (entries.map Prod.fst) + index.val) = (heap index.val).counts := by
  rw [witness_before original input entries length heap order .int .int _ (by
    have bound := index.isLt
    unfold pendingBase ConditionalQueueEncoding.nextBase ConditionalQueueEncoding.scalarBase
    omega)]
  exact ConditionalQueueEncoding.install_counts _ _ _ _ _ _ index

theorem witness_heap (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int)
    (index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1)) :
    QueueScalarEncoding.rawHeap (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.countBase input (entries.map Prod.fst))
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd)))
      index.val = heap index.val := by
  simp only [QueueScalarEncoding.rawHeap, witness_counts, witness_windows]

theorem witness_pending (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    (installWitness original input entries length heap order).unary .int .int (pendingBase input entries) =
      (fun argument => pending original entries argument.toNat) := by
  unfold installWitness
  rw [QueueInitialEncoding.install_before _ _ _ _ _ _ .int .int _ (by unfold budgetBase; omega)]
  have installed := QueueEncoding.install_at
    (ConditionalQueueEncoding.install original input (entries.map Prod.fst)
      (fun index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) => (heap index.val).counts)
      (fun index => (heap index).window) order)
    (pendingBase input entries)
    (auxiliaryFunctions original (length.eval original) (fun index => (heap index).window) entries) 0
  simpa [auxiliaryFunctions] using installed

theorem witness_histogram (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (index : Fin ((popRows entries).length + 1)) :
    (installWitness original input entries length heap order).unary .int .int
      (histogramBase input entries + index.val) =
        histogram original (length.eval original) (fun index => (heap index).window) (popRows entries) index.val := by
  have before : histogramBase input entries + index.val < budgetBase input entries := by
    have bound := index.isLt
    unfold histogramBase budgetBase
    omega
  unfold installWitness
  rw [QueueInitialEncoding.install_before _ _ _ _ _ _ .int .int _ before]
  have installed := QueueEncoding.install_at
    (ConditionalQueueEncoding.install original input (entries.map Prod.fst)
      (fun index : Fin (QueueReadback.writeCount (entries.map Prod.snd) + 1) => (heap index.val).counts)
      (fun index => (heap index).window) order)
    (pendingBase input entries)
    (auxiliaryFunctions original (length.eval original) (fun index => (heap index).window) entries)
    (Fin.mk (index.val + 1) (by have bound := index.isLt; omega))
  simpa [histogramBase, auxiliaryFunctions, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using installed

theorem witness_aux_correct (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) :
    PendingCorrect (installWitness original input entries length heap order) (pendingBase input entries) entries /\
    HistogramCorrect (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd)))
      (histogramBase input entries) length entries := by
  constructor
  next =>
    intro index
    simp only [pendingRef, ConditionalQueueEncoding.guardValue, Term.eval, witness_pending, Int.toNat_natCast]
    exact (pending_congr _ _ entries (witness_guards original input entries length heap order) index.val).symm
  next =>
    intro index key member
    simp only [QueueEncoding.readRef, Term.eval, witness_histogram, witness_inputs, witness_windows]
    have same := histogram_congr _ _ (length.eval original) (fun index => (heap index).window) entries index.val
      (witness_guards original input entries length heap order) (witness_inputs original input entries length heap order)
    rw [show key.term.eval (installWitness original input entries length heap order) = key.eval original from
      congrFun (witness_inputs original input entries length heap order) key]
    exact congrFun same.symm (key.eval original)

theorem replay_complete (assignment : Assignment) (order : Int -> Int) (entries : List Entry)
    (eventIndex source : Nat) (heap : Heap Int)
    (follows : ConditionalQueueAccounting.replay order (heap source) (ConditionalQueueEncoding.evaluate assignment entries)) :
    exists extended : Heap Int, (forall index, index <= source -> extended index = heap index) /\
      forall row, Membership.mem (ConditionalQueueEncoding.annotate eventIndex source entries) row ->
        ConditionalQueueEncoding.RowHolds assignment order extended row := by
  induction entries generalizing eventIndex source heap with
  | nil => exact Exists.intro heap (And.intro (fun _ _ => rfl) (by simp [ConditionalQueueEncoding.annotate]))
  | cons entry rest ih =>
    let next := if entry.1.eval assignment then
      QueueClause.advance (heap source) (QueueScalarEncoding.evalEvent assignment entry.2) else heap source
    have tail : ConditionalQueueAccounting.replay order next (ConditionalQueueEncoding.evaluate assignment rest) := by
      cases active : entry.1.eval assignment <;>
        simp only [ConditionalQueueEncoding.evaluate, List.map_cons, active, ConditionalQueueAccounting.replay] at follows
      next => simpa [next, active] using follows
      next => simpa [next, active] using follows.2
    have guard : entry.1.eval assignment = true ->
        QueueClause.guard order (heap source) (QueueScalarEncoding.evalEvent assignment entry.2) := by
      intro active
      simp only [ConditionalQueueEncoding.evaluate, List.map_cons, active, ConditionalQueueAccounting.replay] at follows
      exact follows.1
    by_cases writing : QueueClause.writes entry.2 = true
    next =>
      let updated := Function.update heap (source + 1) next
      have continuation : ConditionalQueueAccounting.replay order (updated (source + 1))
          (ConditionalQueueEncoding.evaluate assignment rest) := by simpa [updated] using tail
      cases ih (eventIndex + 1) (source + 1) updated continuation with
      | intro extended spec =>
        have old : extended source = heap source := by
          rw [spec.1 source (by omega)]
          simp [updated]
        have new : extended (source + 1) = next := by
          rw [spec.1 (source + 1) (by omega)]
          simp [updated]
        refine Exists.intro extended (And.intro ?_ ?_)
        next =>
          intro index before
          rw [spec.1 index (by omega)]
          simp only [updated, Function.update_of_ne (show Not (index = source + 1) from by omega)]
        next =>
          intro row member
          simp only [ConditionalQueueEncoding.annotate, ConditionalQueueEncoding.clauseFor, writing, ite_true] at member
          cases List.mem_cons.mp member with
          | inl equal =>
            subst row
            cases active : entry.1.eval assignment <;>
              simp [ConditionalQueueEncoding.RowHolds, ConditionalQueueEncoding.Row.clause,
                ConditionalQueueEncoding.clauseFor, writing, active, old, new, next, guard]
          | inr later => exact spec.2 row later
    next =>
      have readonly : QueueClause.writes entry.2 = false := Bool.eq_false_iff.mpr writing
      have evaluated : QueueClause.writes (QueueScalarEncoding.evalEvent assignment entry.2) = false := by
        cases event : entry.2 <;> simp_all [QueueClause.writes, QueueScalarEncoding.evalEvent]
      have stable := QueueClause.advance_readonly (heap source) (QueueScalarEncoding.evalEvent assignment entry.2) evaluated
      have next_eq : next = heap source := by simp [next, stable]
      cases ih (eventIndex + 1) source heap (by simpa only [next_eq] using tail) with
      | intro extended spec =>
        refine Exists.intro extended (And.intro spec.1 ?_)
        intro row member
        simp only [ConditionalQueueEncoding.annotate, ConditionalQueueEncoding.clauseFor, readonly,
          Bool.false_eq_true, ite_false] at member
        cases List.mem_cons.mp member with
        | inl equal =>
          subst row
          have old := spec.1 source (Nat.le_refl _)
          cases active : entry.1.eval assignment <;>
            simp [ConditionalQueueEncoding.RowHolds, ConditionalQueueEncoding.Row.clause,
              ConditionalQueueEncoding.clauseFor, readonly, active, old, stable, guard]
        | inr later => exact spec.2 row later

theorem witness_event (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int) (event : Event InputInt) :
    QueueScalarEncoding.evalEvent (installWitness original input entries length heap order) event =
      QueueScalarEncoding.evalEvent original event := by
  cases event <;> simp only [QueueScalarEncoding.evalEvent, witness_inputs]

theorem witness_trace (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int)
    (rows : forall row, Membership.mem (ConditionalQueueEncoding.annotate 0 0 entries) row ->
      ConditionalQueueEncoding.RowHolds original order heap row) :
    SmtScript.Holds (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.traceBlock (ConditionalQueueEncoding.guardBase input (entries.map Prod.fst))
        (ConditionalQueueEncoding.countBase input (entries.map Prod.fst))
        (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd))) entries) := by
  apply (ConditionalQueueEncoding.trace_block_correct _ _ _ _ entries).mpr
  constructor
  next =>
    apply (ConditionalQueueEncoding.bindings_correct _ _ _).mpr
    intro index
    change (installWitness original input entries length heap order).unary .int .int
      (ConditionalQueueEncoding.guardBase input (entries.map Prod.fst)) (index.val : Int) = _
    rw [witness_before original input entries length heap order .int .int _ (by
      unfold pendingBase ConditionalQueueEncoding.nextBase ConditionalQueueEncoding.scalarBase
        ConditionalQueueEncoding.countBase
      omega), ConditionalQueueEncoding.install_guard_function, ConditionalQueueEncoding.guard_function_at]
    rw [witness_source_term original input entries length heap order _ (List.mem_append_right input (List.getElem_mem index.isLt))]
  next =>
    intro row member
    have bounds := ConditionalQueueEncoding.annotation_bounds entries row member
    have source_bound : row.source < QueueReadback.writeCount (entries.map Prod.snd) + 1 := by
      rw [ConditionalQueueEncoding.write_rows_length] at bounds
      omega
    have target_bound : row.clause.target < QueueReadback.writeCount (entries.map Prod.snd) + 1 := by
      rw [ConditionalQueueEncoding.write_rows_length] at bounds
      omega
    have entry_member : Membership.mem entries row.entry := by
      rw [Eq.symm (ConditionalQueueEncoding.annotate_entries 0 0 entries)]
      exact List.mem_map.mpr (Exists.intro row (And.intro member rfl))
    have source := witness_heap original input entries length heap order (Fin.mk row.source source_bound)
    have target := witness_heap original input entries length heap order (Fin.mk row.clause.target target_bound)
    dsimp only [ConditionalQueueEncoding.Row.clause] at target
    have steps := rows row member
    simp only [ConditionalQueueEncoding.ClauseFacts, witness_guards _ _ _ _ _ _ row.entry entry_member,
      witness_event, witness_inputs, witness_order, source, target]
    cases active : row.entry.1.eval original with
    | false =>
      simp only [ConditionalQueueEncoding.RowHolds, ConditionalQueueEncoding.Row.clause, active, Bool.false_eq_true, ite_false] at steps
      simp [steps]
    | true =>
      simp only [ConditionalQueueEncoding.RowHolds, ConditionalQueueEncoding.Row.clause, active, ite_true] at steps
      simp [steps.1, steps.2, QueueReadback.scalarFields]

theorem select_uses {A : Type} (keys : Finset A) (entries : List (ConditionalQueueAccounting.GuardedEvent A))
    (used : CountedQueue.Uses keys (entries.map Prod.snd)) :
    CountedQueue.Uses keys (ConditionalQueueAccounting.select entries) := by
  induction entries with
  | nil => trivial
  | cons entry rest ih =>
    cases entry with
    | mk active event =>
      cases active <;> cases event <;>
        simp_all [List.map_cons, CountedQueue.Uses, ConditionalQueueAccounting.select]

theorem selected_uses (assignment : Assignment) (entries : List Entry) :
    CountedQueue.Uses ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval assignment)).toFinset
      (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries)) := by
  apply select_uses
  simpa [ConditionalQueueEncoding.keysOf, ConditionalQueueEncoding.evaluate, QueueScalarEncoding.evalTrace,
    List.map_map, Function.comp_def] using
    QueueInitialEncoding.tracked_uses assignment (entries.map Prod.snd)

def encode (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) : SmtScript.Formula :=
  let guards := entries.map Prod.fst
  let writes := QueueReadback.writeCount (entries.map Prod.snd)
  let guardsBase := ConditionalQueueEncoding.guardBase input guards
  let countsBase := guardsBase + 1
  let fieldsBase := countsBase + writes + 1
  let flagsBase := fieldsBase + 3
  let histBase := flagsBase + 1
  let budget := flagsBase + (popRows entries).length + 2
  input ++ (ConditionalQueueEncoding.traceBlock guardsBase countsBase fieldsBase entries ++
    (QueueScalarEncoding.initialBlock fieldsBase length ++
      accountingBlock guardsBase countsBase fieldsBase flagsBase histBase budget length entries))

def render (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) : String :=
  SmtScript.render (encode input entries length)

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula)
    (entries : List Entry) (length : InputInt) (holds : SmtScript.Holds assignment (encode input entries length)) :
    SmtScript.Holds assignment input /\
      exists queue : List Int, (queue.length : Int) = length.eval assignment /\
        QueueStream.concreteFollows queue (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries)) := by
  have parts := (QueueEncoding.holds_append _ _ _).mp holds
  have blocks := (QueueEncoding.holds_append _ _ _).mp parts.2
  have initial_and_aux := (QueueEncoding.holds_append _ _ _).mp blocks.2
  have initial := (QueueScalarEncoding.initial_correct _ _ _).mp initial_and_aux.1
  have head : (QueueScalarEncoding.windows assignment
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst)
        (QueueReadback.writeCount (entries.map Prod.snd))) 0).head = 0 := by
    exact congrArg SignedWindow.head initial.2
  have facts := (accounting_block_correct assignment _ _ _ _ _ _ length entries blocks.1 head).mp initial_and_aux.2
  have replay := (ConditionalQueueEncoding.trace_block_coherent_replay assignment _ _ _ entries blocks.1).2
  rw [initial.2] at replay
  have cursor := (ConditionalQueueAccounting.replay_iff _ _ _).mp replay
  have signed := (QueueClause.cursor_iff_signed _ _ _).mp cursor
  refine And.intro parts.1 ?_
  apply (SignedQueue.signed_exists_iff
    ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval assignment)).toFinset
    (length.eval assignment) initial.1
    (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate assignment entries))
    (selected_uses assignment entries) (QueueTraceEncoding.freshFiller _) (QueueTraceEncoding.filler_fresh _)).mp
  exact Exists.intro (QueueScalarEncoding.order assignment _)
    (Exists.intro (QueueInitialEncoding.rootCounts assignment _) (And.intro facts.2.2.2 signed))

theorem witness_satisfies (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (heap : Heap Int) (order : Int -> Int)
    (input_holds : SmtScript.Holds original input) (nonnegative : 0 <= length.eval original)
    (initial : (heap 0).window = { head := 0, tail := length.eval original })
    (facts : IntegerQueue.RawInitialFacts
      ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval original)).toFinset
      (heap 0).counts (length.eval original).toNat
      (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate original entries)))
    (rows : forall row, Membership.mem (ConditionalQueueEncoding.annotate 0 0 entries) row ->
      ConditionalQueueEncoding.RowHolds original order heap row) :
    SmtScript.Holds (installWitness original input entries length heap order) (encode input entries length) := by
  have trace := witness_trace original input entries length heap order rows
  have fields :
      SmtScript.Holds (installWitness original input entries length heap order)
        (QueueScalarEncoding.initialBlock
          (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst)
            (QueueReadback.writeCount (entries.map Prod.snd))) length) := by
    apply (QueueScalarEncoding.initial_correct _ _ _).mpr
    simpa only [witness_inputs, witness_windows] using And.intro nonnegative initial
  have head : (QueueScalarEncoding.windows (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst)
        (QueueReadback.writeCount (entries.map Prod.snd))) 0).head = 0 := by
    rw [witness_windows]
    exact congrArg SignedWindow.head initial
  have root : QueueInitialEncoding.rootCounts (installWitness original input entries length heap order)
      (ConditionalQueueEncoding.countBase input (entries.map Prod.fst)) = (heap 0).counts := by
    simpa only [QueueInitialEncoding.rootCounts, Nat.add_zero] using
      witness_counts original input entries length heap order 0
  have budget :
      QueueInitialEncoding.AuxCorrect (installWitness original input entries length heap order)
        (ConditionalQueueEncoding.countBase input (entries.map Prod.fst)) (budgetBase input entries)
        length [] (ConditionalQueueEncoding.keysOf entries) := by
    apply QueueInitialEncoding.install_aux_correct
    unfold budgetBase pendingBase ConditionalQueueEncoding.nextBase ConditionalQueueEncoding.scalarBase
    omega
  have accounting :
      SmtScript.Holds (installWitness original input entries length heap order)
        (accountingBlock (ConditionalQueueEncoding.guardBase input (entries.map Prod.fst))
          (ConditionalQueueEncoding.countBase input (entries.map Prod.fst))
          (ConditionalQueueEncoding.scalarBase input (entries.map Prod.fst) (QueueReadback.writeCount (entries.map Prod.snd)))
          (pendingBase input entries) (histogramBase input entries) (budgetBase input entries) length entries) := by
    apply (accounting_block_correct _ _ _ _ _ _ _ _ _ trace head).mpr
    refine And.intro (witness_aux_correct original input entries length heap order) (And.intro budget ?_)
    simpa only [witness_inputs, witness_evaluate, root] using And.intro nonnegative facts
  apply (QueueEncoding.holds_append _ _ _).mpr
  refine And.intro ?_ ((QueueEncoding.holds_append _ _ _).mpr
    (And.intro trace ((QueueEncoding.holds_append _ _ _).mpr (And.intro fields accounting))))
  intro term member
  rw [witness_source_term original input entries length heap order term (List.mem_append_left _ member)]
  exact input_holds term member

theorem encode_complete (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (queue : List Int) (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : QueueStream.concreteFollows queue
      (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate original entries))) :
    exists assignment : Assignment, SmtScript.Holds assignment (encode input entries length) /\
      assignment.constant = original.constant /\
      forall domain result id, Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  have nonnegative : 0 <= length.eval original := by rw [Eq.symm queue_length]; exact Int.natCast_nonneg _
  cases (SignedQueue.signed_exists_iff
    ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval original)).toFinset
    (length.eval original) nonnegative
    (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate original entries))
    (selected_uses original entries) (QueueTraceEncoding.freshFiller _) (QueueTraceEncoding.filler_fresh _)).mpr
      (Exists.intro queue (And.intro queue_length follows)) with
  | intro order witness =>
    cases witness with
    | intro counts spec =>
      let initial : Cursor Int := { counts, window := { head := 0, tail := length.eval original } }
      have replay : ConditionalQueueAccounting.replay order initial (ConditionalQueueEncoding.evaluate original entries) :=
        (ConditionalQueueAccounting.replay_iff _ _ _).mpr ((QueueClause.cursor_iff_signed _ _ _).mpr spec.2)
      cases replay_complete original order entries 0 0 (fun _ => initial) replay with
      | intro heap proof =>
        have root := proof.1 0 (Nat.le_refl _)
        refine Exists.intro (installWitness original input entries length heap order) (And.intro ?_
          (And.intro (witness_constants original input entries length heap order) ?_))
        next =>
          apply witness_satisfies original input entries length heap order input_holds nonnegative
          next => rw [root]
          next => simpa only [root] using spec.1
          next => exact proof.2
        next =>
          intro domain result id member
          exact witness_external original input entries length heap order domain result id member

theorem encode_exists_iff (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input entries length)) <->
      (exists original : Assignment, exists queue : List Int,
        SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
          QueueStream.concreteFollows queue
            (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate original entries))) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input entries length holds
      cases sound.2 with
      | intro queue spec => exact Exists.intro assignment (Exists.intro queue (And.intro sound.1 spec))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro queue spec =>
        cases encode_complete original input entries length queue spec.1 spec.2.1 spec.2.2 with
        | intro assignment proof => exact Exists.intro assignment proof.1

theorem rendered_exists_iff (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) :
    (exists assignment : Assignment, SmtScriptText.runText assignment (render input entries length) = some true) <->
      (exists original : Assignment, exists queue : List Int,
        SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
          QueueStream.concreteFollows queue
            (ConditionalQueueAccounting.select (ConditionalQueueEncoding.evaluate original entries))) := by
  rw [Iff.symm (encode_exists_iff input entries length)]
  apply exists_congr
  intro assignment
  exact (SmtScriptText.formula_text_iff assignment (encode input entries length)).symm

namespace Regression

def fixed (active : Bool) (event : Event InputInt) : Entry := (.boolean active, event)

theorem inactive_pop :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [fixed true (.peek (.literal 0)), fixed false (.pop (.literal 1)),
        fixed true (.send (.literal 0)), fixed true (.length 1)] (.literal 1)) := by
  apply (encode_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro [0] (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [fixed, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term, Term.eval, QueueStream.concreteFollows]

theorem inactive_last_peek :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] [fixed true (.peek (.literal 0)), fixed false (.peek (.literal 1))] (.literal 1)) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro [0] (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [fixed, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term, Term.eval, QueueStream.concreteFollows]

theorem alias_initial_duplicates :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [fixed true (.pop (.symbolic 0)), fixed true (.peek (.symbolic 1)),
        fixed true (.send (.symbolic 1)), fixed true (.length 1)] (.literal 2)) := by
  apply (encode_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro [0, 0] (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [fixed, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term, Term.eval, QueueStream.concreteFollows, QueueEncoding.regressionInput]

theorem outside_initial_peek :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [fixed true (.send (.literal (-4))), fixed true (.peek (.literal (-4)))] (.literal 0)) := by
  apply (encode_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro [] (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [fixed, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term, Term.eval, QueueStream.concreteFollows]

theorem negative_length_rejected (assignment : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : Int) (negative : length < 0) :
    Not (SmtScript.Holds assignment (encode input entries (.literal length))) := by
  intro holds
  cases (encode_sound assignment input entries (.literal length) holds).2 with
  | intro queue spec =>
    have nonnegative := Int.natCast_nonneg queue.length
    have same : (queue.length : Int) = length := spec.1
    omega

theorem arbitrary_initial (queue : List Int) :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [fixed false (.pop (.literal 42)), fixed true (.length queue.length)]
        (.literal (queue.length : Int))) := by
  apply (encode_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro queue (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [fixed, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, Term.eval, QueueStream.concreteFollows]

theorem false_source_guard :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [.not (.app .nodes .bool 31 (.nodes 0))]
        [(.app .nodes .bool 31 (.nodes 0), .pop (.literal 3))] (.literal 0)) /\
      assignment.constant = QueueEncoding.regressionInput.constant /\
      forall domain result id,
        Membership.mem (SmtScript.symbols
          ([.not (.app .nodes .bool 31 (.nodes 0))] ++ [.app .nodes .bool 31 (.nodes 0)]))
          (.unary domain result id) ->
        assignment.unary domain result id = QueueEncoding.regressionInput.unary domain result id := by
  apply encode_complete QueueEncoding.regressionInput _ _ _ []
  next => simp [SmtScript.Holds, Term.eval, QueueEncoding.regressionInput]
  next => rfl
  next =>
    simp [ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      Term.eval, QueueStream.concreteFollows, QueueEncoding.regressionInput]

theorem inactive_pop_length_gap_rejected :
    Not (exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [fixed true (.peek (.literal 0)), fixed false (.pop (.literal 1)),
        fixed true (.send (.literal 0)), fixed true (.length 2)] (.literal 1))) := by
  intro witness
  cases (encode_exists_iff _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro queue spec =>
      have length := spec.2.1
      have follows := spec.2.2
      change (queue.length : Int) = 1 at length
      simp only [fixed, ConditionalQueueEncoding.evaluate, List.map_cons, List.map_nil,
        Term.eval, QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term,
        ConditionalQueueAccounting.select] at follows
      cases queue with
      | nil => simp [QueueStream.concreteFollows] at follows
      | cons head tail =>
        have same : head = 0 := by simpa [QueueStream.concreteFollows] using follows.1
        subst head
        simp [QueueStream.concreteFollows] at follows
        simp only [List.length_cons, Nat.cast_add, Nat.cast_one] at length
        omega

def nativeGuard : Term .bool :=
  .equal (.entryTerm (.app .nodes .entry 11 (.nodes 0))) (.integer 0)

def nativeInput : SmtScript.Formula :=
  [.equal (.entryContent (.app .nodes .entry 11 (.nodes 0))) .signature]

theorem native_domain_and_selectors :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode nativeInput [(nativeGuard, .peek (.literal 0))] (.literal 1)) /\
      assignment.constant = QueueEncoding.regressionInput.constant /\
      forall domain result id, Membership.mem (SmtScript.symbols (nativeInput ++ [nativeGuard])) (.unary domain result id) ->
        assignment.unary domain result id = QueueEncoding.regressionInput.unary domain result id := by
  apply encode_complete QueueEncoding.regressionInput nativeInput [(nativeGuard, .peek (.literal 0))] (.literal 1) [0]
  next => simp [nativeInput, SmtScript.Holds, Term.eval, QueueEncoding.regressionInput]
  next => rfl
  next =>
    simp [nativeGuard, ConditionalQueueEncoding.evaluate, ConditionalQueueAccounting.select,
      QueueScalarEncoding.evalEvent, InputInt.eval, InputInt.term, Term.eval, QueueStream.concreteFollows, QueueEncoding.regressionInput]

end Regression

end CCFRaft.Sparse.ConditionalQueueTraceEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if name.toString.startsWith "CCFRaft.Sparse.ConditionalQueueTraceEncoding." then
      for axiomName in (<- Lean.collectAxioms name) do
        unless [``propext, ``Classical.choice, ``Quot.sound].contains axiomName do
          throwError "disallowed axiom {axiomName} in {name}"
      checked := checked + 1
  Lean.logInfo m!"ConditionalQueueTraceEncoding: {checked} declarations passed the transitive axiom gate"
