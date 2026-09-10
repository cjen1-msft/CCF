import Model
import Mathlib.Data.List.OfFn

set_option autoImplicit false

namespace CCFRaft.Sparse.ArrayLog

-- Semantic model for a future SSA array encoding, not its runtime data structure.
-- decode constructs a concrete witness in proofs; the SMT encoder must not call it.
abbrev LogEntry := Entry Node Nat

structure ArrayLog where
  length : Nat
  entries : Nat -> LogEntry

def ArrayLog.decode (log : ArrayLog) : List LogEntry :=
  List.ofFn (fun i : Fin log.length => log.entries i.val)

def ArrayLog.read (log : ArrayLog) (index : Nat) : Option LogEntry :=
  if index < log.length then some (log.entries index) else none

def ArrayLog.ofList (log : List LogEntry) (default : LogEntry) : ArrayLog :=
  { length := log.length
    entries := fun i => log[i]?.getD default }

def ArrayLog.append (log : ArrayLog) (entry : LogEntry) : ArrayLog :=
  { length := log.length + 1
    entries := Function.update log.entries log.length entry }

def ArrayLog.truncate (log : ArrayLog) (length : Nat) : ArrayLog :=
  { log with length := min length log.length }

theorem decode_length (log : ArrayLog) :
    log.decode.length = log.length := by
  simp [ArrayLog.decode]

theorem decode_read (log : ArrayLog) (index : Nat) (within : index < log.length) :
    log.decode[index]? = some (log.entries index) := by
  simp [ArrayLog.decode, within]

theorem decode_read_all (log : ArrayLog) (index : Nat) :
    log.decode[index]? = log.read index := by
  simp [ArrayLog.decode, ArrayLog.read]

theorem model_entryAt (log : ArrayLog) (index : Nat) :
    entryAt? log.decode index =
      if index = 0 then none else log.read (index - 1) := by
  simp [entryAt?, decode_read_all]

theorem decode_ofList (log : List LogEntry) (default : LogEntry) :
    (ArrayLog.ofList log default).decode = log := by
  simp [ArrayLog.ofList, ArrayLog.decode, List.ofFn_getElem]

theorem decode_append (log : ArrayLog) (entry : LogEntry) :
    (log.append entry).decode = log.decode ++ [entry] := by
  simp only [ArrayLog.append, ArrayLog.decode, List.ofFn_succ',
    List.concat_eq_append, Fin.val_last, Fin.val_castSucc, Function.update_self]
  congr 1
  apply congrArg List.ofFn
  funext i
  simp [Function.update_of_ne (Nat.ne_of_lt i.isLt)]

theorem decode_truncate (log : ArrayLog) (length : Nat) :
    (log.truncate length).decode = log.decode.take length := by
  apply List.ext_getElem
  next => simp [ArrayLog.truncate, ArrayLog.decode]
  next =>
    intro i left right
    simp [ArrayLog.truncate, ArrayLog.decode]

theorem concrete_exists (log : ArrayLog) :
    Exists fun concrete : List LogEntry =>
      concrete.length = log.length /\
      forall index, index < log.length ->
        concrete[index]? = some (log.entries index) :=
  Exists.intro log.decode (And.intro (decode_length log) (decode_read log))

theorem every_concrete_representable (log : List LogEntry) :
    Exists fun symbolic : ArrayLog => symbolic.decode = log :=
  Exists.intro (ArrayLog.ofList log { term := 0, content := .signature })
    (decode_ofList log _)

def Consistent (facts : List (Prod Nat LogEntry)) : Prop :=
  forall left, List.Mem left facts -> forall right, List.Mem right facts ->
    left.1 = right.1 -> left.2 = right.2

noncomputable def completeCells (facts : List (Prod Nat LogEntry)) (index : Nat) :
    LogEntry := by
  classical
  exact if existsValue : Exists fun entry => List.Mem (index, entry) facts then
      Classical.choose existsValue
    else
      { term := 0, content := .signature }

theorem completeCells_read (facts : List (Prod Nat LogEntry))
    (consistent : Consistent facts) (index : Nat) (entry : LogEntry)
    (present : List.Mem (index, entry) facts) :
    completeCells facts index = entry := by
  have existsValue : Exists fun value => List.Mem (index, value) facts :=
    Exists.intro entry present
  simp only [completeCells, dif_pos existsValue]
  exact consistent (index, Classical.choose existsValue)
    (Classical.choose_spec existsValue) (index, entry) present rfl

def ConcreteFacts (log : List LogEntry) (facts : List (Prod Nat LogEntry)) : Prop :=
  forall fact, List.Mem fact facts ->
    fact.1 < log.length /\ log[fact.1]? = some fact.2

theorem sparse_facts_exact (length : Nat) (facts : List (Prod Nat LogEntry)) :
    (Exists fun log : List LogEntry => log.length = length /\ ConcreteFacts log facts) <->
      (forall fact, List.Mem fact facts -> fact.1 < length) /\ Consistent facts := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro log evidence =>
      constructor
      next =>
        intro fact present
        rw [<- evidence.1]
        exact (evidence.2 fact present).1
      next =>
        intro left leftPresent right rightPresent sameIndex
        have sameRead := (evidence.2 left leftPresent).2
        rw [sameIndex, (evidence.2 right rightPresent).2] at sameRead
        exact (Option.some.inj sameRead).symm
  next =>
    intro evidence
    let represented : ArrayLog :=
      { length, entries := completeCells facts }
    refine Exists.intro represented.decode (And.intro (decode_length represented) ?_)
    intro fact present
    have within := evidence.1 fact present
    constructor
    next => simpa [decode_length, represented] using within
    next =>
      rw [decode_read represented fact.1 within]
      exact congrArg some (completeCells_read facts evidence.2 fact.1 fact.2 present)

inductive Instruction where
  | append (entry : LogEntry)
  | truncate (length : Nat)
  | observe (index : Nat) (expected : Option LogEntry)

def arrayFollows (log : ArrayLog) : List Instruction -> Prop
  | [] => True
  | .append entry :: rest => arrayFollows (log.append entry) rest
  | .truncate length :: rest => arrayFollows (log.truncate length) rest
  | .observe index expected :: rest =>
      (if index = 0 then none else log.read (index - 1)) = expected /\
        arrayFollows log rest

def concreteFollows (log : List LogEntry) : List Instruction -> Prop
  | [] => True
  | .append entry :: rest => concreteFollows (log ++ [entry]) rest
  | .truncate length :: rest => concreteFollows (log.take length) rest
  | .observe index expected :: rest =>
      entryAt? log index = expected /\ concreteFollows log rest

theorem follows_correct (log : ArrayLog) (trace : List Instruction) :
    arrayFollows log trace <-> concreteFollows log.decode trace := by
  induction trace generalizing log with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction <;>
      simp [arrayFollows, concreteFollows, ih, decode_append, decode_truncate,
        model_entryAt]

theorem trace_exists_iff (trace : List Instruction) :
    (Exists fun initial : ArrayLog => arrayFollows initial trace) <->
      (Exists fun initial : List LogEntry => concreteFollows initial trace) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro initial follows =>
      exact Exists.intro initial.decode ((follows_correct initial trace).mp follows)
  next =>
    intro witness
    cases witness with
    | intro initial follows =>
      let represented := ArrayLog.ofList initial { term := 0, content := .signature }
      refine Exists.intro represented ((follows_correct represented trace).mpr ?_)
      simpa [represented, decode_ofList] using follows

-- Clauses retain state IDs, never predecessor expressions.
inductive Clause where
  | append (source target : Nat) (entry : LogEntry)
  | truncate (source target length : Nat)
  | observe (source index : Nat) (expected : Option LogEntry)

abbrev Heap := Nat -> ArrayLog

def Clause.Holds (heap : Heap) : Clause -> Prop
  | .append source target entry => heap target = (heap source).append entry
  | .truncate source target length => heap target = (heap source).truncate length
  | .observe source index expected =>
      (if index = 0 then none else (heap source).read (index - 1)) = expected

def Holds (heap : Heap) : List Clause -> Prop
  | [] => True
  | clause :: rest => clause.Holds heap /\ Holds heap rest

def compile (current next : Nat) : List Instruction -> List Clause
  | [] => []
  | .append entry :: rest => .append current next entry :: compile next (next + 1) rest
  | .truncate length :: rest =>
      .truncate current next length :: compile next (next + 1) rest
  | .observe index expected :: rest =>
      .observe current index expected :: compile current next rest

theorem compile_length (trace : List Instruction) (current next : Nat) :
    (compile current next trace).length = trace.length := by
  induction trace generalizing current next with
  | nil => rfl
  | cons instruction rest ih =>
    cases instruction <;> simp [compile, ih]

theorem compile_sound (trace : List Instruction) (current next : Nat) (heap : Heap)
    (holds : Holds heap (compile current next trace)) :
    arrayFollows (heap current) trace := by
  induction trace generalizing current next with
  | nil => trivial
  | cons instruction rest ih =>
    cases instruction with
    | append entry =>
      have follows := ih next (next + 1) holds.2
      have link : heap next = (heap current).append entry := holds.1
      simpa [arrayFollows, link] using follows
    | truncate length =>
      have follows := ih next (next + 1) holds.2
      have link : heap next = (heap current).truncate length := holds.1
      simpa [arrayFollows, link] using follows
    | observe index expected =>
      exact And.intro holds.1 (ih current next holds.2)

theorem compile_complete (trace : List Instruction) (current next : Nat)
    (fresh : current < next) (heap : Heap)
    (follows : arrayFollows (heap current) trace) :
    Exists fun extended : Heap =>
      (forall index, index < next -> extended index = heap index) /\
      Holds extended (compile current next trace) := by
  induction trace generalizing current next heap with
  | nil => exact Exists.intro heap (And.intro (by intros; rfl) trivial)
  | cons instruction rest ih =>
    cases instruction with
    | append entry =>
      let updated := Function.update heap next ((heap current).append entry)
      have ready : arrayFollows (updated next) rest := by
        simpa [updated, arrayFollows] using follows
      obtain witness := ih next (next + 1) (by omega) updated ready
      cases witness with
      | intro extended evidence =>
        refine Exists.intro extended (And.intro ?_ (And.intro ?_ evidence.2))
        next =>
          intro index before
          rw [evidence.1 index (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt before)]
        next =>
          change extended next = (extended current).append entry
          rw [evidence.1 next (by omega), evidence.1 current (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt fresh)]
    | truncate length =>
      let updated := Function.update heap next ((heap current).truncate length)
      have ready : arrayFollows (updated next) rest := by
        simpa [updated, arrayFollows] using follows
      obtain witness := ih next (next + 1) (by omega) updated ready
      cases witness with
      | intro extended evidence =>
        refine Exists.intro extended (And.intro ?_ (And.intro ?_ evidence.2))
        next =>
          intro index before
          rw [evidence.1 index (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt before)]
        next =>
          change extended next = (extended current).truncate length
          rw [evidence.1 next (by omega), evidence.1 current (by omega)]
          simp [updated, Function.update_of_ne (Nat.ne_of_lt fresh)]
    | observe index expected =>
      obtain witness := ih current next fresh heap follows.2
      cases witness with
      | intro extended evidence =>
        refine Exists.intro extended (And.intro evidence.1 (And.intro ?_ evidence.2))
        change
          (if index = 0 then none else (extended current).read (index - 1)) = expected
        rw [evidence.1 current fresh]
        exact follows.1

theorem compiled_exists_iff (trace : List Instruction) :
    (Exists fun heap : Heap => Holds heap (compile 0 1 trace)) <->
      (Exists fun initial : List LogEntry => concreteFollows initial trace) := by
  rw [<- trace_exists_iff]
  constructor
  next =>
    intro witness
    cases witness with
    | intro heap holds =>
      exact Exists.intro (heap 0) (compile_sound trace 0 1 heap holds)
  next =>
    intro witness
    cases witness with
    | intro initial follows =>
      obtain extended := compile_complete trace 0 1 (by omega) (fun _ => initial) follows
      cases extended with
      | intro heap evidence => exact Exists.intro heap evidence.2

end CCFRaft.Sparse.ArrayLog

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.ArrayLog.decode_read_all,
      ``CCFRaft.Sparse.ArrayLog.model_entryAt,
      ``CCFRaft.Sparse.ArrayLog.decode_append,
      ``CCFRaft.Sparse.ArrayLog.decode_truncate,
      ``CCFRaft.Sparse.ArrayLog.concrete_exists,
      ``CCFRaft.Sparse.ArrayLog.every_concrete_representable,
      ``CCFRaft.Sparse.ArrayLog.sparse_facts_exact,
      ``CCFRaft.Sparse.ArrayLog.trace_exists_iff,
      ``CCFRaft.Sparse.ArrayLog.compile_length,
      ``CCFRaft.Sparse.ArrayLog.compiled_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
