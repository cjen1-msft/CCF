import Sparse.ArrayLog

set_option autoImplicit false

namespace CCFRaft.Sparse.IntegerLog

open Sparse.ArrayLog

structure RawEntry where
  term : Int
  content : EntryContent Node Int
  deriving DecidableEq

def decodeContent : EntryContent Node Int -> EntryContent Node Nat
  | .transaction tx => .transaction tx.toNat
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration nodes
  | .retiredCommitted nodes => .retiredCommitted nodes

def encodeContent : EntryContent Node Nat -> EntryContent Node Int
  | .transaction tx => .transaction (tx : Int)
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration nodes
  | .retiredCommitted nodes => .retiredCommitted nodes

def decodeEntry (entry : RawEntry) : LogEntry :=
  { term := entry.term.toNat, content := decodeContent entry.content }

def encodeEntry (entry : LogEntry) : RawEntry :=
  { term := (entry.term : Int), content := encodeContent entry.content }

@[simp] theorem decode_encode_entry (entry : LogEntry) :
    decodeEntry (encodeEntry entry) = entry := by
  cases entry with
  | mk term content =>
    cases content <;> simp [decodeEntry, encodeEntry, decodeContent, encodeContent]

structure RawArrayLog where
  length : Nat
  entries : Nat -> RawEntry

def RawArrayLog.read (log : RawArrayLog) (index : Nat) : Option RawEntry :=
  if index < log.length then some (log.entries index) else none

def RawArrayLog.append (log : RawArrayLog) (entry : RawEntry) : RawArrayLog :=
  { length := log.length + 1
    entries := Function.update log.entries log.length entry }

def RawArrayLog.truncate (log : RawArrayLog) (length : Nat) : RawArrayLog :=
  { log with length := min length log.length }

def decodeLog (log : RawArrayLog) : ArrayLog :=
  { length := log.length, entries := fun index => decodeEntry (log.entries index) }

def encodeLog (log : ArrayLog) : RawArrayLog :=
  { length := log.length, entries := fun index => encodeEntry (log.entries index) }

@[simp] theorem decode_encode_log (log : ArrayLog) :
    decodeLog (encodeLog log) = log := by
  cases log
  simp [decodeLog, encodeLog]

theorem decode_append (log : RawArrayLog) (entry : RawEntry) :
    decodeLog (log.append entry) = (decodeLog log).append (decodeEntry entry) := by
  unfold decodeLog RawArrayLog.append ArrayLog.append
  congr 1
  funext index
  by_cases same : index = log.length <;> simp [same, Function.update]

theorem encode_append (log : ArrayLog) (entry : LogEntry) :
    encodeLog (log.append entry) = (encodeLog log).append (encodeEntry entry) := by
  unfold encodeLog RawArrayLog.append ArrayLog.append
  congr 1
  funext index
  by_cases same : index = log.length <;> simp [same, Function.update]

theorem decode_truncate (log : RawArrayLog) (length : Nat) :
    decodeLog (log.truncate length) = (decodeLog log).truncate length := rfl

theorem encode_truncate (log : ArrayLog) (length : Nat) :
    encodeLog (log.truncate length) = (encodeLog log).truncate length := rfl

theorem decode_read (log : RawArrayLog) (index : Nat) :
    (decodeLog log).read index = (log.read index).map decodeEntry := by
  simp [decodeLog, ArrayLog.read, RawArrayLog.read]

theorem encode_read (log : ArrayLog) (index : Nat) :
    (encodeLog log).read index = (log.read index).map encodeEntry := by
  simp [encodeLog, ArrayLog.read, RawArrayLog.read]

abbrev RawHeap := Nat -> RawArrayLog

def decodeHeap (heap : RawHeap) : Heap := fun id => decodeLog (heap id)
def encodeHeap (heap : Heap) : RawHeap := fun id => encodeLog (heap id)

-- The parent's clauses and compiler are reused without extra validity clauses.
def SourceClauseHolds (heap : RawHeap) : Clause -> Prop
  | .append source target entry =>
      heap target = (heap source).append (encodeEntry entry)
  | .truncate source target length =>
      heap target = (heap source).truncate length
  | .observe source index expected =>
      (if index = 0 then none else (heap source).read (index - 1)) =
        expected.map encodeEntry

def SourceHolds (heap : RawHeap) : List Clause -> Prop
  | [] => True
  | clause :: rest => SourceClauseHolds heap clause /\ SourceHolds heap rest

theorem source_clause_sound (heap : RawHeap) (clause : Clause)
    (holds : SourceClauseHolds heap clause) :
    clause.Holds (decodeHeap heap) := by
  cases clause with
  | append source target entry =>
    have mapped := congrArg decodeLog holds
    simpa [Clause.Holds, decodeHeap, decode_append] using mapped
  | truncate source target length =>
    have mapped := congrArg decodeLog holds
    simpa [Clause.Holds, decodeHeap, decode_truncate] using mapped
  | observe source index expected =>
    have mapped := congrArg (Option.map decodeEntry) holds
    cases expected <;>
      by_cases zero : index = 0 <;>
      simp_all [SourceClauseHolds, Clause.Holds, decodeHeap, decode_read]

theorem source_clause_complete (heap : Heap) (clause : Clause)
    (holds : clause.Holds heap) :
    SourceClauseHolds (encodeHeap heap) clause := by
  cases clause with
  | append source target entry =>
    have mapped := congrArg encodeLog holds
    simpa [SourceClauseHolds, encodeHeap, encode_append] using mapped
  | truncate source target length =>
    have mapped := congrArg encodeLog holds
    simpa [SourceClauseHolds, encodeHeap, encode_truncate] using mapped
  | observe source index expected =>
    have mapped := congrArg (Option.map encodeEntry) holds
    by_cases zero : index = 0 <;>
      simpa [SourceClauseHolds, Clause.Holds, encodeHeap, encode_read, zero] using mapped

theorem source_sound (heap : RawHeap) (clauses : List Clause)
    (holds : SourceHolds heap clauses) : Holds (decodeHeap heap) clauses := by
  induction clauses with
  | nil => trivial
  | cons clause rest ih =>
    exact And.intro (source_clause_sound heap clause holds.1) (ih holds.2)

theorem source_complete (heap : Heap) (clauses : List Clause)
    (holds : Holds heap clauses) : SourceHolds (encodeHeap heap) clauses := by
  induction clauses with
  | nil => trivial
  | cons clause rest ih =>
    exact And.intro (source_clause_complete heap clause holds.1) (ih holds.2)

theorem raw_exists_iff_typed (clauses : List Clause) :
    (Exists fun heap : RawHeap => SourceHolds heap clauses) <->
      (Exists fun heap : Heap => Holds heap clauses) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro heap holds =>
      exact Exists.intro (decodeHeap heap) (source_sound heap clauses holds)
  next =>
    intro witness
    cases witness with
    | intro heap holds =>
      exact Exists.intro (encodeHeap heap) (source_complete heap clauses holds)

theorem raw_compiled_exists_iff (trace : List Instruction) :
    (Exists fun heap : RawHeap => SourceHolds heap (compile 0 1 trace)) <->
      (Exists fun initial : List LogEntry => concreteFollows initial trace) := by
  rw [raw_exists_iff_typed]
  exact compiled_exists_iff trace

-- Negative cells can occur inside the initial length without being observed.
def zeroEntry : LogEntry := { term := 0, content := .transaction 0 }
def negativeEntry : RawEntry := { term := -1, content := .transaction (-2) }

def negativeUnusedLog : RawArrayLog :=
  { length := 2
    entries := fun index => if index = 0 then encodeEntry zeroEntry else negativeEntry }

theorem negative_unused_cell_allowed :
    SourceHolds (fun _ => negativeUnusedLog) [.observe 0 1 (some zeroEntry)] /\
      1 < negativeUnusedLog.length /\
      (negativeUnusedLog.entries 1).term < 0 /\
      (negativeUnusedLog.entries 1).content = .transaction (-2) := by
  norm_num [SourceHolds, SourceClauseHolds, negativeUnusedLog, RawArrayLog.read,
    negativeEntry]

-- Decoding is a retraction, not an injection or a per-heap equivalence.
theorem decode_not_injective :
    Not (negativeEntry = encodeEntry zeroEntry) /\
      decodeEntry negativeEntry = decodeEntry (encodeEntry zeroEntry) := by
  constructor
  next =>
    intro same
    have terms := congrArg RawEntry.term same
    norm_num [negativeEntry, encodeEntry, zeroEntry] at terms
  next => rfl

theorem decoded_observation_not_reflected :
    let heap : RawHeap := fun _ => { length := 1, entries := fun _ => negativeEntry }
    let clause : Clause := .observe 0 1 (some zeroEntry)
    clause.Holds (decodeHeap heap) /\ Not (SourceClauseHolds heap clause) := by
  constructor
  next => rfl
  next =>
    intro holds
    have same : negativeEntry = encodeEntry zeroEntry := Option.some.inj holds
    exact decode_not_injective.1 same

end CCFRaft.Sparse.IntegerLog

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.IntegerLog.decode_encode_entry,
      ``CCFRaft.Sparse.IntegerLog.decode_encode_log,
      ``CCFRaft.Sparse.IntegerLog.decode_append,
      ``CCFRaft.Sparse.IntegerLog.encode_append,
      ``CCFRaft.Sparse.IntegerLog.decode_truncate,
      ``CCFRaft.Sparse.IntegerLog.encode_truncate,
      ``CCFRaft.Sparse.IntegerLog.decode_read,
      ``CCFRaft.Sparse.IntegerLog.encode_read,
      ``CCFRaft.Sparse.IntegerLog.source_sound,
      ``CCFRaft.Sparse.IntegerLog.source_complete,
      ``CCFRaft.Sparse.IntegerLog.raw_exists_iff_typed,
      ``CCFRaft.Sparse.IntegerLog.raw_compiled_exists_iff,
      ``CCFRaft.Sparse.IntegerLog.negative_unused_cell_allowed,
      ``CCFRaft.Sparse.IntegerLog.decode_not_injective,
      ``CCFRaft.Sparse.IntegerLog.decoded_observation_not_reflected] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
