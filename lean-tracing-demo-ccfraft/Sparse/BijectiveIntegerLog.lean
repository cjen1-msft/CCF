import Sparse.IntegerLog
import Mathlib.Logic.Equiv.Nat

set_option autoImplicit false

namespace CCFRaft.Sparse.BijectiveIntegerLog

open Sparse.ArrayLog

def decodeNat : Int -> Nat := Equiv.intEquivNat
def encodeNat : Nat -> Int := Equiv.intEquivNat.symm

-- Integer-only arithmetic corresponding to an SMT ite expression.
def smtDecode (z : Int) : Int := if 0 <= z then 2 * z else -2 * z - 1

@[simp] theorem decode_encode_nat (n : Nat) : decodeNat (encodeNat n) = n :=
  Equiv.intEquivNat.apply_symm_apply n

@[simp] theorem encode_decode_int (z : Int) : encodeNat (decodeNat z) = z :=
  Equiv.intEquivNat.symm_apply_apply z

theorem decode_formula (z : Int) : (decodeNat z : Int) = smtDecode z := by
  cases z with
  | ofNat n =>
    change ((2 * n : Nat) : Int) = smtDecode (Int.ofNat n)
    simp [smtDecode]
  | negSucc n =>
    change ((2 * n + 1 : Nat) : Int) = smtDecode (Int.negSucc n)
    simp [smtDecode, Int.negSucc_eq]
    omega

theorem smt_decode_nonnegative (z : Int) : 0 <= smtDecode z := by
  rw [<- decode_formula]
  omega

theorem encode_formula (n : Nat) :
    encodeNat n =
      if n % 2 = 0 then ((n / 2 : Nat) : Int) else -((n / 2 : Nat) : Int) - 1 := by
  let candidate : Int :=
    if n % 2 = 0 then (n / 2 : Nat) else -((n / 2 : Nat) : Int) - 1
  have valid : smtDecode candidate = (n : Int) := by
    dsimp [candidate, smtDecode]
    split_ifs <;> omega
  have decoded : decodeNat candidate = n := by
    have formula := decode_formula candidate
    omega
  change encodeNat n = candidate
  calc
    encodeNat n = encodeNat (decodeNat candidate) := congrArg encodeNat decoded.symm
    _ = candidate := encode_decode_int candidate

theorem scalar_eq_iff (a b : Int) : decodeNat a = decodeNat b <-> a = b :=
  Equiv.intEquivNat.injective.eq_iff

theorem scalar_ne_iff (a b : Int) :
    Not (decodeNat a = decodeNat b) <-> Not (a = b) :=
  not_congr (scalar_eq_iff a b)

theorem decoded_order_iff (a b : Int) :
    decodeNat a < decodeNat b <-> smtDecode a < smtDecode b := by
  rw [<- decode_formula, <- decode_formula]
  omega

theorem literal_one : encodeNat 1 = -1 := by
  rw [encode_formula]
  norm_num

theorem raw_order_not_preserved :
    (-1 : Int) < 0 /\ decodeNat 0 < decodeNat (-1) := by decide

-- Reuse storage shapes and operations, not the earlier clamping or cast literals.
abbrev RawEntry := Sparse.IntegerLog.RawEntry
abbrev RawArrayLog := Sparse.IntegerLog.RawArrayLog
abbrev RawHeap := Sparse.IntegerLog.RawHeap

def decodeContent : EntryContent Node Int -> EntryContent Node Nat
  | .transaction tx => .transaction (decodeNat tx)
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration nodes
  | .retiredCommitted nodes => .retiredCommitted nodes

def encodeContent : EntryContent Node Nat -> EntryContent Node Int
  | .transaction tx => .transaction (encodeNat tx)
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration nodes
  | .retiredCommitted nodes => .retiredCommitted nodes

@[simp] theorem decode_encode_content (content : EntryContent Node Nat) :
    decodeContent (encodeContent content) = content := by
  cases content <;> simp [decodeContent, encodeContent]

@[simp] theorem encode_decode_content (content : EntryContent Node Int) :
    encodeContent (decodeContent content) = content := by
  cases content <;> simp [decodeContent, encodeContent]

def contentEquiv : Equiv (EntryContent Node Int) (EntryContent Node Nat) where
  toFun := decodeContent
  invFun := encodeContent
  left_inv := encode_decode_content
  right_inv := decode_encode_content

def decodeEntry (entry : RawEntry) : LogEntry :=
  { term := decodeNat entry.term, content := decodeContent entry.content }

def encodeEntry (entry : LogEntry) : RawEntry :=
  { term := encodeNat entry.term, content := encodeContent entry.content }

@[simp] theorem decode_encode_entry (entry : LogEntry) :
    decodeEntry (encodeEntry entry) = entry := by
  cases entry
  simp [decodeEntry, encodeEntry]

@[simp] theorem encode_decode_entry (entry : RawEntry) :
    encodeEntry (decodeEntry entry) = entry := by
  cases entry
  simp [decodeEntry, encodeEntry]

def entryEquiv : Equiv RawEntry LogEntry where
  toFun := decodeEntry
  invFun := encodeEntry
  left_inv := encode_decode_entry
  right_inv := decode_encode_entry

theorem entry_eq_iff (a b : RawEntry) : decodeEntry a = decodeEntry b <-> a = b :=
  entryEquiv.injective.eq_iff

theorem entry_ne_iff (a b : RawEntry) :
    Not (decodeEntry a = decodeEntry b) <-> Not (a = b) :=
  not_congr (entry_eq_iff a b)

def arrayEquiv : Equiv (Nat -> RawEntry) (Nat -> LogEntry) :=
  Equiv.arrowCongr (Equiv.refl Nat) entryEquiv

theorem array_eq_iff (a b : Nat -> RawEntry) :
    (fun index => decodeEntry (a index)) = (fun index => decodeEntry (b index)) <->
      a = b :=
  arrayEquiv.injective.eq_iff

theorem array_ne_iff (a b : Nat -> RawEntry) :
    Not ((fun index => decodeEntry (a index)) = (fun index => decodeEntry (b index))) <->
      Not (a = b) :=
  not_congr (array_eq_iff a b)

def decodeLog (log : RawArrayLog) : ArrayLog :=
  { length := log.length, entries := fun index => decodeEntry (log.entries index) }

def encodeLog (log : ArrayLog) : RawArrayLog :=
  { length := log.length, entries := fun index => encodeEntry (log.entries index) }

@[simp] theorem decode_encode_log (log : ArrayLog) :
    decodeLog (encodeLog log) = log := by
  cases log
  simp [decodeLog, encodeLog]

@[simp] theorem encode_decode_log (log : RawArrayLog) :
    encodeLog (decodeLog log) = log := by
  cases log
  simp [decodeLog, encodeLog]

def logEquiv : Equiv RawArrayLog ArrayLog where
  toFun := decodeLog
  invFun := encodeLog
  left_inv := encode_decode_log
  right_inv := decode_encode_log

theorem log_eq_iff (a b : RawArrayLog) : decodeLog a = decodeLog b <-> a = b :=
  logEquiv.injective.eq_iff

theorem log_ne_iff (a b : RawArrayLog) :
    Not (decodeLog a = decodeLog b) <-> Not (a = b) :=
  not_congr (log_eq_iff a b)

theorem decode_append (log : RawArrayLog) (entry : RawEntry) :
    decodeLog (log.append entry) = (decodeLog log).append (decodeEntry entry) := by
  unfold decodeLog Sparse.IntegerLog.RawArrayLog.append ArrayLog.append
  congr 1
  funext index
  by_cases same : index = log.length <;> simp [same, Function.update]

theorem decode_truncate (log : RawArrayLog) (length : Nat) :
    decodeLog (log.truncate length) = (decodeLog log).truncate length := rfl

theorem decode_read (log : RawArrayLog) (index : Nat) :
    (decodeLog log).read index = (log.read index).map decodeEntry := by
  simp [decodeLog, ArrayLog.read, Sparse.IntegerLog.RawArrayLog.read]

theorem option_literal_iff (actual : Option RawEntry) (expected : Option LogEntry) :
    actual = expected.map encodeEntry <-> actual.map decodeEntry = expected := by
  constructor
  next =>
    intro same
    rw [same]
    cases expected <;> simp
  next =>
    intro same
    have mapped := congrArg (Option.map encodeEntry) same
    cases actual <;> simpa using mapped

theorem option_literal_ne_iff (actual : Option RawEntry) (expected : Option LogEntry) :
    Not (actual = expected.map encodeEntry) <->
      Not (actual.map decodeEntry = expected) :=
  not_congr (option_literal_iff actual expected)

def decodeHeap (heap : RawHeap) : Heap := fun id => decodeLog (heap id)
def encodeHeap (heap : Heap) : RawHeap := fun id => encodeLog (heap id)

@[simp] theorem decode_encode_heap (heap : Heap) :
    decodeHeap (encodeHeap heap) = heap := by
  funext id
  exact decode_encode_log (heap id)

@[simp] theorem encode_decode_heap (heap : RawHeap) :
    encodeHeap (decodeHeap heap) = heap := by
  funext id
  exact encode_decode_log (heap id)

-- Literal entries use zigzag encoding here, never the earlier natural casts.
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

theorem source_clause_iff (heap : RawHeap) (clause : Clause) :
    SourceClauseHolds heap clause <-> clause.Holds (decodeHeap heap) := by
  cases clause with
  | append source target entry =>
    change heap target = (heap source).append (encodeEntry entry) <->
      decodeLog (heap target) = (decodeLog (heap source)).append entry
    rw [<- log_eq_iff, decode_append, decode_encode_entry]
  | truncate source target length =>
    change heap target = (heap source).truncate length <->
      decodeLog (heap target) = (decodeLog (heap source)).truncate length
    rw [<- log_eq_iff, decode_truncate]
  | observe source index expected =>
    simp only [SourceClauseHolds, Clause.Holds, decodeHeap, decode_read]
    rw [option_literal_iff]
    by_cases zero : index = 0 <;> simp [zero]

theorem source_holds_iff (heap : RawHeap) (clauses : List Clause) :
    SourceHolds heap clauses <-> Holds (decodeHeap heap) clauses := by
  induction clauses with
  | nil => rfl
  | cons clause rest ih => simp only [SourceHolds, Holds, source_clause_iff, ih]

theorem raw_exists_iff_typed (clauses : List Clause) :
    (Exists fun heap : RawHeap => SourceHolds heap clauses) <->
      (Exists fun heap : Heap => Holds heap clauses) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro heap holds =>
      exact Exists.intro (decodeHeap heap) ((source_holds_iff heap clauses).mp holds)
  next =>
    intro witness
    cases witness with
    | intro heap holds =>
      refine Exists.intro (encodeHeap heap) ((source_holds_iff _ clauses).mpr ?_)
      simpa using holds

theorem raw_compiled_exists_iff (trace : List Instruction) :
    (Exists fun heap : RawHeap => SourceHolds heap (compile 0 1 trace)) <->
      (Exists fun initial : List LogEntry => concreteFollows initial trace) := by
  rw [raw_exists_iff_typed]
  exact compiled_exists_iff trace

end CCFRaft.Sparse.BijectiveIntegerLog

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_encode_nat,
      ``CCFRaft.Sparse.BijectiveIntegerLog.encode_decode_int,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_formula,
      ``CCFRaft.Sparse.BijectiveIntegerLog.smt_decode_nonnegative,
      ``CCFRaft.Sparse.BijectiveIntegerLog.encode_formula,
      ``CCFRaft.Sparse.BijectiveIntegerLog.scalar_eq_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.scalar_ne_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decoded_order_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.literal_one,
      ``CCFRaft.Sparse.BijectiveIntegerLog.raw_order_not_preserved,
      ``CCFRaft.Sparse.BijectiveIntegerLog.contentEquiv,
      ``CCFRaft.Sparse.BijectiveIntegerLog.entryEquiv,
      ``CCFRaft.Sparse.BijectiveIntegerLog.entry_eq_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.entry_ne_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.arrayEquiv,
      ``CCFRaft.Sparse.BijectiveIntegerLog.array_eq_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.array_ne_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.logEquiv,
      ``CCFRaft.Sparse.BijectiveIntegerLog.log_eq_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.log_ne_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_append,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_truncate,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_read,
      ``CCFRaft.Sparse.BijectiveIntegerLog.option_literal_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.option_literal_ne_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_encode_heap,
      ``CCFRaft.Sparse.BijectiveIntegerLog.encode_decode_heap,
      ``CCFRaft.Sparse.BijectiveIntegerLog.source_clause_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.source_holds_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.raw_exists_iff_typed,
      ``CCFRaft.Sparse.BijectiveIntegerLog.raw_compiled_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
  Lean.logInfo "Sparse bijective integer proof audit passed."
