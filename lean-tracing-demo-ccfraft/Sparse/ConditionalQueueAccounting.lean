import Sparse.QueueClause
import Sparse.QueueAccounting

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueAccounting

open QueueStream (Event segment)
open CountedQueue (readHeads)

variable {A : Type}

abbrev GuardedEvent (A : Type) := Prod Bool (Event A)

def select : List (GuardedEvent A) -> List (Event A)
  | [] => []
  | (false, _) :: rest => select rest
  | (true, event) :: rest => event :: select rest

theorem select_length_le (entries : List (GuardedEvent A)) :
    (select entries).length <= entries.length := by
  induction entries with
  | nil => simp [select]
  | cons entry rest ih =>
    cases entry with
    | mk active event => cases active <;> simp [select] <;> omega

theorem fold_select {S : Type} (step : S -> Event A -> S) (state : S)
    (entries : List (GuardedEvent A)) :
    entries.foldl (fun current entry => if entry.1 then step current entry.2 else current) state =
      (select entries).foldl step state := by
  induction entries generalizing state with
  | nil => rfl
  | cons entry rest ih =>
    cases entry with
    | mk active event => cases active <;> simp [select, List.foldl_cons, ih]

def popKeys : List (Event A) -> List A
  | [] => []
  | .pop key :: rest => key :: popKeys rest
  | _ :: rest => popKeys rest

theorem read_heads_append (trace : List (Event A)) (event : Event A) :
    readHeads (trace ++ [event]) =
      match event with
      | .send _ | .length _ => readHeads trace
      | .pop key | .peek key => popKeys trace ++ [key] := by
  induction trace with
  | nil => cases event <;> rfl
  | cons prior rest ih =>
    cases prior <;> cases event <;> simp [readHeads, popKeys, ih]
    all_goals cases popKeys rest <;> rfl

theorem read_heads_take_pops (trace : List (Event A)) :
    (readHeads trace).take (popKeys trace).length = popKeys trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send key => exact ih
    | length length => exact ih
    | pop key => simpa [readHeads, popKeys] using congrArg (List.cons key) ih
    | peek key =>
      cases heads : readHeads rest with
      | nil =>
        have empty : popKeys rest = [] := by simpa [heads] using ih.symm
        simp [readHeads, popKeys, heads, empty]
      | cons head tail => simpa [readHeads, popKeys, heads] using ih

section Cursor

variable [DecidableEq A]

def replay (order : Int -> A) : QueueClause.Cursor A -> List (GuardedEvent A) -> Prop
  | _, [] => True
  | cursor, (false, _) :: rest => replay order cursor rest
  | cursor, (true, event) :: rest =>
    QueueClause.guard order cursor event /\
      replay order (QueueClause.advance cursor event) rest

theorem replay_iff (order : Int -> A) (cursor : QueueClause.Cursor A)
    (entries : List (GuardedEvent A)) :
    replay order cursor entries <-> QueueClause.cursorFollows order cursor (select entries) := by
  induction entries generalizing cursor with
  | nil => rfl
  | cons entry rest ih =>
    cases entry with
    | mk active event => cases active <;> simp [replay, select, QueueClause.cursorFollows, ih]

def cursorAfter (cursor : QueueClause.Cursor A) (entries : List (GuardedEvent A)) :
    QueueClause.Cursor A :=
  entries.foldl (fun current entry =>
    if entry.1 then QueueClause.advance current entry.2 else current) cursor

theorem cursor_fold_head (trace : List (Event A)) (cursor : QueueClause.Cursor A) :
    (trace.foldl QueueClause.advance cursor).window.head =
      cursor.window.head + ((popKeys trace).length : Int) := by
  induction trace generalizing cursor with
  | nil => simp [popKeys]
  | cons event rest ih =>
    cases event with
    | send key =>
      by_cases zero : cursor.counts key = 0 <;>
        simp [List.foldl_cons, QueueClause.advance, popKeys, zero, ih,
          SignedQueue.SignedWindow.append]
    | pop key =>
      simp [List.foldl_cons, QueueClause.advance, popKeys, ih,
        SignedQueue.SignedWindow.pop, Int.add_assoc, Int.add_comm]
    | peek key => simpa [List.foldl_cons, QueueClause.advance, popKeys] using ih cursor
    | length length => simpa [List.foldl_cons, QueueClause.advance, popKeys] using ih cursor

theorem cursor_after_head (cursor : QueueClause.Cursor A) (entries : List (GuardedEvent A)) :
    (cursorAfter cursor entries).window.head =
      cursor.window.head + ((popKeys (select entries)).length : Int) := by
  rw [cursorAfter, fold_select, cursor_fold_head]

end Cursor

-- This premise says only which key each active head read sees.
def HeadAgrees (order : Int -> A) : Nat -> List (Event A) -> Prop
  | _, [] => True
  | head, .pop key :: rest => order head = key /\ HeadAgrees order (head + 1) rest
  | head, .peek key :: rest => order head = key /\ HeadAgrees order head rest
  | head, _ :: rest => HeadAgrees order head rest

theorem agreed_read_heads (order : Int -> A) (head : Nat) (trace : List (Event A))
    (agree : HeadAgrees order head trace) :
    segment (fun index => order index) head (readHeads trace).length = readHeads trace := by
  induction trace generalizing head with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send key => exact ih head agree
    | length length => exact ih head agree
    | pop key =>
      simp only [readHeads, List.length_cons, QueueStream.segment_cons, agree.1]
      exact congrArg (List.cons key) (ih (head + 1) agree.2)
    | peek key =>
      have future := ih head agree.2
      cases heads : readHeads rest with
      | nil => simp [readHeads, heads, QueueStream.segment_cons, agree.1]
      | cons first tail => simpa only [readHeads, heads] using future

theorem cursor_head_agrees [DecidableEq A] (order : Int -> A)
    (cursor : QueueClause.Cursor A) (head : Nat) (trace : List (Event A))
    (at_head : cursor.window.head = (head : Int))
    (follows : QueueClause.cursorFollows order cursor trace) :
    HeadAgrees order head trace := by
  induction trace generalizing cursor head with
  | nil => trivial
  | cons event rest ih =>
    cases event with
    | send key =>
      apply ih (QueueClause.advance cursor (.send key)) head _ follows.2
      by_cases zero : cursor.counts key = 0 <;>
        simp [QueueClause.advance, zero, SignedQueue.SignedWindow.append, at_head]
    | pop key =>
      refine And.intro (by simpa [at_head] using follows.1.2.1) ?_
      apply ih (QueueClause.advance cursor (.pop key)) (head + 1) _ follows.2
      simp [QueueClause.advance, SignedQueue.SignedWindow.pop, at_head]
    | peek key =>
      exact And.intro (by simpa [at_head] using follows.1.2)
        (ih cursor head at_head follows.2)
    | length length => exact ih cursor head at_head follows.2

section Summary

variable [DecidableEq A]

structure Summary (A : Type) where
  head : Nat
  pending : Bool
  histogram : A -> Int

def initial : Summary A := { head := 0, pending := false, histogram := fun _ => 0 }

def advanceRead (length : Int) (state : Summary A) : Event A -> Summary A
  | .pop key =>
    { head := state.head + 1, pending := false
      histogram := if (state.head : Int) < length then
        Function.update state.histogram key (state.histogram key + 1)
      else state.histogram }
  | .peek _ => { state with pending := true }
  | .send _ | .length _ => state

def summarize (length : Int) (entries : List (GuardedEvent A)) : Summary A :=
  entries.foldl (fun state entry =>
    if entry.1 then advanceRead length state entry.2 else state) initial

theorem summarize_selected (length : Int) (entries : List (GuardedEvent A)) :
    summarize length entries = (select entries).foldl (advanceRead length) initial :=
  fold_select (advanceRead length) initial entries

theorem fold_head (length : Int) (trace : List (Event A)) (state : Summary A) :
    (trace.foldl (advanceRead length) state).head = state.head + (popKeys trace).length := by
  induction trace generalizing state with
  | nil => simp [popKeys]
  | cons event rest ih =>
    cases event <;> simp [List.foldl_cons, advanceRead, popKeys, ih,
      Nat.add_assoc, Nat.add_comm]

theorem summarize_head (length : Int) (entries : List (GuardedEvent A)) :
    (summarize length entries).head = (popKeys (select entries)).length := by
  simp [summarize_selected, fold_head, initial]

theorem head_count (length : Int) (cursor : QueueClause.Cursor A)
    (entries : List (GuardedEvent A)) (starts_at_zero : cursor.window.head = 0) :
    (cursorAfter cursor entries).window.head = ((summarize length entries).head : Int) := by
  simp [cursor_after_head, starts_at_zero, summarize_head]

theorem fold_read_span (length : Int) (trace : List (Event A)) :
    let state := trace.foldl (advanceRead length) (initial : Summary A)
    state.head + (if state.pending then 1 else 0) = (readHeads trace).length := by
  induction trace using List.reverseRecOn with
  | nil => rfl
  | append_singleton trace event ih =>
    simp only [List.foldl_append, List.foldl_cons, List.foldl_nil, read_heads_append]
    cases event <;> simp_all [advanceRead, fold_head, initial]

theorem read_span (length : Int) (entries : List (GuardedEvent A)) :
    (summarize length entries).head +
      (if (summarize length entries).pending then 1 else 0) =
        (readHeads (select entries)).length := by
  rw [summarize_selected]
  exact fold_read_span length (select entries)

theorem cursor_read_span (length : Int) (cursor : QueueClause.Cursor A)
    (entries : List (GuardedEvent A)) (starts_at_zero : cursor.window.head = 0) :
    (cursorAfter cursor entries).window.head +
      (if (summarize length entries).pending then 1 else 0) =
        ((readHeads (select entries)).length : Int) := by
  rw [head_count length cursor entries starts_at_zero]
  have span := congrArg Int.ofNat (read_span length entries)
  cases flag : (summarize length entries).pending <;> simpa [flag] using span

theorem read_span_le (length : Int) (entries : List (GuardedEvent A)) :
    (summarize length entries).head +
      (if (summarize length entries).pending then 1 else 0) <= entries.length := by
  rw [read_span]
  exact (CountedQueue.read_heads_length_le (select entries)).trans (select_length_le entries)

theorem fold_histogram (length : Int) (nonnegative : 0 <= length)
    (trace : List (Event A)) (state : Summary A) :
    (trace.foldl (advanceRead length) state).histogram =
      QueueAccounting.boundedPrefix length.toNat state.head state.histogram (popKeys trace) := by
  induction trace generalizing state with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | pop key =>
      have within : (state.head : Int) < length <-> state.head < length.toNat := by omega
      simp only [List.foldl_cons, ih, advanceRead, popKeys, QueueAccounting.boundedPrefix]
      simp only [within]
    | send key => exact ih state
    | peek key => exact ih { state with pending := true }
    | length observed => exact ih state

theorem read_heads_decompose (length : Int) (order : Int -> A)
    (entries : List (GuardedEvent A)) (agree : HeadAgrees order 0 (select entries)) :
    readHeads (select entries) = popKeys (select entries) ++
      (if (summarize length entries).pending then [order (summarize length entries).head] else []) := by
  have size := read_span length entries
  have heads := agreed_read_heads order 0 (select entries) agree
  have pops := read_heads_take_pops (select entries)
  have head := summarize_head length entries
  cases flag : (summarize length entries).pending with
  | false =>
    have size_eq : (readHeads (select entries)).length = (popKeys (select entries)).length := by
      simpa [flag, head] using size.symm
    simp only [Bool.false_eq_true, ite_false, List.append_nil]
    rwa [Eq.symm size_eq, List.take_length] at pops
  | true =>
    have size_eq : (readHeads (select entries)).length = (popKeys (select entries)).length + 1 := by
      simpa [flag, head] using size.symm
    have cells : readHeads (select entries) =
        segment (fun index => order index) 0 (popKeys (select entries)).length ++
          [order (popKeys (select entries)).length] := by
      rw [Eq.symm heads, size_eq, QueueStream.segment_append, Nat.zero_add]
    have consumed : segment (fun index => order index) 0 (popKeys (select entries)).length =
        popKeys (select entries) := by
      have taken :
          (segment (fun index => order index) 0 (popKeys (select entries)).length).take
            (popKeys (select entries)).length =
              segment (fun index => order index) 0 (popKeys (select entries)).length := by
        apply List.take_of_length_le
        simp only [QueueStream.segment_length, Nat.le_refl]
      rw [cells] at pops
      simpa only [List.take_append, QueueStream.segment_length, Nat.sub_self,
        List.take_zero, List.append_nil, taken] using pops
    simpa [flag, head, consumed] using cells

variable [BEq A] [LawfulBEq A]

theorem pop_histogram_exact (length : Int) (nonnegative : 0 <= length)
    (entries : List (GuardedEvent A)) (key : A) :
    (summarize length entries).histogram key =
      (((popKeys (select entries)).take length.toNat).count key : Int) := by
  rw [summarize_selected, fold_histogram length nonnegative]
  exact QueueAccounting.bounded_prefix_exact length.toNat (popKeys (select entries)) key

def initialHistogram (length : Int) (order : Int -> A)
    (entries : List (GuardedEvent A)) (key : A) : Int :=
  let state := summarize length entries
  state.histogram key +
    if state.pending = true /\ (state.head : Int) < length /\ order state.head = key then 1 else 0

theorem initial_histogram_exact (length : Int) (nonnegative : 0 <= length)
    (order : Int -> A) (entries : List (GuardedEvent A))
    (agree : HeadAgrees order 0 (select entries)) (key : A) :
    initialHistogram length order entries key =
      (((readHeads (select entries)).take length.toNat).count key : Int) := by
  dsimp only [initialHistogram]
  rw [pop_histogram_exact length nonnegative,
    read_heads_decompose length order entries agree]
  cases flag : (summarize length entries).pending with
  | false => simp
  | true =>
    by_cases within : (popKeys (select entries)).length < length.toNat
    next =>
      have scalar_within : ((summarize length entries).head : Int) < length := by
        rw [summarize_head]
        omega
      have take_one :
          ([order (summarize length entries).head] : List A).take
            (length.toNat - (popKeys (select entries)).length) =
              [order (summarize length entries).head] := by
        apply List.take_of_length_le
        simp only [List.length_singleton]
        omega
      simp only [ite_true, List.take_append, take_one, List.count_append]
      by_cases same : order (summarize length entries).head = key <;>
        simp [scalar_within, same]
    next =>
      have scalar_outside : Not (((summarize length entries).head : Int) < length) := by
        rw [summarize_head]
        omega
      have difference : length.toNat - (popKeys (select entries)).length = 0 := by omega
      simp [scalar_outside, List.take_append, difference]

theorem replay_initial_histogram_exact (length : Int) (nonnegative : 0 <= length)
    (order : Int -> A) (cursor : QueueClause.Cursor A) (entries : List (GuardedEvent A))
    (starts_at_zero : cursor.window.head = 0) (follows : replay order cursor entries) (key : A) :
    initialHistogram length order entries key =
      (((readHeads (select entries)).take length.toNat).count key : Int) := by
  apply initial_histogram_exact length nonnegative order entries _ key
  exact cursor_head_agrees order cursor 0 (select entries) starts_at_zero
    ((replay_iff order cursor entries).mp follows)

end Summary

namespace Regression

def inactivePop : List (GuardedEvent Nat) := [(true, .peek 0), (false, .pop 1)]

theorem inactive_pop :
    (summarize 1 inactivePop).head = 0 /\
    (summarize 1 inactivePop).pending = true /\
    initialHistogram 1 (fun _ => 0) inactivePop 0 = 1 /\
    readHeads (select inactivePop) = [0] /\
    readHeads (inactivePop.map Prod.snd) = [1] := by decide

def inactiveLastPeek : List (GuardedEvent Nat) := [(true, .peek 0), (false, .peek 1)]

theorem inactive_last_peek :
    initialHistogram 1 (fun _ => 0) inactiveLastPeek 0 = 1 /\
    readHeads (select inactiveLastPeek) = [0] /\
    readHeads (inactiveLastPeek.map Prod.snd) = [1] := by decide

theorem alias_counts [DecidableEq A] [BEq A] [LawfulBEq A]
    (left right : A) (same : left = right) :
    initialHistogram 2 (fun _ => left) [(true, .pop left), (true, .peek right)] left = 2 := by
  rw [initial_histogram_exact 2 (by decide) (fun _ => left)
    [(true, .pop left), (true, .peek right)] (by simp [select, HeadAgrees, same])]
  simp [select, readHeads, same]

def newlySentPeek : List (GuardedEvent Nat) := [(true, .send 0), (true, .peek 0)]

theorem outside_initial_peek :
    (summarize 0 newlySentPeek).pending = true /\
    initialHistogram 0 (fun _ => 0) newlySentPeek 0 = 0 /\
    (summarize 0 newlySentPeek).histogram 0 + 1 = 1 := by decide

theorem newly_sent_replay :
    replay (fun _ => (0 : Nat))
      { counts := fun _ => 0, window := { head := 0, tail := 0 } } newlySentPeek := by
  simp [newlySentPeek, replay, QueueClause.guard, QueueClause.advance,
    SignedQueue.SignedWindow.append]

theorem missing_order_premise :
    Not (HeadAgrees (fun _ => (0 : Nat)) 0 [.peek 1]) /\
    initialHistogram 1 (fun _ => 0) [(true, .peek (1 : Nat))] 0 = 1 /\
    (((readHeads [.peek (1 : Nat)]).take 1).count 0 : Int) = 0 := by
  simp [HeadAgrees, initialHistogram, summarize, initial, advanceRead, readHeads]

end Regression

end CCFRaft.Sparse.ConditionalQueueAccounting

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if name.toString.startsWith "CCFRaft.Sparse.ConditionalQueueAccounting." then
      for axiomName in (<- Lean.collectAxioms name) do
        unless [``propext, ``Classical.choice, ``Quot.sound].contains axiomName do
          throwError "disallowed axiom {axiomName} in {name}"
      checked := checked + 1
  Lean.logInfo m!"ConditionalQueueAccounting: {checked} declarations passed the transitive axiom gate"
