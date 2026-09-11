import Sparse.QueueScalarEncoding
import Sparse.QueueAccounting

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueInitialEncoding

open Smt (Assignment Term)
open QueueEncoding (InputInt)
open QueueStream (Event)
open QueueAccounting (Accounting account accounts boundedPrefix)

theorem take_step {A : Type} (items : List A) (index : Nat) (bound : index < items.length) :
    items.take (index + 1) = items.take index ++ [items[index]] := by
  induction items generalizing index with
  | nil => simp at bound
  | cons head tail ih =>
    cases index with
    | zero => rfl
    | succ index =>
      simp only [List.take_succ_cons, List.cons_append, List.getElem_cons_succ]
      exact congrArg (List.cons head) (ih index (Nat.lt_of_succ_lt_succ bound))

theorem bounded_append (limit index : Nat) (counts : Int -> Int) (left right : List Int) :
    boundedPrefix limit index counts (left ++ right) =
      boundedPrefix limit (index + left.length) (boundedPrefix limit index counts left) right := by
  induction left generalizing index counts with
  | nil => simp [boundedPrefix]
  | cons head tail ih =>
    by_cases within : index < limit <;>
      simp [boundedPrefix, within, ih, Nat.add_comm, Nat.add_left_comm]

theorem accounts_append (counts : Int -> Int) (state : Accounting Int) (left right : List Int) :
    accounts counts state (left ++ right) = accounts counts (accounts counts state left) right := by
  induction left generalizing state with
  | nil => rfl
  | cons head tail ih => simp [accounts, ih]

def histogram (length : Int) (messages : List Int) (version : Nat) : Int -> Int :=
  boundedPrefix length.toNat 0 (fun _ => 0) (messages.take version)

def accounting (counts : Int -> Int) (keys : List Int) (version : Nat) : Accounting Int :=
  accounts counts { seen := fun _ => false, total := 0 } (keys.take version)

def presence (counts : Int -> Int) (keys : List Int) (version : Nat) (key : Int) : Int :=
  if (accounting counts keys version).seen key then 1 else 0

@[simp] theorem histogram_zero (length : Int) (messages : List Int) (key : Int) :
    histogram length messages 0 key = 0 := rfl

theorem histogram_step (length : Int) (messages : List Int) (index : Nat)
    (bound : index < messages.length) (key : Int) :
    histogram length messages (index + 1) key =
      histogram length messages index key +
        if (index : Int) < length /\ key = messages[index] then 1 else 0 := by
  have prefix_length : (messages.take index).length = index := by simp [Nat.min_eq_left (Nat.le_of_lt bound)]
  have cutoff : index < length.toNat <-> (index : Int) < length := by omega
  unfold histogram
  rw [take_step messages index bound, bounded_append, prefix_length]
  by_cases within : (index : Int) < length <;> by_cases same : key = messages[index] <;>
    simp [boundedPrefix, cutoff, within, same, Function.update_apply]

theorem accounting_step (counts : Int -> Int) (keys : List Int) (index : Nat)
    (bound : index < keys.length) :
    accounting counts keys (index + 1) = account counts (accounting counts keys index) keys[index] := by
  unfold accounting
  rw [take_step keys index bound, accounts_append]
  rfl

@[simp] theorem presence_zero (counts : Int -> Int) (keys : List Int) (key : Int) :
    presence counts keys 0 key = 0 := rfl

theorem presence_step (counts : Int -> Int) (keys : List Int) (index : Nat)
    (bound : index < keys.length) (key : Int) :
    presence counts keys (index + 1) key =
      if key = keys[index] then 1 else presence counts keys index key := by
  unfold presence
  rw [accounting_step counts keys index bound]
  by_cases same : key = keys[index] <;> simp [account, same]

@[simp] theorem tally_zero (counts : Int -> Int) (keys : List Int) :
    (accounting counts keys 0).total = 0 := rfl

theorem tally_step (counts : Int -> Int) (keys : List Int) (index : Nat)
    (bound : index < keys.length) :
    (accounting counts keys (index + 1)).total =
      (accounting counts keys index).total +
        if presence counts keys index keys[index] = 0 then counts keys[index] else 0 := by
  rw [accounting_step counts keys index bound]
  cases seen : (accounting counts keys index).seen keys[index] <;>
    simp [account, presence, seen]

theorem histogram_final (length : Int) (messages : List Int) (key : Int) :
    histogram length messages messages.length key = ((messages.take length.toNat).count key : Int) := by
  simpa [histogram] using QueueAccounting.bounded_prefix_exact length.toNat messages key

theorem tally_final (counts : Int -> Int) (keys : List Int) :
    (accounting counts keys keys.length).total = keys.toFinset.sum counts := by
  simpa [accounting] using QueueAccounting.initial_accounts_exact counts keys

def eventKeys : List (Event InputInt) -> List InputInt
  | [] => []
  | .send key :: rest | .pop key :: rest | .peek key :: rest => (eventKeys rest).insert key
  | .length _ :: rest => eventKeys rest

theorem event_keys_mem (trace : List (Event InputInt)) (key : InputInt) :
    Membership.mem (eventKeys trace) key <->
      Membership.mem trace (.send key) \/ Membership.mem trace (.pop key) \/ Membership.mem trace (.peek key) := by
  induction trace with
  | nil => simp [eventKeys]
  | cons event rest ih =>
    cases event <;> simp [eventKeys, ih, or_assoc, or_left_comm, or_comm]

theorem event_keys_nodup (trace : List (Event InputInt)) : (eventKeys trace).Nodup := by
  induction trace with
  | nil => simp [eventKeys]
  | cons event rest ih =>
    cases event with
    | send key | pop key | peek key => exact ih.insert
    | length length => exact ih

theorem interpreted_event_keys_mem (assignment : Assignment) (trace : List (Event InputInt)) (value : Int) :
    Membership.mem ((eventKeys trace).map (InputInt.eval assignment)).toFinset value <->
      exists key : InputInt, key.eval assignment = value /\
        (Membership.mem trace (.send key) \/ Membership.mem trace (.pop key) \/ Membership.mem trace (.peek key)) := by
  simp only [List.mem_toFinset, List.mem_map, event_keys_mem, and_comm]

theorem repeated_send_keys (key : InputInt) (count : Nat) :
    eventKeys (List.replicate count (.send key)) = if count = 0 then [] else [key] := by
  induction count with
  | zero => rfl
  | succ count ih =>
    rw [List.replicate_succ, eventKeys, ih]
    cases count <;> simp

theorem repeated_cycle_keys_reads (key : InputInt) (count : Nat) :
    eventKeys ((List.replicate count [Event.send key, .pop key]).flatten) =
      (if count = 0 then [] else [key]) /\
    CountedQueue.readHeads ((List.replicate count [Event.send key, .pop key]).flatten) =
      List.replicate count key := by
  induction count with
  | zero => simp [eventKeys, CountedQueue.readHeads]
  | succ count ih =>
    simp only [List.replicate_succ, List.flatten_cons, List.cons_append, List.nil_append,
      eventKeys, CountedQueue.readHeads, ih.1, ih.2]
    cases count <;> simp

theorem distinct_symbolic_keys (left right : Nat) (different : Not (left = right)) :
    eventKeys [.send (.symbolic left), .peek (.symbolic right)] = [.symbolic left, .symbolic right] := by
  simp [eventKeys, different]

theorem read_heads_eval (assignment : Assignment) (trace : List (Event InputInt)) :
    CountedQueue.readHeads (QueueScalarEncoding.evalTrace assignment trace) =
      (CountedQueue.readHeads trace).map (InputInt.eval assignment) := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    simp only [QueueScalarEncoding.evalTrace] at ih
    cases event <;> cases heads : CountedQueue.readHeads rest <;>
      simp [QueueScalarEncoding.evalTrace, QueueScalarEncoding.evalEvent, CountedQueue.readHeads,
        ih, heads]

theorem tracked_uses (assignment : Assignment) (trace : List (Event InputInt)) :
    CountedQueue.Uses ((eventKeys trace).map (InputInt.eval assignment)).toFinset
      (QueueScalarEncoding.evalTrace assignment trace) := by
  have covered : forall rest : List (Event InputInt), forall keys : Finset Int,
      (forall key, Membership.mem (eventKeys rest) key -> Membership.mem keys (key.eval assignment)) ->
      CountedQueue.Uses keys (QueueScalarEncoding.evalTrace assignment rest) := by
    intro rest
    induction rest with
    | nil => intro _ _; trivial
    | cons event tail ih =>
      intro keys included
      cases event with
      | send key | pop key | peek key =>
        exact And.intro (included key (by simp [eventKeys]))
          (ih keys (fun later member => included later (by simp [eventKeys, member])))
      | length length => exact ih keys included
  apply covered
  intro key member
  exact List.mem_toFinset.mpr (List.mem_map.mpr (Exists.intro key (And.intro member rfl)))

def rootCounts (assignment : Assignment) (countBase : Nat) : Int -> Int :=
  assignment.unary .int .int countBase

def seenBase (base prefixSize : Nat) : Nat := base + prefixSize + 1

def tallyId (base prefixSize keySize : Nat) : Nat := base + prefixSize + keySize + 2

def tallyRef (base prefixSize keySize index : Nat) : Term .int :=
  .app .int .int (tallyId base prefixSize keySize) (.integer (index : Int))

def histogramEquation (base : Nat) (length : InputInt) (messages : List InputInt) :
    Fin (messages.length + 1) -> InputInt -> Term .bool
  | Fin.mk 0 _, key => .equal (QueueEncoding.readRef base 0 key) (.integer 0)
  | Fin.mk (index + 1) bound, key =>
    .equal (QueueEncoding.readRef base (index + 1) key)
      (.add (QueueEncoding.readRef base index key)
        (.ite (.and (.not (.le length.term (.integer (index : Int))))
          (.equal key.term messages[index].term)) (.integer 1) (.integer 0)))

def presenceEquation (base prefixSize : Nat) (keys : List InputInt) :
    Fin (keys.length + 1) -> InputInt -> Term .bool
  | Fin.mk 0 _, key => .equal (QueueEncoding.readRef (seenBase base prefixSize) 0 key) (.integer 0)
  | Fin.mk (index + 1) bound, key =>
    .equal (QueueEncoding.readRef (seenBase base prefixSize) (index + 1) key)
      (.ite (.equal key.term keys[index].term) (.integer 1)
        (QueueEncoding.readRef (seenBase base prefixSize) index key))

def tallyEquation (countBase base prefixSize : Nat) (keys : List InputInt) :
    Fin (keys.length + 1) -> Term .bool
  | Fin.mk 0 _ => .equal (tallyRef base prefixSize keys.length 0) (.integer 0)
  | Fin.mk (index + 1) bound =>
    .equal (tallyRef base prefixSize keys.length (index + 1))
      (.add (tallyRef base prefixSize keys.length index)
        (.ite (.equal (QueueEncoding.readRef (seenBase base prefixSize) index keys[index]) (.integer 0))
          (QueueEncoding.readRef countBase 0 keys[index]) (.integer 0)))

def grid (height : Nat) (keys : List InputInt)
    (equation : Fin (height + 1) -> InputInt -> Term .bool) : SmtScript.Formula :=
  (List.ofFn (fun version => keys.map (equation version))).flatten

theorem grid_holds (assignment : Assignment) (height : Nat) (keys : List InputInt)
    (equation : Fin (height + 1) -> InputInt -> Term .bool) :
    SmtScript.Holds assignment (grid height keys equation) <->
      forall version key, Membership.mem keys key -> (equation version key).eval assignment = true := by
  constructor
  next =>
    intro holds version key member
    apply holds
    apply List.mem_flatten.mpr
    exact Exists.intro (keys.map (equation version)) (And.intro
      (List.mem_ofFn.mpr (Exists.intro version rfl))
      (List.mem_map.mpr (Exists.intro key (And.intro member rfl))))
  next =>
    intro every term member
    cases List.mem_flatten.mp member with
    | intro row spec =>
      cases List.mem_ofFn.mp spec.1 with
      | intro version equal =>
        have row_member := spec.2
        rw [Eq.symm equal] at row_member
        cases List.mem_map.mp row_member with
        | intro key selected =>
          rw [Eq.symm selected.2]
          exact every version key selected.1

theorem ofFn_holds (assignment : Assignment) {size : Nat} (terms : Fin size -> Term .bool) :
    SmtScript.Holds assignment (List.ofFn terms) <->
      forall index, (terms index).eval assignment = true := by
  constructor
  next => intro holds index; exact holds _ (List.mem_ofFn.mpr (Exists.intro index rfl))
  next =>
    intro every term member
    cases List.mem_ofFn.mp member with
    | intro index equal => rw [Eq.symm equal]; exact every index

def definitions (countBase base : Nat) (length : InputInt) (messages keys : List InputInt) :
    SmtScript.Formula :=
  grid messages.length keys (histogramEquation base length messages) ++
    (grid keys.length keys (presenceEquation base messages.length keys) ++
      List.ofFn (tallyEquation countBase base messages.length keys))

def checks (countBase base : Nat) (length : InputInt) (messages keys : List InputInt) : SmtScript.Formula :=
  [.le (.integer 0) length.term] ++
    keys.map (fun key =>
      .le (QueueEncoding.readRef base messages.length key) (QueueEncoding.readRef countBase 0 key)) ++
    [.le (tallyRef base messages.length keys.length keys.length) length.term]

def initialBlock (countBase base : Nat) (length : InputInt) (messages keys : List InputInt) : SmtScript.Formula :=
  definitions countBase base length messages keys ++ checks countBase base length messages keys

def HistCorrect (assignment : Assignment) (base : Nat) (length : InputInt) (messages keys : List InputInt) : Prop :=
  forall version : Fin (messages.length + 1), forall key, Membership.mem keys key ->
    assignment.unary .int .int (base + version.val) (key.eval assignment) =
      histogram (length.eval assignment) (messages.map (InputInt.eval assignment)) version.val (key.eval assignment)

def SeenCorrect (assignment : Assignment) (countBase base prefixSize : Nat) (keys : List InputInt) : Prop :=
  forall version : Fin (keys.length + 1), forall key, Membership.mem keys key ->
    assignment.unary .int .int (seenBase base prefixSize + version.val) (key.eval assignment) =
      presence (rootCounts assignment countBase) (keys.map (InputInt.eval assignment)) version.val (key.eval assignment)

def TallyCorrect (assignment : Assignment) (countBase base prefixSize : Nat) (keys : List InputInt) : Prop :=
  forall version : Fin (keys.length + 1),
    assignment.unary .int .int (tallyId base prefixSize keys.length) (version.val : Int) =
      (accounting (rootCounts assignment countBase) (keys.map (InputInt.eval assignment)) version.val).total

def AuxCorrect (assignment : Assignment) (countBase base : Nat)
    (length : InputInt) (messages keys : List InputInt) : Prop :=
  HistCorrect assignment base length messages keys /\
    SeenCorrect assignment countBase base messages.length keys /\
    TallyCorrect assignment countBase base messages.length keys

@[simp] theorem histogram_equation_zero (assignment : Assignment) (base : Nat) (length : InputInt)
    (messages : List InputInt) (key : InputInt) :
    (histogramEquation base length messages 0 key).eval assignment = true <->
      assignment.unary .int .int base (key.eval assignment) = 0 := by
  rw [show (0 : Fin (messages.length + 1)) = Fin.mk 0 (Nat.zero_lt_succ _) from Fin.ext (by simp)]
  change (Term.equal (QueueEncoding.readRef base 0 key) (.integer 0)).eval assignment = true <-> _
  simp [Term.eval, QueueEncoding.readRef, InputInt.eval]

@[simp] theorem presence_equation_zero (assignment : Assignment) (base prefixSize : Nat)
    (keys : List InputInt) (key : InputInt) :
    (presenceEquation base prefixSize keys 0 key).eval assignment = true <->
      assignment.unary .int .int (seenBase base prefixSize) (key.eval assignment) = 0 := by
  rw [show (0 : Fin (keys.length + 1)) = Fin.mk 0 (Nat.zero_lt_succ _) from Fin.ext (by simp)]
  change (Term.equal (QueueEncoding.readRef (seenBase base prefixSize) 0 key) (.integer 0)).eval assignment = true <-> _
  simp [Term.eval, QueueEncoding.readRef, InputInt.eval]

@[simp] theorem tally_equation_zero (assignment : Assignment) (countBase base prefixSize : Nat)
    (keys : List InputInt) :
    (tallyEquation countBase base prefixSize keys 0).eval assignment = true <->
      assignment.unary .int .int (tallyId base prefixSize keys.length) 0 = 0 := by
  rw [show (0 : Fin (keys.length + 1)) = Fin.mk 0 (Nat.zero_lt_succ _) from Fin.ext (by simp)]
  change (Term.equal (tallyRef base prefixSize keys.length 0) (.integer 0)).eval assignment = true <-> _
  simp [Term.eval, tallyRef]

theorem histogram_equation_step (assignment : Assignment) (base : Nat) (length : InputInt)
    (messages : List InputInt) (index : Fin messages.length) (key : InputInt) :
    (histogramEquation base length messages index.succ key).eval assignment = true <->
      assignment.unary .int .int (base + index.val + 1) (key.eval assignment) =
        assignment.unary .int .int (base + index.val) (key.eval assignment) +
          if (index.val : Int) < length.eval assignment /\ key.eval assignment = messages[index.val].eval assignment
          then 1 else 0 := by
  cases index
  simp [histogramEquation, Term.eval, QueueEncoding.readRef, InputInt.eval, Nat.add_assoc]

theorem presence_equation_step (assignment : Assignment) (base prefixSize : Nat)
    (keys : List InputInt) (index : Fin keys.length) (key : InputInt) :
    (presenceEquation base prefixSize keys index.succ key).eval assignment = true <->
      assignment.unary .int .int (seenBase base prefixSize + index.val + 1) (key.eval assignment) =
        if key.eval assignment = keys[index.val].eval assignment then 1
        else assignment.unary .int .int (seenBase base prefixSize + index.val) (key.eval assignment) := by
  cases index
  simp [presenceEquation, Term.eval, QueueEncoding.readRef, InputInt.eval, Nat.add_assoc]

theorem tally_equation_step (assignment : Assignment) (countBase base prefixSize : Nat)
    (keys : List InputInt) (index : Fin keys.length) :
    (tallyEquation countBase base prefixSize keys index.succ).eval assignment = true <->
      assignment.unary .int .int (tallyId base prefixSize keys.length) ((index.val + 1 : Nat) : Int) =
        assignment.unary .int .int (tallyId base prefixSize keys.length) (index.val : Int) +
          if assignment.unary .int .int (seenBase base prefixSize + index.val) (keys[index.val].eval assignment) = 0
          then rootCounts assignment countBase (keys[index.val].eval assignment) else 0 := by
  cases index
  simp [tallyEquation, tallyRef, Term.eval, QueueEncoding.readRef, rootCounts, InputInt.eval]

theorem histogram_definitions_correct (assignment : Assignment) (base : Nat) (length : InputInt)
    (messages keys : List InputInt) :
    SmtScript.Holds assignment (grid messages.length keys (histogramEquation base length messages)) <->
      HistCorrect assignment base length messages keys := by
  rw [grid_holds]
  constructor
  next =>
    intro every version
    induction version using Fin.induction with
    | zero =>
      intro key member
      simpa using (histogram_equation_zero assignment base length messages key).mp (every 0 key member)
    | succ index ih =>
      intro key member
      simp only [Fin.val_castSucc] at ih
      simp only [Fin.val_succ]
      have equation := (histogram_equation_step assignment base length messages index key).mp
        (every index.succ key member)
      rw [ih key member] at equation
      rw [histogram_step _ _ index.val (by simp)]
      simpa only [Nat.add_assoc, List.getElem_map] using equation
  next =>
    intro correct version key member
    cases version using Fin.cases with
    | zero =>
      apply (histogram_equation_zero assignment base length messages key).mpr
      simpa using correct 0 key member
    | succ index =>
      apply (histogram_equation_step assignment base length messages index key).mpr
      simp only [Nat.add_assoc]
      have current := correct index.succ key member
      have previous := correct index.castSucc key member
      simp only [Fin.val_succ, Fin.val_castSucc] at current previous
      rw [current, previous]
      simpa using
        histogram_step (length.eval assignment) (messages.map (InputInt.eval assignment)) index.val
          (by simp) (key.eval assignment)

theorem presence_definitions_correct (assignment : Assignment) (countBase base prefixSize : Nat)
    (keys : List InputInt) :
    SmtScript.Holds assignment (grid keys.length keys (presenceEquation base prefixSize keys)) <->
      SeenCorrect assignment countBase base prefixSize keys := by
  rw [grid_holds]
  constructor
  next =>
    intro every version
    induction version using Fin.induction with
    | zero =>
      intro key member
      simpa using (presence_equation_zero assignment base prefixSize keys key).mp (every 0 key member)
    | succ index ih =>
      intro key member
      simp only [Fin.val_castSucc] at ih
      simp only [Fin.val_succ]
      have equation := (presence_equation_step assignment base prefixSize keys index key).mp
        (every index.succ key member)
      rw [ih key member] at equation
      rw [presence_step _ _ index.val (by simp)]
      simpa only [Nat.add_assoc, List.getElem_map] using equation
  next =>
    intro correct version key member
    cases version using Fin.cases with
    | zero =>
      apply (presence_equation_zero assignment base prefixSize keys key).mpr
      simpa using correct 0 key member
    | succ index =>
      apply (presence_equation_step assignment base prefixSize keys index key).mpr
      simp only [Nat.add_assoc]
      have current := correct index.succ key member
      have previous := correct index.castSucc key member
      simp only [Fin.val_succ, Fin.val_castSucc] at current previous
      rw [current, previous]
      simpa using
        presence_step (rootCounts assignment countBase) (keys.map (InputInt.eval assignment)) index.val
          (by simp) (key.eval assignment)

theorem tally_definitions_correct (assignment : Assignment) (countBase base prefixSize : Nat)
    (keys : List InputInt) (seen : SeenCorrect assignment countBase base prefixSize keys) :
    SmtScript.Holds assignment (List.ofFn (tallyEquation countBase base prefixSize keys)) <->
      TallyCorrect assignment countBase base prefixSize keys := by
  rw [ofFn_holds]
  constructor
  next =>
    intro every version
    induction version using Fin.induction with
    | zero =>
      simpa using (tally_equation_zero assignment countBase base prefixSize keys).mp (every 0)
    | succ index ih =>
      simp only [Fin.val_castSucc] at ih
      simp only [Fin.val_succ]
      have equation := (tally_equation_step assignment countBase base prefixSize keys index).mp
        (every index.succ)
      have seen_value := seen index.castSucc keys[index.val] (List.getElem_mem index.isLt)
      simp only [Fin.val_castSucc] at seen_value
      rw [ih, seen_value] at equation
      rw [tally_step _ _ index.val (by simp)]
      simpa only [List.getElem_map] using equation
  next =>
    intro correct version
    cases version using Fin.cases with
    | zero =>
      apply (tally_equation_zero assignment countBase base prefixSize keys).mpr
      simpa using correct 0
    | succ index =>
      apply (tally_equation_step assignment countBase base prefixSize keys index).mpr
      have current := correct index.succ
      have previous := correct index.castSucc
      have seen_value := seen index.castSucc keys[index.val] (List.getElem_mem index.isLt)
      simp only [Fin.val_succ, Fin.val_castSucc] at current previous seen_value
      rw [current, previous, seen_value]
      simpa using
        tally_step (rootCounts assignment countBase) (keys.map (InputInt.eval assignment)) index.val
          (by simp)

theorem definitions_correct (assignment : Assignment) (countBase base : Nat)
    (length : InputInt) (messages keys : List InputInt) :
    SmtScript.Holds assignment (definitions countBase base length messages keys) <->
      AuxCorrect assignment countBase base length messages keys := by
  rw [definitions, QueueEncoding.holds_append, QueueEncoding.holds_append,
    histogram_definitions_correct, presence_definitions_correct assignment countBase]
  constructor
  next =>
    intro facts
    exact And.intro facts.1 (And.intro facts.2.1
      ((tally_definitions_correct assignment countBase base messages.length keys facts.2.1).mp facts.2.2))
  next =>
    intro facts
    exact And.intro facts.1 (And.intro facts.2.1
      ((tally_definitions_correct assignment countBase base messages.length keys facts.2.1).mpr facts.2.2))

theorem checks_correct (assignment : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (hist : HistCorrect assignment base length messages keys)
    (tally : TallyCorrect assignment countBase base messages.length keys) :
    SmtScript.Holds assignment (checks countBase base length messages keys) <->
      0 <= length.eval assignment /\
      (forall key, Membership.mem keys key ->
        (((messages.map (InputInt.eval assignment)).take (length.eval assignment).toNat).count
          (key.eval assignment) : Int) <= rootCounts assignment countBase (key.eval assignment)) /\
      (keys.map (InputInt.eval assignment)).toFinset.sum (rootCounts assignment countBase) <= length.eval assignment := by
  have last_hist (key : InputInt) (member : Membership.mem keys key) :
      assignment.unary .int .int (base + messages.length) (key.eval assignment) =
        (((messages.map (InputInt.eval assignment)).take (length.eval assignment).toNat).count
          (key.eval assignment) : Int) :=
    (hist (Fin.mk messages.length (Nat.lt_succ_self _)) key member).trans
      (by simpa only [List.length_map] using
        histogram_final (length.eval assignment) (messages.map (InputInt.eval assignment)) (key.eval assignment))
  have last_tally :
      assignment.unary .int .int (tallyId base messages.length keys.length) (keys.length : Int) =
        (keys.map (InputInt.eval assignment)).toFinset.sum (rootCounts assignment countBase) :=
    (tally (Fin.mk keys.length (Nat.lt_succ_self _))).trans
      (by simpa only [List.length_map] using
        tally_final (rootCounts assignment countBase) (keys.map (InputInt.eval assignment)))
  have native :
      SmtScript.Holds assignment (checks countBase base length messages keys) <->
        0 <= length.eval assignment /\
        (forall key, Membership.mem keys key ->
          assignment.unary .int .int (base + messages.length) (key.eval assignment) <=
            rootCounts assignment countBase (key.eval assignment)) /\
        assignment.unary .int .int (tallyId base messages.length keys.length) (keys.length : Int) <=
          length.eval assignment := by
    rw [checks, QueueEncoding.holds_append, QueueEncoding.holds_append]
    simp [SmtScript.Holds, Term.eval, QueueEncoding.readRef, tallyRef, rootCounts, InputInt.eval, and_assoc]
  rw [native, last_tally]
  constructor
  next =>
    intro facts
    refine And.intro facts.1 (And.intro ?_ facts.2.2)
    intro key member
    rw [Eq.symm (last_hist key member)]
    exact facts.2.1 key member
  next =>
    intro facts
    refine And.intro facts.1 (And.intro ?_ facts.2.2)
    intro key member
    rw [last_hist key member]
    exact facts.2.1 key member

theorem initial_block_correct (assignment : Assignment) (countBase base : Nat) (length : InputInt)
    (trace : List (Event InputInt)) (keys : List InputInt) :
    SmtScript.Holds assignment (initialBlock countBase base length (CountedQueue.readHeads trace) keys) <->
      AuxCorrect assignment countBase base length (CountedQueue.readHeads trace) keys /\
      0 <= length.eval assignment /\
      IntegerQueue.RawInitialFacts (keys.map (InputInt.eval assignment)).toFinset
        (rootCounts assignment countBase) (length.eval assignment).toNat (QueueScalarEncoding.evalTrace assignment trace) := by
  rw [initialBlock, QueueEncoding.holds_append, definitions_correct]
  constructor
  next =>
    intro facts
    have checked := (checks_correct assignment countBase base length _ keys facts.1.1 facts.1.2.2).mp facts.2
    refine And.intro facts.1 (And.intro checked.1 (And.intro ?_ ?_))
    next =>
      intro value member
      cases List.mem_map.mp (List.mem_toFinset.mp member) with
      | intro key selected =>
        rw [Eq.symm selected.2, read_heads_eval]
        exact checked.2.1 key selected.1
    next =>
      simpa only [Int.toNat_of_nonneg checked.1] using checked.2.2
  next =>
    intro facts
    refine And.intro facts.1
      ((checks_correct assignment countBase base length _ keys facts.1.1 facts.1.2.2).mpr
        (And.intro facts.2.1 (And.intro ?_ ?_)))
    next =>
      intro key member
      have lower := facts.2.2.1 (key.eval assignment)
        (List.mem_toFinset.mpr (List.mem_map.mpr (Exists.intro key (And.intro member rfl))))
      simpa only [read_heads_eval] using lower
    next =>
      simpa only [Int.toNat_of_nonneg facts.2.1] using facts.2.2.2

def auxBase (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) : Nat :=
  max (QueueEncoding.freshBase (QueueScalarEncoding.encode input (eventKeys trace) trace [] length))
    (QueueScalarEncoding.nextBase input (eventKeys trace) trace [])

def nextBase (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) : Nat :=
  auxBase input trace length + (CountedQueue.readHeads trace).length + (eventKeys trace).length + 3

def encode (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) : SmtScript.Formula :=
  QueueScalarEncoding.encode input (eventKeys trace) trace [] length ++
    initialBlock (QueueEncoding.freshBase input) (auxBase input trace length) length
      (CountedQueue.readHeads trace) (eventKeys trace)

def encodeCached (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) : SmtScript.Formula :=
  let keys := eventKeys trace
  let countBase := QueueEncoding.freshBase input
  let counts := input ++ QueueEncoding.countFormula keys trace [] countBase
  let scalarBase := max (QueueEncoding.freshBase counts) (countBase + QueueReadback.writeCount trace + 1)
  let scalars := counts ++
    (QueueScalarEncoding.initialBlock scalarBase length ++
      QueueScalarEncoding.scalarBlock countBase scalarBase trace)
  let auxiliaryBase := max (QueueEncoding.freshBase scalars) (scalarBase + 3)
  scalars ++ initialBlock countBase auxiliaryBase length (CountedQueue.readHeads trace) keys

@[csimp] theorem encode_eq_cached : encode = encodeCached := by
  funext input trace length
  rfl

def render (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) : String :=
  SmtScript.render (encode input trace length)

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) :
    SmtScript.Holds assignment (encode input trace length) <->
      SmtScript.Holds assignment input /\
      QueueEncoding.CountSemantics assignment (eventKeys trace) trace []
        (QueueEncoding.values assignment (QueueEncoding.freshBase input)) /\
      QueueScalarEncoding.Semantics assignment (QueueEncoding.freshBase input) length trace
        (QueueScalarEncoding.windows assignment (QueueScalarEncoding.scalarBase input (eventKeys trace) trace []))
        (QueueScalarEncoding.order assignment (QueueScalarEncoding.scalarBase input (eventKeys trace) trace [])) /\
      IntegerQueue.RawInitialFacts ((eventKeys trace).map (InputInt.eval assignment)).toFinset
        (rootCounts assignment (QueueEncoding.freshBase input)) (length.eval assignment).toNat
        (QueueScalarEncoding.evalTrace assignment trace) /\
      AuxCorrect assignment (QueueEncoding.freshBase input) (auxBase input trace length) length
        (CountedQueue.readHeads trace) (eventKeys trace) := by
  rw [encode, QueueEncoding.holds_append, QueueScalarEncoding.encode_correct, initial_block_correct]
  constructor
  next =>
    intro facts
    exact And.intro facts.1.1 (And.intro facts.1.2.1
      (And.intro facts.1.2.2 (And.intro facts.2.2.2 facts.2.1)))
  next =>
    intro facts
    exact And.intro (And.intro facts.1 (And.intro facts.2.1 facts.2.2.1))
      (And.intro facts.2.2.2.2 (And.intro facts.2.2.1.1 facts.2.2.2.1))

def auxiliaryFunctions (original : Assignment) (countBase : Nat) (length : InputInt)
    (messages keys : List InputInt) : Fin (messages.length + keys.length + 2 + 1) -> Int -> Int :=
  fun slot argument =>
    if slot.val <= messages.length then
      histogram (length.eval original) (messages.map (InputInt.eval original)) slot.val argument
    else if slot.val <= messages.length + keys.length + 1 then
      presence (rootCounts original countBase) (keys.map (InputInt.eval original))
        (slot.val - (messages.length + 1)) argument
    else (accounting (rootCounts original countBase) (keys.map (InputInt.eval original)) argument.toNat).total

def installInitial (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) : Assignment :=
  QueueEncoding.installCounts original base (auxiliaryFunctions original countBase length messages keys)

theorem install_inputs (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) :
    InputInt.eval (installInitial original countBase base length messages keys) = InputInt.eval original := by
  funext value
  exact QueueEncoding.input_install original base _ value

theorem install_before (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (domain result : Smt.Ty) (id : Nat) (before : id < base) :
    (installInitial original countBase base length messages keys).unary domain result id =
      original.unary domain result id :=
  QueueEncoding.install_outside original base _ domain result id (Or.inl before)

theorem install_histogram (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (version : Fin (messages.length + 1)) :
    (installInitial original countBase base length messages keys).unary .int .int (base + version.val) =
      histogram (length.eval original) (messages.map (InputInt.eval original)) version.val := by
  have within := Nat.le_of_lt_succ version.isLt
  rw [installInitial, QueueEncoding.install_at original base _ (Fin.mk version.val (by omega))]
  funext argument
  simp only [auxiliaryFunctions, if_pos within]

theorem install_presence (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (version : Fin (keys.length + 1)) :
    (installInitial original countBase base length messages keys).unary .int .int
        (seenBase base messages.length + version.val) =
      presence (rootCounts original countBase) (keys.map (InputInt.eval original)) version.val := by
  have bound := version.isLt
  have after_hist : Not (messages.length + 1 + version.val <= messages.length) := by omega
  have within : messages.length + 1 + version.val <= messages.length + keys.length + 1 := by omega
  have offset : seenBase base messages.length + version.val = base + (messages.length + 1 + version.val) := by
    simp [seenBase, Nat.add_assoc]
  rw [offset, installInitial,
    QueueEncoding.install_at original base _ (Fin.mk (messages.length + 1 + version.val) (by omega))]
  funext argument
  simp only [auxiliaryFunctions, if_neg after_hist, if_pos within, Nat.add_sub_cancel_left]

theorem install_tally (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) :
    (installInitial original countBase base length messages keys).unary .int .int
        (tallyId base messages.length keys.length) =
      fun argument =>
        (accounting (rootCounts original countBase) (keys.map (InputInt.eval original)) argument.toNat).total := by
  have after_hist : Not (messages.length + keys.length + 2 <= messages.length) := by omega
  have after_seen : Not (messages.length + keys.length + 2 <= messages.length + keys.length + 1) := by omega
  have offset : tallyId base messages.length keys.length = base + (messages.length + keys.length + 2) := by
    simp [tallyId, Nat.add_assoc]
  rw [offset, installInitial,
    QueueEncoding.install_at original base _ (Fin.mk (messages.length + keys.length + 2) (Nat.lt_succ_self _))]
  funext argument
  simp only [auxiliaryFunctions, if_neg after_hist, if_neg after_seen]

theorem install_aux_correct (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (count_before : countBase < base) :
    AuxCorrect (installInitial original countBase base length messages keys) countBase base length messages keys := by
  have inputs := install_inputs original countBase base length messages keys
  have counts := install_before original countBase base length messages keys .int .int countBase count_before
  refine And.intro ?_ (And.intro ?_ ?_)
  next =>
    intro version key _
    rw [install_histogram, inputs]
  next =>
    intro version key _
    simp only [install_presence, inputs, rootCounts, counts]
  next =>
    intro version
    simp only [install_tally, inputs, rootCounts, counts, Int.toNat_natCast]

theorem scalar_range_before_aux (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) :
    QueueScalarEncoding.scalarBase input (eventKeys trace) trace [] + 3 <= auxBase input trace length :=
  Nat.le_max_right _ _

theorem count_before_aux (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) :
    QueueEncoding.freshBase input < auxBase input trace length := by
  have counts := QueueScalarEncoding.count_range_before_scalar input (eventKeys trace) trace []
  have scalars := scalar_range_before_aux input trace length
  omega

theorem auxiliary_symbol_fresh (input : SmtScript.Formula) (trace : List (Event InputInt))
    (length : InputInt) (slot : Nat) :
    Not (Membership.mem (SmtScript.symbols (QueueScalarEncoding.encode input (eventKeys trace) trace [] length))
      (.unary .int .int (auxBase input trace length + slot))) := by
  intro member
  have bound := QueueEncoding.input_symbol_bound _ _ member
  have before : QueueEncoding.freshBase (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) <=
      auxBase input trace length := Nat.le_max_left _ _
  change auxBase input trace length + slot <
    QueueEncoding.freshBase (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) at bound
  omega

theorem install_count_values (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) :
    QueueEncoding.values (size := QueueReadback.writeCount trace)
      (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
        (CountedQueue.readHeads trace) (eventKeys trace)) (QueueEncoding.freshBase input) =
      QueueEncoding.values original (QueueEncoding.freshBase input) := by
  funext version
  have counts := QueueScalarEncoding.count_range_before_scalar input (eventKeys trace) trace []
  have scalars := scalar_range_before_aux input trace length
  have bound := version.isLt
  exact install_before original _ _ length _ _ .int .int _ (by omega)

theorem install_scalar_functions (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (slot : Fin 3) :
    (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
      (CountedQueue.readHeads trace) (eventKeys trace)).unary .int .int
        (QueueScalarEncoding.scalarBase input (eventKeys trace) trace [] + slot.val) =
      original.unary .int .int (QueueScalarEncoding.scalarBase input (eventKeys trace) trace [] + slot.val) := by
  have before := scalar_range_before_aux input trace length
  have bound := slot.isLt
  exact install_before original _ _ length _ _ .int .int _ (by omega)

theorem install_after_aux (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (domain result : Smt.Ty) (id : Nat)
    (after_aux : nextBase input trace length <= id) :
    (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
      (CountedQueue.readHeads trace) (eventKeys trace)).unary domain result id =
      original.unary domain result id :=
  QueueEncoding.install_outside original _ _ domain result id (Or.inr (by
    simpa only [nextBase, Nat.add_assoc] using after_aux))

theorem install_old_term (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (term : Term .bool)
    (present : Membership.mem (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) term) :
    term.eval (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
      (CountedQueue.readHeads trace) (eventKeys trace)) = term.eval original := by
  apply QueueEncoding.eval_install
  intro symbol member
  have declared := (SmtScript.symbol_coverage
    (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) symbol).mpr
      (Exists.intro term (And.intro present (by simpa only [SmtScript.lower_symbols] using member)))
  have bound := QueueEncoding.input_symbol_bound _ symbol declared
  exact Nat.lt_of_lt_of_le bound (Nat.le_max_left _ _)

theorem old_block_preserved (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) :
    SmtScript.Holds
      (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
        (CountedQueue.readHeads trace) (eventKeys trace))
      (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) <->
      SmtScript.Holds original (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) := by
  constructor
  next =>
    intro holds term present
    rw [Eq.symm (install_old_term original input trace length term present)]
    exact holds term present
  next =>
    intro holds term present
    rw [install_old_term original input trace length term present]
    exact holds term present

theorem eval_trace_install (original : Assignment) (countBase base : Nat) (length : InputInt)
    (messages keys : List InputInt) (trace : List (Event InputInt)) :
    QueueScalarEncoding.evalTrace (installInitial original countBase base length messages keys) trace =
      QueueScalarEncoding.evalTrace original trace := by
  unfold QueueScalarEncoding.evalTrace
  congr 1
  funext event
  cases event <;> simp [QueueScalarEncoding.evalEvent, installInitial]

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt)
    (old : SmtScript.Holds original (QueueScalarEncoding.encode input (eventKeys trace) trace [] length))
    (facts : IntegerQueue.RawInitialFacts ((eventKeys trace).map (InputInt.eval original)).toFinset
      (rootCounts original (QueueEncoding.freshBase input)) (length.eval original).toNat
      (QueueScalarEncoding.evalTrace original trace)) :
    SmtScript.Holds
      (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
        (CountedQueue.readHeads trace) (eventKeys trace))
      (encode input trace length) := by
  have before := count_before_aux input trace length
  have auxiliary := install_aux_correct original (QueueEncoding.freshBase input) (auxBase input trace length)
    length (CountedQueue.readHeads trace) (eventKeys trace) before
  have nonnegative := ((QueueScalarEncoding.encode_correct original input (eventKeys trace) trace [] length).mp old).2.2.1
  rw [encode, QueueEncoding.holds_append, initial_block_correct]
  refine And.intro ((old_block_preserved original input trace length).mpr old)
    (And.intro auxiliary (And.intro ?_ ?_))
  next =>
    rw [install_inputs]
    exact nonnegative
  next =>
    have counts := install_before original (QueueEncoding.freshBase input) (auxBase input trace length)
      length (CountedQueue.readHeads trace) (eventKeys trace) .int .int (QueueEncoding.freshBase input) before
    simpa only [install_inputs, rootCounts, counts, eval_trace_install] using facts

theorem encode_exists_iff (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input trace length)) <->
    (exists original : Assignment,
      SmtScript.Holds original (QueueScalarEncoding.encode input (eventKeys trace) trace [] length) /\
      IntegerQueue.RawInitialFacts ((eventKeys trace).map (InputInt.eval original)).toFinset
        (rootCounts original (QueueEncoding.freshBase input)) (length.eval original).toNat
        (QueueScalarEncoding.evalTrace original trace)) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      rw [encode, QueueEncoding.holds_append, initial_block_correct] at holds
      exact Exists.intro assignment (And.intro holds.1 holds.2.2.2)
  next =>
    intro witness
    cases witness with
    | intro original facts =>
      exact Exists.intro
        (installInitial original (QueueEncoding.freshBase input) (auxBase input trace length) length
          (CountedQueue.readHeads trace) (eventKeys trace))
        (install_satisfies original input trace length facts.1 facts.2)

theorem alias_checks (assignment : Assignment) (countBase base : Nat) (length left right : InputInt)
    (same_key : left.eval assignment = right.eval assignment)
    (auxiliary : AuxCorrect assignment countBase base length [] [left, right]) :
    SmtScript.Holds assignment (checks countBase base length [] [left, right]) <->
      0 <= length.eval assignment /\ 0 <= rootCounts assignment countBase (left.eval assignment) /\
        rootCounts assignment countBase (left.eval assignment) <= length.eval assignment := by
  rw [checks_correct assignment countBase base length [] [left, right] auxiliary.1 auxiliary.2.2]
  simp [same_key]

theorem final_peek_lower_bound (assignment : Assignment) (countBase base : Nat) (length key : InputInt)
    (nonempty : 1 <= length.eval assignment)
    (auxiliary : AuxCorrect assignment countBase base length (CountedQueue.readHeads [.peek key]) [key])
    (holds : SmtScript.Holds assignment (checks countBase base length (CountedQueue.readHeads [.peek key]) [key])) :
    1 <= rootCounts assignment countBase (key.eval assignment) := by
  have lower := ((checks_correct assignment countBase base length _ [key] auxiliary.1 auxiliary.2.2).mp holds).2.1 key
    (by simp)
  have enough : [key.eval assignment].length <= (length.eval assignment).toNat := by simp; omega
  simpa [CountedQueue.readHeads, List.take_of_length_le enough] using lower

theorem duplicate_initial_occurrences (assignment : Assignment) (countBase base : Nat) (length key : InputInt)
    (long_enough : 2 <= length.eval assignment)
    (auxiliary : AuxCorrect assignment countBase base length (CountedQueue.readHeads [.pop key, .pop key]) [key])
    (holds : SmtScript.Holds assignment
      (checks countBase base length (CountedQueue.readHeads [.pop key, .pop key]) [key])) :
    2 <= rootCounts assignment countBase (key.eval assignment) := by
  have lower := ((checks_correct assignment countBase base length _ [key] auxiliary.1 auxiliary.2.2).mp holds).2.1 key
    (by simp)
  have enough : [key.eval assignment, key.eval assignment].length <= (length.eval assignment).toNat := by simp; omega
  simpa [CountedQueue.readHeads, List.take_of_length_le enough] using lower

theorem empty_initial_length (original : Assignment) (countBase base : Nat) (length : InputInt)
    (before : countBase < base) (nonnegative : 0 <= length.eval original) :
    SmtScript.Holds (installInitial original countBase base length [] []) (initialBlock countBase base length [] []) /\
      rootCounts (installInitial original countBase base length [] []) countBase = rootCounts original countBase := by
  refine And.intro ?_ (install_before original countBase base length [] [] .int .int countBase before)
  apply (initial_block_correct _ countBase base length [] []).mpr
  refine And.intro (install_aux_correct original countBase base length [] [] before) (And.intro ?_ ?_)
  next => rw [install_inputs]; exact nonnegative
  next => simp [IntegerQueue.RawInitialFacts]

theorem negative_length_rejected (assignment : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (negative : length.eval assignment < 0) :
    Not (SmtScript.Holds assignment (encode input trace length)) := by
  intro holds
  have nonnegative := ((encode_correct assignment input trace length).mp holds).2.2.1.1
  exact not_lt_of_ge nonnegative negative

end CCFRaft.Sparse.QueueInitialEncoding

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueInitialEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueInitialEncoding: allowed-axiom gate passed."
