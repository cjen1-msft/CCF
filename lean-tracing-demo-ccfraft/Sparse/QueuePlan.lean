import Sparse.QueueReadback

set_option autoImplicit false

namespace CCFRaft.Sparse.QueuePlan

open Sparse.QueueStream (Event concreteFollows)
open Sparse.QueueClause
open Sparse.QueueReadback
open Sparse.SignedQueue (SignedWindow)
open Sparse.IntegerQueue (RawInitialFacts)
open Sparse.CountedQueue (Uses)

variable {A : Type}

inductive StoreOp (A : Type) where
  | send (message : A)
  | pop (message : A)

def StoreOp.event : StoreOp A -> Event A
  | .send message => .send message
  | .pop message => .pop message

def StoreOp.key : StoreOp A -> A
  | .send message | .pop message => message

def operations : List (Event A) -> List (StoreOp A)
  | [] => []
  | .send message :: rest => .send message :: operations rest
  | .pop message :: rest => .pop message :: operations rest
  | .peek _ :: rest | .length _ :: rest => operations rest

theorem operations_length (trace : List (Event A)) :
    (operations trace).length = writeCount trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    cases event <;> simp_all [operations, writeCount, writes]

def operation (trace : List (Event A)) (index : Fin (writeCount trace)) : StoreOp A :=
  (operations trace)[index.val]'(by rw [operations_length]; exact index.isLt)

def graph (trace : List (Event A)) (reads : Fin (writeCount trace + 1) -> A -> Int) :
    Readback.Graph A Int (writeCount trace) where
  stores index :=
    { prior := index.castSucc
      key := (operation trace index).key
      value := storeValue (reads index.castSucc (operation trace index).key)
        (operation trace index).event }
  earlier index := Nat.lt_succ_self index.val

def writeClause (current index : Nat) (op : StoreOp A) : Clause A :=
  { event := op.event, source := current + index, target := current + index + 1 }

theorem compile_writes (trace : List (Event A)) (current : Nat) :
    (compile current (current + 1) trace).filter (fun clause => writes clause.event) =
      (operations trace).mapIdx (writeClause current) := by
  induction trace generalizing current with
  | nil => rfl
  | cons event rest ih =>
    simp only [writes] at ih
    cases event <;>
      simp [compile, writes, operations, StoreOp.event, List.mapIdx_cons,
        writeClause, ih]
    all_goals
      congr 1
      funext index op
      simp [writeClause, Nat.add_comm, Nat.add_left_comm]

theorem write_clause_mem (trace : List (Event A)) (current : Nat)
    (index : Fin (writeCount trace)) :
    Membership.mem (compile current (current + 1) trace)
      (writeClause current index.val (operation trace index)) := by
  suffices member : Membership.mem
      ((compile current (current + 1) trace).filter (fun clause => writes clause.event))
      (writeClause current index.val (operation trace index)) from (List.mem_filter.mp member).1
  rw [compile_writes]
  apply List.mem_iff_getElem.mpr
  refine Exists.intro index.val (Exists.intro ?_ ?_)
  next => simp [operations_length, index.isLt]
  next => simp [operation]

theorem writing_clause_index (trace : List (Event A)) (current : Nat) (clause : Clause A)
    (member : Membership.mem (compile current (current + 1) trace) clause)
    (writing : writes clause.event = true) :
    exists index : Fin (writeCount trace),
      clause = writeClause current index.val (operation trace index) := by
  have filtered : Membership.mem
      ((compile current (current + 1) trace).filter (fun item => writes item.event)) clause :=
    List.mem_filter.mpr (And.intro member writing)
  rw [compile_writes] at filtered
  cases List.mem_iff_getElem.mp filtered with
  | intro index witness =>
    cases witness with
    | intro bound selected =>
      have within : index < writeCount trace := by simpa [operations_length] using bound
      refine Exists.intro (Fin.mk index within) ?_
      simpa [operation] using selected.symm

theorem readonly_reference (trace : List (Event A)) (current : Nat) (clause : Clause A)
    (member : Membership.mem (compile current (current + 1) trace) clause)
    (readonly : writes clause.event = false) : clause.target = clause.source := by
  induction trace generalizing current with
  | nil => simp [compile] at member
  | cons event rest ih =>
    simp only [compile] at member
    split at member
    next writing =>
      cases List.mem_cons.mp member with
      | inl equal =>
        subst clause
        change writes event = false at readonly
        simp_all
      | inr later => exact ih _ later
    next =>
      cases List.mem_cons.mp member with
      | inl equal => subst clause; rfl
      | inr later => exact ih _ later

theorem compile_bounds (trace : List (Event A)) (current : Nat) (clause : Clause A)
    (member : Membership.mem (compile current (current + 1) trace) clause) :
    clause.source <= current + writeCount trace /\
      clause.target <= current + writeCount trace := by
  induction trace generalizing current with
  | nil => simp [compile] at member
  | cons event rest ih =>
    simp only [compile] at member
    split at member
    next writing =>
      have count : writeCount (event :: rest) = writeCount rest + 1 := by
        simp [writeCount, writing]
      cases List.mem_cons.mp member with
      | inl equal => subst clause; simp only at *; omega
      | inr later =>
        have next := ih _ later
        constructor <;> omega
    next writing =>
      have count : writeCount (event :: rest) = writeCount rest := by
        simp [writeCount, writing]
      cases List.mem_cons.mp member with
      | inl equal => subst clause; simp only at *; omega
      | inr later =>
        have next := ih _ later
        constructor <;> omega

variable [DecidableEq A] {size : Nat}

def ancestors (limit : Fin (size + 1)) (key : A) : Finset (Prod (Fin (size + 1)) A) :=
  (Finset.univ : Finset (Fin (limit.val + 1))).image fun prior =>
    (Fin.mk prior.val (Nat.lt_of_lt_of_le prior.isLt
      (Nat.succ_le_succ (Nat.le_of_lt_succ limit.isLt))), key)

theorem mem_ancestors (limit version : Fin (size + 1)) (key message : A) :
    Membership.mem (ancestors limit key) (version, message) <->
      version.val <= limit.val /\ message = key := by
  simp only [ancestors, Finset.mem_image, Finset.mem_univ, true_and]
  constructor
  next =>
    intro witness
    cases witness with
    | intro prior equal =>
      have ids := congrArg (fun pair => pair.1.val) equal
      have keys := congrArg Prod.snd equal
      have bound := prior.isLt
      exact And.intro (by simp only at ids; omega) keys.symm
  next =>
    intro bounds
    refine Exists.intro (Fin.mk version.val (by omega)) ?_
    apply Prod.ext
    next => rfl
    next => exact bounds.2.symm

theorem ancestors_downward (limit version prior : Fin (size + 1)) (key message : A)
    (before : prior.val <= version.val)
    (member : Membership.mem (ancestors limit key) (version, message)) :
    Membership.mem (ancestors limit key) (prior, message) := by
  have bounds := (mem_ancestors limit version key message).mp member
  exact (mem_ancestors limit prior key message).mpr
    (And.intro (Nat.le_trans before bounds.1) bounds.2)

def demands (keys : Finset A) (trace : List (Event A)) :
    Finset (Prod (Fin (writeCount trace + 1)) A) :=
  Union.union (keys.biUnion (fun key => ancestors 0 key))
    (Finset.univ.biUnion (fun index : Fin (writeCount trace) =>
      ancestors index.castSucc (operation trace index).key))

theorem initial_demand (keys : Finset A) (trace : List (Event A)) (key : A)
    (tracked : Membership.mem keys key) : Membership.mem (demands keys trace) (0, key) := by
  apply Finset.mem_union_left
  apply Finset.mem_biUnion.mpr
  exact Exists.intro key (And.intro tracked ((mem_ancestors 0 0 key key).mpr (by simp)))

theorem old_count_demand (keys : Finset A) (trace : List (Event A))
    (index : Fin (writeCount trace)) :
    Membership.mem (demands keys trace) (index.castSucc, (operation trace index).key) := by
  apply Finset.mem_union_right
  apply Finset.mem_biUnion.mpr
  exact Exists.intro index (And.intro (Finset.mem_univ _)
    ((mem_ancestors _ _ _ _).mpr (And.intro (Nat.le_refl _) rfl)))

theorem demands_downward (keys : Finset A) (trace : List (Event A))
    (version prior : Fin (writeCount trace + 1)) (key : A)
    (before : prior.val <= version.val)
    (member : Membership.mem (demands keys trace) (version, key)) :
    Membership.mem (demands keys trace) (prior, key) := by
  cases Finset.mem_union.mp member with
  | inl root =>
    cases Finset.mem_biUnion.mp root with
    | intro message spec =>
      exact Finset.mem_union_left _ (Finset.mem_biUnion.mpr (Exists.intro message
        (And.intro spec.1 (ancestors_downward 0 version prior message key before spec.2))))
  | inr old =>
    cases Finset.mem_biUnion.mp old with
    | intro index spec =>
      exact Finset.mem_union_right _ (Finset.mem_biUnion.mpr (Exists.intro index
        (And.intro spec.1 (ancestors_downward _ version prior _ key before spec.2))))

theorem generated_closed (keys : Finset A) (trace : List (Event A))
    (reads : Fin (writeCount trace + 1) -> A -> Int) :
    Readback.Closed (graph trace reads) (demands keys trace) := by
  intro index key member _
  exact demands_downward keys trace index.succ index.castSucc key
    (Nat.le_succ _) member

theorem generated_linked (keys : Finset A) (trace : List (Event A))
    (reads : Fin (writeCount trace + 1) -> A -> Int) (clause : Clause A)
    (member : Membership.mem (compile 0 1 trace) clause) :
    Linked (graph trace reads) reads (demands keys trace) clause := by
  by_cases writing : writes clause.event = true
  next =>
    cases writing_clause_index trace 0 clause member writing with
    | intro index equal =>
      subst clause
      have old := old_count_demand keys trace index
      cases op : operation trace index <;>
        simp only [writeClause, StoreOp.event, Linked]
      all_goals
        refine Exists.intro index ?_
        simpa [writeClause, graph, op, StoreOp.event, StoreOp.key] using old
  next =>
    have readonly := Bool.eq_false_iff.mpr writing
    have same := readonly_reference trace 0 clause member readonly
    cases clause with
    | mk event source target =>
      cases event <;> simp_all [Linked, writes]

theorem generated_plan (keys : Finset A) (trace : List (Event A))
    (reads : Fin (writeCount trace + 1) -> A -> Int) :
    Plan (graph trace reads) reads (demands keys trace) (compile 0 1 trace) := by
  have build : forall clauses : List (Clause A),
      (forall clause, Membership.mem clauses clause ->
        Linked (graph trace reads) reads (demands keys trace) clause) ->
      Plan (graph trace reads) reads (demands keys trace) clauses := by
    intro clauses
    induction clauses with
    | nil => intro _; trivial
    | cons clause rest ih =>
      intro every
      exact And.intro (every clause (by simp))
        (ih (fun later member => every later (List.mem_cons_of_mem clause member)))
  exact build _ (generated_linked keys trace reads)

theorem holds_member (order : Int -> A) (state : Heap A) (clauses : List (Clause A))
    (holds : Holds order state clauses) (clause : Clause A)
    (member : Membership.mem clauses clause) : clause.Holds order state := by
  induction clauses with
  | nil => simp at member
  | cons first rest ih =>
    cases List.mem_cons.mp member with
    | inl equal => subst clause; exact holds.1
    | inr later => exact ih holds.2 later

theorem store_counts (op : StoreOp A) (source target : Cursor A)
    (link : target = advance source op.event) :
    target.counts = Function.update source.counts op.key
      (storeValue (source.counts op.key) op.event) := by
  have fields := (field_equations_iff source target op.event).mpr link
  cases op <;> exact fields.2.2

theorem array_from_heap (trace : List (Event A)) (order : Int -> A) (state : Heap A)
    (holds : Holds order state (compile 0 1 trace)) (version : Fin (writeCount trace + 1)) :
    Readback.array (graph trace (fun index => (state index.val).counts)) (state 0).counts version =
      (state version.val).counts := by
  induction version using Fin.induction with
  | zero =>
    funext key
    exact Readback.array_root _ _ key
  | succ index ih =>
    have selected := holds_member order state _ holds _
      (write_clause_mem trace 0 index)
    have counts := store_counts (operation trace index)
      (state index.val) (state (index.val + 1)) (by simpa [writeClause] using selected.2)
    rw [array_update _ _ index rfl, ih]
    exact counts.symm

theorem equations_from_heap (keys : Finset A) (trace : List (Event A))
    (order : Int -> A) (state : Heap A) (holds : Holds order state (compile 0 1 trace)) :
    Readback.Equations (graph trace (fun index => (state index.val).counts)) none
      (demands keys trace) (fun index => (state index.val).counts) := by
  have equal : Readback.array (graph trace (fun index => (state index.val).counts))
      (state 0).counts = (fun index => (state index.val).counts) := by
    funext index
    exact array_from_heap trace order state holds index
  have equations := Readback.array_equations
    (graph trace (fun index => (state index.val).counts)) none (demands keys trace)
    (state 0).counts (by simp)
  simpa only [equal] using equations

omit [DecidableEq A] in
theorem restrict_heap_at (state : Heap A) (index : Fin (size + 1)) :
    heap (fun version : Fin (size + 1) => (state version.val).counts)
      (fun version => (state version).window) index.val = state index.val := by
  rw [heap_at]

theorem scalars_from_heap (trace : List (Event A)) (order : Int -> A) (state : Heap A)
    (holds : Holds order state (compile 0 1 trace)) :
    ScalarHolds order
      (heap (fun index : Fin (writeCount trace + 1) => (state index.val).counts)
        (fun index => (state index).window)) (compile 0 1 trace) := by
  let restricted := heap (fun index : Fin (writeCount trace + 1) => (state index.val).counts)
    (fun index => (state index).window)
  have every (clause : Clause A) (member : Membership.mem (compile 0 1 trace) clause) :
      guard order (restricted clause.source) clause.event /\
      scalarFields (restricted clause.source) (restricted clause.target) clause.event := by
    have bounds := compile_bounds trace 0 clause member
    have source := restrict_heap_at state
      (Fin.mk clause.source (show clause.source < writeCount trace + 1 by omega))
    have target := restrict_heap_at state
      (Fin.mk clause.target (show clause.target < writeCount trace + 1 by omega))
    change restricted clause.source = state clause.source at source
    change restricted clause.target = state clause.target at target
    rw [source, target]
    have selected := holds_member order state _ holds clause member
    exact And.intro selected.1
      (And.intro (congrArg (fun cursor => cursor.window.head) selected.2)
        (congrArg (fun cursor => cursor.window.tail) selected.2))
  have build : forall clauses : List (Clause A),
      (forall clause, Membership.mem clauses clause ->
        guard order (restricted clause.source) clause.event /\
          scalarFields (restricted clause.source) (restricted clause.target) clause.event) ->
      ScalarHolds order restricted clauses := by
    intro clauses
    induction clauses with
    | nil => intro _; trivial
    | cons clause rest ih =>
      intro all
      exact And.intro (all clause (by simp))
        (ih (fun later member => all later (List.mem_cons_of_mem clause member)))
  exact build _ every

variable [BEq A]

def Constraints (keys : Finset A) (length : Int) (trace : List (Event A))
    (reads : Fin (writeCount trace + 1) -> A -> Int)
    (windows : Nat -> SignedWindow) (order : Int -> A) : Prop :=
  windows 0 = { head := 0, tail := length } /\
    Readback.Equations (graph trace reads) none (demands keys trace) reads /\
    RawInitialFacts keys (reads 0) length.toNat trace /\
    ScalarHolds order (heap reads windows) (compile 0 1 trace)

variable [LawfulBEq A]

theorem generated_exists_iff (keys : Finset A) (length : Int) (nonnegative : 0 <= length)
    (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler)) :
    (exists order : Int -> A, exists reads : Fin (writeCount trace + 1) -> A -> Int,
      exists windows : Nat -> SignedWindow, Constraints keys length trace reads windows order) <->
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro order witness =>
      cases witness with
      | intro reads witness =>
        cases witness with
        | intro windows finite =>
          exact finite_queue_sound keys length nonnegative trace uses filler fresh
            (graph trace reads) reads (demands keys trace) windows order finite.1
            (initial_demand keys trace) (generated_closed keys trace reads)
            (generated_plan keys trace reads) finite.2.1 finite.2.2.1 finite.2.2.2
  next =>
    intro concrete
    cases (QueueClause.compiled_exists_iff keys length nonnegative trace uses filler fresh).mpr
        concrete with
    | intro order witness =>
      cases witness with
      | intro state spec =>
        refine Exists.intro order
          (Exists.intro (fun index => (state index.val).counts)
          (Exists.intro (fun index => (state index).window) ?_))
        exact And.intro spec.1 (And.intro
          (equations_from_heap keys trace order state spec.2.2)
          (And.intro spec.2.1 (scalars_from_heap trace order state spec.2.2)))

theorem empty_trace_negative_counts (length : Nat) :
    Constraints ({} : Finset Nat) (length : Int) [] (fun _ _ => -7)
      (fun _ => { head := 0, tail := (length : Int) }) (fun _ => 0) := by
  simp [Constraints, demands, writeCount, Readback.Equations, RawInitialFacts,
    ScalarHolds, compile]

theorem generated_duplicate_trace :
    exists order : Int -> Nat,
      exists reads : Fin (writeCount QueueReadback.exampleTrace + 1) -> Nat -> Int,
      exists windows : Nat -> SignedWindow,
        Constraints {1} 0 QueueReadback.exampleTrace reads windows order := by
  apply (generated_exists_iff {1} 0 (by omega) QueueReadback.exampleTrace
    (by simp [QueueReadback.exampleTrace, Uses]) 2 (by simp)).mpr
  exact Exists.intro [] (And.intro rfl (by simp [QueueReadback.exampleTrace, concreteFollows]))

end CCFRaft.Sparse.QueuePlan

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueuePlan).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueuePlan: allowed-axiom gate passed."
