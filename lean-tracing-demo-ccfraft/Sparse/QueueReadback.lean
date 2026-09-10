import Sparse.Readback
import Sparse.QueueClause

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueReadback

open Sparse.QueueStream (Event concreteFollows)
open Sparse.QueueClause
open Sparse.SignedQueue (SignedWindow)
open Sparse.IntegerQueue (RawInitialFacts)
open Sparse.CountedQueue (Uses)

variable {A : Type} [DecidableEq A] {size : Nat}

-- Only graph IDs are used by writes. This extends their heap to the existing Nat interface.
def heap (reads : Fin (size + 1) -> A -> Int) (windows : Nat -> SignedWindow) : Heap A :=
  fun index =>
    { counts := if bound : index < size + 1 then reads (Fin.mk index bound) else reads 0
      window := windows index }

omit [DecidableEq A] in
@[simp] theorem heap_at (reads : Fin (size + 1) -> A -> Int)
    (windows : Nat -> SignedWindow) (index : Fin (size + 1)) :
    heap reads windows index.val = { counts := reads index, window := windows index.val } := by
  simp [heap, index.isLt]

def scalarFields (source target : Cursor A) (event : Event A) : Prop :=
  target.window.head = (advance source event).window.head /\
    target.window.tail = (advance source event).window.tail

def ScalarHolds (order : Int -> A) (state : Heap A) : List (Clause A) -> Prop
  | [] => True
  | clause :: rest =>
    (guard order (state clause.source) clause.event /\
      scalarFields (state clause.source) (state clause.target) clause.event) /\
    ScalarHolds order state rest

def storeValue (old : Int) : Event A -> Int
  | .send _ => if old = 0 then 1 else old
  | .pop _ => old - 1
  | .peek _ | .length _ => old

def WriteLink (graph : Readback.Graph A Int size)
    (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A)) (clause : Clause A) (message : A) : Prop :=
  exists index : Fin size,
    clause.source = index.val /\ clause.target = index.val + 1 /\
    (graph.stores index).prior = index.castSucc /\
    (graph.stores index).key = message /\
    (graph.stores index).value = storeValue (reads index.castSucc message) clause.event /\
    Membership.mem demands (index.castSucc, message)

def Linked (graph : Readback.Graph A Int size)
    (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A)) (clause : Clause A) : Prop :=
  match clause.event with
  | .send message | .pop message => WriteLink graph reads demands clause message
  | .peek _ | .length _ => clause.target = clause.source

def Plan (graph : Readback.Graph A Int size) (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A)) : List (Clause A) -> Prop
  | [] => True
  | clause :: rest => Linked graph reads demands clause /\ Plan graph reads demands rest

theorem array_update (graph : Readback.Graph A Int size) (root : A -> Int)
    (index : Fin size) (prior : (graph.stores index).prior = index.castSucc) :
    Readback.array graph root index.succ =
      Function.update (Readback.array graph root index.castSucc)
        (graph.stores index).key (graph.stores index).value := by
  funext key
  rw [Readback.array_store, prior]
  simp only [Function.update_apply]

theorem linked_step (graph : Readback.Graph A Int size)
    (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A)) (root : A -> Int)
    (windows : Nat -> SignedWindow) (order : Int -> A) (clause : Clause A)
    (linked : Linked graph reads demands clause)
    (agree : forall version key, Membership.mem demands (version, key) ->
      Readback.array graph root version key = reads version key) :
    (guard order (heap reads windows clause.source) clause.event /\
      scalarFields (heap reads windows clause.source) (heap reads windows clause.target)
        clause.event) <->
      clause.Holds order (heap (Readback.array graph root) windows) := by
  cases clause with
  | mk event source target =>
    cases event with
    | send message =>
      cases linked with
      | intro index spec =>
        have source_eq : source = index.val := spec.1
        have target_eq : target = index.val + 1 := spec.2.1
        have observed := agree index.castSucc message spec.2.2.2.2.2
        have update := array_update graph root index spec.2.2.1
        rw [spec.2.2.2.1, spec.2.2.2.2.1] at update
        subst source
        subst target
        have source_at := heap_at reads windows index.castSucc
        have target_at := heap_at reads windows index.succ
        have real_source := heap_at (Readback.array graph root) windows index.castSucc
        have real_target := heap_at (Readback.array graph root) windows index.succ
        simp only [Fin.val_castSucc, Fin.val_succ] at source_at target_at real_source real_target
        simp only [Clause.Holds, source_at, target_at, real_source, real_target]
        rw [cursor_eq_iff]
        by_cases zero : reads index.castSucc message = 0
        next =>
          simp only [storeValue, zero, if_true] at update
          simp [QueueClause.guard, scalarFields, advance, observed, zero, update,
            SignedWindow.append]
        next =>
          have unchanged : Readback.array graph root index.succ =
              Readback.array graph root index.castSucc := by
            simp only [storeValue, zero, if_false] at update
            simpa only [Eq.symm observed, Function.update_eq_self] using update
          simp [QueueClause.guard, scalarFields, advance, observed, zero, unchanged]
    | pop message =>
      cases linked with
      | intro index spec =>
        have source_eq : source = index.val := spec.1
        have target_eq : target = index.val + 1 := spec.2.1
        have observed := agree index.castSucc message spec.2.2.2.2.2
        have update := array_update graph root index spec.2.2.1
        rw [spec.2.2.2.1, spec.2.2.2.2.1] at update
        subst source
        subst target
        have source_at := heap_at reads windows index.castSucc
        have target_at := heap_at reads windows index.succ
        have real_source := heap_at (Readback.array graph root) windows index.castSucc
        have real_target := heap_at (Readback.array graph root) windows index.succ
        simp only [Fin.val_castSucc, Fin.val_succ] at source_at target_at real_source real_target
        simp only [Clause.Holds, source_at, target_at, real_source, real_target]
        rw [cursor_eq_iff]
        simp only [storeValue, Eq.symm observed] at update
        simp [QueueClause.guard, scalarFields, advance, observed, update,
          SignedWindow.pop]
    | peek message =>
      change target = source at linked
      subst target
      simp [Clause.Holds, QueueClause.guard, scalarFields, advance, heap]
    | length length =>
      change target = source at linked
      subst target
      simp [Clause.Holds, QueueClause.guard, scalarFields, advance, heap]

theorem plan_lift_iff (graph : Readback.Graph A Int size)
    (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A)) (root : A -> Int)
    (windows : Nat -> SignedWindow) (order : Int -> A) (clauses : List (Clause A))
    (plan : Plan graph reads demands clauses)
    (agree : forall version key, Membership.mem demands (version, key) ->
      Readback.array graph root version key = reads version key) :
    ScalarHolds order (heap reads windows) clauses <->
      Holds order (heap (Readback.array graph root) windows) clauses := by
  induction clauses with
  | nil => rfl
  | cons clause rest ih =>
    exact and_congr (linked_step graph reads demands root windows order clause plan.1 agree)
      (ih plan.2)

theorem finite_heap_iff (graph : Readback.Graph A Int size)
    (reads : Fin (size + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (size + 1)) A))
    (windows : Nat -> SignedWindow) (order : Int -> A) (clauses : List (Clause A))
    (closed : Readback.Closed graph demands) (plan : Plan graph reads demands clauses) :
    (Readback.Equations graph none demands reads /\
      ScalarHolds order (heap reads windows) clauses) <->
    exists root : A -> Int,
      (forall version key, Membership.mem demands (version, key) ->
        Readback.array graph root version key = reads version key) /\
      Holds order (heap (Readback.array graph root) windows) clauses := by
  constructor
  next =>
    intro finite
    cases (Readback.finite_readback_iff graph none demands reads closed).mp finite.1 with
    | intro root spec =>
      exact Exists.intro root (And.intro spec.2
        ((plan_lift_iff graph reads demands root windows order clauses plan spec.2).mp finite.2))
  next =>
    intro witness
    cases witness with
    | intro root spec =>
      refine And.intro ?_
        ((plan_lift_iff graph reads demands root windows order clauses plan spec.1).mpr spec.2)
      apply (Readback.finite_readback_iff graph none demands reads closed).mpr
      exact Exists.intro root (And.intro (by simp) spec.1)

def writeCount (trace : List (Event A)) : Nat :=
  (trace.filter writes).length

variable [BEq A]

omit [DecidableEq A] in
theorem initial_facts_congr (keys : Finset A) (left right : A -> Int)
    (length : Nat) (trace : List (Event A))
    (agree : forall message, Membership.mem keys message -> left message = right message) :
    RawInitialFacts keys left length trace <-> RawInitialFacts keys right length trace := by
  have total : keys.sum left = keys.sum right := Finset.sum_congr rfl agree
  unfold RawInitialFacts
  apply and_congr
  next =>
    apply forall_congr'
    intro message
    apply forall_congr'
    intro tracked
    rw [agree message tracked]
  next => rw [total]

theorem compiled_queue_iff (keys : Finset A) (length : Int) (trace : List (Event A))
    (graph : Readback.Graph A Int (writeCount trace))
    (reads : Fin (writeCount trace + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (writeCount trace + 1)) A))
    (windows : Nat -> SignedWindow) (order : Int -> A)
    (initial : windows 0 = { head := 0, tail := length })
    (initial_demands : forall message, Membership.mem keys message ->
      Membership.mem demands (0, message))
    (closed : Readback.Closed graph demands)
    (plan : Plan graph reads demands (compile 0 1 trace)) :
    (Readback.Equations graph none demands reads /\
      RawInitialFacts keys (reads 0) length.toNat trace /\
      ScalarHolds order (heap reads windows) (compile 0 1 trace)) <->
    exists root : A -> Int,
      (forall version key, Membership.mem demands (version, key) ->
        Readback.array graph root version key = reads version key) /\
      (heap (Readback.array graph root) windows 0).window = { head := 0, tail := length } /\
      RawInitialFacts keys (heap (Readback.array graph root) windows 0).counts length.toNat trace /\
      Holds order (heap (Readback.array graph root) windows) (compile 0 1 trace) := by
  constructor
  next =>
    intro finite
    cases (finite_heap_iff graph reads demands windows order (compile 0 1 trace) closed plan).mp
        (And.intro finite.1 finite.2.2) with
    | intro root spec =>
      have observed : forall message, Membership.mem keys message ->
          (heap (Readback.array graph root) windows 0).counts message = reads 0 message := by
        intro message tracked
        simpa [heap] using spec.1 0 message (initial_demands message tracked)
      refine Exists.intro root (And.intro spec.1 (And.intro ?_ (And.intro ?_ spec.2)))
      next => exact initial
      next => exact (initial_facts_congr keys _ _ length.toNat trace observed).mpr finite.2.1
  next =>
    intro witness
    cases witness with
    | intro root spec =>
      have finite :=
        (finite_heap_iff graph reads demands windows order (compile 0 1 trace) closed plan).mpr
          (Exists.intro root (And.intro spec.1 spec.2.2.2))
      have observed : forall message, Membership.mem keys message ->
          (heap (Readback.array graph root) windows 0).counts message = reads 0 message := by
        intro message tracked
        simpa [heap] using spec.1 0 message (initial_demands message tracked)
      exact And.intro finite.1 (And.intro
        ((initial_facts_congr keys _ _ length.toNat trace observed).mp spec.2.2.1) finite.2)

variable [LawfulBEq A]

theorem finite_queue_sound (keys : Finset A) (length : Int) (nonnegative : 0 <= length)
    (trace : List (Event A)) (uses : Uses keys trace)
    (filler : A) (fresh : Not (Membership.mem keys filler))
    (graph : Readback.Graph A Int (writeCount trace))
    (reads : Fin (writeCount trace + 1) -> A -> Int)
    (demands : Finset (Prod (Fin (writeCount trace + 1)) A))
    (windows : Nat -> SignedWindow) (order : Int -> A)
    (initial : windows 0 = { head := 0, tail := length })
    (initial_demands : forall message, Membership.mem keys message ->
      Membership.mem demands (0, message))
    (closed : Readback.Closed graph demands)
    (plan : Plan graph reads demands (compile 0 1 trace))
    (equations : Readback.Equations graph none demands reads)
    (facts : RawInitialFacts keys (reads 0) length.toNat trace)
    (scalars : ScalarHolds order (heap reads windows) (compile 0 1 trace)) :
    exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace := by
  cases (compiled_queue_iff keys length trace graph reads demands windows order initial
      initial_demands closed plan).mp (And.intro equations (And.intro facts scalars)) with
  | intro root spec =>
    apply (QueueClause.compiled_exists_iff keys length nonnegative trace uses filler fresh).mp
    exact Exists.intro order (Exists.intro (heap (Readback.array graph root) windows) spec.2)

def exampleTrace : List (Event Nat) :=
  [.send 1, .peek 1, .send 1, .pop 1, .length 0]

def exampleGraph : Readback.Graph Nat Int 3 where
  stores index :=
    { prior := index.castSucc, key := 1, value := if index.val < 2 then 1 else 0 }
  earlier index := Nat.lt_succ_self index.val

def exampleReads (version : Fin 4) (message : Nat) : Int :=
  if message = 1 then (if version.val = 1 \/ version.val = 2 then 1 else 0) else -7

def exampleDemands : Finset (Prod (Fin 4) Nat) :=
  Finset.univ.product {1}

def exampleWindows (index : Nat) : SignedWindow :=
  { head := if index = 3 then 1 else 0, tail := if index = 0 then 0 else 1 }

theorem duplicate_send_pop_example :
    (exists queue : List Nat, (queue.length : Int) = 0 /\ concreteFollows queue exampleTrace) /\
      exampleReads 0 2 = -7 := by
  have closed : Readback.Closed exampleGraph exampleDemands := by
    intro index key member different
    have same : 1 = key := by simpa [exampleDemands] using member
    subst key
    exact (different rfl).elim
  have equations : Readback.Equations exampleGraph none exampleDemands exampleReads := by
    constructor
    next => simp
    next =>
      intro index key member
      have same : 1 = key := by simpa [exampleDemands] using member
      subst key
      fin_cases index <;> norm_num [exampleGraph, exampleReads]
  have plan : Plan exampleGraph exampleReads exampleDemands (compile 0 1 exampleTrace) := by
    change WriteLink exampleGraph exampleReads exampleDemands
        { event := .send 1, source := 0, target := 1 } 1 /\
      (1 = 1 /\
      (WriteLink exampleGraph exampleReads exampleDemands
        { event := .send 1, source := 1, target := 2 } 1 /\
      (WriteLink exampleGraph exampleReads exampleDemands
        { event := .pop 1, source := 2, target := 3 } 1 /\ (3 = 3 /\ True))))
    refine And.intro (Exists.intro 0 ?_) (And.intro rfl
      (And.intro (Exists.intro 1 ?_) (And.intro (Exists.intro 2 ?_) (And.intro rfl True.intro))))
    all_goals norm_num [exampleGraph, exampleReads, exampleDemands, storeValue]
  have scalars : ScalarHolds (fun _ => 1) (heap exampleReads exampleWindows)
      (compile 0 1 exampleTrace) := by
    norm_num [ScalarHolds, exampleTrace, compile, writes, scalarFields, QueueClause.guard,
      advance, heap, exampleReads, exampleWindows, SignedWindow.append, SignedWindow.pop]
  refine And.intro ?_ rfl
  apply finite_queue_sound {1} 0 (by omega) exampleTrace
    (by simp [Uses, exampleTrace]) 2 (by simp) exampleGraph exampleReads exampleDemands
    exampleWindows (fun _ => 1) rfl
    (by
      intro message tracked
      exact Finset.mem_product.mpr (And.intro (Finset.mem_univ _) tracked))
    closed plan equations ?_ scalars
  norm_num [RawInitialFacts, exampleReads]

end CCFRaft.Sparse.QueueReadback

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueReadback).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueReadback: allowed-axiom gate passed."
