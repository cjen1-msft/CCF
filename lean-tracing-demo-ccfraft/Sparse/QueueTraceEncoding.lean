import Sparse.QueueInitialEncoding
import Sparse.SmtScriptText

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueTraceEncoding

open Smt (Assignment)
open QueueEncoding (InputInt)
open QueueStream (Event concreteFollows)
open QueueScalarEncoding (evalEvent evalTrace write_count_eval)
open QueueReadback (writeCount)

def evalOperation (assignment : Assignment) : QueuePlan.StoreOp InputInt -> QueuePlan.StoreOp Int
  | .send key => .send (key.eval assignment)
  | .pop key => .pop (key.eval assignment)

theorem operations_eval (assignment : Assignment) (trace : List (Event InputInt)) :
    QueuePlan.operations (evalTrace assignment trace) =
      (QueuePlan.operations trace).map (evalOperation assignment) := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    simp only [evalTrace] at ih
    cases event <;> simp [evalTrace, evalEvent, QueuePlan.operations, evalOperation, ih]

theorem operation_eval (assignment : Assignment) (trace : List (Event InputInt))
    (index : Fin (writeCount trace)) (actual : Fin (writeCount (evalTrace assignment trace)))
    (same : actual.val = index.val) :
    QueuePlan.operation (evalTrace assignment trace) actual =
      evalOperation assignment (QueuePlan.operation trace index) := by
  simp [QueuePlan.operation, operations_eval, same]

theorem demand_mem {A : Type} [DecidableEq A] (keys : Finset A) (trace : List (Event A))
    (version : Fin (writeCount trace + 1)) (key : A) :
    Membership.mem (QueuePlan.demands keys trace) (version, key) <->
      (version.val = 0 /\ Membership.mem keys key) \/
      exists index : Fin (writeCount trace),
        version.val <= index.val /\ key = (QueuePlan.operation trace index).key := by
  simp [QueuePlan.demands, QueuePlan.mem_ancestors, and_comm]

theorem semantic_demand_mem (assignment : Assignment) (keys : List InputInt) (trace : List (Event InputInt))
    (version : Fin (writeCount trace + 1)) (key : Int) :
    Membership.mem (QueueEncoding.semanticDemands assignment keys trace []) (version, key) <->
      (version.val = 0 /\ Membership.mem (keys.map (InputInt.eval assignment)).toFinset key) \/
      exists index : Fin (writeCount trace),
        version.val <= index.val /\ key = (QueuePlan.operation trace index).key.eval assignment := by
  have query_members (query : Prod (Fin (writeCount trace + 1)) InputInt) :
      Membership.mem (QueueEncoding.syntaxDemands keys trace []) query <->
        Membership.mem (QueuePlan.demands keys.toFinset trace) query := by
    simp only [QueueEncoding.syntaxDemands, List.mem_toFinset, QueueEncoding.syntax_members,
      List.not_mem_nil, false_and, exists_false, or_false]
  constructor
  next =>
    intro member
    cases Finset.mem_image.mp member with
    | intro query spec =>
      cases query with
      | mk prior value =>
        have version_eq := congrArg Prod.fst spec.2
        have key_eq := congrArg Prod.snd spec.2
        change prior = version at version_eq
        change value.eval assignment = key at key_eq
        subst prior
        subst key
        cases (demand_mem keys.toFinset trace version value).mp ((query_members _).mp spec.1) with
        | inl root =>
          exact Or.inl (And.intro root.1 (List.mem_toFinset.mpr
            (List.mem_map.mpr (Exists.intro value (And.intro (List.mem_toFinset.mp root.2) rfl)))))
        | inr write =>
          cases write with
          | intro index selected =>
            exact Or.inr (Exists.intro index (And.intro selected.1 (congrArg (InputInt.eval assignment) selected.2)))
  next =>
    intro member
    cases member with
    | inl root =>
      cases List.mem_map.mp (List.mem_toFinset.mp root.2) with
      | intro value selected =>
        apply Finset.mem_image.mpr
        exact Exists.intro (version, value) (And.intro
          ((query_members _).mpr ((demand_mem _ _ _ _).mpr
            (Or.inl (And.intro root.1 (List.mem_toFinset.mpr selected.1)))))
          (Prod.ext rfl selected.2))
    | inr write =>
      cases write with
      | intro index selected =>
        apply Finset.mem_image.mpr
        exact Exists.intro (version, (QueuePlan.operation trace index).key) (And.intro
          ((query_members _).mpr ((demand_mem _ _ _ _).mpr
            (Or.inr (Exists.intro index (And.intro selected.1 rfl)))))
          (Prod.ext rfl selected.2.symm))

theorem demand_alignment (assignment : Assignment) (keys : List InputInt) (trace : List (Event InputInt))
    (version : Fin (writeCount trace + 1)) (actual : Fin (writeCount (evalTrace assignment trace) + 1))
    (same : actual.val = version.val) (key : Int) :
    Membership.mem (QueueEncoding.semanticDemands assignment keys trace []) (version, key) <->
      Membership.mem (QueuePlan.demands (keys.map (InputInt.eval assignment)).toFinset
        (evalTrace assignment trace)) (actual, key) := by
  rw [semantic_demand_mem, demand_mem, same]
  apply or_congr Iff.rfl
  constructor
  next =>
    intro witness
    cases witness with
    | intro index spec =>
      let interpreted : Fin (writeCount (evalTrace assignment trace)) :=
        Fin.mk index.val (by rw [write_count_eval]; exact index.isLt)
      refine Exists.intro interpreted (And.intro spec.1 ?_)
      rw [operation_eval assignment trace index interpreted rfl]
      cases op : QueuePlan.operation trace index <;>
        simpa [evalOperation, QueuePlan.StoreOp.key, op] using spec.2
  next =>
    intro witness
    cases witness with
    | intro index spec =>
      let syntactic : Fin (writeCount trace) :=
        Fin.mk index.val (by rw [Eq.symm (write_count_eval assignment trace)]; exact index.isLt)
      refine Exists.intro syntactic (And.intro spec.1 ?_)
      rw [operation_eval assignment trace syntactic index rfl] at spec
      cases op : QueuePlan.operation trace syntactic <;>
        simpa [evalOperation, QueuePlan.StoreOp.key, op] using spec.2

theorem store_alignment (assignment : Assignment) (trace : List (Event InputInt))
    (reads : Nat -> Int -> Int) (index : Fin (writeCount trace))
    (actual : Fin (writeCount (evalTrace assignment trace))) (same : actual.val = index.val) :
    let interpreted := (QueuePlan.graph (evalTrace assignment trace) (fun i => reads i.val)).stores actual
    let syntactic := (QueueEncoding.interpretedGraph assignment trace (fun i => reads i.val)).stores index
    interpreted.prior.val = syntactic.prior.val /\
      interpreted.key = syntactic.key /\ interpreted.value = syntactic.value := by
  simp only [QueuePlan.graph, QueueEncoding.interpretedGraph, Fin.val_castSucc,
    operation_eval assignment trace index actual same, same]
  cases op : QueuePlan.operation trace index <;>
    simp [evalOperation, QueuePlan.StoreOp.key, QueuePlan.StoreOp.event, QueueReadback.storeValue]

theorem equations_alignment (assignment : Assignment) (keys : List InputInt) (trace : List (Event InputInt))
    (reads : Nat -> Int -> Int) :
    Readback.Equations (QueueEncoding.interpretedGraph assignment trace (fun i => reads i.val)) none
      (QueueEncoding.semanticDemands assignment keys trace []) (fun i => reads i.val) <->
    Readback.Equations (QueuePlan.graph (evalTrace assignment trace) (fun i => reads i.val)) none
      (QueuePlan.demands (keys.map (InputInt.eval assignment)).toFinset (evalTrace assignment trace))
      (fun i => reads i.val) := by
  constructor
  next =>
    intro equations
    refine And.intro (by simp) ?_
    intro actual key member
    let index : Fin (writeCount trace) :=
      Fin.mk actual.val (by rw [Eq.symm (write_count_eval assignment trace)]; exact actual.isLt)
    have selected := equations.2 index key
      ((demand_alignment assignment keys trace index.succ actual.succ (by simp [index]) key).mpr member)
    have aligned := store_alignment assignment trace reads index actual rfl
    change reads actual.succ.val key =
      if key = ((QueuePlan.graph (evalTrace assignment trace) (fun i => reads i.val)).stores actual).key
      then ((QueuePlan.graph (evalTrace assignment trace) (fun i => reads i.val)).stores actual).value
      else reads ((QueuePlan.graph (evalTrace assignment trace) (fun i => reads i.val)).stores actual).prior.val key
    rw [aligned.2.1, aligned.2.2, aligned.1]
    simpa only [Fin.val_succ] using selected
  next =>
    intro equations
    refine And.intro (by simp) ?_
    intro index key member
    let actual : Fin (writeCount (evalTrace assignment trace)) :=
      Fin.mk index.val (by rw [write_count_eval]; exact index.isLt)
    have selected := equations.2 actual key
      ((demand_alignment assignment keys trace index.succ actual.succ (by simp [actual]) key).mp member)
    have aligned := store_alignment assignment trace reads index actual rfl
    simpa only [aligned.2.1, aligned.2.2, aligned.1, Fin.val_succ] using selected

theorem heap_alignment (assignment : Assignment) (trace : List (Event InputInt))
    (reads : Nat -> Int -> Int) (windows : Nat -> SignedQueue.SignedWindow) :
    QueueReadback.heap (size := writeCount (evalTrace assignment trace)) (fun i => reads i.val) windows =
      QueueReadback.heap (size := writeCount trace) (fun i => reads i.val) windows := by
  funext index
  simp [QueueReadback.heap, write_count_eval]

def trackedKeys (assignment : Assignment) (trace : List (Event InputInt)) : Finset Int :=
  ((QueueInitialEncoding.eventKeys trace).map (InputInt.eval assignment)).toFinset

def freshFiller (keys : Finset Int) : Int :=
  ((keys.sup Int.natAbs + 1 : Nat) : Int)

theorem filler_fresh (keys : Finset Int) : Not (Membership.mem keys (freshFiller keys)) := by
  intro member
  have bound := Finset.le_sup (f := Int.natAbs) member
  change ((keys.sup Int.natAbs + 1 : Nat) : Int).natAbs <= keys.sup Int.natAbs at bound
  rw [Int.natAbs_natCast] at bound
  omega

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt)
    (holds : SmtScript.Holds assignment (QueueInitialEncoding.encode input trace length)) :
    SmtScript.Holds assignment input /\
      exists queue : List Int, (queue.length : Int) = length.eval assignment /\
        concreteFollows queue (evalTrace assignment trace) := by
  have valid := (QueueInitialEncoding.encode_correct assignment input trace length).mp holds
  refine And.intro valid.1 ?_
  let reads : Nat -> Int -> Int := fun index =>
    assignment.unary .int .int (QueueEncoding.freshBase input + index)
  have equations := (equations_alignment assignment (QueueInitialEncoding.eventKeys trace) trace reads).mp valid.2.1.1
  have scalars := valid.2.2.1
  have scalar_holds := scalars.2.2
  change QueueReadback.ScalarHolds _
    (QueueReadback.heap (fun i => reads i.val) _) _ at scalar_holds
  rw [Eq.symm (heap_alignment assignment trace reads _)] at scalar_holds
  apply (QueuePlan.generated_exists_iff (trackedKeys assignment trace) (length.eval assignment) scalars.1
    (evalTrace assignment trace) (QueueInitialEncoding.tracked_uses assignment trace)
    (freshFiller (trackedKeys assignment trace)) (filler_fresh _)).mp
  refine Exists.intro _ (Exists.intro (fun i => reads i.val) (Exists.intro _
    (And.intro scalars.2.1 (And.intro equations (And.intro ?_ scalar_holds)))))
  simpa [reads, QueueInitialEncoding.rootCounts] using valid.2.2.2.1

theorem eval_trace_install_counts {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) (trace : List (Event InputInt)) :
    evalTrace (QueueEncoding.installCounts original base counts) trace = evalTrace original trace := by
  unfold evalTrace
  congr 1
  funext event
  cases event <;> simp [evalEvent]

def installWitness (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (state : QueueClause.Heap Int) (order : Int -> Int) : Assignment :=
  let counted := QueueEncoding.installCounts original (QueueEncoding.freshBase input)
    (fun index : Fin (writeCount trace + 1) => (state index.val).counts)
  let scalar := QueueScalarEncoding.installScalars counted
    (QueueScalarEncoding.scalarBase input (QueueInitialEncoding.eventKeys trace) trace [])
    (fun index => (state index).window) order
  QueueInitialEncoding.installInitial scalar (QueueEncoding.freshBase input)
    (QueueInitialEncoding.auxBase input trace length) length
    (CountedQueue.readHeads trace) (QueueInitialEncoding.eventKeys trace)

theorem witness_constants (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (state : QueueClause.Heap Int) (order : Int -> Int) :
    (installWitness original input trace length state order).constant = original.constant := rfl

theorem witness_external (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (state : QueueClause.Heap Int) (order : Int -> Int)
    (domain result : Smt.Ty) (id : Nat)
    (member : Membership.mem (SmtScript.symbols input) (.unary domain result id)) :
    (installWitness original input trace length state order).unary domain result id = original.unary domain result id := by
  have before := QueueEncoding.input_symbol_bound input _ member
  change id < QueueEncoding.freshBase input at before
  have count_range := QueueScalarEncoding.count_range_before_scalar input (QueueInitialEncoding.eventKeys trace) trace []
  have scalar_range := QueueInitialEncoding.scalar_range_before_aux input trace length
  unfold installWitness
  rw [QueueInitialEncoding.install_before _ (QueueEncoding.freshBase input)
    (QueueInitialEncoding.auxBase input trace length) length _ _ domain result id (by omega)]
  rw [QueueScalarEncoding.install_outside _
    (QueueScalarEncoding.scalarBase input (QueueInitialEncoding.eventKeys trace) trace [])
    _ _ domain result id (Or.inl (by omega))]
  exact QueueEncoding.install_outside original _ _ domain result id (Or.inl before)

theorem encode_from_heap (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (state : QueueClause.Heap Int) (order : Int -> Int)
    (input_holds : SmtScript.Holds original input) (nonnegative : 0 <= length.eval original)
    (initial : (state 0).window = { head := 0, tail := length.eval original })
    (facts : IntegerQueue.RawInitialFacts (trackedKeys original trace) (state 0).counts
      (length.eval original).toNat (evalTrace original trace))
    (clauses : QueueClause.Holds order state (QueueClause.compile 0 1 (evalTrace original trace))) :
    SmtScript.Holds (installWitness original input trace length state order)
      (QueueInitialEncoding.encode input trace length) := by
  let counts : Fin (writeCount trace + 1) -> Int -> Int := fun index => (state index.val).counts
  let windows := fun index => (state index).window
  let counted := QueueEncoding.installCounts original (QueueEncoding.freshBase input) counts
  let scalar := QueueScalarEncoding.installScalars counted
    (QueueScalarEncoding.scalarBase input (QueueInitialEncoding.eventKeys trace) trace []) windows order
  have equations := (equations_alignment original (QueueInitialEncoding.eventKeys trace) trace
    (fun index => (state index).counts)).mpr
      (QueuePlan.equations_from_heap (trackedKeys original trace) (evalTrace original trace) order state clauses)
  have count_semantics : QueueEncoding.CountSemantics original (QueueInitialEncoding.eventKeys trace) trace [] counts :=
    And.intro equations (by simp [QueueEncoding.ObservationsHold])
  have count_holds := QueueEncoding.install_satisfies original input (QueueInitialEncoding.eventKeys trace) trace []
    counts input_holds count_semantics
  have scalar_holds := QueuePlan.scalars_from_heap (evalTrace original trace) order state clauses
  rw [heap_alignment original trace (fun index => (state index).counts) windows] at scalar_holds
  have scalar_semantics : QueueScalarEncoding.Semantics counted (QueueEncoding.freshBase input) length trace windows order := by
    simpa only [QueueScalarEncoding.Semantics, counted, QueueEncoding.input_install, QueueEncoding.values_install,
      eval_trace_install_counts] using And.intro nonnegative (And.intro initial scalar_holds)
  have old := QueueScalarEncoding.install_satisfies counted input (QueueInitialEncoding.eventKeys trace) trace []
    length windows order count_holds scalar_semantics
  have family_equal : QueueEncoding.values (size := writeCount trace) scalar (QueueEncoding.freshBase input) = counts := by
    rw [QueueScalarEncoding.install_count_values, QueueEncoding.values_install]
  have root_equal : QueueInitialEncoding.rootCounts scalar (QueueEncoding.freshBase input) = (state 0).counts := by
    simpa [QueueEncoding.values, QueueInitialEncoding.rootCounts, counts] using
      congrFun family_equal (0 : Fin (writeCount trace + 1))
  have inputs_equal : InputInt.eval scalar = InputInt.eval original := by
    funext value
    simp [scalar, counted, QueueScalarEncoding.installScalars]
  have trace_equal : evalTrace scalar trace = evalTrace original trace := by
    dsimp only [scalar]
    rw [QueueScalarEncoding.eval_trace_install, eval_trace_install_counts]
  apply QueueInitialEncoding.install_satisfies scalar input trace length old
  simpa only [trackedKeys, inputs_equal, root_equal, trace_equal] using facts

theorem encode_complete (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (queue : List Int)
    (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (evalTrace original trace)) :
    exists assignment : Assignment,
      SmtScript.Holds assignment (QueueInitialEncoding.encode input trace length) /\
      assignment.constant = original.constant /\
      forall domain result id, Membership.mem (SmtScript.symbols input) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  have nonnegative : 0 <= length.eval original := by
    rw [Eq.symm queue_length]
    exact Int.natCast_nonneg _
  cases (QueueClause.compiled_exists_iff (trackedKeys original trace) (length.eval original) nonnegative
      (evalTrace original trace) (QueueInitialEncoding.tracked_uses original trace)
      (freshFiller (trackedKeys original trace)) (filler_fresh _)).mpr
        (Exists.intro queue (And.intro queue_length follows)) with
  | intro order witness =>
    cases witness with
    | intro state spec =>
      refine Exists.intro (installWitness original input trace length state order)
        (And.intro (encode_from_heap original input trace length state order
          input_holds nonnegative spec.1 spec.2.1 spec.2.2) (And.intro rfl ?_))
      intro domain result id member
      exact witness_external original input trace length state order domain result id member

theorem encode_exists_iff (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) :
    (exists assignment : Assignment,
      SmtScript.Holds assignment (QueueInitialEncoding.encode input trace length)) <->
    (exists original : Assignment, exists queue : List Int,
      SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
        concreteFollows queue (evalTrace original trace)) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input trace length holds
      cases sound.2 with
      | intro queue follows =>
        exact Exists.intro assignment (Exists.intro queue (And.intro sound.1 follows))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro queue spec =>
        cases encode_complete original input trace length queue spec.1 spec.2.1 spec.2.2 with
        | intro assignment holds =>
          exact Exists.intro assignment holds.1

theorem rendered_exists_iff (input : SmtScript.Formula) (trace : List (Event InputInt)) (length : InputInt) :
    (exists assignment : Assignment,
      SmtScriptText.runText assignment (QueueInitialEncoding.render input trace length) = some true) <->
    (exists original : Assignment, exists queue : List Int,
      SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
        concreteFollows queue (evalTrace original trace)) := by
  rw [Iff.symm (encode_exists_iff input trace length)]
  apply exists_congr
  intro assignment
  exact (SmtScriptText.formula_text_iff assignment (QueueInitialEncoding.encode input trace length)).symm

theorem alias_send_peek (original : Assignment) (left right : InputInt)
    (same_key : left.eval original = right.eval original) :
    exists assignment : Assignment,
      SmtScript.Holds assignment
        (QueueInitialEncoding.encode [] [.send left, .send right, .peek right, .length 1] (.literal 0)) /\
      assignment.constant = original.constant := by
  cases encode_complete original [] [.send left, .send right, .peek right, .length 1] (.literal 0) []
      (by simp [SmtScript.Holds]) rfl
      (by simp [evalTrace, evalEvent, concreteFollows, same_key]) with
  | intro assignment spec => exact Exists.intro assignment (And.intro spec.1 spec.2.1)

theorem duplicate_pop_peek (original : Assignment) (key : InputInt) :
    exists assignment : Assignment,
      SmtScript.Holds assignment
        (QueueInitialEncoding.encode [] [.pop key, .peek key, .length 1] (.literal 2)) /\
      assignment.constant = original.constant := by
  cases encode_complete original [] [.pop key, .peek key, .length 1] (.literal 2)
      [key.eval original, key.eval original] (by simp [SmtScript.Holds]) rfl
      (by simp [evalTrace, evalEvent, concreteFollows]) with
  | intro assignment spec => exact Exists.intro assignment (And.intro spec.1 spec.2.1)

theorem empty_peek_unsatisfiable (key : InputInt) :
    Not (exists assignment : Assignment,
      SmtScript.Holds assignment (QueueInitialEncoding.encode [] [.peek key] (.literal 0))) := by
  intro witness
  cases (encode_exists_iff [] [.peek key] (.literal 0)).mp witness with
  | intro original witness =>
    cases witness with
    | intro queue spec =>
      have length_zero : queue.length = 0 := by
        have equal := spec.2.1
        change (queue.length : Int) = 0 at equal
        omega
      have empty : queue = [] := by simpa using length_zero
      subst queue
      simpa [evalTrace, evalEvent, concreteFollows] using spec.2.2

end CCFRaft.Sparse.QueueTraceEncoding

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueTraceEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueTraceEncoding: allowed-axiom gate passed."
