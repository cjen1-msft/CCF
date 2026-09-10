import Sparse.IntervalEncoding
import Sparse.IntervalQueries
import Mathlib.Data.List.Nodup

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalPredicate

open Smt (Assignment Term)
open QueueEncoding (InputInt)
open IntervalEncoding (InputNat SymbolicGraph natValue)
open IntervalReadback (Address Demand)

variable {roots size : Nat}

inductive Operand (size : Nat) where
  | cell (version : Fin size)
  | input (value : InputInt)
  deriving DecidableEq, Repr

def Operand.references : Operand size -> List (Fin size)
  | .cell version => [version]
  | .input _ => []

def Operand.eval (assignment : Assignment) (values : Fin size -> Int) : Operand size -> Int
  | .cell version => values version
  | .input value => value.eval assignment

def Operand.lower (roots base : Nat) (position : InputNat) : Operand size -> Term .int
  | .cell version => IntervalEncoding.readRef base (Address.version (roots := roots) version) position
  | .input value => value.term

theorem Operand.locality (operand : Operand size) (assignment : Assignment)
    (left right : Fin size -> Int)
    (agree : forall version, Membership.mem operand.references version ->
      left version = right version) :
    operand.eval assignment left = operand.eval assignment right := by
  cases operand with
  | cell version => exact agree version (by simp [Operand.references])
  | input _ => rfl

theorem Operand.lower_correct (operand : Operand size) (assignment : Assignment)
    (roots base : Nat) (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    (operand.lower roots base position).eval assignment =
      operand.eval assignment (fun version =>
        IntervalEncoding.reads assignment base (Address.version (roots := roots) version)
          (natValue assignment position)) := by
  cases operand with
  | cell version => exact IntervalEncoding.readRef_eval assignment base _ position nonnegative
  | input _ => rfl

inductive Predicate (size : Nat) where
  | eq (left right : Operand size)
  | ne (left right : Operand size)
  | le (left right : Operand size)
  | lt (left right : Operand size)
  deriving DecidableEq, Repr

def Predicate.references : Predicate size -> List (Fin size)
  | .eq left right | .ne left right | .le left right | .lt left right =>
    left.references ++ right.references

def Predicate.eval (assignment : Assignment) (values : Fin size -> Int) : Predicate size -> Bool
  | .eq left right => decide (left.eval assignment values = right.eval assignment values)
  | .ne left right => decide (Not (left.eval assignment values = right.eval assignment values))
  | .le left right => decide (left.eval assignment values <= right.eval assignment values)
  | .lt left right => decide (left.eval assignment values < right.eval assignment values)

def Predicate.lower (roots base : Nat) (position : InputNat) : Predicate size -> Term .bool
  | .eq left right => .equal (left.lower roots base position) (right.lower roots base position)
  | .ne left right => .not (.equal (left.lower roots base position) (right.lower roots base position))
  | .le left right => .le (left.lower roots base position) (right.lower roots base position)
  | .lt left right => .not (.le (right.lower roots base position) (left.lower roots base position))

theorem Predicate.locality (predicate : Predicate size) (assignment : Assignment)
    (left right : Fin size -> Int)
    (agree : forall version, Membership.mem predicate.references version ->
      left version = right version) :
    predicate.eval assignment left = predicate.eval assignment right := by
  cases predicate <;> rename_i first second
  all_goals
    have first_eq := first.locality assignment left right
      (fun version present => agree version (List.mem_append.mpr (Or.inl present)))
    have second_eq := second.locality assignment left right
      (fun version present => agree version (List.mem_append.mpr (Or.inr present)))
    simp only [Predicate.eval, first_eq, second_eq]

theorem Predicate.lower_correct (predicate : Predicate size) (assignment : Assignment)
    (roots base : Nat) (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    (predicate.lower roots base position).eval assignment =
      predicate.eval assignment (fun version =>
        IntervalEncoding.reads assignment base (Address.version (roots := roots) version)
          (natValue assignment position)) := by
  cases predicate <;>
    simp [Predicate.lower, Predicate.eval, Term.eval,
      Operand.lower_correct _ assignment roots base position nonnegative]
  simp only [<- decide_not, not_lt]

theorem Predicate.lower_alias (predicate : Predicate size) (assignment : Assignment)
    (roots base : Nat) (left right : InputNat)
    (left_nonnegative : 0 <= assignment.constant .int left)
    (right_nonnegative : 0 <= assignment.constant .int right)
    (equalPositions : assignment.constant .int left = assignment.constant .int right) :
    (predicate.lower roots base left).eval assignment =
      (predicate.lower roots base right).eval assignment := by
  rw [predicate.lower_correct assignment roots base left left_nonnegative,
    predicate.lower_correct assignment roots base right right_nonnegative]
  have same : natValue assignment left = natValue assignment right :=
    congrArg Int.toNat equalPositions
  rw [same]

structure Query (size : Nat) where
  lower : InputNat
  upper : InputNat
  predicate : Predicate size
  deriving DecidableEq, Repr

def Query.toLocalQuery (assignment : Assignment) (query : Query size) :
    IntervalQueries.LocalQuery size Int where
  lower := natValue assignment query.lower
  upper := natValue assignment query.upper
  accepts values := query.predicate.eval assignment values = true
  references := query.predicate.references
  locality left right agree := by rw [query.predicate.locality assignment left right agree]

-- zeroID is supplied metadata. This function neither allocates it nor asserts its value.
def cutIds (zeroID : InputNat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : List InputNat :=
  (zeroID :: (graph.endpoints ++ queries.flatMap (fun query => [query.lower, query.upper]))).dedup

theorem cutIds_membership (zeroID : InputNat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (id : InputNat) :
    Membership.mem (cutIds zeroID graph queries) id <->
      Membership.mem
        (zeroID :: (graph.endpoints ++ queries.flatMap (fun query => [query.lower, query.upper]))) id := by
  simp only [cutIds, List.mem_dedup]

theorem cutIds_nodup (zeroID : InputNat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : (cutIds zeroID graph queries).Nodup :=
  List.nodup_dedup _

def references (predicates : List (Predicate size)) : List (Fin size) :=
  (predicates.flatMap Predicate.references).dedup

theorem references_membership (predicates : List (Predicate size)) (version : Fin size) :
    Membership.mem (references predicates) version <->
      exists predicate, Membership.mem predicates predicate /\
        Membership.mem predicate.references version := by
  simp [references]

theorem references_nodup (predicates : List (Predicate size)) : (references predicates).Nodup :=
  List.nodup_dedup _

def requestOccurrences (cuts : List InputNat) (predicates : List (Predicate size)) :
    List (Demand roots size) :=
  (cuts.product (predicates.flatMap Predicate.references)).map
    (fun pair => (Address.version pair.2, pair.1))

-- Both inputs are deduplicated before the product is constructed.
def requests (cuts : List InputNat) (predicates : List (Predicate size)) :
    List (Demand roots size) :=
  (cuts.dedup.product (references predicates)).map
    (fun pair => (Address.version pair.2, pair.1))

theorem requests_membership (cuts : List InputNat) (predicates : List (Predicate size))
    (demand : Demand roots size) :
    Membership.mem (requests cuts predicates) demand <->
      Membership.mem (requestOccurrences cuts predicates) demand := by
  simp [requests, requestOccurrences, references]

theorem requests_nodup (cuts : List InputNat) (predicates : List (Predicate size)) :
    (requests (roots := roots) cuts predicates).Nodup := by
  apply ((List.nodup_dedup cuts).product (references_nodup predicates)).map
  intro left right same
  cases left
  cases right
  simp only [Prod.mk.injEq, Address.version.injEq] at same
  exact Prod.ext same.2 same.1

def planned (graph : SymbolicGraph roots size) (cuts : List InputNat)
    (predicates : List (Predicate size)) : List (Demand roots size) :=
  IntervalDemandPlan.plan graph (requests cuts predicates)

theorem planned_nodup (graph : SymbolicGraph roots size) (cuts : List InputNat)
    (predicates : List (Predicate size)) : (planned graph cuts predicates).Nodup :=
  IntervalDemandPlan.plan_nodup graph _

theorem plan_membership_congr (graph : SymbolicGraph roots size)
    (left right : List (Demand roots size))
    (same : forall demand, Membership.mem left demand <-> Membership.mem right demand)
    (demand : Demand roots size) :
    Membership.mem (IntervalDemandPlan.plan graph left) demand <->
      Membership.mem (IntervalDemandPlan.plan graph right) demand := by
  have inclusion (first second : List (Demand roots size))
      (included : forall cell, Membership.mem first cell -> Membership.mem second cell)
      (member : Membership.mem (IntervalDemandPlan.plan graph first) demand) :
      Membership.mem (IntervalDemandPlan.plan graph second) demand := by
    apply List.mem_toFinset.mp
    apply IntervalDemandPlan.plan_minimal graph first _ (IntervalDemandPlan.plan_closed graph second)
      (fun cell present => List.mem_toFinset.mpr
        (IntervalDemandPlan.plan_includes graph second cell (included cell present))) demand member
  exact Iff.intro (inclusion left right (fun cell => (same cell).mp))
    (inclusion right left (fun cell => (same cell).mpr))

theorem planned_membership (graph : SymbolicGraph roots size) (cuts : List InputNat)
    (predicates : List (Predicate size)) (demand : Demand roots size) :
    Membership.mem (planned graph cuts predicates) demand <->
      Membership.mem (IntervalDemandPlan.plan graph (requestOccurrences cuts predicates)) demand :=
  plan_membership_congr graph _ _ (requests_membership cuts predicates) demand

theorem empty_references_regression :
    requests (roots := 2) [4, 4, 9]
      [Predicate.le (size := 1) (.input (.literal (-5))) (.input (.symbolic 7))] = [] := by
  decide

theorem repeated_inputs_regression :
    (requests (roots := 2) [7, 7, 9, 7]
      [Predicate.eq (size := 1) (.cell 0) (.cell 0),
       Predicate.eq (.cell 0) (.cell 0)]).length = 2 := by
  decide

theorem aliased_positions_regression (assignment : Assignment)
    (nonnegative : 0 <= assignment.constant .int 7)
    (equalPositions : assignment.constant .int 7 = assignment.constant .int 9) :
    (requests (roots := 2) [7, 9]
      [Predicate.lt (size := 1) (.cell 0) (.input (.literal 5))]).length = 2 /\
      ((Predicate.lt (size := 1) (.cell 0) (.input (.literal 5))).lower 2 10 7).eval assignment =
        ((Predicate.lt (size := 1) (.cell 0) (.input (.literal 5))).lower 2 10 9).eval assignment := by
  exact And.intro (by decide) (Predicate.lower_alias _ assignment 2 10 7 9 nonnegative
    (by rw [<- equalPositions]; exact nonnegative) equalPositions)

theorem signed_order_regression (assignment : Assignment) :
    (Predicate.lt (size := 0) (.input (.literal (-5))) (.input (.literal (-2)))).eval
      assignment Fin.elim0 = true := by
  rfl

theorem supplied_zero_regression (zeroID : InputNat) :
    cutIds zeroID (VersionedIntervals.Graph.empty : SymbolicGraph 0 0) [] = [zeroID] := by
  simp [cutIds, VersionedIntervals.Graph.endpoints]

theorem symbol_zero_regression (assignment : Assignment)
    (value : assignment.constant .int 0 = 11) :
    natValue assignment 0 = 11 := by
  simp [natValue, value]

private def mismatchValues (position version : Fin 2) : Int :=
  if position.val = 0 /\ version.val = 1 then 1 else 0

theorem existential_mismatch_not_pointwise_ne (assignment : Assignment) :
    (exists position : Fin 2,
      (Predicate.ne (.cell 0) (.cell 1)).eval assignment (mismatchValues position) = true) /\
    Not (forall position : Fin 2,
      (Predicate.ne (.cell 0) (.cell 1)).eval assignment (mismatchValues position) = true) := by
  constructor
  next => exact Exists.intro 0 rfl
  next =>
    intro all_positions
    have impossible := all_positions 1
    simp [Predicate.eval, Operand.eval, mismatchValues] at impossible

end CCFRaft.Sparse.IntervalPredicate

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalPredicate).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.IntervalPredicate: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.IntervalPredicate.Predicate.lower_correct
#print axioms CCFRaft.Sparse.IntervalPredicate.Predicate.lower_alias
#print axioms CCFRaft.Sparse.IntervalPredicate.requests_nodup
#print axioms CCFRaft.Sparse.IntervalPredicate.planned_membership
#print axioms CCFRaft.Sparse.IntervalPredicate.existential_mismatch_not_pointwise_ne
