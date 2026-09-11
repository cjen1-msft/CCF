import Sparse.IntervalQueryEncoding
import Sparse.JointIntervalCompletion

set_option autoImplicit false

namespace CCFRaft.Sparse.JointIntervalEncoding

open Smt (Assignment Term)
open IntervalPredicate (Operand Query)
open IntervalEncoding (Observation InputNat SymbolicGraph natTerm natValue)
open IntervalReadback (Address Demand Reads actual)
open IntervalQueryEncoding (interpretedQueries augmented interpretedDemands)
open VersionedIntervals (RootArrays)

variable {roots size : Nat}

def pointIds (observation : Observation roots size) : List Nat :=
  observation.position :: IntervalQueryEncoding.operandIds (Operand.input (size := size) observation.expected)

def metadataIds (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : List Nat :=
  IntervalQueryEncoding.metadataIds graph queries ++ observations.flatMap pointIds

def boundIds (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : List Nat :=
  IntervalQueryEncoding.boundIds graph queries ++ observations.map Observation.position

def reservedIds (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) : List Nat :=
  (SmtScript.symbols input).map QueueEncoding.symbolId ++ metadataIds graph queries observations

def zeroId (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) : Nat :=
  (reservedIds input graph queries observations).toFinset.sup id + 1

theorem reserved_below_zero (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (id : Nat)
    (present : Membership.mem (reservedIds input graph queries observations) id) :
    id < zeroId input graph queries observations := by
  exact Nat.lt_succ_of_le (Finset.le_sup (f := fun n : Nat => n) (List.mem_toFinset.mpr present))

def Domains (assignment : Assignment) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : Prop :=
  forall id, Membership.mem (boundIds graph queries observations) id -> 0 <= assignment.constant .int id

theorem query_domains (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (domains : Domains assignment graph queries observations) :
    IntervalQueryEncoding.Domains assignment graph queries :=
  fun id present => domains id (List.mem_append.mpr (Or.inl present))

theorem point_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (domains : Domains assignment graph queries observations) (observation : Observation roots size)
    (present : Membership.mem observations observation) :
    0 <= assignment.constant .int observation.position :=
  domains observation.position (List.mem_append.mpr (Or.inr
    (List.mem_map.mpr (Exists.intro observation (And.intro present rfl)))))

def points (assignment : Assignment) (observations : List (Observation roots size)) : List (Demand roots size) :=
  observations.map (fun observation => (observation.address, natValue assignment observation.position))

def cutIds (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : List Nat :=
  (IntervalPredicate.cutIds zeroID graph queries ++ observations.map Observation.position).dedup

def seeds (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : List (Demand roots size) :=
  (IntervalPredicate.requests (cutIds zeroID graph queries observations) (queries.map Query.predicate) ++
    IntervalEncoding.requested observations).dedup

def planned (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : List (Demand roots size) :=
  IntervalDemandPlan.plan graph (seeds zeroID graph queries observations)

theorem cut_image (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (zero_value : assignment.constant .int zeroID = 0) (position : Nat) :
    Membership.mem (JointIntervalCompletion.cuts (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations)) position <->
    exists id, Membership.mem (cutIds zeroID graph queries observations) id /\ natValue assignment id = position := by
  rw [JointIntervalCompletion.cuts_membership,
    IntervalQueryEncoding.cut_image assignment zeroID graph queries zero_value]
  have point_positions : (points assignment observations).map Prod.snd =
      (observations.map Observation.position).map (natValue assignment) := by
    simp [points, List.map_map, Function.comp_def]
  rw [point_positions]
  simp only [cutIds, List.mem_dedup, List.mem_append, or_and_right, exists_or, List.mem_map]

theorem cut_nonnegative (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (zero_value : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries observations)
    (id : Nat) (present : Membership.mem (cutIds zeroID graph queries observations) id) :
    0 <= assignment.constant .int id := by
  cases List.mem_append.mp (List.mem_dedup.mp present) with
  | inl original =>
    exact IntervalQueryEncoding.cut_nonnegative assignment zeroID graph queries zero_value
      (query_domains assignment graph queries observations domains) id original
  | inr point => exact domains id (List.mem_append.mpr (Or.inr point))

theorem point_requested (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) (observation : Observation roots size)
    (present : Membership.mem observations observation) :
    Membership.mem (seeds zeroID graph queries observations) (observation.address, observation.position) :=
  List.mem_dedup.mpr (List.mem_append.mpr (Or.inr
    (List.mem_map.mpr (Exists.intro observation (And.intro present rfl)))))

theorem reference_requested (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) (id : Nat)
    (cut : Membership.mem (cutIds zeroID graph queries observations) id)
    (query : Query size) (present : Membership.mem queries query) (version : Fin size)
    (referenced : Membership.mem query.predicate.references version) :
    Membership.mem (seeds zeroID graph queries observations) (.version version, id) := by
  apply List.mem_dedup.mpr
  apply List.mem_append.mpr
  apply Or.inl
  apply List.mem_map.mpr
  refine Exists.intro (id, version) (And.intro ?_ rfl)
  apply List.mem_product.mpr
  refine And.intro (List.mem_dedup.mpr cut) ?_
  apply (IntervalPredicate.references_membership _ version).mpr
  exact Exists.intro query.predicate (And.intro
    (List.mem_map.mpr (Exists.intro query (And.intro present rfl))) referenced)

theorem seed_position (zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) (demand : Demand roots size)
    (present : Membership.mem (seeds zeroID graph queries observations) demand) :
    Membership.mem (cutIds zeroID graph queries observations) demand.2 := by
  cases List.mem_append.mp (List.mem_dedup.mp present) with
  | inl query =>
    cases List.mem_map.mp query with
    | intro pair spec => cases spec.2; exact List.mem_dedup.mp (List.mem_product.mp spec.1).1
  | inr point =>
    cases List.mem_map.mp point with
    | intro observation spec =>
      cases spec.2
      exact List.mem_dedup.mpr (List.mem_append.mpr (Or.inr
        (List.mem_map.mpr (Exists.intro observation (And.intro spec.1 rfl)))))

theorem request_covered (assignment : Assignment) (zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (zero_value : assignment.constant .int zeroID = 0) (demand : Demand roots size)
    (present : Membership.mem (JointIntervalCompletion.requests (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations)) demand) :
    Membership.mem (interpretedDemands assignment (planned zeroID graph queries observations)) demand := by
  have include_seed (cell : Demand roots size) (member : Membership.mem (seeds zeroID graph queries observations) cell) :
      Membership.mem (interpretedDemands assignment (planned zeroID graph queries observations))
        (cell.1, natValue assignment cell.2) :=
    Finset.mem_image.mpr (Exists.intro cell (And.intro (List.mem_toFinset.mpr
      (IntervalDemandPlan.plan_includes graph (seeds zeroID graph queries observations) cell member)) rfl))
  cases List.mem_append.mp (List.mem_dedup.mp present) with
  | inr point =>
    cases List.mem_map.mp point with
    | intro observation spec =>
      cases spec.2
      exact include_seed _ (point_requested zeroID graph queries observations observation spec.1)
  | inl query =>
    cases List.mem_map.mp query with
    | intro pair spec =>
      cases spec.2
      have product := List.mem_product.mp spec.1
      cases List.mem_flatMap.mp (List.mem_dedup.mp product.2) with
      | intro localQuery selected =>
        cases List.mem_map.mp selected.1 with
        | intro query original =>
          cases original.2
          cases (cut_image assignment zeroID graph queries observations zero_value pair.1).mp
              (List.mem_toFinset.mpr product.1) with
          | intro id cut =>
            have included := include_seed _ (reference_requested zeroID graph queries observations
              id cut.1 query original.1 pair.2 selected.2)
            simpa only [cut.2] using included

def guardFormula (base zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : SmtScript.Formula :=
  queries.flatMap (fun query => (cutIds zeroID graph queries observations).map
    (IntervalQueryEncoding.guardTerm (roots := roots) base query))

def readFormula (base zeroID : Nat) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : SmtScript.Formula :=
  (planned zeroID graph queries observations).map
    (IntervalEncoding.readEquation base (IntervalEncoding.templates base graph)
      (IntervalEncoding.templates_size base graph))

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : SmtScript.Formula :=
  let zeroID := zeroId input graph queries observations
  let initial := augmented input zeroID
  let base := QueueEncoding.freshBase initial
  let cuts := cutIds zeroID graph queries observations
  let requests := (IntervalPredicate.requests cuts (queries.map Query.predicate) ++
    IntervalEncoding.requested observations).dedup
  let table := IntervalEncoding.templates base graph
  initial ++ (boundIds graph queries observations).dedup.map (fun id => Term.le (.integer 0) (natTerm id)) ++
    (IntervalDemandPlan.plan graph requests).map
      (IntervalEncoding.readEquation base table (IntervalEncoding.templates_size base graph)) ++
    queries.flatMap (fun query => cuts.map (IntervalQueryEncoding.guardTerm (roots := roots) base query)) ++
    observations.map (IntervalEncoding.observationEquation base)

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) : String :=
  SmtScript.render (encode input graph queries observations)

theorem guards_correct (assignment : Assignment) (base zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (zero_value : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries observations) :
    SmtScript.Holds assignment (guardFormula base zeroID graph queries observations) <->
    JointIntervalCompletion.CutPredicates (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations)
      (IntervalEncoding.reads assignment base) := by
  constructor
  next =>
    intro holds localQuery present cut active
    cases List.mem_map.mp present with
    | intro query spec =>
      cases spec.2
      cases (cut_image assignment zeroID graph queries observations zero_value cut.val).mp cut.property with
      | intro id selected =>
        have guarded := (IntervalQueryEncoding.guard_correct (roots := roots) assignment base query id
          (cut_nonnegative assignment zeroID graph queries observations zero_value domains id selected.1)).mp
            (holds _ (List.mem_flatMap.mpr (Exists.intro query (And.intro spec.1
              (List.mem_map.mpr (Exists.intro id (And.intro selected.1 rfl)))))))
        rw [selected.2] at guarded
        exact guarded active
  next =>
    intro valid term present
    cases List.mem_flatMap.mp present with
    | intro query selected =>
      cases List.mem_map.mp selected.2 with
      | intro id spec =>
        rw [<- spec.2]
        apply (IntervalQueryEncoding.guard_correct (roots := roots) assignment base query id
          (cut_nonnegative assignment zeroID graph queries observations zero_value domains id spec.1)).mpr
        exact valid (query.toLocalQuery assignment)
          (List.mem_map.mpr (Exists.intro query (And.intro selected.1 rfl)))
          (Subtype.mk (natValue assignment id)
            ((cut_image assignment zeroID graph queries observations zero_value _).mpr
              (Exists.intro id (And.intro spec.1 rfl))))

theorem read_correct (assignment : Assignment) (base zeroID : Nat) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (zero_value : assignment.constant .int zeroID = 0) (domains : Domains assignment graph queries observations) :
    SmtScript.Holds assignment (readFormula base zeroID graph queries observations) <->
    IntervalReadback.Equations (IntervalEncoding.interpret assignment graph)
      (interpretedDemands assignment (planned zeroID graph queries observations))
      (IntervalEncoding.reads assignment base) :=
  IntervalQueryEncoding.reads_at_demands_correct assignment base graph _
    (fun demand present => cut_nonnegative assignment zeroID graph queries observations zero_value domains demand.2
      (IntervalQueryEncoding.plan_positions graph (seeds zeroID graph queries observations) _
        (seed_position zeroID graph queries observations) demand present))

theorem point_domains (assignment : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (domains : Domains assignment graph queries observations) :
    IntervalEncoding.Domains assignment graph observations := by
  intro id present
  cases List.mem_append.mp present with
  | inl endpoint =>
    exact domains id (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl endpoint))))
  | inr position =>
    cases List.mem_map.mp position with
    | intro demand spec =>
      rw [<- spec.2]
      apply IntervalQueryEncoding.plan_positions graph (IntervalEncoding.requested observations)
        (fun index => 0 <= assignment.constant .int index) ?_ demand spec.1
      intro cell member
      cases List.mem_map.mp member with
      | intro observation selected =>
        cases selected.2
        exact point_nonnegative assignment graph queries observations domains observation selected.1

def Semantics (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) : Prop :=
  let zeroID := zeroId input graph queries observations
  let base := QueueEncoding.freshBase (augmented input zeroID)
  SmtScript.Holds assignment input /\ assignment.constant .int zeroID = 0 /\
    Domains assignment graph queries observations /\
    IntervalReadback.Equations (IntervalEncoding.interpret assignment graph)
      (interpretedDemands assignment (planned zeroID graph queries observations)) (IntervalEncoding.reads assignment base) /\
    JointIntervalCompletion.CutPredicates (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations) (IntervalEncoding.reads assignment base) /\
    IntervalEncoding.ObservationsHold assignment (IntervalEncoding.reads assignment base) observations

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) :
    SmtScript.Holds assignment (encode input graph queries observations) <->
      Semantics assignment input graph queries observations := by
  let zeroID := zeroId input graph queries observations
  let base := QueueEncoding.freshBase (augmented input zeroID)
  change SmtScript.Holds assignment (augmented input zeroID ++
    (boundIds graph queries observations).dedup.map (fun id => Term.le (.integer 0) (natTerm id)) ++
    readFormula base zeroID graph queries observations ++ guardFormula base zeroID graph queries observations ++
    observations.map (IntervalEncoding.observationEquation base)) <-> _
  have bounds :
      SmtScript.Holds assignment ((boundIds graph queries observations).dedup.map
        (fun id => Term.le (.integer 0) (natTerm id))) <-> Domains assignment graph queries observations := by
    simp [SmtScript.Holds, Domains, natTerm, Term.eval]
  simp only [QueueEncoding.holds_append, IntervalQueryEncoding.augmented_correct, bounds]
  constructor
  next =>
    intro valid
    have domains := valid.1.1.1.2
    have zero_value := valid.1.1.1.1.2
    exact And.intro valid.1.1.1.1.1 (And.intro zero_value (And.intro domains (And.intro
      ((read_correct assignment base zeroID graph queries observations zero_value domains).mp valid.1.1.2)
      (And.intro ((guards_correct assignment base zeroID graph queries observations zero_value domains).mp valid.1.2)
        ((IntervalEncoding.observations_correct assignment graph observations
          (point_domains assignment graph queries observations domains) base).mp valid.2)))))
  next =>
    intro valid
    have domains := valid.2.2.1
    exact And.intro (And.intro (And.intro (And.intro (And.intro valid.1 valid.2.1) domains)
      ((read_correct assignment base zeroID graph queries observations valid.2.1 domains).mpr valid.2.2.2.1))
      ((guards_correct assignment base zeroID graph queries observations valid.2.1 domains).mpr valid.2.2.2.2.1))
      ((IntervalEncoding.observations_correct assignment graph observations
        (point_domains assignment graph queries observations domains) base).mpr valid.2.2.2.2.2)

def Concrete (assignment : Assignment) (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) (arrays : RootArrays roots Int) : Prop :=
  IntervalQueryEncoding.Realizes assignment graph queries arrays /\
    IntervalEncoding.ObservationsHold assignment (actual (IntervalEncoding.interpret assignment graph) arrays) observations

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size))
    (holds : SmtScript.Holds assignment (encode input graph queries observations)) :
    SmtScript.Holds assignment input /\ Domains assignment graph queries observations /\
      exists arrays : RootArrays roots Int, Concrete assignment graph queries observations arrays := by
  have valid := (encode_correct assignment input graph queries observations).mp holds
  let zeroID := zeroId input graph queries observations
  let base := QueueEncoding.freshBase (augmented input zeroID)
  have compiled : JointIntervalCompletion.Compiled (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations) (IntervalEncoding.reads assignment base) := by
    refine And.intro ?_ valid.2.2.2.2.1
    intro address position present
    apply valid.2.2.2.1 address position
    exact IntervalDemandPlan.plan_minimal (IntervalEncoding.interpret assignment graph) _ _
      (IntervalQueryEncoding.plan_image_closed assignment graph (seeds zeroID graph queries observations))
      (request_covered assignment zeroID graph queries observations valid.2.1)
      (address, position) (List.mem_toFinset.mp present)
  refine And.intro valid.1 (And.intro valid.2.2.1 ?_)
  cases JointIntervalCompletion.compiled_realizes (IntervalEncoding.interpret assignment graph)
      (interpretedQueries assignment queries) (points assignment observations) _ compiled with
  | intro arrays completed =>
    refine Exists.intro arrays (And.intro completed.1 ?_)
    intro observation present
    have agree := completed.2 observation.address (natValue assignment observation.position)
      (JointIntervalCompletion.point_requested _ _ (points assignment observations) _
        (List.mem_map.mpr (Exists.intro observation (And.intro present rfl))))
    exact agree.trans (valid.2.2.2.2.2 observation present)

theorem metadata_bound (graph : SymbolicGraph roots size) (queries : List (Query size))
    (observations : List (Observation roots size)) (id : Nat)
    (present : Membership.mem (boundIds graph queries observations) id) :
    Membership.mem (metadataIds graph queries observations) id := by
  cases List.mem_append.mp present with
  | inl bound => exact List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl bound)))
  | inr point =>
    cases List.mem_map.mp point with
    | intro observation spec =>
      rw [<- spec.2]
      exact List.mem_append.mpr (Or.inr (List.mem_flatMap.mpr
        (Exists.intro observation (And.intro spec.1 (by simp [pointIds])))))

theorem observations_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (cells : Reads roots size Int)
    (agree : forall id, Membership.mem (metadataIds graph queries observations) id ->
      left.constant .int id = right.constant .int id) :
    IntervalEncoding.ObservationsHold left cells observations <->
      IntervalEncoding.ObservationsHold right cells observations := by
  unfold IntervalEncoding.ObservationsHold
  apply forall_congr'
  intro observation
  apply forall_congr'
  intro present
  have hp := agree observation.position (List.mem_append.mpr (Or.inr
    (List.mem_flatMap.mpr (Exists.intro observation (And.intro present (by simp [pointIds]))))))
  have he := IntervalQueryEncoding.operand_congr left right
    (Operand.input (size := size) observation.expected) (fun _ => 0)
    (fun id member => agree id (List.mem_append.mpr (Or.inr (List.mem_flatMap.mpr
      (Exists.intro observation (And.intro present (List.mem_cons_of_mem _ member)))))))
  change cells observation.address (natValue left observation.position) = observation.expected.eval left <->
    cells observation.address (natValue right observation.position) = observation.expected.eval right
  change observation.expected.eval left = observation.expected.eval right at he
  simp only [natValue, hp, he]

theorem concrete_congr (left right : Assignment) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (agree : forall id, Membership.mem (metadataIds graph queries observations) id ->
      left.constant .int id = right.constant .int id) :
    Concrete left graph queries observations arrays <-> Concrete right graph queries observations arrays := by
  have original_agree := fun id present => agree id (List.mem_append.mpr (Or.inl present))
  have graph_equal := IntervalQueryEncoding.interpret_congr left right graph
    (fun id present => original_agree id (List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl present)))))
  unfold Concrete
  rw [IntervalQueryEncoding.realizes_congr left right graph queries arrays original_agree, graph_equal]
  exact and_congr Iff.rfl (observations_congr left right graph queries observations _ agree)

def install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int) : Assignment :=
  let zeroID := zeroId input graph queries observations
  IntervalEncoding.install (IntervalQueryEncoding.setZero original zeroID) (augmented input zeroID) graph arrays

def nextFunctionId (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) : Nat :=
  QueueEncoding.freshBase (augmented input (zeroId input graph queries observations)) + roots + size + 1

theorem install_constant_other (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (ty : Smt.Ty) (id : Nat) (different : Not (id = zeroId input graph queries observations)) :
    (install original input graph queries observations arrays).constant ty id = original.constant ty id := by
  cases ty with
  | bool => rfl
  | int => exact IntervalQueryEncoding.setZero_other original _ id different

theorem install_metadata (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (id : Nat) (present : Membership.mem (metadataIds graph queries observations) id) :
    (install original input graph queries observations arrays).constant .int id = original.constant .int id := by
  apply install_constant_other
  have bound := reserved_below_zero input graph queries observations id (List.mem_append.mpr (Or.inr present))
  omega

theorem install_input_preserved (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int) :
    SmtScript.Holds (install original input graph queries observations arrays) input <-> SmtScript.Holds original input := by
  let zeroID := zeroId input graph queries observations
  have initialized := IntervalQueryEncoding.input_setZero_fresh original input zeroID
    (fun symbol present => reserved_below_zero input graph queries observations _
      (List.mem_append.mpr (Or.inl (List.mem_map.mpr (Exists.intro symbol (And.intro present rfl))))))
  have installed := IntervalEncoding.install_input_preserved
    (IntervalQueryEncoding.setZero original zeroID) (augmented input zeroID) graph arrays
  rw [IntervalQueryEncoding.augmented_correct, IntervalQueryEncoding.augmented_correct] at installed
  have initialized_zero : (IntervalQueryEncoding.setZero original zeroID).constant .int zeroID = 0 := by
    simp [IntervalQueryEncoding.setZero]
  have installed_zero : (IntervalEncoding.install (IntervalQueryEncoding.setZero original zeroID)
      (augmented input zeroID) graph arrays).constant .int zeroID = 0 := initialized_zero
  simp only [installed_zero, initialized_zero, and_true] at installed
  exact installed.trans initialized

theorem install_unary_outside (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (domain result : Smt.Ty) (id : Nat)
    (outside_range : id < QueueEncoding.freshBase (augmented input (zeroId input graph queries observations)) \/
      nextFunctionId input graph queries observations <= id) :
    (install original input graph queries observations arrays).unary domain result id =
      original.unary domain result id := by
  unfold install IntervalEncoding.install
  rw [QueueEncoding.install_outside _ _ _ domain result id
    (by simpa only [nextFunctionId, Nat.add_assoc] using outside_range)]
  rfl

theorem install_extra_slot (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int) :
    (install original input graph queries observations arrays).unary .int .int
        (QueueEncoding.freshBase (augmented input (zeroId input graph queries observations)) + (roots + size)) =
      original.unary .int .int
        (QueueEncoding.freshBase (augmented input (zeroId input graph queries observations)) + (roots + size)) :=
  IntervalEncoding.install_extra_slot (IntervalQueryEncoding.setZero original (zeroId input graph queries observations))
    (augmented input (zeroId input graph queries observations)) graph arrays

theorem install_external (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (domain result : Smt.Ty) (id : Nat)
    (present : Membership.mem (SmtScript.symbols input) (.unary domain result id)) :
    (install original input graph queries observations arrays).unary domain result id =
      original.unary domain result id := by
  apply install_unary_outside
  apply Or.inl
  apply QueueEncoding.input_symbol_bound _ (.unary domain result id)
  cases (SmtScript.symbol_coverage input _).mp present with
  | intro term spec =>
    exact (SmtScript.symbol_coverage _ _).mpr
      (Exists.intro term (And.intro (List.mem_append.mpr (Or.inl spec.1)) spec.2))

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) (arrays : RootArrays roots Int)
    (input_holds : SmtScript.Holds original input) (domains : Domains original graph queries observations)
    (concrete : Concrete original graph queries observations arrays) :
    SmtScript.Holds (install original input graph queries observations arrays) (encode input graph queries observations) := by
  let zeroID := zeroId input graph queries observations
  let finished := install original input graph queries observations arrays
  have agree := install_metadata original input graph queries observations arrays
  have new_domains : Domains finished graph queries observations := by
    intro id present
    rw [agree id (metadata_bound graph queries observations id present)]
    exact domains id present
  have new_concrete := (concrete_congr finished original graph queries observations arrays agree).mpr concrete
  have read_exact :
      IntervalEncoding.reads finished (QueueEncoding.freshBase (augmented input zeroID)) =
        actual (IntervalEncoding.interpret finished graph) arrays := by
    change IntervalEncoding.reads (IntervalEncoding.install
      (IntervalQueryEncoding.setZero original zeroID) (augmented input zeroID) graph arrays) _ = _
    rw [IntervalEncoding.reads_install]
    simp only [finished, install, IntervalEncoding.install, IntervalEncoding.interpret_install]
    rfl
  apply (encode_correct finished input graph queries observations).mpr
  refine And.intro ((install_input_preserved original input graph queries observations arrays).mpr input_holds)
    (And.intro (by simp [finished, install, IntervalEncoding.install, QueueEncoding.installCounts,
      IntervalQueryEncoding.setZero]) (And.intro new_domains ?_))
  rw [read_exact]
  refine And.intro (fun address position _ =>
    IntervalReadback.actual_equation (IntervalEncoding.interpret finished graph) arrays address position) ?_
  exact And.intro (JointIntervalCompletion.realizes_compiled (IntervalEncoding.interpret finished graph)
    (interpretedQueries finished queries) (points finished observations) arrays new_concrete.1).2 new_concrete.2

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) :
    (exists assignment : Assignment, SmtScriptText.runText assignment (render input graph queries observations) = some true) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph queries observations /\
        Concrete original graph queries observations arrays) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input graph queries observations holds
      cases sound.2.2 with
      | intro arrays concrete =>
        exact Exists.intro assignment (Exists.intro arrays (And.intro sound.1 (And.intro sound.2.1 concrete)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays spec =>
        exact Exists.intro (install original input graph queries observations arrays)
          (install_satisfies original input graph queries observations arrays spec.1 spec.2.1 spec.2.2)

theorem without_points_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) :
    (exists assignment : Assignment, SmtScriptText.runText assignment (render input graph queries []) = some true) <->
    (exists assignment : Assignment, SmtScriptText.runText assignment
      (IntervalQueryEncoding.render input graph queries) = some true) := by
  rw [rendered_exists_iff, IntervalQueryEncoding.rendered_exists_iff]
  simp only [Concrete, IntervalEncoding.ObservationsHold, List.not_mem_nil, false_implies, implies_true,
    and_true, Domains, boundIds, List.map_nil, List.append_nil, IntervalQueryEncoding.Domains]

private def regressionAssignment (position : Int) : Assignment where
  constant ty id :=
    match ty with
    | .bool => false
    | .int => if id = 1 then 10 else if id = 2 \/ id = 3 then position else 0
  unary _ result _ _ := match result with | .bool => false | .int => 0

private def singleGraph : SymbolicGraph 1 1 := .push .empty (.root 0)

private def zeroQuery : Query 1 :=
  { lower := 0, upper := 1, predicate := .eq (.cell 0) (.input (.literal 0)) }

private def fixedBounds (position : Int) : SmtScript.Formula :=
  [.equal (natTerm 0) (.integer 0), .equal (natTerm 1) (.integer 10),
    .equal (natTerm 2) (.integer position)]

theorem point_inside_conflict_regression :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render (fixedBounds 5) singleGraph [zeroQuery]
        [{ address := .root 0, position := 2, expected := .literal 1 }]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have bounds : assignment.constant .int 0 = 0 /\ assignment.constant .int 1 = 10 /\
          assignment.constant .int 2 = 5 := by
        simpa [SmtScript.Holds, fixedBounds, natTerm, Term.eval] using spec.1
      have query := spec.2.2.1 (zeroQuery.toLocalQuery assignment).toQuery
        (by simp [IntervalQueries.schemas, interpretedQueries]) 5
        (by simp [zeroQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, bounds])
      have point := spec.2.2.2 { address := .root 0, position := 2, expected := .literal 1 } (by simp)
      have query_value : arrays 0 5 = 0 := of_decide_eq_true query
      change arrays 0 (natValue assignment 2) = 1 at point
      simp only [natValue, bounds.2.2] at point
      change arrays 0 5 = 1 at point
      rw [query_value] at point
      contradiction

private def outsidePoints : List (Observation 1 1) :=
  [{ address := .root 0, position := 2, expected := .literal (-7) },
    { address := .version 0, position := 3, expected := .literal (-7) }]

theorem outside_root_version_position_alias_regression :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render (fixedBounds 12 ++ [.equal (natTerm 2) (natTerm 3)]) singleGraph [zeroQuery] outsidePoints) = some true := by
  apply (rendered_exists_iff _ _ _ _).mpr
  refine Exists.intro (regressionAssignment 12) (Exists.intro (fun _ position => if position = 12 then -7 else 0)
    (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))))
  next => simp [SmtScript.Holds, fixedBounds, natTerm, Term.eval, regressionAssignment]
  next =>
    intro id present
    simp [boundIds, IntervalQueryEncoding.boundIds, singleGraph, VersionedIntervals.Graph.endpoints,
      VersionedIntervals.Version.endpoints, zeroQuery, outsidePoints] at present
    rcases present with same | same | same | same <;> subst id <;> simp [regressionAssignment]
  next =>
    intro query present position active
    have same : query = (zeroQuery.toLocalQuery (regressionAssignment 12)).toQuery := by
      simpa [IntervalQueries.schemas, interpretedQueries] using present
    subst query
    have different : Not (position = 12) := by
      simp [zeroQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside, natValue, regressionAssignment] at active
      omega
    change decide ((if position = 12 then (-7 : Int) else 0) = 0) = true
    simp only [if_neg different]
    rfl
  next =>
    intro observation present
    simp only [outsidePoints, List.mem_cons, List.not_mem_nil, or_false] at present
    cases present with
    | inl same =>
      subst observation
      change (if natValue (regressionAssignment 12) 2 = 12 then (-7 : Int) else 0) = -7
      rfl
    | inr same =>
      subst observation
      change (if natValue (regressionAssignment 12) 3 = 12 then (-7 : Int) else 0) = -7
      rfl

theorem conflicting_duplicate_regression (graph : SymbolicGraph roots size)
    (address : Address roots size) (position : InputNat) :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] graph [] [{ address, position, expected := .literal 0 },
        { address, position, expected := .literal 1 }]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have first := spec.2.2.2 { address, position, expected := .literal 0 } (by simp)
      have second := spec.2.2.2 { address, position, expected := .literal 1 } (by simp)
      change actual (IntervalEncoding.interpret assignment graph) arrays address (natValue assignment position) = 0 at first
      change actual (IntervalEncoding.interpret assignment graph) arrays address (natValue assignment position) = 1 at second
      omega

theorem conflicting_root_version_position_alias_regression :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 2) (natTerm 3)] singleGraph []
        [{ address := .root 0, position := 2, expected := .literal 0 },
          { address := .version 0, position := 3, expected := .literal 1 }]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have same : assignment.constant .int 2 = assignment.constant .int 3 := by
        simpa [SmtScript.Holds, natTerm, Term.eval] using spec.1
      have first := spec.2.2.2 { address := .root 0, position := 2, expected := .literal 0 } (by simp)
      have second := spec.2.2.2 { address := .version 0, position := 3, expected := .literal 1 } (by simp)
      change arrays 0 (natValue assignment 2) = 0 at first
      change arrays 0 (natValue assignment 3) = 1 at second
      simp only [natValue, same] at first second
      omega

theorem negative_position_regression :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 2) (.integer (-1))] singleGraph []
        [{ address := .root 0, position := 2, expected := .literal (-7) }]) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have negative : assignment.constant .int 2 = -1 := by
        simpa [SmtScript.Holds, natTerm, Term.eval] using spec.1
      have nonnegative := point_nonnegative assignment singleGraph [] _ spec.2.1
        { address := .root 0, position := 2, expected := .literal (-7) } (by simp)
      change 0 <= assignment.constant .int 2 at nonnegative
      rw [negative] at nonnegative
      contradiction

theorem negative_symbolic_expected_regression :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 2) (.integer (-7))] (.empty : SymbolicGraph 1 0) []
        [{ address := .root 0, position := 1, expected := .symbolic 2 }]) = some true := by
  apply (rendered_exists_iff _ _ _ _).mpr
  refine Exists.intro (regressionAssignment (-7)) (Exists.intro (fun _ _ => -7)
    (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_))))
  next => simp [SmtScript.Holds, natTerm, Term.eval, regressionAssignment]
  next =>
    intro id present
    have same : id = 1 := by
      simpa [boundIds, IntervalQueryEncoding.boundIds, VersionedIntervals.Graph.endpoints] using present
    subst id
    simp [regressionAssignment]
  next =>
    intro query present
    simp [IntervalQueries.schemas, interpretedQueries] at present
  next =>
    intro observation present
    have same : observation = { address := .root 0, position := 1, expected := .symbolic 2 } := by
      simpa using present
    subst observation
    rfl

theorem empty_modes_regression :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] (.empty : SymbolicGraph 0 0) [] []) = some true := by
  apply (rendered_exists_iff _ _ _ _).mpr
  refine Exists.intro (regressionAssignment 0) (Exists.intro (fun root => Fin.elim0 root) ?_)
  simp [SmtScript.Holds, Domains, boundIds, IntervalQueryEncoding.boundIds, VersionedIntervals.Graph.endpoints,
    Concrete, IntervalQueryEncoding.Realizes, VersionedIntervals.Realizes, IntervalQueries.schemas,
    interpretedQueries, IntervalEncoding.ObservationsHold]

theorem empty_or_reversed_regression (lower upper : Nat) (reversed : upper <= lower) :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] (.empty : SymbolicGraph 0 0)
        [{ lower := 2, upper := 3, predicate := .eq (.input (.literal 0)) (.input (.literal 1)) }] []) = some true := by
  apply (without_points_iff _ _ _).mpr
  exact IntervalQueryEncoding.empty_or_reversed_regression lower upper reversed

theorem point_only_sparse_regression :
    planned 100 (.push (.push .empty (.root 0)) (.root 1) : SymbolicGraph 2 2) []
      [{ address := .version 1, position := 70, expected := .literal (-7) },
        { address := .version 1, position := 70, expected := .literal (-7) }] =
      [(.root 1, 70), (.version 1, 70)] := by
  decide +kernel

theorem high_point_metadata_regression :
    zeroId [] (.empty : SymbolicGraph 1 0) []
      [{ address := .root 0, position := 70, expected := .symbolic 1000 }] = 1001 /\
    nextFunctionId [] (.empty : SymbolicGraph 1 0) []
      [{ address := .root 0, position := 70, expected := .symbolic 1000 }] = 1004 := by
  decide +kernel

end CCFRaft.Sparse.JointIntervalEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.JointIntervalEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.JointIntervalEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.JointIntervalEncoding.rendered_exists_iff
#print axioms CCFRaft.Sparse.JointIntervalEncoding.install_metadata
#print axioms CCFRaft.Sparse.JointIntervalEncoding.install_input_preserved
