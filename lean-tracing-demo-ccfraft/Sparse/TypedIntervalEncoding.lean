import Sparse.IntervalEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedIntervalEncoding

open Smt (Ty Term Assignment)
open VersionedIntervals (Graph Version RootArrays)
open IntervalReadback (Address Demand Reads lookup actual)
open IntervalEncoding (InputNat natTerm natValue)

variable {ty : Ty} {roots size prior count : Nat}

abbrev SymbolicGraph (roots : Nat) (ty : Ty) (size : Nat) := Graph roots (Term ty) size

structure Observation (roots size : Nat) (ty : Ty) where
  address : Address roots size
  position : InputNat
  expected : Term ty

def interpretNode (assignment : Assignment) : Version roots (Term ty) prior -> Version roots ty.denote prior
  | .root root => .root root
  | .constant value => .constant (value.eval assignment)
  | .splice lower upper inside outside => .splice (natValue assignment lower) (natValue assignment upper) inside outside

def interpret (assignment : Assignment) : {size : Nat} -> SymbolicGraph roots ty size -> Graph roots ty.denote size
  | _, .empty => .empty
  | _, .push previous node => .push (interpret assignment previous) (interpretNode assignment node)

theorem lookup_interpret (assignment : Assignment) (graph : SymbolicGraph roots ty size) (version : Fin size) :
    lookup (interpret assignment graph) version = interpretNode assignment (lookup graph version) := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last => simp [interpret, lookup]
    | cast version => simpa [interpret, lookup] using ih version

theorem dependencies_interpret (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (address : Address roots size) :
    IntervalReadback.dependencies (interpret assignment graph) address = IntervalReadback.dependencies graph address := by
  cases address with
  | root _ => rfl
  | version version =>
    simp only [IntervalReadback.dependencies, lookup_interpret]
    cases lookup graph version <;> rfl

def requested (observations : List (Observation roots size ty)) : List (Demand roots size) :=
  observations.map (fun observation => (observation.address, observation.position))

def planned (graph : SymbolicGraph roots ty size) (observations : List (Observation roots size ty)) :
    List (Demand roots size) :=
  IntervalDemandPlan.plan graph (requested observations)

def positions (graph : SymbolicGraph roots ty size) (observations : List (Observation roots size ty)) : List InputNat :=
  graph.endpoints ++ (planned graph observations).map Prod.snd

def Domains (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : Prop :=
  forall position, Membership.mem (positions graph observations) position -> 0 <= assignment.constant .int position

def readRef (base : Nat) (address : Address roots size) (position : InputNat) : Term ty :=
  .app .int ty (base + (IntervalEncoding.slot address).val) (natTerm position)

def reads (assignment : Assignment) (base : Nat) : Reads roots size ty.denote :=
  fun address position => assignment.unary .int ty (base + (IntervalEncoding.slot address).val) (position : Int)

def nodeTerm (base : Nat) (node : Version roots (Term ty) prior) (position : InputNat) : Term ty :=
  match node with
  | .root root => .app .int ty (base + root.val) (natTerm position)
  | .constant value => value
  | .splice lower upper inside outside =>
    .ite (.and (.le (natTerm lower) (natTerm position)) (.not (.le (natTerm upper) (natTerm position))))
      (.app .int ty (base + (roots + inside.val)) (natTerm position))
      (.app .int ty (base + (roots + outside.val)) (natTerm position))

def templates (base : Nat) : {size : Nat} -> SymbolicGraph roots ty size -> Array (InputNat -> Term ty)
  | _, .empty => #[]
  | _, .push previous node => (templates base previous).push (nodeTerm base node)

theorem templates_size (base : Nat) (graph : SymbolicGraph roots ty size) : (templates base graph).size = size := by
  induction graph with
  | empty => rfl
  | push previous node ih => simp [templates, ih]

theorem templates_get (base : Nat) (graph : SymbolicGraph roots ty size) (version : Fin size) :
    (templates base graph)[version.val]'(by rw [templates_size]; exact version.isLt) =
      nodeTerm base (lookup graph version) := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last => simp [templates, lookup, Array.getElem_push, templates_size]
    | cast version => simp [templates, lookup, Array.getElem_push, templates_size, version.isLt, ih]

def readEquation (base : Nat) (table : Array (InputNat -> Term ty)) (size_eq : table.size = size)
    (demand : Demand roots size) : Term .bool :=
  match demand.1 with
  | .root _ => .boolean true
  | .version version => .equal (readRef base demand.1 demand.2)
      ((table[version.val]'(by rw [size_eq]; exact version.isLt)) demand.2)

def nodeMax : Version roots (Term ty) prior -> Nat
  | .root _ => 0
  | .constant term => SymbolBounds.termMax term
  | .splice lower upper _ _ => max lower upper

def graphMax : {size : Nat} -> SymbolicGraph roots ty size -> Nat
  | _, .empty => 0
  | _, .push previous node => max (graphMax previous) (nodeMax node)

def observationMax : List (Observation roots size ty) -> Nat
  | [] => 0
  | observation :: rest => max (max observation.position (SymbolBounds.termMax observation.expected)) (observationMax rest)

def base (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : Nat :=
  max (SymbolBounds.formulaMax input) (max (graphMax graph) (observationMax observations)) + 1

def nextFunctionId (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : Nat :=
  base input graph observations + roots + size

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : SmtScript.Formula :=
  let first := base input graph observations
  let demands := planned graph observations
  let table := templates first graph
  input ++ (graph.endpoints ++ demands.map Prod.snd).dedup.map (fun id => .le (.integer 0) (natTerm id)) ++
    demands.map (readEquation first table (templates_size first graph)) ++
    observations.map (fun observation => .equal (readRef first observation.address observation.position) observation.expected)

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : String :=
  SmtScript.render (encode input graph observations)

theorem readRef_eval (assignment : Assignment) (base : Nat) (address : Address roots size) (position : InputNat)
    (nonnegative : 0 <= assignment.constant .int position) :
    (readRef (ty := ty) base address position).eval assignment = reads assignment base address (natValue assignment position) := by
  simp [readRef, reads, natTerm, natValue, Term.eval, Int.toNat_of_nonneg nonnegative]

theorem equation_correct (assignment : Assignment) (graph : SymbolicGraph roots ty size) (base : Nat)
    (demand : Demand roots size) (nonnegative : 0 <= assignment.constant .int demand.2) :
    (readEquation base (templates base graph) (templates_size base graph) demand).eval assignment = true <->
      IntervalReadback.Equation (interpret assignment graph) (reads assignment base)
        demand.1 (natValue assignment demand.2) := by
  cases demand with
  | mk address position =>
    cases address with
    | root root => simp [readEquation, Term.eval, IntervalReadback.Equation]
    | version version =>
      simp only [readEquation, templates_get, Term.eval, decide_eq_true_eq,
        readRef_eval assignment base _ position nonnegative, IntervalReadback.Equation,
        IntervalReadback.readValue, lookup_interpret]
      cases node : lookup graph version <;>
        simp [nodeTerm, interpretNode, Term.eval, reads, IntervalEncoding.slot, IntervalReadback.earlier,
          natTerm, natValue, Int.toNat_of_nonneg nonnegative]

def interpretedDemands (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : Finset (Demand roots size) :=
  (planned graph observations).toFinset.image (fun demand => (demand.1, natValue assignment demand.2))

theorem interpreted_closed (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) :
    IntervalReadback.Closed (interpret assignment graph) (interpretedDemands assignment graph observations) := by
  intro address position member child dependency
  cases Finset.mem_image.mp member with
  | intro demand spec =>
    cases spec.2
    exact Finset.mem_image.mpr (Exists.intro (child, demand.2) (And.intro
      (IntervalDemandPlan.plan_closed graph (requested observations) demand.1 demand.2 spec.1 child
        (by simpa only [dependencies_interpret] using dependency)) rfl))

theorem observation_requested (graph : SymbolicGraph roots ty size) (observations : List (Observation roots size ty))
    (observation : Observation roots size ty) (member : Membership.mem observations observation) :
    Membership.mem (planned graph observations) (observation.address, observation.position) :=
  IntervalDemandPlan.plan_includes graph (requested observations) _
    (List.mem_map.mpr (Exists.intro observation (And.intro member rfl)))

theorem position_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (domains : Domains assignment graph observations)
    (demand : Demand roots size) (member : Membership.mem (planned graph observations) demand) :
    0 <= assignment.constant .int demand.2 :=
  domains demand.2 (List.mem_append.mpr (Or.inr (List.mem_map.mpr (Exists.intro demand (And.intro member rfl)))))

def ObservationsHold (assignment : Assignment) (cells : Reads roots size ty.denote)
    (observations : List (Observation roots size ty)) : Prop :=
  forall observation, Membership.mem observations observation ->
    cells observation.address (natValue assignment observation.position) = observation.expected.eval assignment

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) :
    SmtScript.Holds assignment (encode input graph observations) <->
      SmtScript.Holds assignment input /\ Domains assignment graph observations /\
      IntervalReadback.Equations (interpret assignment graph) (interpretedDemands assignment graph observations)
        (reads assignment (base input graph observations)) /\
      ObservationsHold assignment (reads assignment (base input graph observations)) observations := by
  simp only [encode, QueueEncoding.holds_append]
  have domains_iff :
      SmtScript.Holds assignment ((positions graph observations).dedup.map (fun id => .le (.integer 0) (natTerm id))) <->
        Domains assignment graph observations := by
    simp [SmtScript.Holds, Domains, natTerm, Term.eval]
  simp only [positions] at domains_iff
  rw [domains_iff]
  have equations_iff (domains : Domains assignment graph observations) :
      SmtScript.Holds assignment ((planned graph observations).map
        (readEquation (base input graph observations) (templates (base input graph observations) graph)
          (templates_size _ graph))) <->
      IntervalReadback.Equations (interpret assignment graph) (interpretedDemands assignment graph observations)
        (reads assignment (base input graph observations)) := by
    have point (demand : Demand roots size) (member : Membership.mem (planned graph observations) demand) :=
      equation_correct assignment graph (base input graph observations) demand
        (position_nonnegative assignment graph observations domains demand member)
    simp only [SmtScript.Holds, List.forall_mem_map]
    refine (forall_congr' (fun demand => forall_congr' (fun member => point demand member))).trans ?_
    simp [IntervalReadback.Equations, interpretedDemands]
  have observations_iff (domains : Domains assignment graph observations) :
      SmtScript.Holds assignment (observations.map (fun observation =>
        Term.equal (readRef (base input graph observations) observation.address observation.position) observation.expected)) <->
        ObservationsHold assignment (reads assignment (base input graph observations)) observations := by
    simp only [SmtScript.Holds, List.forall_mem_map, Term.eval, decide_eq_true_eq]
    apply forall_congr'
    intro observation
    apply forall_congr'
    intro member
    rw [readRef_eval assignment _ _ _ (position_nonnegative assignment graph observations domains _
      (observation_requested graph observations observation member))]
  constructor
  next =>
    intro spec
    exact And.intro spec.1.1.1 (And.intro spec.1.1.2
      (And.intro ((equations_iff spec.1.1.2).mp spec.1.2) ((observations_iff spec.1.1.2).mp spec.2)))
  next =>
    intro spec
    exact And.intro (And.intro (And.intro spec.1 spec.2.1) ((equations_iff spec.2.1).mpr spec.2.2.1))
      ((observations_iff spec.2.1).mpr spec.2.2.2)

def installUF (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote) : Assignment where
  constant := original.constant
  unary domain result id :=
    if inside : first <= id /\ id < first + count then
      if sorts : domain = .int /\ result = ty then
        fun argument => cast (congrArg Ty.denote sorts.2.symm)
          (values (Fin.mk (id - first) (by omega)) (cast (congrArg Ty.denote sorts.1) argument))
      else original.unary domain result id
    else original.unary domain result id

theorem install_at (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote) (index : Fin count) :
    (installUF original first values).unary .int ty (first + index.val) = values index := by
  have inside : first <= first + index.val /\ first + index.val < first + count := by
    have bound := index.isLt
    omega
  simp [installUF, inside]

theorem install_outside (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote)
    (domain result : Ty) (id : Nat) (outside : id < first \/ first + count <= id) :
    (installUF original first values).unary domain result id = original.unary domain result id := by
  have not_inside : Not (first <= id /\ id < first + count) := by omega
  simp only [installUF, dif_neg not_inside]

theorem eval_install (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote)
    {result : Ty} (term : Term result) (below : SymbolBounds.termMax term < first) :
    term.eval (installUF original first values) = term.eval original := by
  induction term with
  | boolean _ | integer _ | unknown _ _ => rfl
  | app domain result id argument ih =>
    have bounds : id < first /\ SymbolBounds.termMax argument < first := by
      simpa only [SymbolBounds.termMax, max_lt_iff] using below
    simp only [Term.eval, ih bounds.2, install_outside original first values domain result id (Or.inl bounds.1)]
  | add left right ihl ihr | sub left right ihl ihr | le left right ihl ihr
  | equal left right ihl ihr | and left right ihl ihr | implies left right ihl ihr =>
    have bounds : SymbolBounds.termMax left < first /\ SymbolBounds.termMax right < first := by
      simpa only [SymbolBounds.termMax, max_lt_iff] using below
    simp only [Term.eval, ihl bounds.1, ihr bounds.2]
  | not value ih => exact congrArg Bool.not (ih below)
  | ite condition yes no ihc ihy ihn =>
    have bounds : SymbolBounds.termMax condition < first /\
        SymbolBounds.termMax yes < first /\ SymbolBounds.termMax no < first := by
      simpa only [SymbolBounds.termMax, max_lt_iff] using below
    simp only [Term.eval, ihc bounds.1, ihy bounds.2.1, ihn bounds.2.2]

theorem term_functions_preserved (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote)
    {resultTy : Ty} (term : Term resultTy) (below : SymbolBounds.termMax term < first)
    (domain result : Ty) (id : Nat) (member : Membership.mem (SmtScript.termSymbols term) (.unary domain result id)) :
    (installUF original first values).unary domain result id = original.unary domain result id := by
  have bound : id <= SymbolBounds.termMax term := by
    rw [SymbolBounds.termMax_correct]
    exact Finset.le_sup (f := SymbolBounds.symbolId) (List.mem_toFinset.mpr member)
  exact install_outside original first values domain result id (Or.inl (Nat.lt_of_le_of_lt bound below))

theorem base_bounds (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) :
    SymbolBounds.formulaMax input < base input graph observations /\
    graphMax graph < base input graph observations /\ observationMax observations < base input graph observations := by
  unfold base
  omega

theorem formula_term_bound (input : SmtScript.Formula) (term : Term .bool) (member : Membership.mem input term) :
    SymbolBounds.termMax term <= SymbolBounds.formulaMax input := by
  induction input with
  | nil => simp at member
  | cons head rest ih =>
    cases List.mem_cons.mp member with
    | inl same => subst term; exact Nat.le_max_left _ _
    | inr present => exact Nat.le_trans (ih present) (Nat.le_max_right _ _)

theorem observation_bound (observations : List (Observation roots size ty)) (observation : Observation roots size ty)
    (member : Membership.mem observations observation) :
    max observation.position (SymbolBounds.termMax observation.expected) <= observationMax observations := by
  induction observations with
  | nil => simp at member
  | cons head rest ih =>
    cases List.mem_cons.mp member with
    | inl same => subst observation; exact Nat.le_max_left _ _
    | inr present => exact Nat.le_trans (ih present) (Nat.le_max_right _ _)

theorem lookup_bound (graph : SymbolicGraph roots ty size) (version : Fin size) :
    nodeMax (lookup graph version) <= graphMax graph := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last => simp [lookup, graphMax]
    | cast version =>
      simpa only [lookup, Fin.lastCases_castSucc] using Nat.le_trans (ih version) (Nat.le_max_left _ (nodeMax node))

theorem constant_term_bound (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (version : Fin size) (term : Term ty)
    (constant : lookup graph version = .constant term) :
    SymbolBounds.termMax term < base input graph observations := by
  have bound := lookup_bound graph version
  rw [constant] at bound
  exact Nat.lt_of_le_of_lt bound (base_bounds input graph observations).2.1

theorem interpret_install (original : Assignment) (first : Nat) (values : Fin count -> Int -> ty.denote)
    (graph : SymbolicGraph roots ty size) (below : graphMax graph < first) :
    interpret (installUF original first values) graph = interpret original graph := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    have bounds : graphMax previous < first /\ nodeMax node < first := by
      simpa only [graphMax, max_lt_iff] using below
    simp only [interpret, ih bounds.1]
    cases node with
    | root _ => rfl
    | constant term => simp only [interpretNode, eval_install original first values term bounds.2]
    | splice _ _ _ _ => rfl

def cellIndex (address : Address roots size) : Fin (roots + size) :=
  Fin.mk (IntervalEncoding.slot address).val (by
    cases address with
    | root root => change root.val < roots + size; have bound := root.isLt; omega
    | version version => change roots + version.val < roots + size; have bound := version.isLt; omega)

def family (graph : Graph roots ty.denote size) (arrays : RootArrays roots ty.denote) :
    Fin (roots + size) -> Int -> ty.denote :=
  fun index position =>
    if root : index.val < roots then arrays (Fin.mk index.val root) position.toNat
    else VersionedIntervals.evaluate graph arrays position.toNat
      (Fin.mk (index.val - roots) (by have bound := index.isLt; omega))

theorem family_at (graph : Graph roots ty.denote size) (arrays : RootArrays roots ty.denote)
    (address : Address roots size) (position : Nat) :
    family graph arrays (cellIndex address) (position : Int) = actual graph arrays address position := by
  cases address with
  | root root => simp [family, cellIndex, IntervalEncoding.slot, root.isLt, actual]
  | version version =>
    have not_root : Not (roots + version.val < roots) := by omega
    simp [family, cellIndex, IntervalEncoding.slot, not_root, actual]

def install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (arrays : RootArrays roots ty.denote) : Assignment :=
  installUF original (base input graph observations) (family (interpret original graph) arrays)

theorem reads_install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (arrays : RootArrays roots ty.denote) :
    reads (install original input graph observations arrays) (base input graph observations) =
      actual (interpret original graph) arrays := by
  funext address position
  change (installUF original _ (family (interpret original graph) arrays)).unary .int ty
    (base input graph observations + (cellIndex address).val) (position : Int) = _
  rw [install_at]
  exact family_at _ arrays address position

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (arrays : RootArrays roots ty.denote)
    (input_holds : SmtScript.Holds original input) (domains : Domains original graph observations)
    (observed : ObservationsHold original (actual (interpret original graph) arrays) observations) :
    SmtScript.Holds (install original input graph observations arrays) (encode input graph observations) := by
  have bounds := base_bounds input graph observations
  apply (encode_correct _ input graph observations).mpr
  refine And.intro ?_ (And.intro domains ?_)
  next =>
    intro term member
    rw [show term.eval (install original input graph observations arrays) = term.eval original from
      eval_install original _ _ term (Nat.lt_of_le_of_lt (formula_term_bound input term member) bounds.1)]
    exact input_holds term member
  next =>
    rw [reads_install]
    rw [show interpret (install original input graph observations arrays) graph = interpret original graph from
      interpret_install original _ _ graph bounds.2.1]
    refine And.intro (fun address position _ => IntervalReadback.actual_equation _ arrays address position) ?_
    intro observation member
    have expected := eval_install original (base input graph observations)
      (family (interpret original graph) arrays) observation.expected
      (Nat.lt_of_le_of_lt (Nat.le_trans (Nat.le_max_right _ _) (observation_bound observations observation member)) bounds.2.2)
    change actual (interpret original graph) arrays observation.address (natValue original observation.position) =
      observation.expected.eval (installUF original _ _)
    rw [expected]
    exact observed observation member

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) (holds : SmtScript.Holds assignment (encode input graph observations)) :
    SmtScript.Holds assignment input /\ Domains assignment graph observations /\
      exists arrays : RootArrays roots ty.denote, ObservationsHold assignment (actual (interpret assignment graph) arrays) observations := by
  have valid := (encode_correct assignment input graph observations).mp holds
  refine And.intro valid.1 (And.intro valid.2.1 ?_)
  cases (IntervalReadback.finite_readback_iff (interpret assignment graph) (interpretedDemands assignment graph observations)
      (reads assignment (base input graph observations)) (interpreted_closed assignment graph observations)).mp valid.2.2.1 with
  | intro arrays agree =>
    refine Exists.intro arrays ?_
    intro observation member
    exact (agree _ _ (Finset.mem_image.mpr (Exists.intro (observation.address, observation.position)
      (And.intro (List.mem_toFinset.mpr (observation_requested graph observations observation member)) rfl)))).trans
        (valid.2.2.2 observation member)

theorem rendered_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) :
    (exists assignment : Assignment, SmtScriptText.runText assignment (render input graph observations) = some true) <->
    (exists original : Assignment, exists arrays : RootArrays roots ty.denote,
      SmtScript.Holds original input /\ Domains original graph observations /\
        ObservationsHold original (actual (interpret original graph) arrays) observations) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input graph observations holds
      cases sound.2.2 with
      | intro arrays observed => exact Exists.intro assignment (Exists.intro arrays (And.intro sound.1 (And.intro sound.2.1 observed)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays spec =>
        exact Exists.intro (install original input graph observations arrays)
          (install_satisfies original input graph observations arrays spec.1 spec.2.1 spec.2.2)

namespace Regression

def signature : EntryValue.Entry := { term := -1, content := .signature }
def transaction : EntryValue.Entry := { term := 0, content := .transaction (-1) }

def fixtureAssignment (lower upper position : Nat) : Assignment where
  constant sort id :=
    match sort with
    | .bool => false
    | .int => if id = 0 then lower else if id = 1 then upper else if id = 2 then position else 0
    | .nodes => 0
    | .content => .signature
    | .entry => transaction
  unary _ result id _ :=
    match result with
    | .bool => false
    | .int => 0
    | .nodes => 0
    | .content => .signature
    | .entry => if id = 900 then
        (if lower <= position /\ position < upper then signature else transaction) else signature

def spliceGraph : SymbolicGraph 1 .entry 3 :=
  .push (.push (.push .empty (.root 0)) (.constant (.app .int .entry 700 (natTerm 3)))) (.splice 0 1 1 0)

def splicePoints : List (Observation 1 3 .entry) :=
  [{ address := .root 0, position := 2, expected := .unknown .entry 801 },
    { address := .version 2, position := 2, expected := .app .int .entry 900 (natTerm 2) }]

theorem native_splice (lower upper position : Nat) :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 0) (.integer lower), .equal (natTerm 1) (.integer upper),
        .equal (natTerm 2) (.integer position)] spliceGraph splicePoints) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro (fixtureAssignment lower upper position) (Exists.intro (fun _ _ => transaction)
    (And.intro (by simp [SmtScript.Holds, Term.eval, natTerm, fixtureAssignment]) (And.intro ?_ ?_)))
  next =>
    intro id _
    change 0 <= (if id = 0 then (lower : Int) else if id = 1 then upper else if id = 2 then position else 0)
    split_ifs <;> omega
  next =>
    intro observation member
    simp only [splicePoints, List.mem_cons, List.not_mem_nil, or_false] at member
    cases member with
    | inl same => subst observation; rfl
    | inr same => subst observation; rfl

def aliasPoints : List (Observation 1 0 .entry) :=
  [{ address := .root 0, position := 0, expected := .unknown .entry 100 },
    { address := .root 0, position := 1, expected := .unknown .entry 101 }]

theorem conflicting_native_aliases :
    Not (exists assignment : Assignment, SmtScriptText.runText assignment
      (render [.equal (natTerm 0) (natTerm 1), .not (.equal (.unknown .entry 100) (.unknown .entry 101))]
        (.empty : SymbolicGraph 1 .entry 0) aliasPoints) = some true) := by
  intro witness
  cases (rendered_exists_iff _ _ _).mp witness with
  | intro assignment witness =>
    cases witness with
    | intro arrays spec =>
      have positions_same : assignment.constant .int 0 = assignment.constant .int 1 := by
        simpa [Term.eval, natTerm] using spec.1 (.equal (natTerm 0) (natTerm 1)) (by simp)
      have different : Not (assignment.constant .entry 100 = assignment.constant .entry 101) := by
        simpa [Term.eval] using spec.1 (.not (.equal (.unknown .entry 100) (.unknown .entry 101))) (by simp)
      have first := spec.2.2 { address := .root 0, position := 0, expected := .unknown .entry 100 } (by simp [aliasPoints])
      have second := spec.2.2 { address := .root 0, position := 1, expected := .unknown .entry 101 } (by simp [aliasPoints])
      change arrays 0 (natValue assignment 0) = assignment.constant .entry 100 at first
      change arrays 0 (natValue assignment 1) = assignment.constant .entry 101 at second
      simp only [natValue, positions_same] at first second
      exact different (first.symm.trans second)

def unusedConstant : SymbolicGraph 0 .entry 1 :=
  .push .empty (.constant (.app .int .entry 2000 (natTerm 500)))

theorem metadata_reservation :
    base [] spliceGraph splicePoints = 901 /\ nextFunctionId [] spliceGraph splicePoints = 905 /\
      base [] unusedConstant [] = 2001 /\ nextFunctionId [] unusedConstant [] = 2002 := by
  decide +kernel

theorem unused_constant_full_function (original : Assignment) :
    (install original [] unusedConstant [] (fun root => Fin.elim0 root)).unary .int .entry 2000 =
      original.unary .int .entry 2000 := by
  apply install_outside
  exact Or.inl (by decide +kernel)

theorem expected_full_function (original : Assignment) (arrays : RootArrays 1 EntryValue.Entry) :
    (install original [] spliceGraph splicePoints arrays).unary .int .entry 900 = original.unary .int .entry 900 := by
  apply install_outside
  exact Or.inl (by decide +kernel)

def nestedPoint : Observation 1 0 .entry :=
  { address := .root 0, position := 700,
    expected := .app .content .entry 800 (.app .nodes .content 3000 (.unknown .nodes 99)) }

theorem nested_native_metadata :
    base [] (.empty : SymbolicGraph 1 .entry 0) [nestedPoint] = 3001 /\
    base [.equal (.app .entry .nodes 4000 (.unknown .entry 4)) (.unknown .nodes 5)]
      (.empty : SymbolicGraph 1 .entry 0) [nestedPoint] = 4001 /\
    base [] (.empty : SymbolicGraph 1 .entry 0) [{ nestedPoint with position := 10000 }] = 10001 := by
  decide +kernel

theorem native_empty_mode :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] (.empty : SymbolicGraph 0 .nodes 0) []) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro (fixtureAssignment 0 0 0) (Exists.intro (fun root => Fin.elim0 root) ?_)
  simp [SmtScript.Holds, Domains, positions, Graph.endpoints, planned, IntervalDemandPlan.plan,
    IntervalDemandPlan.walk, requested, ObservationsHold]

end Regression

end CCFRaft.Sparse.TypedIntervalEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.TypedIntervalEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.TypedIntervalEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.TypedIntervalEncoding.rendered_exists_iff
#print axioms CCFRaft.Sparse.TypedIntervalEncoding.eval_install
