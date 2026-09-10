import Sparse.IntervalDemandPlan
import Sparse.QueueEncoding
import Sparse.SmtScriptText

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalEncoding

open Smt (Assignment Term)
open VersionedIntervals (Graph Version RootArrays)
open IntervalReadback (Address Demand Reads actual lookup)
open QueueEncoding (InputInt freshBase)

-- Endpoint and position naturals are scalar symbol IDs, not literal indices.
abbrev InputNat := Nat
abbrev SymbolicGraph (roots size : Nat) := Graph roots Int size

variable {roots size prior : Nat}

def natTerm (id : InputNat) : Term .int := .unknown .int id
def natValue (assignment : Assignment) (id : InputNat) : Nat :=
  (assignment.constant .int id).toNat

def interpretNode (assignment : Assignment) : Version roots Int prior -> Version roots Int prior
  | .root arrayID => .root arrayID
  | .constant value => .constant value
  | .splice lower upper inside outside =>
    .splice (natValue assignment lower) (natValue assignment upper) inside outside

def interpret (assignment : Assignment) :
    {size : Nat} -> SymbolicGraph roots size -> Graph roots Int size
  | _, .empty => .empty
  | _, .push previous node => .push (interpret assignment previous) (interpretNode assignment node)

theorem lookup_interpret (assignment : Assignment) (graph : SymbolicGraph roots size)
    (version : Fin size) :
    lookup (interpret assignment graph) version = interpretNode assignment (lookup graph version) := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last => simp [interpret, lookup]
    | cast version => simpa [interpret, lookup] using ih version

theorem dependencies_interpret (assignment : Assignment) (graph : SymbolicGraph roots size)
    (address : Address roots size) :
    IntervalReadback.dependencies (interpret assignment graph) address =
      IntervalReadback.dependencies graph address := by
  cases address with
  | root _ => rfl
  | version version =>
    simp only [IntervalReadback.dependencies, lookup_interpret]
    cases lookup graph version <;> rfl

structure Observation (roots size : Nat) where
  address : Address roots size
  position : InputNat
  expected : InputInt

def requested (observations : List (Observation roots size)) : List (Demand roots size) :=
  observations.map fun observation => (observation.address, observation.position)

def demands (graph : SymbolicGraph roots size) (observations : List (Observation roots size)) :
    List (Demand roots size) :=
  IntervalDemandPlan.plan graph (requested observations)

def domainInputs (graph : SymbolicGraph roots size) (observations : List (Observation roots size)) :
    List InputNat :=
  graph.endpoints ++ (demands graph observations).map Prod.snd

def Domains (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : Prop :=
  forall id, Membership.mem (domainInputs graph observations) id ->
    0 <= assignment.constant .int id

def domainFormula (graph : SymbolicGraph roots size) (observations : List (Observation roots size)) :
    SmtScript.Formula :=
  (domainInputs graph observations).map fun id => .le (.integer 0) (natTerm id)

theorem domains_correct (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    SmtScript.Holds assignment (domainFormula graph observations) <->
      Domains assignment graph observations := by
  simp [SmtScript.Holds, domainFormula, Domains, natTerm, Term.eval]

def semanticDemands (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : Finset (Demand roots size) :=
  (demands graph observations).toFinset.image
    (fun demand => (demand.1, natValue assignment demand.2))

theorem semantic_closed (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    IntervalReadback.Closed (interpret assignment graph) (semanticDemands assignment graph observations) := by
  intro address position present child dependency
  cases Finset.mem_image.mp present with
  | intro demand spec =>
    cases spec.2
    apply Finset.mem_image.mpr
    refine Exists.intro (child, demand.2) (And.intro ?_ rfl)
    exact IntervalDemandPlan.plan_closed graph (requested observations) demand.1 demand.2 spec.1
      child (by simpa only [dependencies_interpret] using dependency)

def slot (address : Address roots size) : Fin (roots + size + 1) :=
  match address with
  | .root arrayID => Fin.mk arrayID.val (by have h := arrayID.isLt; omega)
  | .version version => Fin.mk (roots + version.val) (by have h := version.isLt; omega)

def readRef (base : Nat) (address : Address roots size) (position : InputNat) : Term .int :=
  .app .int .int (base + (slot address).val) (natTerm position)

def reads (assignment : Assignment) (base : Nat) : Reads roots size Int :=
  fun address position => assignment.unary .int .int (base + (slot address).val) (position : Int)

-- Each node contributes a flat RHS template with at most two child applications.
def nodeTerm (base : Nat) (node : Version roots Int prior) (position : InputNat) : Term .int :=
  match node with
  | .root arrayID => .app .int .int (base + arrayID.val) (natTerm position)
  | .constant value => .integer value
  | .splice lower upper inside outside =>
    .ite (.and (.le (natTerm lower) (natTerm position))
      (.not (.le (natTerm upper) (natTerm position))))
      (.app .int .int (base + (roots + inside.val)) (natTerm position))
      (.app .int .int (base + (roots + outside.val)) (natTerm position))

def templates (base : Nat) : {size : Nat} -> SymbolicGraph roots size ->
    Array (InputNat -> Term .int)
  | _, .empty => #[]
  | _, .push previous node => (templates base previous).push (nodeTerm base node)

theorem templates_size (base : Nat) (graph : SymbolicGraph roots size) :
    (templates base graph).size = size := by
  induction graph with
  | empty => rfl
  | push previous node ih => simp [templates, ih]

theorem templates_get (base : Nat) (graph : SymbolicGraph roots size) (version : Fin size) :
    (templates base graph)[version.val]'(by rw [templates_size]; exact version.isLt) =
      nodeTerm base (lookup graph version) := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last => simp [templates, lookup, Array.getElem_push, templates_size]
    | cast version =>
      simp [templates, lookup, Array.getElem_push, templates_size, version.isLt, ih]

def readEquation (base : Nat) (table : Array (InputNat -> Term .int))
    (size_eq : table.size = size) (demand : Demand roots size) : Term .bool :=
  match demand.1 with
  | .root _ => .boolean true
  | .version version =>
    .equal (readRef base demand.1 demand.2)
      ((table[version.val]'(by rw [size_eq]; exact version.isLt)) demand.2)

def readFormula (base : Nat) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : SmtScript.Formula :=
  let table := templates base graph
  (demands graph observations).map (readEquation base table (templates_size base graph))

def observationEquation (base : Nat) (observation : Observation roots size) : Term .bool :=
  .equal (readRef base observation.address observation.position) observation.expected.term

def encode (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : SmtScript.Formula :=
  let base := freshBase input
  let planned := demands graph observations
  let table := templates base graph
  input ++ ((graph.endpoints ++ planned.map Prod.snd).map
    (fun id => Term.le (.integer 0) (natTerm id))) ++
    planned.map (readEquation base table (templates_size base graph)) ++
    observations.map (observationEquation base)

def commands (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : List SmtScript.Command :=
  SmtScript.compile (encode input graph observations)

def render (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : String :=
  SmtScript.render (encode input graph observations)

theorem position_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) (valid : Domains assignment graph observations)
    (demand : Demand roots size) (present : Membership.mem (demands graph observations) demand) :
    0 <= assignment.constant .int demand.2 :=
  valid demand.2 (List.mem_append.mpr (Or.inr
    (List.mem_map.mpr (Exists.intro demand (And.intro present rfl)))))

theorem observation_requested (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) (observation : Observation roots size)
    (present : Membership.mem observations observation) :
    Membership.mem (demands graph observations) (observation.address, observation.position) :=
  IntervalDemandPlan.plan_includes graph (requested observations) _
    (List.mem_map.mpr (Exists.intro observation (And.intro present rfl)))

theorem readRef_eval (assignment : Assignment) (base : Nat) (address : Address roots size)
    (position : InputNat) (nonnegative : 0 <= assignment.constant .int position) :
    (readRef base address position).eval assignment =
      reads assignment base address (natValue assignment position) := by
  simp [readRef, reads, natTerm, natValue, Term.eval, Int.toNat_of_nonneg nonnegative]

theorem nodeTerm_eval (assignment : Assignment) (graph : SymbolicGraph roots size)
    (base : Nat) (version : Fin size) (position : InputNat)
    (nonnegative : 0 <= assignment.constant .int position) :
    (nodeTerm base (lookup graph version) position).eval assignment =
      IntervalReadback.readValue (interpret assignment graph) (reads assignment base)
        version (natValue assignment position) := by
  simp only [IntervalReadback.readValue, lookup_interpret]
  cases node : lookup graph version with
  | root arrayID =>
    simp [nodeTerm, interpretNode, reads, slot, natTerm, natValue, Term.eval,
      Int.toNat_of_nonneg nonnegative]
  | constant value => rfl
  | splice lower upper inside outside =>
    simp [nodeTerm, interpretNode, Term.eval, natTerm, reads, slot, IntervalReadback.earlier,
      natValue, Int.toNat_of_nonneg nonnegative]

theorem readEquation_correct (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) (valid : Domains assignment graph observations)
    (base : Nat) (demand : Demand roots size)
    (present : Membership.mem (demands graph observations) demand) :
    (readEquation base (templates base graph) (templates_size base graph) demand).eval assignment = true <->
      IntervalReadback.Equation (interpret assignment graph) (reads assignment base)
        demand.1 (natValue assignment demand.2) := by
  have nonnegative := position_nonnegative assignment graph observations valid demand present
  cases demand with
  | mk address position =>
    cases address with
    | root _ => simp [readEquation, IntervalReadback.Equation, Term.eval]
    | version version =>
      simp only [readEquation, templates_get, Term.eval, decide_eq_true_eq]
      rw [readRef_eval assignment base _ position nonnegative,
        nodeTerm_eval assignment graph base version position nonnegative]
      rfl

theorem reads_correct (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) (valid : Domains assignment graph observations)
    (base : Nat) :
    SmtScript.Holds assignment (readFormula base graph observations) <->
      IntervalReadback.Equations (interpret assignment graph)
        (semanticDemands assignment graph observations) (reads assignment base) := by
  constructor
  next =>
    intro holds address position present
    cases Finset.mem_image.mp present with
    | intro demand spec =>
      cases spec.2
      apply (readEquation_correct assignment graph observations valid base demand
        (List.mem_toFinset.mp spec.1)).mp
      exact holds _ (List.mem_map.mpr (Exists.intro demand
        (And.intro (List.mem_toFinset.mp spec.1) rfl)))
  next =>
    intro equations term present
    cases List.mem_map.mp present with
    | intro demand spec =>
      rw [<- spec.2]
      apply (readEquation_correct assignment graph observations valid base demand spec.1).mpr
      exact equations demand.1 (natValue assignment demand.2)
        (Finset.mem_image.mpr (Exists.intro demand
          (And.intro (List.mem_toFinset.mpr spec.1) rfl)))

def ObservationsHold (assignment : Assignment) (values : Reads roots size Int)
    (observations : List (Observation roots size)) : Prop :=
  forall observation, Membership.mem observations observation ->
    values observation.address (natValue assignment observation.position) =
      observation.expected.eval assignment

theorem observations_correct (assignment : Assignment) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) (valid : Domains assignment graph observations)
    (base : Nat) :
    SmtScript.Holds assignment (observations.map (observationEquation base)) <->
      ObservationsHold assignment (reads assignment base) observations := by
  have point (observation : Observation roots size) (present : Membership.mem observations observation) :
      (observationEquation base observation).eval assignment = true <->
        reads assignment base observation.address (natValue assignment observation.position) =
          observation.expected.eval assignment := by
    simp only [observationEquation, Term.eval, decide_eq_true_eq]
    rw [readRef_eval assignment base observation.address observation.position
      (position_nonnegative assignment graph observations valid _
        (observation_requested graph observations observation present))]
    rfl
  constructor
  next =>
    intro holds observation present
    exact (point observation present).mp
      (holds _ (List.mem_map.mpr (Exists.intro observation (And.intro present rfl))))
  next =>
    intro holds term present
    cases List.mem_map.mp present with
    | intro observation spec =>
      rw [<- spec.2]
      exact (point observation spec.1).mpr (holds observation spec.1)

def Semantics (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (observations : List (Observation roots size)) : Prop :=
  SmtScript.Holds assignment input /\
    Domains assignment graph observations /\
    IntervalReadback.Equations (interpret assignment graph)
      (semanticDemands assignment graph observations) (reads assignment (freshBase input)) /\
    ObservationsHold assignment (reads assignment (freshBase input)) observations

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (observations : List (Observation roots size)) :
    SmtScript.Holds assignment (encode input graph observations) <->
      Semantics assignment input graph observations := by
  change SmtScript.Holds assignment (input ++ domainFormula graph observations ++
    readFormula (freshBase input) graph observations ++
    observations.map (observationEquation (freshBase input))) <-> _
  simp only [QueueEncoding.holds_append, domains_correct, Semantics]
  constructor
  next =>
    intro valid
    exact And.intro valid.1.1.1 (And.intro valid.1.1.2
      (And.intro ((reads_correct assignment graph observations valid.1.1.2 _).mp valid.1.2)
        ((observations_correct assignment graph observations valid.1.1.2 _).mp valid.2)))
  next =>
    intro valid
    exact And.intro (And.intro (And.intro valid.1 valid.2.1)
      ((reads_correct assignment graph observations valid.2.1 _).mpr valid.2.2.1))
      ((observations_correct assignment graph observations valid.2.1 _).mpr valid.2.2.2)

def familySlots (original : Assignment) (base : Nat) (graph : SymbolicGraph roots size)
    (arrays : RootArrays roots Int) : Fin (roots + size + 1) -> Int -> Int :=
  fun index position =>
    if root : index.val < roots then arrays (Fin.mk index.val root) position.toNat
    else if version : index.val < roots + size then
      VersionedIntervals.evaluate (interpret original graph) arrays position.toNat
        (Fin.mk (index.val - roots) (by omega))
    else original.unary .int .int (base + index.val) position

theorem familySlots_at (original : Assignment) (base : Nat) (graph : SymbolicGraph roots size)
    (arrays : RootArrays roots Int) (address : Address roots size) (position : Nat) :
    familySlots original base graph arrays (slot address) (position : Int) =
      actual (interpret original graph) arrays address position := by
  cases address with
  | root arrayID =>
    simp [familySlots, slot, arrayID.isLt, actual]
  | version version =>
    have not_root : Not (roots + version.val < roots) := by omega
    have in_versions : roots + version.val < roots + size := by have h := version.isLt; omega
    simp [familySlots, slot, not_root, in_versions, actual]

-- The extra slot and all function IDs outside this block retain their original values.
def install (original : Assignment) (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (arrays : RootArrays roots Int) : Assignment :=
  QueueEncoding.installCounts original (freshBase input)
    (familySlots original (freshBase input) graph arrays)

theorem install_input_preserved (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (arrays : RootArrays roots Int) :
    SmtScript.Holds (install original input graph arrays) input <->
      SmtScript.Holds original input :=
  QueueEncoding.input_preserved input original _

theorem install_extra_slot (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (arrays : RootArrays roots Int) :
    (install original input graph arrays).unary .int .int (freshBase input + (roots + size)) =
      original.unary .int .int (freshBase input + (roots + size)) := by
  change (QueueEncoding.installCounts original (freshBase input)
    (familySlots original (freshBase input) graph arrays)).unary .int .int
      (freshBase input + (Fin.last (roots + size)).val) = _
  rw [QueueEncoding.install_at]
  funext position
  simp [familySlots]

@[simp] theorem natValue_install {count : Nat} (original : Assignment) (base : Nat)
    (values : Fin (count + 1) -> Int -> Int) (id : InputNat) :
    natValue (QueueEncoding.installCounts original base values) id = natValue original id := rfl

@[simp] theorem interpret_install {count : Nat} (original : Assignment) (base : Nat)
    (values : Fin (count + 1) -> Int -> Int) (graph : SymbolicGraph roots size) :
    interpret (QueueEncoding.installCounts original base values) graph = interpret original graph := by
  induction graph with
  | empty => rfl
  | push previous node ih =>
    cases node <;> simp only [interpret, interpretNode, natValue_install, ih]

@[simp] theorem semanticDemands_install {count : Nat} (original : Assignment) (base : Nat)
    (values : Fin (count + 1) -> Int -> Int) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    semanticDemands (QueueEncoding.installCounts original base values) graph observations =
      semanticDemands original graph observations := by
  simp only [semanticDemands, natValue_install]

@[simp] theorem observations_install {count : Nat} (original : Assignment) (base : Nat)
    (values : Fin (count + 1) -> Int -> Int) (cells : Reads roots size Int)
    (observations : List (Observation roots size)) :
    ObservationsHold (QueueEncoding.installCounts original base values) cells observations <->
      ObservationsHold original cells observations := by
  simp only [ObservationsHold, natValue_install, QueueEncoding.input_install]

theorem reads_install (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (arrays : RootArrays roots Int) :
    reads (install original input graph arrays) (freshBase input) =
      actual (interpret original graph) arrays := by
  funext address position
  change (QueueEncoding.installCounts original (freshBase input)
    (familySlots original (freshBase input) graph arrays)).unary .int .int
      (freshBase input + (slot address).val) (position : Int) = _
  rw [QueueEncoding.install_at]
  exact familySlots_at original (freshBase input) graph arrays address position

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (observations : List (Observation roots size))
    (arrays : RootArrays roots Int) (input_holds : SmtScript.Holds original input)
    (domains : Domains original graph observations)
    (observed : ObservationsHold original (actual (interpret original graph) arrays) observations) :
    SmtScript.Holds (install original input graph arrays) (encode input graph observations) := by
  apply (encode_correct _ input graph observations).mpr
  refine And.intro ((install_input_preserved original input graph arrays).mpr input_holds)
    (And.intro domains (And.intro ?_ ?_))
  next =>
    rw [reads_install]
    simp only [install, interpret_install, semanticDemands_install]
    intro address position _
    exact IntervalReadback.actual_equation (interpret original graph) arrays address position
  next =>
    rw [reads_install]
    simpa only [install, observations_install] using observed

theorem encode_sound (assignment : Assignment) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots size) (observations : List (Observation roots size))
    (holds : SmtScript.Holds assignment (encode input graph observations)) :
    SmtScript.Holds assignment input /\ Domains assignment graph observations /\
      exists arrays : RootArrays roots Int,
        (forall address position,
          Membership.mem (semanticDemands assignment graph observations) (address, position) ->
          actual (interpret assignment graph) arrays address position =
            reads assignment (freshBase input) address position) /\
        ObservationsHold assignment (actual (interpret assignment graph) arrays) observations := by
  have valid := (encode_correct assignment input graph observations).mp holds
  refine And.intro valid.1 (And.intro valid.2.1 ?_)
  cases (IntervalReadback.finite_readback_iff (interpret assignment graph)
      (semanticDemands assignment graph observations) (reads assignment (freshBase input))
      (semantic_closed assignment graph observations)).mp valid.2.2.1 with
  | intro arrays agree =>
    refine Exists.intro arrays (And.intro agree ?_)
    intro observation present
    have member : Membership.mem (semanticDemands assignment graph observations)
        (observation.address, natValue assignment observation.position) :=
      Finset.mem_image.mpr (Exists.intro (observation.address, observation.position)
        (And.intro (List.mem_toFinset.mpr
          (observation_requested graph observations observation present)) rfl))
    exact (agree _ _ member).trans (valid.2.2.2 observation present)

theorem encode_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input graph observations)) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph observations /\
        ObservationsHold original (actual (interpret original graph) arrays) observations) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have sound := encode_sound assignment input graph observations holds
      cases sound.2.2 with
      | intro arrays spec =>
        exact Exists.intro assignment (Exists.intro arrays
          (And.intro sound.1 (And.intro sound.2.1 spec.2)))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro arrays spec =>
        exact Exists.intro (install original input graph arrays)
          (install_satisfies original input graph observations arrays spec.1 spec.2.1 spec.2.2)

theorem commands_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    (exists assignment : Assignment, SmtScript.run assignment (commands input graph observations) = some true) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph observations /\
        ObservationsHold original (actual (interpret original graph) arrays) observations) := by
  simp only [commands, <- SmtScript.formula_holds_iff]
  exact encode_exists_iff input graph observations

theorem text_exists_iff (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) :
    (exists assignment : Assignment,
      SmtScriptText.runText assignment (render input graph observations) = some true) <->
    (exists original : Assignment, exists arrays : RootArrays roots Int,
      SmtScript.Holds original input /\ Domains original graph observations /\
        ObservationsHold original (actual (interpret original graph) arrays) observations) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  exact encode_exists_iff input graph observations

end CCFRaft.Sparse.IntervalEncoding

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.IntervalEncoding: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.IntervalEncoding.encode_sound
#print axioms CCFRaft.Sparse.IntervalEncoding.install_satisfies
#print axioms CCFRaft.Sparse.IntervalEncoding.commands_exists_iff
