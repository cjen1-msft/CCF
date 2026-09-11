import Sparse.TypedIntervalEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedIntervalReadBlock

open Smt (Ty Term Assignment)
open VersionedIntervals (RootArrays)
open IntervalReadback (Address Demand Reads actual)
open IntervalEncoding (InputNat natTerm natValue)
open TypedIntervalEncoding (SymbolicGraph interpret reads readRef)

variable {ty : Ty} {roots size : Nat}

def planned (graph : SymbolicGraph roots ty size) (requests : List (Demand roots size)) :
    List (Demand roots size) :=
  IntervalDemandPlan.plan graph requests

theorem planned_nodup (graph : SymbolicGraph roots ty size) (requests : List (Demand roots size)) :
    (planned graph requests).Nodup :=
  IntervalDemandPlan.plan_nodup graph requests

theorem requested_mem (graph : SymbolicGraph roots ty size) (requests : List (Demand roots size))
    (demand : Demand roots size) (member : Membership.mem requests demand) :
    Membership.mem (planned graph requests) demand :=
  IntervalDemandPlan.plan_includes graph requests demand member

def interpretedDemands (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) : Finset (Demand roots size) :=
  (planned graph requests).toFinset.image (fun demand => (demand.1, natValue assignment demand.2))

theorem interpreted_closed (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) :
    IntervalReadback.Closed (interpret assignment graph) (interpretedDemands assignment graph requests) := by
  intro address position member child dependency
  cases Finset.mem_image.mp member with
  | intro demand spec =>
    cases spec.2
    exact Finset.mem_image.mpr (Exists.intro (child, demand.2) (And.intro
      (IntervalDemandPlan.plan_closed graph requests demand.1 demand.2 spec.1 child
        (by simpa only [TypedIntervalEncoding.dependencies_interpret] using dependency)) rfl))

def equationsFor (first : Nat) (graph : SymbolicGraph roots ty size)
    (demands : List (Demand roots size)) : SmtScript.Formula :=
  let table := TypedIntervalEncoding.templates first graph
  demands.map (TypedIntervalEncoding.readEquation first table (TypedIntervalEncoding.templates_size first graph))

def equations (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) : SmtScript.Formula :=
  equationsFor first graph (planned graph requests)

theorem equations_correct (assignment : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size))
    (nonnegative : forall demand, Membership.mem (planned graph requests) demand ->
      0 <= assignment.constant .int demand.2) :
    SmtScript.Holds assignment (equations first graph requests) <->
      IntervalReadback.Equations (interpret assignment graph) (interpretedDemands assignment graph requests)
        (reads assignment first) := by
  simp only [equations, equationsFor, SmtScript.Holds, List.forall_mem_map]
  refine (forall_congr' (fun demand => forall_congr' (fun member =>
    TypedIntervalEncoding.equation_correct assignment graph first demand (nonnegative demand member)))).trans ?_
  simp [IntervalReadback.Equations, interpretedDemands]

def Agrees (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (demands : List (Demand roots size)) (cells : Reads roots size ty.denote)
    (arrays : RootArrays roots ty.denote) : Prop :=
  forall demand, Membership.mem demands demand ->
    actual (interpret assignment graph) arrays demand.1 (natValue assignment demand.2) =
      cells demand.1 (natValue assignment demand.2)

theorem equations_readback_iff (assignment : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size))
    (nonnegative : forall demand, Membership.mem (planned graph requests) demand ->
      0 <= assignment.constant .int demand.2) :
    SmtScript.Holds assignment (equations first graph requests) <->
      exists arrays : RootArrays roots ty.denote,
        Agrees assignment graph (planned graph requests) (reads assignment first) arrays := by
  rw [equations_correct assignment first graph requests nonnegative,
    IntervalReadback.finite_readback_iff _ _ _ (interpreted_closed assignment graph requests)]
  simp [Agrees, interpretedDemands]

theorem rootArrays_agree (assignment : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size))
    (nonnegative : forall demand, Membership.mem (planned graph requests) demand ->
      0 <= assignment.constant .int demand.2)
    (holds : SmtScript.Holds assignment (equations first graph requests)) :
    Agrees assignment graph (planned graph requests) (reads assignment first)
      (IntervalReadback.rootArrays (reads (size := size) assignment first)) := by
  intro demand member
  exact IntervalReadback.actual_agrees _ _ _ (interpreted_closed assignment graph requests)
    ((equations_correct assignment first graph requests nonnegative).mp holds) _ _
    (Finset.mem_image.mpr (Exists.intro demand (And.intro (List.mem_toFinset.mpr member) rfl)))

theorem agrees_requested (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) (cells : Reads roots size ty.denote)
    (arrays : RootArrays roots ty.denote)
    (agree : Agrees assignment graph (planned graph requests) cells arrays) :
    Agrees assignment graph requests cells arrays :=
  fun demand member => agree demand (requested_mem graph requests demand member)

def positions (graph : SymbolicGraph roots ty size) (requests : List (Demand roots size)) : List InputNat :=
  graph.endpoints ++ (planned graph requests).map Prod.snd

def Domains (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) : Prop :=
  forall position, Membership.mem (positions graph requests) position -> 0 <= assignment.constant .int position

def domainFormula (ids : List InputNat) : SmtScript.Formula :=
  ids.dedup.map (fun id => .le (.integer 0) (natTerm id))

def block (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) : SmtScript.Formula :=
  let demands := planned graph requests
  domainFormula (graph.endpoints ++ demands.map Prod.snd) ++ equationsFor first graph demands

theorem position_nonnegative (assignment : Assignment) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) (domains : Domains assignment graph requests)
    (demand : Demand roots size) (member : Membership.mem (planned graph requests) demand) :
    0 <= assignment.constant .int demand.2 :=
  domains demand.2 (List.mem_append.mpr (Or.inr (List.mem_map.mpr (Exists.intro demand (And.intro member rfl)))))

theorem block_correct (assignment : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) :
    SmtScript.Holds assignment (block first graph requests) <->
      Domains assignment graph requests /\
        IntervalReadback.Equations (interpret assignment graph) (interpretedDemands assignment graph requests)
          (reads assignment first) := by
  have domain_iff : SmtScript.Holds assignment (domainFormula (positions graph requests)) <->
      Domains assignment graph requests := by
    simp [domainFormula, SmtScript.Holds, Domains, natTerm, Term.eval]
  change SmtScript.Holds assignment (domainFormula (positions graph requests) ++ equations first graph requests) <-> _
  rw [QueueEncoding.holds_append, domain_iff]
  exact and_congr_right (fun domains =>
    equations_correct assignment first graph requests (position_nonnegative assignment graph requests domains))

theorem block_readback_iff (assignment : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (requests : List (Demand roots size)) :
    SmtScript.Holds assignment (block first graph requests) <->
      Domains assignment graph requests /\
        exists arrays : RootArrays roots ty.denote,
          Agrees assignment graph (planned graph requests) (reads assignment first) arrays := by
  rw [block_correct, IntervalReadback.finite_readback_iff _ _ _ (interpreted_closed assignment graph requests)]
  simp [Agrees, interpretedDemands]

-- The caller reserves the entire range [first, first + roots + size).
def install (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) : Assignment :=
  TypedIntervalEncoding.installUF original first (TypedIntervalEncoding.family (interpret original graph) arrays)

theorem install_reads (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) :
    reads (install original first graph arrays) first = actual (interpret original graph) arrays := by
  funext address position
  change (TypedIntervalEncoding.installUF original first
    (TypedIntervalEncoding.family (interpret original graph) arrays)).unary .int ty
      (first + (TypedIntervalEncoding.cellIndex address).val) (position : Int) = _
  rw [TypedIntervalEncoding.install_at]
  exact TypedIntervalEncoding.family_at _ arrays address position

theorem install_constants (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) :
    (install original first graph arrays).constant = original.constant := rfl

theorem install_selectors (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) :
    (install original first graph arrays).selectors = original.selectors := rfl

theorem install_external (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (domain result : Ty) (id : Nat)
    (outside : id < first \/ first + roots + size <= id) :
    (install original first graph arrays).unary domain result id = original.unary domain result id :=
  TypedIntervalEncoding.install_outside original first _ domain result id (by simpa [Nat.add_assoc] using outside)

theorem install_source_term (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) {resultTy : Ty} (term : Term resultTy)
    (below : SymbolBounds.termMax term < first) :
    term.eval (install original first graph arrays) = term.eval original /\
      forall domain result id, Membership.mem (SmtScript.termSymbols term) (.unary domain result id) ->
        (install original first graph arrays).unary domain result id = original.unary domain result id :=
  And.intro (TypedIntervalEncoding.eval_install original first _ term below)
    (TypedIntervalEncoding.term_functions_preserved original first _ term below)

theorem install_graph (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (below : TypedIntervalEncoding.graphMax graph < first) :
    interpret (install original first graph arrays) graph = interpret original graph :=
  TypedIntervalEncoding.interpret_install original first _ graph below

theorem install_readRef (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (address : Address roots size) (position : InputNat)
    (nonnegative : 0 <= original.constant .int position) :
    (readRef first address position).eval (install original first graph arrays) =
      actual (interpret original graph) arrays address (natValue original position) := by
  rw [TypedIntervalEncoding.readRef_eval (install original first graph arrays) first address position
    (show 0 <= (install original first graph arrays).constant .int position from nonnegative), install_reads]
  rfl

theorem install_input_iff (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (input : SmtScript.Formula)
    (below : SymbolBounds.formulaMax input < first) :
    SmtScript.Holds (install original first graph arrays) input <-> SmtScript.Holds original input := by
  apply forall_congr'
  intro term
  apply forall_congr'
  intro member
  rw [(install_source_term original first graph arrays term
    (Nat.lt_of_le_of_lt (TypedIntervalEncoding.formula_term_bound input term member) below)).1]

theorem install_block_iff (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (requests : List (Demand roots size))
    (below : TypedIntervalEncoding.graphMax graph < first) :
    SmtScript.Holds (install original first graph arrays) (block first graph requests) <->
      Domains original graph requests := by
  rw [block_correct, install_graph original first graph arrays below, install_reads]
  exact and_iff_left (fun address position _ => IntervalReadback.actual_equation _ arrays address position)

theorem install_unit_iff (original : Assignment) (first : Nat) (graph : SymbolicGraph roots ty size)
    (arrays : RootArrays roots ty.denote) (requests : List (Demand roots size)) (input : SmtScript.Formula)
    (input_below : SymbolBounds.formulaMax input < first)
    (graph_below : TypedIntervalEncoding.graphMax graph < first) :
    SmtScript.Holds (install original first graph arrays) (input ++ block first graph requests) <->
      SmtScript.Holds original input /\ Domains original graph requests := by
  rw [QueueEncoding.holds_append, install_input_iff original first graph arrays input input_below,
    install_block_iff original first graph arrays requests graph_below]

namespace Regression

def rootGraph (ty : Ty) : SymbolicGraph 1 ty 1 := .push .empty (.root 0)

theorem empty_block (first : Nat) :
    block first (.empty : SymbolicGraph 0 ty 0) [] = [] := by
  simp [block, planned, IntervalDemandPlan.plan, IntervalDemandPlan.walk, domainFormula,
    equationsFor, VersionedIntervals.Graph.endpoints]

theorem duplicate_requests :
    (planned (rootGraph .entry) [(.version 0, 7), (.version 0, 7), (.root 0, 7)]).length = 2 := by
  decide +kernel

theorem aliased_positions (assignment : Assignment) (first : Nat) (address : Address roots size)
    (left right : InputNat) (same : assignment.constant .int left = assignment.constant .int right) :
    (readRef (ty := ty) first address left).eval assignment =
      (readRef (ty := ty) first address right).eval assignment := by
  simp only [TypedIntervalEncoding.readRef, Term.eval, natTerm, same]

def spliceGraph (term : Term ty) : SymbolicGraph 1 ty 3 :=
  .push (.push (.push .empty (.root 0)) (.constant term)) (.splice 0 1 1 0)

theorem both_children_planned :
    (planned (spliceGraph (.integer (-3))) [(.version 2, 9)]).length = 4 /\
      Membership.mem (planned (spliceGraph (.integer (-3))) [(.version 2, 9)]) (.version 0, 9) /\
      Membership.mem (planned (spliceGraph (.integer (-3))) [(.version 2, 9)]) (.version 1, 9) := by
  decide +kernel

theorem inactive_extra_request (original : Assignment) (first : Nat)
    (arrays : RootArrays 1 ty.denote) (term : Term ty)
    (below : TypedIntervalEncoding.graphMax (spliceGraph term) < first)
    (domains : Domains original (spliceGraph term) [(.version 2, 9), (.root 0, 20)]) :
    SmtScript.Holds (install original first (spliceGraph term) arrays)
      (block first (spliceGraph term) [(.version 2, 9), (.root 0, 20)]) :=
  (install_block_iff original first (spliceGraph term) arrays _ below).mpr domains

theorem all_sorts_install (original : Assignment) (arrays : RootArrays 1 ty.denote) :
    reads (install original 0 (rootGraph ty) arrays) 0 = actual (interpret original (rootGraph ty)) arrays :=
  install_reads original 0 (rootGraph ty) arrays

theorem high_unused_constant (original : Assignment) :
    (install original 2001
      (.push .empty (.constant (.app .int .entry 2000 (natTerm 500))) : SymbolicGraph 0 .entry 1)
      (fun root => Fin.elim0 root)).unary .int .entry 2000 = original.unary .int .entry 2000 := by
  apply install_external
  exact Or.inl (by decide +kernel)

theorem reservation_end (original : Assignment) (arrays : RootArrays 1 ty.denote) :
    (install original 100 (rootGraph ty) arrays).unary .int ty 102 = original.unary .int ty 102 := by
  apply install_external
  exact Or.inr (by decide +kernel)

def check (assignment : Assignment) (formula : SmtScript.Formula) : Bool :=
  formula.all (fun term => term.eval assignment)

theorem check_correct (assignment : Assignment) (formula : SmtScript.Formula) :
    check assignment formula = true <-> SmtScript.Holds assignment formula := by
  simp [check, SmtScript.Holds]

def constantCheck (term : Term ty) : Bool :=
  let graph : SymbolicGraph 0 ty 1 := .push .empty (.constant term)
  let original := TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0
  check (install original 100 graph (fun root => Fin.elim0 root))
    (block 100 graph [(.version 0, 9)])

theorem all_five_constant_sorts :
    constantCheck (.boolean true) = true /\
    constantCheck (.integer (-3)) = true /\
    constantCheck (.nodes 7) = true /\
    constantCheck (.transaction (.integer (-4))) = true /\
    constantCheck (.entry (.integer (-1)) .signature) = true := by
  decide +kernel

theorem inactive_child_not_pruned :
    let original := TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0
    let graph := spliceGraph (.integer (-3))
    (TypedIntervalEncoding.readEquation (roots := 1) 100 (TypedIntervalEncoding.templates 100 graph)
      (TypedIntervalEncoding.templates_size 100 graph) (.version 2, 9)).eval original = true /\
    check original (block 100 graph [(.version 2, 9)]) = false := by
  decide +kernel

theorem false_guard_does_not_disable_requests :
    let original := TypedIntervalEncoding.Regression.fixtureAssignment 0 0 0
    check original [.implies (.boolean false) (.boolean false)] = true /\
    check original (block 100 (spliceGraph (.integer (-3))) [(.version 2, 9)] ++
      [.implies (.boolean false) (.boolean false)]) = false := by
  decide +kernel

end Regression

end CCFRaft.Sparse.TypedIntervalReadBlock

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.TypedIntervalReadBlock).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.TypedIntervalReadBlock: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.TypedIntervalReadBlock.block_readback_iff
#print axioms CCFRaft.Sparse.TypedIntervalReadBlock.install_unit_iff
