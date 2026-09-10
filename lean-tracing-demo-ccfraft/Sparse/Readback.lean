import Mathlib.Data.Finset.Basic
import Mathlib.Data.Finset.Union
import Mathlib.Data.Fin.Basic

set_option autoImplicit false

namespace CCFRaft.Sparse.Readback

variable {K V : Type} {size : Nat} [DecidableEq K]

structure Store (K V : Type) (size : Nat) where
  prior : Fin (size + 1)
  key : K
  value : V

structure Graph (K V : Type) (size : Nat) where
  stores : Fin size -> Store K V size
  earlier : forall index, (stores index).prior.val < index.val + 1

def array (graph : Graph K V size) (root : K -> V) :
    Fin (size + 1) -> K -> V
  | Fin.mk 0 _, key => root key
  | Fin.mk (index + 1) bound, key =>
    let store := graph.stores (Fin.mk index (Nat.lt_of_succ_lt_succ bound))
    if key = store.key then store.value else array graph root store.prior key
termination_by version _ => version.val
decreasing_by exact graph.earlier _

@[simp] theorem array_root (graph : Graph K V size) (root : K -> V) (key : K) :
    array graph root 0 key = root key := by
  rw [array.eq_def]
  rfl

theorem array_store (graph : Graph K V size) (root : K -> V)
    (index : Fin size) (key : K) :
    array graph root index.succ key =
      if key = (graph.stores index).key then (graph.stores index).value
      else array graph root (graph.stores index).prior key := by
  rw [array.eq_def]
  rfl

def Closed (graph : Graph K V size) (demands : Finset (Prod (Fin (size + 1)) K)) : Prop :=
  forall index key, Membership.mem demands (index.succ, key) ->
    Not (key = (graph.stores index).key) ->
      Membership.mem demands ((graph.stores index).prior, key)

def Equations (graph : Graph K V size) (default : Option V)
    (demands : Finset (Prod (Fin (size + 1)) K)) (reads : Fin (size + 1) -> K -> V) : Prop :=
  (forall key, Membership.mem demands (0, key) ->
    forall value, default = some value -> reads 0 key = value) /\
  forall index key, Membership.mem demands (index.succ, key) ->
    reads index.succ key =
      if key = (graph.stores index).key then (graph.stores index).value
      else reads (graph.stores index).prior key

theorem array_equations (graph : Graph K V size) (default : Option V)
    (demands : Finset (Prod (Fin (size + 1)) K)) (root : K -> V)
    (constant : forall value, default = some value -> root = fun _ => value) :
    Equations graph default demands (array graph root) := by
  constructor
  next =>
    intro key _ value present
    simp [constant value present]
  next =>
    intro index key _
    exact array_store graph root index key

theorem array_agrees (graph : Graph K V size) (default : Option V)
    (demands : Finset (Prod (Fin (size + 1)) K)) (reads : Fin (size + 1) -> K -> V)
    (closed : Closed graph demands) (equations : Equations graph default demands reads)
    (root : K -> V)
    (root_agrees : forall key, Membership.mem demands (0, key) -> root key = reads 0 key)
    (version : Fin (size + 1)) (key : K) (demanded : Membership.mem demands (version, key)) :
    array graph root version key = reads version key := by
  have agree : forall rank, forall node : Fin (size + 1), node.val = rank ->
      forall query, Membership.mem demands (node, query) ->
        array graph root node query = reads node query := by
    intro rank
    induction rank using Nat.strong_induction_on with
    | h rank ih =>
      intro node equal query member
      cases node using Fin.cases with
      | zero => simpa only [array_root] using root_agrees query member
      | succ index =>
        rw [array_store, equations.2 index query member]
        by_cases same : query = (graph.stores index).key
        next => simp only [same, if_true]
        next =>
          simp only [same, if_false]
          have smaller : (graph.stores index).prior.val < rank := by
            rw [Eq.symm equal]
            exact graph.earlier index
          exact ih _ smaller _ rfl query (closed index query member same)
  exact agree version.val version rfl key demanded

theorem finite_readback_iff (graph : Graph K V size) (default : Option V)
    (demands : Finset (Prod (Fin (size + 1)) K)) (reads : Fin (size + 1) -> K -> V)
    (closed : Closed graph demands) :
    Equations graph default demands reads <->
      exists root : K -> V,
        (forall value, default = some value -> root = fun _ => value) /\
        forall version key, Membership.mem demands (version, key) ->
          array graph root version key = reads version key := by
  constructor
  next =>
    intro equations
    let root : K -> V := fun key => default.getD (reads 0 key)
    have root_agrees :
        forall key, Membership.mem demands (0, key) -> root key = reads 0 key := by
      intro key demanded
      cases present : default with
      | none => simp [root, present]
      | some value => simpa [root, present] using (equations.1 key demanded value present).symm
    refine Exists.intro root (And.intro ?_ ?_)
    next =>
      intro value present
      funext key
      simp [root, present]
    next => exact array_agrees graph default demands reads closed equations root root_agrees
  next =>
    intro witness
    cases witness with
    | intro root spec =>
      refine And.intro ?_ ?_
      next =>
        intro key demanded value present
        have agree := spec.2 0 key demanded
        simpa [spec.1 value present] using agree.symm
      next =>
        intro index key demanded
        rw [Eq.symm (spec.2 index.succ key demanded), array_store]
        by_cases same : key = (graph.stores index).key
        next => simp only [same, if_true]
        next =>
          simp only [same, if_false]
          exact spec.2 (graph.stores index).prior key (closed index key demanded same)

def queryDemands (graph : Graph K V size) :
    Fin (size + 1) -> K -> Finset (Prod (Fin (size + 1)) K)
  | Fin.mk 0 _, key => {(0, key)}
  | Fin.mk (index + 1) bound, key =>
    let node : Fin size := Fin.mk index (Nat.lt_of_succ_lt_succ bound)
    let store := graph.stores node
    insert (node.succ, key)
      (if key = store.key then {} else queryDemands graph store.prior key)
termination_by version _ => version.val
decreasing_by exact graph.earlier _

@[simp] theorem query_demands_root (graph : Graph K V size) (key : K) :
    queryDemands graph 0 key = {(0, key)} := by
  rw [queryDemands.eq_def]
  rfl

theorem query_demands_store (graph : Graph K V size) (index : Fin size) (key : K) :
    queryDemands graph index.succ key =
      insert (index.succ, key)
        (if key = (graph.stores index).key then {}
          else queryDemands graph (graph.stores index).prior key) := by
  rw [queryDemands.eq_def]
  rfl

theorem query_demands_spec (graph : Graph K V size) (version : Fin (size + 1)) (key : K) :
    Membership.mem (queryDemands graph version key) (version, key) /\
      Closed graph (queryDemands graph version key) := by
  have spec : forall rank, forall node : Fin (size + 1), node.val = rank ->
      forall query,
        Membership.mem (queryDemands graph node query) (node, query) /\
          Closed graph (queryDemands graph node query) := by
    intro rank
    induction rank using Nat.strong_induction_on with
    | h rank ih =>
      intro node equal query
      cases node using Fin.cases with
      | zero =>
        constructor
        next => simp
        next =>
          intro index key member _
          simp at member
      | succ index =>
        rw [query_demands_store]
        refine And.intro (Finset.mem_insert_self _ _) ?_
        have smaller : (graph.stores index).prior.val < rank := by
          rw [Eq.symm equal]
          exact graph.earlier index
        have prior := ih _ smaller (graph.stores index).prior rfl query
        intro selected key member different
        cases Finset.mem_insert.mp member with
        | inl current =>
          have nodes : selected = index := Fin.succ_inj.mp (Prod.mk.inj current).1
          have keys : key = query := (Prod.mk.inj current).2
          subst selected
          subst key
          exact Finset.mem_insert_of_mem
            (by simpa only [different, if_false] using prior.1)
        | inr previous =>
          by_cases same : query = (graph.stores index).key
          next => simp [same] at previous
          next =>
            have predecessor := prior.2 selected key
              (by simpa only [same, if_false] using previous) different
            exact Finset.mem_insert_of_mem
              (by simpa only [same, if_false] using predecessor)
  exact spec version.val version rfl key

def compileDemands (graph : Graph K V size)
    (requests : Finset (Prod (Fin (size + 1)) K)) : Finset (Prod (Fin (size + 1)) K) :=
  requests.biUnion (fun query => queryDemands graph query.1 query.2)

theorem compile_demands_spec (graph : Graph K V size)
    (requests : Finset (Prod (Fin (size + 1)) K)) :
    (forall query, Membership.mem requests query ->
      Membership.mem (compileDemands graph requests) query) /\
      Closed graph (compileDemands graph requests) := by
  constructor
  next =>
    intro query requested
    exact Finset.mem_biUnion.mpr
      (Exists.intro query (And.intro requested (query_demands_spec graph query.1 query.2).1))
  next =>
    intro index key demanded different
    cases Finset.mem_biUnion.mp demanded with
    | intro query spec =>
      exact Finset.mem_biUnion.mpr (Exists.intro query (And.intro spec.1
        ((query_demands_spec graph query.1 query.2).2 index key spec.2 different)))

theorem compiled_readback_iff (graph : Graph K V size) (default : Option V)
    (requests : Finset (Prod (Fin (size + 1)) K)) (reads : Fin (size + 1) -> K -> V) :
    Equations graph default (compileDemands graph requests) reads <->
      exists root : K -> V,
        (forall value, default = some value -> root = fun _ => value) /\
        forall version key, Membership.mem (compileDemands graph requests) (version, key) ->
          array graph root version key = reads version key :=
  finite_readback_iff graph default (compileDemands graph requests) reads
    (compile_demands_spec graph requests).2

end CCFRaft.Sparse.Readback

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.Readback.array_root,
      ``CCFRaft.Sparse.Readback.array_store,
      ``CCFRaft.Sparse.Readback.array_equations,
      ``CCFRaft.Sparse.Readback.array_agrees,
      ``CCFRaft.Sparse.Readback.finite_readback_iff,
      ``CCFRaft.Sparse.Readback.query_demands_root,
      ``CCFRaft.Sparse.Readback.query_demands_store,
      ``CCFRaft.Sparse.Readback.query_demands_spec,
      ``CCFRaft.Sparse.Readback.compile_demands_spec,
      ``CCFRaft.Sparse.Readback.compiled_readback_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
  Lean.logInfo "Sparse.Readback: all exported theorems passed the allowed-axiom gate."
