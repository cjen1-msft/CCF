import Sparse.IntervalReadback

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalDemandPlan

open VersionedIntervals (Version Graph RootArrays)
open IntervalReadback (Address Demand Reads earlier lookup actual Equations Closed)

variable {roots size prior : Nat} {A : Type}

inductive Links (roots size : Nat) where
  | root (arrayID : Fin roots)
  | constant
  | splice (insideVersion outsideVersion : Fin size)

def Links.children : Links roots size -> List (Address roots size)
  | .root arrayID => [.root arrayID]
  | .constant => []
  | .splice insideVersion outsideVersion => [.version insideVersion, .version outsideVersion]

def links (node : Version roots A prior) (bound : prior <= size) : Links roots size :=
  match node with
  | .root arrayID => .root arrayID
  | .constant _ => .constant
  | .splice _ _ insideVersion outsideVersion =>
    .splice (Fin.mk insideVersion.val (Nat.lt_of_lt_of_le insideVersion.isLt bound))
      (Fin.mk outsideVersion.val (Nat.lt_of_lt_of_le outsideVersion.isLt bound))

-- The final ID bound stays fixed throughout this single traversal.
def flattenAux : {prior : Nat} -> Graph roots A prior -> (prior <= size) ->
    Array (Links roots size)
  | _, .empty, _ => #[]
  | _, .push previous node, bound =>
    let earlier_bound := Nat.le_trans (Nat.le_succ _) bound
    (flattenAux previous earlier_bound).push (links node earlier_bound)

theorem flattenAux_size (graph : Graph roots A prior) (bound : prior <= size) :
    (flattenAux graph bound).size = prior := by
  induction graph with
  | empty => rfl
  | push previous node ih => simp [flattenAux, ih]

theorem flattenAux_get (graph : Graph roots A prior) (bound : prior <= size)
    (version : Fin prior) :
    (flattenAux graph bound)[version.val]'(by rw [flattenAux_size]; exact version.isLt) =
      links (lookup graph version) (Nat.le_trans (Nat.le_of_lt version.isLt) bound) := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last =>
      simp [flattenAux, lookup, Array.getElem_push, flattenAux_size]
    | cast version =>
      simp [flattenAux, lookup, Array.getElem_push, flattenAux_size, version.isLt, ih]

structure Table (roots size : Nat) where
  entries : Array (Links roots size)
  size_eq : entries.size = size
  backward : forall version : Fin size,
    match entries[version.val]'(by rw [size_eq]; exact version.isLt) with
    | .splice insideVersion outsideVersion =>
      insideVersion.val < version.val /\ outsideVersion.val < version.val
    | _ => True

def table (graph : Graph roots A size) : Table roots size where
  entries := flattenAux graph (Nat.le_refl _)
  size_eq := flattenAux_size graph _
  backward version := by
    rw [flattenAux_get]
    cases node : lookup graph version with
    | root _ => trivial
    | constant _ => trivial
    | splice lower upper insideVersion outsideVersion =>
      exact And.intro insideVersion.isLt outsideVersion.isLt

def Table.children (flat : Table roots size) : Address roots size -> List (Address roots size)
  | .root _ => []
  | .version version =>
    (flat.entries[version.val]'(by rw [flat.size_eq]; exact version.isLt)).children

theorem table_children (graph : Graph roots A size) (address : Address roots size) :
    (table graph).children address = IntervalReadback.dependencies graph address := by
  cases address with
  | root _ => rfl
  | version version =>
    simp only [Table.children, table, flattenAux_get]
    cases node : lookup graph version <;>
      simp [IntervalReadback.dependencies, node, links, Links.children, earlier]

def nextDemands (flat : Table roots size) (demand : Demand roots size) : List (Demand roots size) :=
  (flat.children demand.1).map fun child => (child, demand.2)

-- These weights are only a termination measure, not runtime fuel.
def weight (demand : Demand roots size) : Nat := 3 ^ demand.1.rank
def workWeight (pending : List (Demand roots size)) : Nat := (pending.map weight).sum

@[simp] theorem workWeight_cons (demand : Demand roots size) (rest : List (Demand roots size)) :
    workWeight (demand :: rest) = weight demand + workWeight rest := rfl

@[simp] theorem workWeight_append (left right : List (Demand roots size)) :
    workWeight (left ++ right) = workWeight left + workWeight right := by
  simp [workWeight, List.map_append, List.sum_append]

theorem weight_positive (demand : Demand roots size) : 0 < weight demand :=
  Nat.pow_pos (by omega)

theorem next_weight_lt (flat : Table roots size) (demand : Demand roots size) :
    workWeight (nextDemands flat demand) < weight demand := by
  cases demand with
  | mk address position =>
    cases address with
    | root _ => simp [nextDemands, Table.children, workWeight, weight, Address.rank]
    | version version =>
      have positive : 0 < 3 ^ version.val := Nat.pow_pos (by omega)
      have backward := flat.backward version
      cases node : flat.entries[version.val]'(by rw [flat.size_eq]; exact version.isLt) with
      | root arrayID =>
        simp [nextDemands, Table.children, node, Links.children, workWeight, weight,
          Address.rank, Nat.pow_succ]
        omega
      | constant =>
        simp [nextDemands, Table.children, node, Links.children, workWeight, weight, Address.rank]
      | splice insideVersion outsideVersion =>
        rw [node] at backward
        have inside := Nat.pow_le_pow_right (by omega : 1 <= 3) (Nat.succ_le_of_lt backward.1)
        have outside := Nat.pow_le_pow_right (by omega : 1 <= 3) (Nat.succ_le_of_lt backward.2)
        simp only [Nat.pow_succ] at inside outside
        simp [nextDemands, Table.children, node, Links.children, workWeight, weight,
          Address.rank, Nat.pow_succ]
        omega

def walk (flat : Table roots size) (seen pending : List (Demand roots size)) :
    List (Demand roots size) :=
  match pending with
  | [] => seen
  | demand :: rest =>
    if Membership.mem seen demand then walk flat seen rest
    else walk flat (demand :: seen) (nextDemands flat demand ++ rest)
termination_by workWeight pending
decreasing_by
  all_goals simp only [workWeight_cons, workWeight_append]
  next => have positive := weight_positive demand; omega
  next => have smaller := next_weight_lt flat demand; omega

def plan (graph : Graph roots A size) (requests : List (Demand roots size)) :
    List (Demand roots size) :=
  walk (table graph) [] requests

structure WalkSpec (flat : Table roots size)
    (seen pending result : List (Demand roots size)) : Prop where
  keeps : forall demand, Membership.mem seen demand -> Membership.mem result demand
  covers : forall demand, Membership.mem pending demand -> Membership.mem result demand
  expanded : forall demand, Membership.mem result demand ->
    Membership.mem seen demand \/
      (forall child, Membership.mem (nextDemands flat demand) child -> Membership.mem result child)
  minimal : forall allowed : Demand roots size -> Prop,
    (forall demand, allowed demand ->
      forall child, Membership.mem (nextDemands flat demand) child -> allowed child) ->
    (forall demand, Membership.mem seen demand -> allowed demand) ->
    (forall demand, Membership.mem pending demand -> allowed demand) ->
    forall demand, Membership.mem result demand -> allowed demand
  nodup : seen.Nodup -> result.Nodup

theorem spec_nil (flat : Table roots size) (seen : List (Demand roots size)) :
    WalkSpec flat seen [] seen := by
  constructor
  next => exact fun _ member => member
  next => intro demand member; simp at member
  next => exact fun _ member => Or.inl member
  next => intro allowed _ old _ demand member; exact old demand member
  next => exact fun nodup => nodup

theorem spec_skip (flat : Table roots size) (seen : List (Demand roots size))
    (demand : Demand roots size) (rest result : List (Demand roots size))
    (present : Membership.mem seen demand) (spec : WalkSpec flat seen rest result) :
    WalkSpec flat seen (demand :: rest) result := by
  constructor
  next => exact spec.keeps
  next =>
    intro requested member
    cases List.mem_cons.mp member with
    | inl same => subst requested; exact spec.keeps demand present
    | inr later => exact spec.covers requested later
  next => exact spec.expanded
  next =>
    intro allowed closed old pending
    exact spec.minimal allowed closed old
      (fun query member => pending query (List.mem_cons_of_mem demand member))
  next => exact spec.nodup

theorem spec_step (flat : Table roots size) (seen : List (Demand roots size))
    (demand : Demand roots size) (rest result : List (Demand roots size))
    (fresh : Not (Membership.mem seen demand))
    (spec : WalkSpec flat (demand :: seen) (nextDemands flat demand ++ rest) result) :
    WalkSpec flat seen (demand :: rest) result := by
  constructor
  next =>
    intro query member
    exact spec.keeps query (List.mem_cons_of_mem demand member)
  next =>
    intro query member
    cases List.mem_cons.mp member with
    | inl same => subst query; exact spec.keeps demand (by simp)
    | inr later => exact spec.covers query (List.mem_append.mpr (Or.inr later))
  next =>
    intro query member
    cases spec.expanded query member with
    | inl old =>
      cases List.mem_cons.mp old with
      | inl same =>
        subst query
        exact Or.inr (fun child dependency =>
          spec.covers child (List.mem_append.mpr (Or.inl dependency)))
      | inr initial => exact Or.inl initial
    | inr expanded => exact Or.inr expanded
  next =>
    intro allowed closed old pending query member
    have current := pending demand (by simp)
    apply spec.minimal allowed closed ?_ ?_ query member
    next =>
      intro selected present
      cases List.mem_cons.mp present with
      | inl same => subst selected; exact current
      | inr initial => exact old selected initial
    next =>
      intro selected present
      cases List.mem_append.mp present with
      | inl dependency => exact closed demand current selected dependency
      | inr later => exact pending selected (List.mem_cons_of_mem demand later)
  next =>
    intro nodup
    exact spec.nodup (List.nodup_cons.mpr (And.intro fresh nodup))

theorem walk_spec (flat : Table roots size) (seen pending : List (Demand roots size)) :
    WalkSpec flat seen pending (walk flat seen pending) := by
  fun_induction walk flat seen pending with
  | case1 seen => exact spec_nil flat seen
  | case2 seen demand rest present ih => exact spec_skip flat seen demand rest _ present ih
  | case3 seen demand rest fresh ih => exact spec_step flat seen demand rest _ fresh ih

theorem plan_nodup (graph : Graph roots A size) (requests : List (Demand roots size)) :
    (plan graph requests).Nodup :=
  (walk_spec (table graph) [] requests).nodup (by simp)

theorem plan_includes (graph : Graph roots A size) (requests : List (Demand roots size))
    (demand : Demand roots size) (requested : Membership.mem requests demand) :
    Membership.mem (plan graph requests) demand :=
  (walk_spec (table graph) [] requests).covers demand requested

theorem plan_closed (graph : Graph roots A size) (requests : List (Demand roots size)) :
    Closed graph (plan graph requests).toFinset := by
  intro address position member child dependency
  have expanded := (walk_spec (table graph) [] requests).expanded (address, position)
    (List.mem_toFinset.mp member)
  cases expanded with
  | inl initial => simp at initial
  | inr children =>
    apply List.mem_toFinset.mpr
    apply children (child, position)
    apply List.mem_map.mpr
    exact Exists.intro child (And.intro
      (by simpa only [table_children] using dependency) rfl)

theorem plan_minimal (graph : Graph roots A size) (requests : List (Demand roots size))
    (allowed : Finset (Demand roots size)) (closed : Closed graph allowed)
    (includes : forall demand, Membership.mem requests demand -> Membership.mem allowed demand) :
    forall demand, Membership.mem (plan graph requests) demand -> Membership.mem allowed demand := by
  apply (walk_spec (table graph) [] requests).minimal (fun demand => Membership.mem allowed demand)
  next =>
    intro demand present child member
    cases List.mem_map.mp member with
    | intro address spec =>
      rw [<- spec.2]
      exact closed demand.1 demand.2 present address
        (by simpa only [table_children] using spec.1)
  next => intro demand member; simp at member
  next => exact includes

theorem planned_readback_iff (graph : Graph roots A size) (requests : List (Demand roots size))
    (reads : Reads roots size A) :
    Equations graph (plan graph requests).toFinset reads <->
      exists arrays : RootArrays roots A,
        forall address position, Membership.mem (plan graph requests) (address, position) ->
          actual graph arrays address position = reads address position := by
  simpa only [List.mem_toFinset] using
    IntervalReadback.finite_readback_iff graph (plan graph requests).toFinset reads
      (plan_closed graph requests)

theorem requested_readback_iff (graph : Graph roots A size)
    (requests : List (Demand roots size)) (requested : Reads roots size A) :
    (exists reads : Reads roots size A,
      (forall address position, Membership.mem requests (address, position) ->
        reads address position = requested address position) /\
      Equations graph (plan graph requests).toFinset reads) <->
    (exists arrays : RootArrays roots A,
      forall address position, Membership.mem requests (address, position) ->
        actual graph arrays address position = requested address position) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro reads spec =>
      cases (planned_readback_iff graph requests reads).mp spec.2 with
      | intro arrays agree =>
        refine Exists.intro arrays ?_
        intro address position member
        exact (agree address position (plan_includes graph requests _ member)).trans
          (spec.1 address position member)
  next =>
    intro witness
    cases witness with
    | intro arrays agree =>
      refine Exists.intro (actual graph arrays) (And.intro agree ?_)
      intro address position _
      exact IntervalReadback.actual_equation graph arrays address position

end CCFRaft.Sparse.IntervalDemandPlan

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalDemandPlan).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.IntervalDemandPlan: allowed-axiom gate passed."

#print axioms CCFRaft.Sparse.IntervalDemandPlan.table_children
#print axioms CCFRaft.Sparse.IntervalDemandPlan.plan_nodup
#print axioms CCFRaft.Sparse.IntervalDemandPlan.plan_closed
#print axioms CCFRaft.Sparse.IntervalDemandPlan.plan_minimal
#print axioms CCFRaft.Sparse.IntervalDemandPlan.requested_readback_iff
