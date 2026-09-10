import Sparse.VersionedIntervals

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalReadback

open VersionedIntervals (Version Graph RootArrays evaluate)

variable {roots size : Nat} {A : Type}

def lookup : {size : Nat} -> (graph : Graph roots A size) ->
    (version : Fin size) -> Version roots A version.val
  | _, .empty, version => Fin.elim0 version
  | _, .push previous node, version =>
    Fin.lastCases node (fun earlier => lookup previous earlier) version

def earlier (version : Fin size) (child : Fin version.val) : Fin size :=
  Fin.mk child.val (Nat.lt_trans child.isLt version.isLt)

theorem earlier_last (child : Fin size) :
    earlier (Fin.last size) child = child.castSucc := rfl

theorem earlier_castSucc (version : Fin size) (child : Fin version.val) :
    earlier version.castSucc child = (earlier version child).castSucc := rfl

theorem values_lookup (graph : Graph roots A size) (rootValues : Fin roots -> A)
    (position : Nat) (version : Fin size) :
    graph.values rootValues position version =
      (lookup graph version).value rootValues
        (fun child => graph.values rootValues position (earlier version child)) position := by
  induction graph with
  | empty => exact Fin.elim0 version
  | push previous node ih =>
    induction version using Fin.lastCases with
    | last =>
      simp only [lookup, Fin.lastCases_last, Graph.values, Fin.snoc_last, earlier_last,
        Fin.snoc_castSucc]
    | cast version =>
      simp only [lookup, Fin.lastCases_castSucc, Graph.values, Fin.snoc_castSucc,
        earlier_castSucc]
      exact ih version

inductive Address (roots size : Nat) where
  | root (arrayID : Fin roots)
  | version (versionID : Fin size)
  deriving DecidableEq

def Address.rank : Address roots size -> Nat
  | .root _ => 0
  | .version versionID => versionID.val + 1

abbrev Demand (roots size : Nat) := Prod (Address roots size) Nat
abbrev Reads (roots size : Nat) (A : Type) := Address roots size -> Nat -> A

def actual (graph : Graph roots A size) (arrays : RootArrays roots A) :
    Reads roots size A
  | .root arrayID, position => arrays arrayID position
  | .version version, position => evaluate graph arrays position version

def dependencies (graph : Graph roots A size) : Address roots size -> List (Address roots size)
  | .root _ => []
  | .version version =>
    match lookup graph version with
    | .root arrayID => [.root arrayID]
    | .constant _ => []
    | .splice _ _ insideVersion outsideVersion =>
      [.version (earlier version insideVersion), .version (earlier version outsideVersion)]

def readValue (graph : Graph roots A size) (reads : Reads roots size A)
    (version : Fin size) (position : Nat) : A :=
  match lookup graph version with
  | .root arrayID => reads (.root arrayID) position
  | .constant value => value
  | .splice lower upper insideVersion outsideVersion =>
    if lower <= position /\ position < upper then
      reads (.version (earlier version insideVersion)) position
    else reads (.version (earlier version outsideVersion)) position

def Equation (graph : Graph roots A size) (reads : Reads roots size A) :
    Address roots size -> Nat -> Prop
  | .root _, _ => True
  | .version version, position =>
    reads (.version version) position = readValue graph reads version position

def Equations (graph : Graph roots A size) (demands : Finset (Demand roots size))
    (reads : Reads roots size A) : Prop :=
  forall address position, Membership.mem demands (address, position) ->
    Equation graph reads address position

def Closed (graph : Graph roots A size) (demands : Finset (Demand roots size)) : Prop :=
  forall address position, Membership.mem demands (address, position) ->
    forall child, Membership.mem (dependencies graph address) child ->
      Membership.mem demands (child, position)

theorem dependency_earlier (graph : Graph roots A size) (address child : Address roots size)
    (member : Membership.mem (dependencies graph address) child) :
    child.rank < address.rank := by
  cases address with
  | root _ => simp [dependencies] at member
  | version version =>
    cases node : lookup graph version with
    | root arrayID =>
      have same : child = .root arrayID := by simpa [dependencies, node] using member
      subst child
      simp [Address.rank]
    | constant _ => simp [dependencies, node] at member
    | splice lower upper insideVersion outsideVersion =>
      simp only [dependencies, node, List.mem_cons, List.not_mem_nil, or_false] at member
      cases member with
      | inl same =>
        subst child
        change insideVersion.val + 1 < version.val + 1
        exact Nat.succ_lt_succ insideVersion.isLt
      | inr same =>
        subst child
        change outsideVersion.val + 1 < version.val + 1
        exact Nat.succ_lt_succ outsideVersion.isLt

theorem readValue_congr (graph : Graph roots A size) (left right : Reads roots size A)
    (version : Fin size) (position : Nat)
    (agree : forall child, Membership.mem (dependencies graph (.version version)) child ->
      left child position = right child position) :
    readValue graph left version position = readValue graph right version position := by
  cases node : lookup graph version with
  | root arrayID =>
    simpa only [readValue, node] using agree (.root arrayID) (by simp [dependencies, node])
  | constant _ => simp only [readValue, node]
  | splice lower upper insideVersion outsideVersion =>
    simp only [readValue, node]
    rw [agree (.version (earlier version insideVersion)) (by simp [dependencies, node]),
      agree (.version (earlier version outsideVersion)) (by simp [dependencies, node])]

theorem actual_equation (graph : Graph roots A size) (arrays : RootArrays roots A)
    (address : Address roots size) (position : Nat) :
    Equation graph (actual graph arrays) address position := by
  cases address with
  | root _ => trivial
  | version version =>
    change graph.values (fun arrayID => arrays arrayID position) position version = _
    rw [values_lookup]
    cases node : lookup graph version <;>
      simp only [readValue, node, Version.value, actual, evaluate]

def rootArrays (reads : Reads roots size A) : RootArrays roots A :=
  fun arrayID position => reads (.root arrayID) position

theorem actual_agrees (graph : Graph roots A size) (demands : Finset (Demand roots size))
    (reads : Reads roots size A) (closed : Closed graph demands)
    (equations : Equations graph demands reads) :
    forall address position, Membership.mem demands (address, position) ->
      actual graph (rootArrays reads) address position = reads address position := by
  have agree : forall rank, forall address : Address roots size, address.rank = rank ->
      forall position, Membership.mem demands (address, position) ->
        actual graph (rootArrays reads) address position = reads address position := by
    intro rank
    induction rank using Nat.strong_induction_on with
    | h rank ih =>
      intro address equal position member
      cases address with
      | root _ => rfl
      | version version =>
        have children : forall child,
            Membership.mem (dependencies graph (.version version)) child ->
            actual graph (rootArrays reads) child position = reads child position := by
          intro child dependency
          have smaller := dependency_earlier graph (.version version) child dependency
          rw [equal] at smaller
          exact ih child.rank smaller child rfl position
            (closed (.version version) position member child dependency)
        calc
          actual graph (rootArrays reads) (.version version) position =
              readValue graph (actual graph (rootArrays reads)) version position :=
            actual_equation graph (rootArrays reads) (.version version) position
          _ = readValue graph reads version position :=
            readValue_congr graph _ _ version position children
          _ = reads (.version version) position :=
            (equations (.version version) position member).symm
  exact fun address => agree address.rank address rfl

theorem equations_of_agree (graph : Graph roots A size)
    (demands : Finset (Demand roots size)) (reads : Reads roots size A)
    (closed : Closed graph demands) (arrays : RootArrays roots A)
    (agree : forall address position, Membership.mem demands (address, position) ->
      actual graph arrays address position = reads address position) :
    Equations graph demands reads := by
  intro address position member
  cases address with
  | root _ => trivial
  | version version =>
    have children := readValue_congr graph (actual graph arrays) reads version position
      (fun child dependency => agree child position
        (closed (.version version) position member child dependency))
    change reads (.version version) position = readValue graph reads version position
    rw [<- agree (.version version) position member, <- children]
    exact actual_equation graph arrays (.version version) position

theorem finite_readback_iff (graph : Graph roots A size)
    (demands : Finset (Demand roots size)) (reads : Reads roots size A)
    (closed : Closed graph demands) :
    Equations graph demands reads <->
      exists arrays : RootArrays roots A,
        forall address position, Membership.mem demands (address, position) ->
          actual graph arrays address position = reads address position := by
  constructor
  next =>
    intro equations
    exact Exists.intro (rootArrays reads) (actual_agrees graph demands reads closed equations)
  next =>
    intro witness
    cases witness with
    | intro arrays agree => exact equations_of_agree graph demands reads closed arrays agree

-- Closure follows both children without inspecting either bound or the position.
def queryDemands (graph : Graph roots A size) :
    Address roots size -> Nat -> Finset (Demand roots size)
  | .root arrayID, position => {(.root arrayID, position)}
  | .version version, position =>
    match lookup graph version with
    | .root arrayID => {(.version version, position), (.root arrayID, position)}
    | .constant _ => {(.version version, position)}
    | .splice _ _ insideVersion outsideVersion =>
      insert (.version version, position)
        (Union.union
          (queryDemands graph (.version (earlier version insideVersion)) position)
          (queryDemands graph (.version (earlier version outsideVersion)) position))
termination_by address _ => address.rank
decreasing_by
  all_goals simp only [Address.rank, earlier]; omega

theorem closed_union (graph : Graph roots A size) (left right : Finset (Demand roots size))
    (left_closed : Closed graph left) (right_closed : Closed graph right) :
    Closed graph (Union.union left right) := by
  intro address position member child dependency
  cases Finset.mem_union.mp member with
  | inl present =>
    exact Finset.mem_union_left _ (left_closed address position present child dependency)
  | inr present =>
    exact Finset.mem_union_right _ (right_closed address position present child dependency)

theorem closed_insert (graph : Graph roots A size) (demands : Finset (Demand roots size))
    (address : Address roots size) (position : Nat) (closed : Closed graph demands)
    (children : forall child, Membership.mem (dependencies graph address) child ->
      Membership.mem demands (child, position)) :
    Closed graph (insert (address, position) demands) := by
  intro selected index member child dependency
  cases Finset.mem_insert.mp member with
  | inl same =>
    have address_equal := (Prod.mk.inj same).1
    have position_equal := (Prod.mk.inj same).2
    subst selected
    subst index
    exact Finset.mem_insert_of_mem (children child dependency)
  | inr present =>
    exact Finset.mem_insert_of_mem (closed selected index present child dependency)

theorem closed_singleton (graph : Graph roots A size) (address : Address roots size)
    (position : Nat) (leaf : dependencies graph address = []) :
    Closed graph {(address, position)} := by
  apply closed_insert graph {} address position
  next =>
    intro selected index member
    simp at member
  next =>
    intro child member
    simp [leaf] at member

theorem query_demands_spec (graph : Graph roots A size) (address : Address roots size)
    (position : Nat) :
    Membership.mem (queryDemands graph address position) (address, position) /\
      Closed graph (queryDemands graph address position) := by
  have spec : forall rank, forall selected : Address roots size, selected.rank = rank ->
      Membership.mem (queryDemands graph selected position) (selected, position) /\
        Closed graph (queryDemands graph selected position) := by
    intro rank
    induction rank using Nat.strong_induction_on with
    | h rank ih =>
      intro selected equal
      cases selected with
      | root arrayID =>
        rw [queryDemands.eq_def]
        exact And.intro (by simp)
          (closed_singleton graph (.root arrayID) position rfl)
      | version version =>
        rw [queryDemands.eq_def]
        cases node : lookup graph version with
        | root arrayID =>
          simp only [node]
          refine And.intro (by simp) ?_
          apply closed_insert graph {(.root arrayID, position)} (.version version) position
          next => exact closed_singleton graph (.root arrayID) position rfl
          next =>
            intro child member
            have same : child = .root arrayID := by simpa [dependencies, node] using member
            simp [same]
        | constant value =>
          simp only [node]
          exact And.intro (by simp)
            (closed_singleton graph (.version version) position (by simp [dependencies, node]))
        | splice lower upper insideVersion outsideVersion =>
          simp only [node]
          have left_dep : Membership.mem (dependencies graph (.version version))
              (.version (earlier version insideVersion)) := by simp [dependencies, node]
          have right_dep : Membership.mem (dependencies graph (.version version))
              (.version (earlier version outsideVersion)) := by simp [dependencies, node]
          have left_less := dependency_earlier graph _ _ left_dep
          have right_less := dependency_earlier graph _ _ right_dep
          rw [equal] at left_less right_less
          have left := ih _ left_less (.version (earlier version insideVersion)) rfl
          have right := ih _ right_less (.version (earlier version outsideVersion)) rfl
          refine And.intro (Finset.mem_insert_self _ _) ?_
          apply closed_insert
          next => exact closed_union graph _ _ left.2 right.2
          next =>
            intro child member
            simp only [dependencies, node, List.mem_cons, List.not_mem_nil, or_false] at member
            cases member with
            | inl same => subst child; exact Finset.mem_union_left _ left.1
            | inr same => subst child; exact Finset.mem_union_right _ right.1
  exact spec address.rank address rfl

def compileDemands (graph : Graph roots A size) (requests : Finset (Demand roots size)) :
    Finset (Demand roots size) :=
  requests.biUnion fun request => queryDemands graph request.1 request.2

theorem compile_demands_spec (graph : Graph roots A size)
    (requests : Finset (Demand roots size)) :
    (forall request, Membership.mem requests request ->
      Membership.mem (compileDemands graph requests) request) /\
    Closed graph (compileDemands graph requests) := by
  constructor
  next =>
    intro request member
    exact Finset.mem_biUnion.mpr (Exists.intro request
      (And.intro member (query_demands_spec graph request.1 request.2).1))
  next =>
    intro address position member child dependency
    cases Finset.mem_biUnion.mp member with
    | intro request spec =>
      exact Finset.mem_biUnion.mpr (Exists.intro request
        (And.intro spec.1
          ((query_demands_spec graph request.1 request.2).2 address position spec.2 child dependency)))

theorem compiled_readback_iff (graph : Graph roots A size)
    (requests : Finset (Demand roots size)) (reads : Reads roots size A) :
    Equations graph (compileDemands graph requests) reads <->
      exists arrays : RootArrays roots A,
        forall address position, Membership.mem (compileDemands graph requests) (address, position) ->
          actual graph arrays address position = reads address position :=
  finite_readback_iff graph (compileDemands graph requests) reads
    (compile_demands_spec graph requests).2

theorem requested_readback_iff (graph : Graph roots A size)
    (requests : Finset (Demand roots size)) (requested : Reads roots size A) :
    (exists reads : Reads roots size A,
      (forall address position, Membership.mem requests (address, position) ->
        reads address position = requested address position) /\
      Equations graph (compileDemands graph requests) reads) <->
    (exists arrays : RootArrays roots A,
      forall address position, Membership.mem requests (address, position) ->
        actual graph arrays address position = requested address position) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro reads spec =>
      cases (compiled_readback_iff graph requests reads).mp spec.2 with
      | intro arrays agree =>
        refine Exists.intro arrays ?_
        intro address position member
        exact (agree address position
          ((compile_demands_spec graph requests).1 (address, position) member)).trans
            (spec.1 address position member)
  next =>
    intro witness
    cases witness with
    | intro arrays agree =>
      refine Exists.intro (actual graph arrays) (And.intro agree ?_)
      intro address position _
      exact actual_equation graph arrays address position

end CCFRaft.Sparse.IntervalReadback

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.IntervalReadback).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.IntervalReadback: allowed-axiom gate passed."

#print axioms CCFRaft.Sparse.IntervalReadback.values_lookup
#print axioms CCFRaft.Sparse.IntervalReadback.compiled_readback_iff
#print axioms CCFRaft.Sparse.IntervalReadback.requested_readback_iff
