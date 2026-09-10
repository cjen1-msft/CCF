import Sparse.Queue

set_option autoImplicit false

namespace CCFRaft.Sparse.PartialQueue

open Sparse.Queue

variable {N T : Type} [DecidableEq N] [Fintype N]

private theorem known_realizability (known : Finset N)
    (parts : N -> List (Message N T))
    (wf : forall source, Membership.mem known source ->
      forall m, Membership.mem (parts source) m -> m.source = source) :
    exists queue : List (Message N T),
      queue.length = known.sum (fun source => (parts source).length) /\
      forall source, Membership.mem known source -> partition source queue = parts source := by
  classical
  -- This completion is a proof witness, not a constraint on unmentioned parts.
  let completed := fun source => if Membership.mem known source then parts source else []
  have completed_wf : WellFormed completed := by
    intro source m hm
    by_cases present : Membership.mem known source
    next => exact wf source present m (by simpa [completed, present] using hm)
    next => simp [completed, present] at hm
  let queue := realize Finset.univ.toList completed
  have partitions : forall source, partition source queue = completed source :=
    realizability completed completed_wf
  refine Exists.intro queue (And.intro ?_ ?_)
  next =>
    rw [<- sum_partition_length queue]
    simp_rw [partitions]
    simp [completed, apply_ite]
  next =>
    intro source present
    simpa [completed, present] using partitions source

theorem partial_family_iff (known : Finset N)
    (parts : N -> List (Message N T)) (n : Nat)
    (wf : forall source, Membership.mem known source ->
      forall m, Membership.mem (parts source) m -> m.source = source) :
    (exists queue : List (Message N T), queue.length = n /\
      forall source, Membership.mem known source -> partition source queue = parts source) <->
    known.sum (fun source => (parts source).length) <= n /\
      (known = Finset.univ -> known.sum (fun source => (parts source).length) = n) := by
  classical
  constructor
  next =>
    intro feasible
    let queue := feasible.choose
    have length_eq := feasible.choose_spec.1
    have agrees := feasible.choose_spec.2
    have known_lengths :
        known.sum (fun source => (parts source).length) =
          known.sum (fun source => (partition source queue).length) := by
      apply Finset.sum_congr rfl
      intro source present
      rw [agrees source present]
    constructor
    next =>
      rw [known_lengths, <- length_eq, <- sum_partition_length queue]
      exact Finset.sum_le_sum_of_subset_of_nonneg (Finset.subset_univ known)
        (by intros; omega)
    next =>
      intro all_known
      rw [known_lengths, all_known, sum_partition_length, length_eq]
  next =>
    intro conditions
    have budget := conditions.1
    have saturated := conditions.2
    have base_exists := known_realizability known parts wf
    let base := base_exists.choose
    have base_length : base.length = known.sum (fun source => (parts source).length) :=
      base_exists.choose_spec.1
    have base_matches := base_exists.choose_spec.2
    by_cases all_known : known = Finset.univ
    next =>
      exact Exists.intro base
        (And.intro (base_length.trans (saturated all_known)) base_matches)
    next =>
      have missing : exists source, Not (Membership.mem known source) := by
        by_contra none_missing
        apply all_known
        apply Finset.ext
        intro source
        simp only [Finset.mem_univ, iff_true]
        by_contra absent
        exact none_missing (Exists.intro source absent)
      let unknown := missing.choose
      have absent : Not (Membership.mem known unknown) := missing.choose_spec
      -- Repeated actual packets supply any residual, without a no-duplicates invariant.
      let filler : Message N T :=
        .proposeVoteRequest { term := 0, source := unknown, destination := unknown }
      let residual := n - known.sum (fun source => (parts source).length)
      refine Exists.intro (base ++ List.replicate residual filler) (And.intro ?_ ?_)
      next =>
        simp only [List.length_append, List.length_replicate, base_length]
        exact Nat.add_sub_of_le budget
      next =>
        intro source present
        have different : Not (unknown = source) := by
          intro same
          apply absent
          rw [same]
          exact present
        have empty : partition source (List.replicate residual filler) = [] := by
          apply List.filter_eq_nil_iff.mpr
          intro m hm
          have same : m = filler := (List.mem_replicate.mp hm).2
          simp [same, filler, Message.source, different]
        simp only [partition, List.filter_append]
        change partition source base ++ partition source (List.replicate residual filler) =
          parts source
        rw [empty, List.append_nil, base_matches source present]

theorem node_nat_partial_family_iff (known : Finset CCFRaft.Node)
    (parts : CCFRaft.Node -> List (Message CCFRaft.Node Nat)) (n : Nat)
    (wf : forall source, Membership.mem known source ->
      forall m, Membership.mem (parts source) m -> m.source = source) :
    (exists queue : List (Message CCFRaft.Node Nat), queue.length = n /\
      forall source, Membership.mem known source -> partition source queue = parts source) <->
    known.sum (fun source => (parts source).length) <= n /\
      (known = Finset.univ -> known.sum (fun source => (parts source).length) = n) :=
  partial_family_iff known parts n wf

theorem empty_known_unconstrained
    (parts : CCFRaft.Node -> List (Message CCFRaft.Node Nat)) (n : Nat) :
    exists queue : List (Message CCFRaft.Node Nat), queue.length = n /\
      forall source, Membership.mem (Finset.empty : Finset CCFRaft.Node) source ->
        partition source queue = parts source := by
  apply (node_nat_partial_family_iff Finset.empty parts n (by simp [Finset.empty])).mpr
  constructor
  next => simp [Finset.empty]
  next =>
    intro all_known
    have not_all : Not (Finset.empty = (Finset.univ : Finset CCFRaft.Node)) := by decide
    exact False.elim (not_all all_known)

private def node0 : CCFRaft.Node := Fin.mk 0 (by decide)
private def node1 : CCFRaft.Node := Fin.mk 1 (by decide)

private def packet0 (destination : CCFRaft.Node) : Message CCFRaft.Node Nat :=
  .proposeVoteRequest { term := 0, source := node0, destination := destination }

-- In a queue at node0, the last two packets have malformed destinations.
-- At every other source, this unmentioned parts value has the wrong source.
private def mixedParts (_ : CCFRaft.Node) : List (Message CCFRaft.Node Nat) :=
  [packet0 node0, packet0 node1, packet0 node1]

private theorem mixed_wf (source : CCFRaft.Node)
    (present : Membership.mem ({node0} : Finset CCFRaft.Node) source)
    (m : Message CCFRaft.Node Nat) (hm : Membership.mem (mixedParts source) m) :
    m.source = source := by
  have same : source = node0 := by simpa using present
  subst source
  simp only [mixedParts, List.mem_cons, List.not_mem_nil, or_false] at hm
  rcases hm with h | h | h <;> subst m <;> rfl

theorem duplicates_self_malformed (residual : Nat) :
    exists queue : List (Message CCFRaft.Node Nat), queue.length = 3 + residual /\
      forall source, Membership.mem ({node0} : Finset CCFRaft.Node) source ->
        partition source queue = mixedParts source := by
  apply (node_nat_partial_family_iff {node0} mixedParts (3 + residual) mixed_wf).mpr
  constructor
  next => simp [mixedParts]
  next =>
    intro all_known
    have present : Membership.mem ({node0} : Finset CCFRaft.Node) node1 := by
      rw [all_known]
      exact Finset.mem_univ node1
    have different : Not (node1 = node0) := by decide
    exact False.elim (different (Finset.mem_singleton.mp present))

theorem insufficient_length :
    Not (exists queue : List (Message CCFRaft.Node Nat), queue.length = 2 /\
      forall source, Membership.mem ({node0} : Finset CCFRaft.Node) source ->
        partition source queue = mixedParts source) := by
  intro feasible
  have budget := ((node_nat_partial_family_iff {node0} mixedParts 2 mixed_wf).mp feasible).1
  simp [mixedParts] at budget

theorem all_sources_empty_no_residual (n : Nat) :
    (exists queue : List (Message CCFRaft.Node Nat), queue.length = n /\
      forall source, Membership.mem (Finset.univ : Finset CCFRaft.Node) source ->
        partition source queue = []) <-> n = 0 := by
  rw [node_nat_partial_family_iff Finset.univ (fun _ => []) n (by simp)]
  simp [eq_comm]


end CCFRaft.Sparse.PartialQueue

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.PartialQueue.partial_family_iff,
      ``CCFRaft.Sparse.PartialQueue.node_nat_partial_family_iff,
      ``CCFRaft.Sparse.PartialQueue.empty_known_unconstrained,
      ``CCFRaft.Sparse.PartialQueue.duplicates_self_malformed,
      ``CCFRaft.Sparse.PartialQueue.insufficient_length,
      ``CCFRaft.Sparse.PartialQueue.all_sources_empty_no_residual] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
    Lean.logInfo m!"axiom gate passed: {theoremName}"
