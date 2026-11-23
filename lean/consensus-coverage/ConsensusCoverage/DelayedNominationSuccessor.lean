module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.DelayedNominationArms
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.DelayedNominationSingleton
import all ConsensusCoverage.Historical
import all ConsensusCoverage.Timely
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.DelayedNomination

open ActionProfile CCF Consensus Consensus.Model Consensus.Model.Node
open Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private theorem configuration_member {l : List Node.Configuration} {cfg : Node.Configuration}
    (mem : cfg ∈ l) {v : NodeID} (member : v ∈ cfg.nodes) :
    v ∈ configurationMembers l := by
  have loop (l : List Node.Configuration) (acc : Finset NodeID) :
      (v ∈ acc ∨ ∃ cfg ∈ l, v ∈ cfg.nodes) →
        v ∈ l.foldl (fun ns x => ns ∪ x.nodes) acc := by
    induction l generalizing acc with
    | nil => simp
    | cons hd tl ih =>
      intro h
      apply ih
      simp only [List.mem_cons, Finset.mem_union] at h ⊢
      grind
  exact loop l ∅ (.inr ⟨cfg, mem, member⟩)

private theorem no_successor_members {st : NodeState} {actor : NodeID}
    (no : findSuccessor st actor = none)
    {cfg : Node.Configuration} (active : cfg ∈ st.activeConfigurations) :
    ∀ v ∈ cfg.nodes, v = actor := by
  let rank (v : NodeID) :=
    (st.matchIndex v, latestMembershipIndex st.activeConfigurations v, v)
  let choose (best : Option NodeID) (v : NodeID) :=
    match best with
    | none => some v
    | some selected => if rankBelow (rank selected) (rank v) then some v else best
  have staysSome (l : List NodeID) (a : NodeID) : l.foldl choose (some a) ≠ none := by
    induction l generalizing a with
    | nil => simp
    | cons hd tl ih =>
      change tl.foldl choose (choose (some a) hd) ≠ none
      dsimp only [choose]
      split <;> apply ih
  have empty : (eligiblePeers st actor).sort = [] := by
    change (eligiblePeers st actor).sort.foldl choose none = none at no
    cases h : (eligiblePeers st actor).sort with
    | nil => rfl
    | cons hd tl =>
      rw [h] at no
      exact (staysSome tl hd no).elim
  intro v mem
  by_cases same : v = actor
  · exact same
  · exfalso
    have all : v ∈ st.activeMembers := configuration_member active mem
    have target : v ∈ (eligiblePeers st actor).sort :=
      Finset.mem_sort.mpr (Finset.mem_erase.mpr ⟨same, Finset.mem_union.mpr (.inl all)⟩)
    rw [empty] at target
    exact List.not_mem_nil target

private theorem majority_nonempty {cfg : Node.Configuration} {xs : Finset NodeID}
    (majority : hasConfigurationMajority xs cfg) : cfg.nodes.Nonempty := by
  classical
  by_cases h : cfg.nodes.Nonempty
  · exact h
  · have eq : xs ∩ cfg.nodes = ∅ := by
      apply Finset.ext
      intro v
      exact iff_of_false (fun mem => h ⟨v, (Finset.mem_inter.mp mem).2⟩) (Finset.notMem_empty _)
    unfold hasConfigurationMajority at majority
    rw [eq, Finset.card_empty] at majority
    omega

private theorem configurations_nonempty_of_cert {l : List Entry} {base i : Nat}
    {votes : Finset NodeID} (quorum : hasQuorum (Timely.bounded l base i) votes)
    (backed : ∀ cfg ∈ configurationHistory (l.take base), cfg.nodes.Nonempty) :
    ∀ cfg ∈ configurationHistory (l.take i), cfg.nodes.Nonempty := by
  intro cfg mem
  have configMem := configuration_prefix (List.take_prefix i l) mem
  have upper : cfg.index ≤ i := by
    have bounds := mem_history_filterMap mem
    simp only [List.length_take] at bounds
    omega
  by_cases earlier : cfg.index ≤ base
  · obtain ⟨rest, eq, later⟩ := configurationHistory_split l base
    rw [eq, List.mem_append] at configMem
    exact backed cfg (configMem.resolve_right fun h => (Nat.not_lt_of_ge earlier) (later cfg h))
  · exact majority_nonempty (hasQuorum_majority quorum
      (List.mem_filter.mpr ⟨active_of_later configMem (Nat.lt_of_not_ge earlier), decide_eq_true upper⟩))

private theorem configurations_nonempty_of_historical [Config.InitialConfiguration]
    {history k part} (key : Historical.Committed history k part) :
    ∀ cfg ∈ configurationHistory part, cfg.nodes.Nonempty := by
  induction key with
  | fresh cert =>
    obtain ⟨_, quorum, _⟩ := cert.2.2.2.2.2
    exact configurations_nonempty_of_cert quorum (by simp [configurationHistory])
  | chained cert _ _ within ih =>
    obtain ⟨_, quorum, _⟩ := cert.2.2.2.2.2
    exact configurations_nonempty_of_cert quorum (fun cfg mem => ih cfg (configuration_prefix within mem))
  | past _ ih => exact ih

private theorem configurations_nonempty_of_key (s : Step) {k part}
    (key : CommitKeys.committedBefore s k part) :
    ∀ cfg ∈ configurationHistory part, cfg.nodes.Nonempty := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact configurations_nonempty_of_historical
    ((CommitKeys.mem_historical _ _ _).mp ((CommitKeys.step_mem s _ _).mpr key))

private theorem singleton_quorum {st : NodeState} {actor : NodeID} {base i : Nat} {votes : Finset NodeID}
    (no : findSuccessor st actor = none) (le : st.commitIndex ≤ base)
    (quorum : hasQuorum (Timely.bounded st.log base i) votes)
    (backed : ∀ cfg ∈ configurationHistory (st.log.take base), cfg.nodes.Nonempty) :
    hasQuorum (Timely.bounded st.log st.commitIndex i) {actor} := by
  refine ⟨fun empty => quorum.1 (List.eq_nil_of_subset_nil (empty ▸ Timely.bounded_subset (index := i) le)),
    List.all_eq_true.mpr (fun cfg mem => decide_eq_true ?_)⟩
  have active := (List.mem_filter.mp mem).1
  have all := no_successor_members no active
  have nonempty : cfg.nodes.Nonempty := by
    rcases Timely.earlier_or_later (Nat.le_refl base) mem with earlier | later
    · have h := (activeConfigurations_sublist st.log st.commitIndex).subset (List.mem_filter.mp earlier).1
      obtain ⟨rest, eq, greater⟩ := configurationHistory_split st.log base
      rw [eq, List.mem_append] at h
      exact backed cfg (h.resolve_right (fun bad =>
        Nat.not_lt_of_ge (of_decide_eq_true (List.mem_filter.mp earlier).2) (greater cfg bad)))
    · exact majority_nonempty (hasQuorum_majority quorum later)
  obtain ⟨v, present⟩ := nonempty
  have same := all v present
  have eq : cfg.nodes = {actor} := by
    apply Finset.ext
    intro x
    rw [Finset.mem_singleton]
    exact ⟨all x, fun h => (h.trans same.symm).symm ▸ present⟩
  rw [show hasConfigurationMajority {actor} cfg =
      ((({actor} : Finset NodeID) ∩ cfg.nodes).card * 2 > cfg.nodes.card) from rfl, eq]
  have inter : ({actor} : Finset NodeID) ∩ {actor} = {actor} := by
    apply Finset.ext
    simp only [Finset.mem_inter, and_self, implies_true]
  rw [inter]
  change 1 * 2 > 1
  decide

/-- Without an election, the certifying leader is the nominating bootstrap
primary. If it has no successor then its own log supplies the quorum at its
commit index, and Timely says the key was already present. -/
public theorem sends_of_test (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    sends s.before s.act = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have st := stable s h
  apply (sends_iff s st).mpr
  cases target : findSuccessor c.pre c.actor with
  | some v => exact ⟨v, rfl⟩
  | none =>
    exfalso
    have noElection := ((test_iff s).mp h).2.2.2
    have ran := c.tr.ran
    change (Node.step (Capabilities.record c.actor) c.actor c.pre c.event).run {} =
      some (c.post, c.tr.outputs) at ran
    rw [st.event] at ran
    obtain ⟨_, _, _, role, _⟩ := nominate_sends c.actor c.pre {} _ _ ran
    obtain ⟨k, part, key, fresh⟩ := newKey s h
    change Committed (s.frame.advance s.after) k part at key
    rcases key with prior | ⟨n, x, b, i, certAfter, rfl, backing⟩
    · exact fresh prior
    have cert := (BackingStutter.commitStep_iff_of_nodes c.inv st.nodes).mp certAfter
    have term : k = BOOTSTRAP_TERM ∧ n = Config.INITIAL_PRIMARY := by
      rcases certAfter.1.2.2.2 with boot | ⟨l, j, elected⟩
      · exact boot
      · exact (noElection n k l j elected).elim
    have actor : n = c.actor := by
      have led := (c.pre_led role).mono s.after
      rcases led with boot | ⟨l, j, elected⟩
      · exact term.2.trans boot.2.symm
      · exact (noElection c.actor c.pre.currentTerm l j elected).elim
    subst n
    have eq := c.now_pre cert.1.1
    subst x
    have timely := Timely.folded s.folded
    by_cases small : b ≤ c.pre.commitIndex
    · exact fresh (timely _ _ _ _ _ cert small)
    obtain ⟨now, le, len, signed, signedTerm, vs, quorum, _⟩ := cert
    have behind : c.pre.commitIndex ≤ b := by omega
    have nonempty : ∀ cfg ∈ configurationHistory (c.pre.log.take b), cfg.nodes.Nonempty := by
      rcases backing with zero | ⟨e, p, old, _, within⟩
      · omega
      · exact fun cfg mem => configurations_nonempty_of_key s old cfg (configuration_prefix within mem)
    have rebase : CommitStep s.frame c.actor c.pre k c.pre.commitIndex i := by
      refine ⟨now, Nat.le_trans behind le, len, signed, signedTerm, {c.actor},
        singleton_quorum target behind quorum nonempty, ?_⟩
      intro v mem
      rw [Finset.mem_singleton] at mem
      subst v
      exact ⟨c.pre.log, now.2.1 ▸ c.inv.observed _ _ c.pre_now, List.take_prefix ..⟩
    exact fresh (timely _ _ _ _ _ rebase (Nat.le_refl _))

end ConsensusCoverage.DelayedNomination
