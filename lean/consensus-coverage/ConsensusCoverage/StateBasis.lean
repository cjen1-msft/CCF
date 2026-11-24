module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.ReachPath
public import ConsensusCoverage.Classes
import all ConsensusCoverage.Classes
import all Consensus.Proofs.SafetyInvariant

/-!
# Two-bit basis for the generated state questions

The original questions and the signature-content cases decode on arbitrary
frames. The two commit-chain cases additionally use the invariant that each
recorded commitment has a chain. A node at index zero can witness `Backing`
if there is a ghost committed part: its empty prefix fits.
-/

namespace ConsensusCoverage.StateBasis

open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Classes

-- Like the generated dispatcher, this interface talks about the private proof
-- frame imported above; it does not change the safety proof's module boundary.
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Some current node has commit index zero. -/
public def Zero (f : Frame) : Prop :=
  ∃ n st, (n, st) ∈ f.current.nodes ∧ st.commitIndex = 0

/-- Some current node's committed prefix fits in a ghost committed part. -/
public def Backing (f : Frame) : Prop :=
  ∃ n st term part, (n, st) ∈ f.current.nodes ∧ Committed f term part ∧
    st.committedLog <+: part

/-- Each recorded commitment has its invariant chain of quorum evidence. -/
public def ChainEvidence [Config.InitialConfiguration] (f : Frame) : Prop := CommitChains f.logs

/-- Decode a state question from the truth values of the two basis predicates. -/
@[expose] public def decode (zero backing : Prop) : StateBranch → Prop
  | .committed_logs_comparable_left_backed_inl => zero
  | .committed_logs_comparable_right_backed_inl => zero ∧ backing
  | _ => backing

section
variable [Config.InitialConfiguration]

private abbrev nilPath (f : Frame) : Prop :=
  (reach% state_signatureIndex_le_maxCommittableIndex_values_nil[0]) f

private abbrev signedPath (f : Frame) (log : List Entry) (i : Nat) : Prop :=
  (reach% state_signatureIndex_le_maxCommittableIndex_mem_cons_inl[0]) f log i

private theorem left_inl (f : Frame) :
    state_committed_logs_comparable_left_backed_inl f ↔ Zero f := by
  constructor
  · rintro ⟨n, st, mem, _, _, zero⟩
    exact ⟨n, st, mem, zero⟩
  · rintro ⟨n, st, mem, zero⟩
    exact ⟨n, st, mem, 0, Or.inl zero, zero⟩

private theorem left_inr (f : Frame) :
    state_committed_logs_comparable_left_backed_inr f ↔ Backing f := by
  constructor
  · rintro ⟨n, st, mem, _, _, ⟨term, part, committed, _, pref⟩, _⟩
    exact ⟨n, st, term, part, mem, committed, pref⟩
  · rintro ⟨n, st, term, part, mem, committed, pref⟩
    have w := And.intro committed (And.intro (Nat.le_refl term) pref)
    exact ⟨n, st, mem, term, Or.inr ⟨term, part, w⟩, ⟨term, part, w⟩, term,
      ⟨part, w⟩, part, w, w.1, w.2, w.2⟩

private theorem right_inl (f : Frame) :
    state_committed_logs_comparable_right_backed_inl f ↔ Zero f ∧ Backing f := by
  constructor
  · rintro ⟨n, m, st, other, mem, mem', _, _, ⟨term, part, committed, _, pref⟩, _, _, _, _, _,
      _, _, _, ⟨_, _, zero⟩⟩
    exact ⟨⟨m, other, mem', zero⟩, ⟨n, st, term, part, mem, committed, pref⟩⟩
  · rintro ⟨⟨m, other, mem', zero⟩, ⟨n, st, term, part, mem, committed, pref⟩⟩
    have w := And.intro committed (And.intro (Nat.le_refl term) pref)
    exact ⟨n, m, st, other, mem, mem', term, Or.inr ⟨term, part, w⟩,
      ⟨term, part, w⟩, term, ⟨part, w⟩, part, w, w.1, w.2, w.2.1, w.2.2, 0, Or.inl zero,
      zero⟩

-- The two nodes and the two committed parts in these generated telescopes
-- need not differ. One backing witness suffices, using prefix reflexivity.
private theorem backing_pair (f : Frame) :
    (state_committed_logs_comparable_right_backed_inr f ↔ Backing f) ∧
    (state_committed_logs_comparable_committed_comparable_inl f ↔ Backing f) ∧
    (state_committed_logs_comparable_committed_comparable_inr f ↔ Backing f) := by
  refine ⟨?_, ?_, ?_⟩ <;>
    (constructor
     · rintro ⟨n, _, st, _, mem, _, _, _, ⟨term, part, committed, _, pref⟩, _⟩
       exact ⟨n, st, term, part, mem, committed, pref⟩
     · rintro ⟨n, st, term, part, mem, committed, pref⟩
       have w := And.intro committed (And.intro (Nat.le_refl term) pref)
       have somePart : ∃ p, Committed f term p ∧ term ≤ term ∧ st.committedLog <+: p :=
         ⟨part, w⟩
       have earlier : ∃ k p, Committed f k p ∧ k ≤ term ∧ st.committedLog <+: p :=
         ⟨term, part, w⟩
       refine ⟨n, n, st, st, mem, mem, term, Or.inr earlier, earlier, term, somePart, part,
         w, w.1, w.2, w.2.1, w.2.2, term, Or.inr earlier, earlier, term, somePart, part,
         w, w.1, w.2, w.2.1, ?_⟩
       first | exact w.2.2 | exact ⟨w.2.2, List.prefix_refl part⟩)

private theorem nilPath_iff (f : Frame) : nilPath f ↔ Backing f := by
  change (((state_committed_logs_comparable_right_backed_inr f ∧ True) ∧ True) ∧ True) ↔ _
  simp only [and_true, (backing_pair f).1]

private theorem backing_of_path {f : Frame} {log : List Entry} {index : Nat}
    (h : signedPath f log index) : Backing f := by
  obtain ⟨_, _, ⟨⟨reached, _⟩, _⟩, _⟩ := h
  exact (backing_pair f).1.mp reached

-- The generated telescope has forgotten the link between
-- these log arguments and the backing witnesses. The singleton is sufficient.
private def signedLog : List Entry := [⟨0, .signature⟩]

private theorem signed_reach (f : Frame) (h : Backing f) : signedPath f signedLog 1 :=
  ⟨signedLog, signedLog, ⟨⟨(backing_pair f).1.mpr h, trivial⟩, signedLog, signedLog, rfl, rfl⟩,
    List.prefix_refl _, rfl, rfl, rfl⟩

private abbrev paired (f : Frame) : Prop :=
  (reach% state_tip_chain_fresh[0,0,0]) f

private theorem paired_iff (f : Frame) : paired f ↔ Backing f :=
  (backing_pair f).1

private theorem signature_content (f : Frame) :
    state_isSignature_eq_true_content_signature f ↔ Backing f := by
  constructor
  · rintro ⟨⟨h, _⟩, _⟩
    apply (paired_iff f).mp
    rcases h with ⟨_, _, paths, _⟩ | ⟨short, _⟩ | ⟨short, _⟩
    · rcases paths with one | two | three | four
      · obtain ⟨_, _, ⟨_, _, p, _⟩, _⟩ := one
        exact p.1.1
      · obtain ⟨_, _, ⟨_, _, ⟨_, _, p, _⟩, _⟩, _⟩ := two
        exact p.1.1
      · obtain ⟨_, _, _, ⟨_, _, p, _⟩, _⟩ := three
        exact p.1.1
      · obtain ⟨_, _, _, ⟨_, _, ⟨_, _, p, _⟩, _⟩, _⟩ := four
        exact p.1.1
    · exact short.1.1.1
    · exact short.1.1.1.1
  · intro backed
    exact ⟨⟨.inr (.inl ⟨⟨⟨⟨(paired_iff f).mpr backed, trivial⟩, trivial⟩,
      trivial⟩, trivial⟩), trivial⟩, trivial⟩

private theorem base_commit {f : Frame} {k p} (chain : CommitChain f.logs k p)
    (old : Committed f k p) :
    ∃ l k i, CommitFacts f.logs l k 0 i ∧ Committed f k (l.take i) := by
  induction chain with
  | fresh facts => exact ⟨_, _, _, facts, old⟩
  | backed _ prior _ _ _ ih => exact ih prior

private abbrev tipPath (f : Frame) (k : Nat) (p : List Entry) : Prop :=
  (reach% state_tip_chain_fresh[0]) f k p

private theorem backing_of_tip {f : Frame} {k p} (h : tipPath f k p) : Backing f := by
  apply (paired_iff f).mp
  rcases h with ⟨⟨reach, _⟩, _⟩ | ⟨_, _, reach, _⟩
  · exact reach
  · exact reach.1.1

private theorem tip_cases (f : Frame) (chains : CommitChains f.logs) :
    (state_tip_chain_fresh f ↔ Backing f) ∧ (state_tip_chain_backed f ↔ Backing f) := by
  have witness (backed : Backing f) : ∃ l k i, CommitFacts f.logs l k 0 i ∧
      Committed f k (l.take i) ∧ tipPath f k (l.take i) := by
    have ⟨_, _, k, p, _, committed, _⟩ := backed
    obtain ⟨l, k, i, facts, old⟩ := base_commit (chains k p committed) committed
    exact ⟨l, k, i, facts, old, .inl ⟨⟨(paired_iff f).mpr backed, trivial⟩, k, l.take i, old, rfl, rfl⟩⟩
  refine ⟨⟨fun ⟨_, _, p, _⟩ => backing_of_tip p, ?_⟩, ⟨fun ⟨_, _, p, _⟩ => backing_of_tip p, ?_⟩⟩
  · intro backed
    obtain ⟨l, k, i, facts, _, path⟩ := witness backed
    exact ⟨k, l.take i, path, l, k, i, facts, rfl, facts, rfl,
      CommitChain.fresh facts, HEq.rfl, .fresh facts⟩
  · intro backed
    obtain ⟨l, k, i, facts, prior, path⟩ := witness backed
    have chain : CommitChain f.logs k (l.take i) := .fresh facts
    have within : l.take 0 <+: l.take i := List.nil_prefix
    have extended := CommitChain.backed facts prior chain (Nat.le_refl k) within
    exact ⟨k, l.take i, path, l, k, 0, i, k, l.take i, facts, prior, chain,
      Nat.le_refl k, within, rfl, facts, Nat.le_refl k, rfl, extended, HEq.rfl, extended⟩

omit [Config.InitialConfiguration] in
private theorem best_le_fold (log : List Entry) (values : List Nat) (best : Nat) :
    best ≤ values.foldl (fun b i => if isSignatureAt log i then max b i else b) best := by
  induction values generalizing best with
  | nil => exact Nat.le_refl _
  | cons i rest ih =>
    rw [List.foldl_cons]
    split
    · exact Nat.le_trans (Nat.le_max_left _ _) (ih _)
    · exact ih _

@[expose] public def nonChain : StateBranch → Bool
  | .tip_chain_fresh | .tip_chain_backed => false
  | _ => true

/-- The original two-bit equivalence still holds without invariants on all non-chain questions. -/
public theorem ctx_iff_decode_nonChain (f : Frame) (b : StateBranch) (base : nonChain b = true) :
    ctx f b ↔ decode (Zero f) (Backing f) b := by
  cases b with
  | committed_logs_comparable_left_backed_inl => exact left_inl f
  | committed_logs_comparable_left_backed_inr => exact left_inr f
  | committed_logs_comparable_right_backed_inl => exact right_inl f
  | committed_logs_comparable_right_backed_inr => exact (backing_pair f).1
  | committed_logs_comparable_committed_comparable_inl => exact (backing_pair f).2.1
  | committed_logs_comparable_committed_comparable_inr => exact (backing_pair f).2.2
  | signatureIndex_le_maxCommittableIndex_values_nil =>
    constructor
    · rintro (⟨reached, _⟩ | ⟨_, _, reached, _⟩)
      · exact (nilPath_iff f).mp reached
      · exact backing_of_path reached
    · intro h
      exact Or.inl ⟨(nilPath_iff f).mpr h, trivial⟩
  | signatureIndex_le_maxCommittableIndex_values_cons =>
    constructor
    · rintro (⟨_, _, reached, _⟩ | ⟨_, _, reached, _⟩) <;>
        exact backing_of_path reached
    · intro h
      exact Or.inl ⟨signedLog, 1, signed_reach f h, [], by simp, rfl, Nat.le_refl _,
        best_le_fold signedLog⟩
  | signatureIndex_le_maxCommittableIndex_mem_cons_inl =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, by simp, rfl, rfl, Nat.le_refl _,
        best_le_fold signedLog⟩
  | signatureIndex_le_maxCommittableIndex_signature_pos =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, 0, by simp, rfl, by simp, 1, [],
        Nat.le_refl, rfl, rfl, Nat.le_refl _, rfl⟩
  | signatureIndex_le_maxCommittableIndex_signature_neg =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 1, [], by simp, 0, by simp, rfl, by simp, 0, [],
        Nat.le_refl, by decide, rfl, Nat.le_refl _, rfl⟩
  | signatureIndex_le_maxCommittableIndex_mem_cons_inr =>
    constructor
    · rintro ⟨_, _, reached, _⟩
      exact backing_of_path reached
    · intro h
      exact ⟨signedLog, 1, signed_reach f h, 0, [1], fun best _ => Nat.le_max_right best 1,
        by simp, by simp, rfl, Nat.le_refl _, best_le_fold signedLog⟩
  | isSignature_eq_true_content_signature => exact signature_content f
  | isSignature_eq_true_content_transaction => exact signature_content f
  | tip_chain_fresh | tip_chain_backed => cases base

/-- Decode all state questions on frames with committed-chain evidence. -/
public theorem ctx_iff_decode (f : Frame) (chains : ChainEvidence f) (b : StateBranch) :
    ctx f b ↔ decode (Zero f) (Backing f) b := by
  cases b <;> first
    | exact ctx_iff_decode_nonChain f _ rfl
    | exact (tip_cases f chains).1
    | exact (tip_cases f chains).2

end

/-- On arbitrary frames the non-chain questions still distinguish exactly the two basis bits. -/
public theorem ctx_equiv_iff_nonChain (cfg cfg' : Config.InitialConfiguration) (f g : Frame) :
    (∀ b, nonChain b = true → (@ctx cfg f b ↔ @ctx cfg' g b)) ↔
      (Zero f ↔ Zero g) ∧ (Backing f ↔ Backing g) := by
  constructor
  · intro h
    have probe (b : StateBranch) (base : nonChain b = true) :
        decode (Zero f) (Backing f) b ↔ decode (Zero g) (Backing g) b :=
      (@ctx_iff_decode_nonChain cfg f b base).symm.trans
        ((h b base).trans (@ctx_iff_decode_nonChain cfg' g b base))
    exact ⟨probe .committed_logs_comparable_left_backed_inl rfl,
      probe .committed_logs_comparable_left_backed_inr rfl⟩
  · rintro ⟨zero, backing⟩ b base
    rw [@ctx_iff_decode_nonChain cfg f b base, @ctx_iff_decode_nonChain cfg' g b base]
    cases b <;> simp only [decode, zero, backing]

/-- The left `inl` and `inr` are probes for the two bits, even when comparing
frames under different initial configurations. -/
public theorem ctx_equiv_iff (cfg cfg' : Config.InitialConfiguration) (f g : Frame)
    (chains : @ChainEvidence cfg f) (chains' : @ChainEvidence cfg' g) :
    (∀ b, @ctx cfg f b ↔ @ctx cfg' g b) ↔
      (Zero f ↔ Zero g) ∧ (Backing f ↔ Backing g) := by
  constructor
  · intro h
    exact (ctx_equiv_iff_nonChain cfg cfg' f g).mp (fun b _ => h b)
  · rintro ⟨zero, backing⟩ b
    rw [@ctx_iff_decode cfg f chains b, @ctx_iff_decode cfg' g chains' b]
    cases b <;> simp only [decode, zero, backing]

end ConsensusCoverage.StateBasis
