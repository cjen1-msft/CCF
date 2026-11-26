module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CanonicalLogs
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.LeaderEffect
import all Consensus.Proofs.SafetyInvariant

/-! Replay evidence and formula-independent reader certificates. -/

namespace ConsensusCoverage.ReadersAtoms

open CCF CCF.MultiNodeTransitionSystem
open ActionProfile FullProfile GuardedDomain
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 16384
set_option linter.unusedSectionVars false

deriving instance DecidableEq for Event

instance : DecidableEq Model.Envelope := fun a b =>
  decidable_of_iff ((a == b) = true) beq_iff_eq

instance : DecidableEq (Outputs NodeID Message Notification) := fun a b =>
  letI : DecidableEq Notification := fun x _ => nomatch x
  decidable_of_iff ((a.outgoing == b.outgoing) = true ∧ a.notifications = b.notifications) (by
    cases a; cases b; simp only [beq_iff_eq, Outputs.mk.injEq])

theorem prefix_witness_iff {α : Type u} (p q : List α) :
    (∃ r, p <+: r ∧ (q <+: r ∨ r <+: q)) ↔ p <+: q ∨ q <+: p := by
  constructor
  · rintro ⟨r, pr, qr | rq⟩
    · exact List.prefix_or_prefix_of_prefix pr qr
    · exact Or.inl (pr.trans rq)
  · rintro (pq | qp)
    · exact ⟨q, pq, Or.inl (by simp)⟩
    · exact ⟨p, by simp, Or.inl qp⟩

theorem campaignFacts_iff [Config.InitialConfiguration] {g : LogFacts.Ghost} {v : VoteFacts.Ghost}
    {a : Nat → List Entry → Prop} {n : NodeID} {t : Nat} {l : List Entry} {i b : Nat} :
    CampaignFacts g v a n t l i b ↔ Rooted Config.GENESIS l ∧ i ≤ l.length ∧
      (let j := max i (maxCommittableIndex l)
       0 < j → termAt l j < t ∧ ∃ p, a (termAt l j) p ∧ j ≤ p.length ∧ l.take j = p.take j) ∧
      ∃ xs, hasQuorum (activeConfigurations l i) xs ∧ ∀ x ∈ xs,
        (⟨x, t, some n⟩ : VoteFacts.Stamp) ∈ v ∧ VoterRank g a x t b (vals t l i) :=
  ⟨fun ⟨r, f, a, v⟩ => ⟨r, f, a, v⟩, fun ⟨r, f, a, v⟩ => ⟨r, f, a, v⟩⟩

theorem electionCert_iff [Config.InitialConfiguration] {g : LogFacts.Ghost} {v : VoteFacts.Ghost}
    {n : NodeID} {k : Nat} {l : List Entry} {i : Nat} :
    ElectionCert g v n k l i ↔ 3 ≤ k ∧ Rooted Config.GENESIS l ∧ i ≤ l.length ∧
      (i = 0 ∨ ∃ e p, g.committed e p ∧ e < k ∧ l.take i <+: p) ∧
      ∃ xs, hasQuorum (activeConfigurations l i) xs ∧ ∀ x ∈ xs,
        (⟨x, k, some n⟩ : VoteFacts.Stamp) ∈ v :=
  ⟨fun ⟨a, r, f, b, q⟩ => ⟨a, r, f, b, q⟩, fun ⟨a, r, f, b, q⟩ => ⟨a, r, f, b, q⟩⟩

instance (m : Message) : Decidable (Bumping m) := by
  cases m <;> simp only [Bumping] <;> infer_instance

instance (root : Entry) (log : List Entry) : Decidable (Rooted root log) := by
  unfold Rooted
  infer_instance

/-! ## Certificate combinators -/

theorem guard_any {α : Type u} (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (bounded : ∀ x, p x → x ∈ xs)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.attach.any fun x => test x.1 x.2) = true ↔ ∃ x, p x := by
  constructor
  · intro yes
    obtain ⟨⟨x, mem⟩, _, pass⟩ := List.any_eq_true.mp yes
    exact ⟨x, (pointwise x mem).mp pass⟩
  · rintro ⟨x, hx⟩
    exact List.any_eq_true.mpr ⟨⟨x, bounded x hx⟩, List.mem_attach .., (pointwise x _).mpr hx⟩

theorem guard_all {α : Type u} (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.attach.all fun x => test x.1 x.2) = true ↔ ∀ x, x ∈ xs → p x := by
  rw [List.all_eq_true]
  constructor
  · intro h x mem
    exact (pointwise x mem).mp (h ⟨x, mem⟩ (List.mem_attach ..))
  · intro h ⟨x, mem⟩ _
    exact (pointwise x mem).mpr (h x mem)

theorem guard_all_finset {α : Type} [LT α] (s : CCF.Finset α) (p : α → Prop)
    (test : (x : α) → x ∈ s.val → Bool)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (s.val.attach.all fun x => test x.1 x.2) = true ↔ ∀ x, x ∈ s → p x :=
  guard_all s.val p test pointwise

theorem and_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (a && b) = true ↔ p ∧ q := by rw [Bool.and_eq_true, hp, hq]

theorem or_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (a || b) = true ↔ p ∨ q := by rw [Bool.or_eq_true, hp, hq]

theorem not_cert {a : Bool} {p : Prop} (hp : a = true ↔ p) :
    (!a) = true ↔ ¬ p := by simp [← hp]

theorem iff_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (a == b) = true ↔ (p ↔ q) := by
  rw [← hp, ← hq]; cases a <;> cases b <;> simp

theorem imp_cert {a b : Bool} {p q : Prop} (hp : a = true ↔ p) (hq : b = true ↔ q) :
    (!a || b) = true ↔ (p → q) := by
  rw [← hp, ← hq]; cases a <;> cases b <;> simp

theorem dite_cert {P : Prop} {Q : P → Prop} {b : Bool} (hb : b = true ↔ P) (test : P → Bool)
    (pointwise : ∀ h, test h = true ↔ Q h) :
    (if h : b = true then test (hb.mp h) else false) = true ↔ ∃ h : P, Q h := by
  split
  · next yes =>
    rw [pointwise]
    exact ⟨fun q => ⟨_, q⟩, fun ⟨_, q⟩ => q⟩
  · next no => exact ⟨fun h => absurd h Bool.false_ne_true, fun ⟨h, _⟩ => (no (hb.mpr h)).elim⟩

theorem forall_prop_cert {P : Prop} {Q : P → Prop} {b : Bool} (hb : b = true ↔ P) (test : P → Bool)
    (pointwise : ∀ h, test h = true ↔ Q h) :
    (if h : b = true then test (hb.mp h) else true) = true ↔ ∀ h : P, Q h := by
  split
  · next yes =>
    rw [pointwise]
    exact ⟨fun q _ => q, fun q => q _⟩
  · next no => exact ⟨fun _ h => (no (hb.mpr h)).elim, fun _ => rfl⟩

theorem quorum_cert (cs : List Node.Configuration) {P : NodeID → Prop} (test : NodeID → Bool)
    (pointwise : ∀ x, test x = true ↔ P x) :
    CommitMonitor.quorum cs test = true ↔ ∃ voters, hasQuorum cs voters ∧ ∀ v ∈ voters, P v := by
  rw [CommitMonitor.quorum_iff]
  simp only [pointwise]

/-- The quorum shape after `simp` has split `hasQuorum` and hoisted `cs ≠ []`. -/
theorem quorum_all_cert (cs : List Node.Configuration) {P : NodeID → Prop} (test : NodeID → Bool)
    (pointwise : ∀ x, test x = true ↔ P x) :
    (cs.isEmpty || CommitMonitor.quorum cs test) = true ↔
      ∃ voters : CCF.Finset NodeID,
        (cs.all fun c => decide (hasConfigurationMajority voters c)) = true ∧ ∀ v ∈ voters, P v := by
  by_cases empty : cs = []
  · subst empty
    simp only [List.isEmpty_nil, Bool.true_or, List.all_nil, true_and, true_iff]
    exact ⟨{}, fun v mem => absurd mem (by simp)⟩
  · have := quorum_cert cs test pointwise
    have ne : cs.isEmpty = false := by simpa using empty
    rw [ne, Bool.false_or, this]
    simp only [hasQuorum, ne_eq, empty, not_false_eq_true, true_and]

/-! ## Guard lemmas: a witness of a formula lies in an explicit finite list -/

theorem guard_fst {α β : Type} {a : α} {b : β} {L : List (α × β)} (h : (a, b) ∈ L) :
    a ∈ L.map Prod.fst := List.mem_map_of_mem (f := Prod.fst) h

theorem guard_snd {α β : Type} {a : α} {b : β} {L : List (α × β)} (h : (a, b) ∈ L) :
    b ∈ L.map Prod.snd := List.mem_map_of_mem (f := Prod.snd) h

theorem guard_eq {α : Sort u} {a b : α} (h : a = b) : True ∧ a = b := ⟨trivial, h⟩

theorem guard_eq_left {α : Type u} {a b : α} (h : a = b) : a ∈ [b] := List.mem_singleton.mpr h

theorem guard_eq_right {α : Type u} {a b : α} (h : b = a) : a ∈ [b] := List.mem_singleton.mpr h.symm

theorem guard_some_left {α : Type u} {a : α} {o : Option α} (h : o = some a) : a ∈ o.toList :=
  Option.mem_toList.mpr h

theorem guard_some_right {α : Type u} {a : α} {o : Option α} (h : some a = o) : a ∈ o.toList :=
  Option.mem_toList.mpr h.symm

theorem guard_lt {a b : Nat} (h : a < b) : a ∈ List.range b := List.mem_range.mpr h

theorem guard_le {a b : Nat} (h : a ≤ b) : a ∈ List.range (b + 1) :=
  List.mem_range.mpr (Nat.lt_succ_of_le h)

/-! ## Saturation of unbounded natural witnesses

If every occurrence of `x : Nat` in `P x` is in an atom that is constant once
`x` exceeds a threshold, `P x ↔ P (min x B)` for `B` above all thresholds, so
the witness can be bounded by `B`. -/

theorem nat_saturate {P P' : Nat → Prop} (B : Nat) (H : ∀ x w, w = min x B → (P x ↔ P' w)) :
    (∃ x, P x) ↔ ∃ x, x < B + 1 ∧ P x := by
  constructor
  · rintro ⟨x, px⟩
    refine ⟨min x B, by omega, ?_⟩
    exact (H (min x B) (min x B) (by omega)).mpr ((H x (min x B) rfl).mp px)
  · rintro ⟨x, -, px⟩
    exact ⟨x, px⟩

theorem nat_saturate_all {P P' : Nat → Prop} (B : Nat) (H : ∀ x w, w = min x B → (P x ↔ P' w)) :
    (∀ x, P x) ↔ ∀ x, x < B + 1 → P x := by
  constructor
  · exact fun h x _ => h x
  · intro h x
    exact (H x (min x B) rfl).mpr ((H (min x B) (min x B) (by omega)).mp (h _ (by omega)))

theorem sat_head (b rest : Nat) : b ≤ max b rest := Nat.le_max_left _ _

theorem sat_tail (b : Nat) {c rest : Nat} (h : c ≤ rest) : c ≤ max b rest :=
  Nat.le_trans h (Nat.le_max_right _ _)

theorem sat_take {α : Type} (L : List α) {x w B : Nat} (hb : L.length ≤ B) (hw : w = min x B) :
    L.take x = L.take w := by
  subst hw
  by_cases h : x ≤ B
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right (by omega), List.take_of_length_le (by omega),
      List.take_of_length_le hb]

theorem sat_drop {α : Type} (L : List α) {x w B : Nat} (hb : L.length ≤ B) (hw : w = min x B) :
    L.drop x = L.drop w := by
  subst hw
  by_cases h : x ≤ B
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right (by omega), List.drop_of_length_le (by omega),
      List.drop_of_length_le hb]

theorem sat_ge {c x w B : Nat} (hb : c ≤ B) (hw : w = min x B) : (c ≤ x) = (c ≤ w) := by
  subst hw; apply propext; omega

theorem sat_gt {c x w B : Nat} (hb : c + 1 ≤ B) (hw : w = min x B) : (c < x) = (c < w) := by
  subst hw; apply propext; omega

theorem sat_le {c x w B : Nat} (hb : c + 1 ≤ B) (hw : w = min x B) : (x ≤ c) = (w ≤ c) := by
  subst hw; apply propext; omega

theorem sat_lt {c x w B : Nat} (hb : c ≤ B) (hw : w = min x B) : (x < c) = (w < c) := by
  subst hw; apply propext; omega

theorem sat_eq {c x w B : Nat} (hb : c + 1 ≤ B) (hw : w = min x B) : (x = c) = (w = c) := by
  subst hw; apply propext; omega

theorem sat_eq' {c x w B : Nat} (hb : c + 1 ≤ B) (hw : w = min x B) : (c = x) = (c = w) := by
  subst hw; apply propext; omega

def prefixes {α : Type} (l : List α) : List (List α) :=
  (List.range (l.length + 1)).map (l.take ·)

theorem guard_prefix {α : Type} {a l : List α} (h : a <+: l) : a ∈ prefixes l := by
  rw [List.prefix_iff_eq_take] at h
  exact List.mem_map.mpr ⟨a.length, List.mem_range.mpr (Nat.lt_succ_of_le (List.IsPrefix.length_le
    (h ▸ List.take_prefix _ _))), h.symm⟩

theorem guard_finset {α : Type} [LT α] {a : α} {s : CCF.Finset α} (h : a ∈ s) : a ∈ s.val := h

theorem guard_or {α : Type u} {p q : Prop} {a : α} {L R : List α} (h : p ∨ q)
    (l : p → a ∈ L) (r : q → a ∈ R) : a ∈ L ++ R :=
  h.elim (fun hp => List.mem_append_left _ (l hp)) (fun hq => List.mem_append_right _ (r hq))

/-! ## Executable readers of the remaining ghost relations -/

/-- Grants are exact for any explicit request. -/
def grantedIn (h : List Model.State) (v c k : Nat) (r : RequestVoteRequest) : Bool :=
  match h with
  | [] => false
  | s :: rest => (GrantMonitor.scan ⟨v, c, k, r⟩ s rest).granted

theorem grantedIn_iff (h : List Model.State) (v c k : Nat) (r : RequestVoteRequest) :
    grantedIn h v c k r = true ↔ Historical.Granted h v c k r := by
  cases h with
  | nil =>
    simp only [grantedIn, Bool.false_eq_true, false_iff]
    rintro ⟨_, _, _, suf, _⟩
    have := suf.length_le
    simp at this
  | cons s rest => exact (GrantMonitor.correct ⟨v, c, k, r⟩ s rest).2

/-- An election with its exact campaign log and commit index. -/
def electionExact (t s : Model.State) (rest : List Model.State) (n k : Nat) (l : List Entry)
    (i : Nat) : Bool :=
  s.nodes.any fun (old, x) => t.nodes.any fun (newId, y) =>
    decide (old = n ∧ newId = n ∧ x.log = l ∧ x.commitIndex = i ∧ i ≤ l.length ∧
      (x.currentTerm < k ∨ (x.currentTerm = k ∧ x.role = .candidate)) ∧ y.currentTerm = k ∧
      (y.role = .primary ∨ y.role = .none) ∧ l.take (maxCommittableIndex l) <+: y.log ∧ 3 ≤ k) &&
      CommitMonitor.quorum (activeConfigurations l i) fun v =>
        grantedIn (t :: s :: rest) v n k (LogFacts.requestAt k l i)

theorem electionExact_iff (t s : Model.State) (rest : List Model.State) (n k : Nat)
    (l : List Entry) (i : Nat) :
    electionExact t s rest n k l i = true ↔ Historical.ElectStep t s rest n k l i := by
  simp only [electionExact, List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq,
    CommitMonitor.quorum_iff, grantedIn_iff, Historical.ElectStep]
  constructor
  · rintro ⟨_, x, old, _, y, new, ⟨rfl, rfl, rfl, rfl, facts⟩, votes⟩
    exact ⟨x, y, old, new, rfl, rfl, facts.1, facts.2.1, facts.2.2.1,
      facts.2.2.2.1, facts.2.2.2.2.1, facts.2.2.2.2.2, votes⟩
  · rintro ⟨x, y, old, new, rfl, rfl, le, term, eq, role, sub, floor, votes⟩
    exact ⟨n, x, old, n, y, new, ⟨rfl, rfl, rfl, rfl, le, term, eq, role, sub, floor⟩, votes⟩

def electedExact (n k : Nat) (l : List Entry) (i : Nat) : List Model.State → Bool
  | t :: s :: h => electionExact t s h n k l i || electedExact n k l i (s :: h)
  | _ => false

/-- Every node entry recorded anywhere in a history. -/
def histNodes (h : List Model.State) : List (NodeID × NodeState) := h.flatMap (·.nodes)

theorem mem_histNodes {h : List Model.State} {s : Model.State} {p : NodeID × NodeState}
    (hs : s ∈ h) (hp : p ∈ s.nodes) : p ∈ histNodes h :=
  List.mem_flatMap.mpr ⟨s, hs, hp⟩

theorem electionExact_mem {t s : Model.State} {rest : List Model.State} {n k : Nat}
    {l : List Entry} {i : Nat} (e : electionExact t s rest n k l i = true) :
    (∃ x, (n, x) ∈ s.nodes ∧ x.log = l ∧ x.commitIndex = i) ∧
      ∃ y, (n, y) ∈ t.nodes ∧ y.currentTerm = k := by
  simp only [electionExact, List.any_eq_true, Prod.exists, Bool.and_eq_true,
    decide_eq_true_eq] at e
  obtain ⟨a, x, hx, b, y, hy, ⟨rfl, rfl, rfl, rfl, -, -, rfl, -⟩, -⟩ := e
  exact ⟨⟨x, hx, rfl, rfl⟩, y, hy, rfl⟩

theorem electedExact_mem {n k : Nat} {l : List Entry} {i : Nat} :
    ∀ {h : List Model.State}, electedExact n k l i h = true →
      (∃ x, (n, x) ∈ histNodes h ∧ x.log = l ∧ x.commitIndex = i) ∧
        ∃ y, (n, y) ∈ histNodes h ∧ y.currentTerm = k
  | [] | [_] => by simp [electedExact]
  | t :: s :: rest => by
    rw [electedExact, Bool.or_eq_true]
    rintro (e | e)
    · obtain ⟨⟨x, hx, hl, hi⟩, y, hy, hk⟩ := electionExact_mem e
      exact ⟨⟨x, mem_histNodes (by simp) hx, hl, hi⟩, y, mem_histNodes (by simp) hy, hk⟩
    · obtain ⟨⟨x, hx, hl, hi⟩, y, hy, hk⟩ := electedExact_mem e
      have sub : ∀ p, p ∈ histNodes (s :: rest) → p ∈ histNodes (t :: s :: rest) := by
        intro p hp
        simp only [histNodes, List.flatMap_cons, List.mem_append] at hp ⊢
        exact Or.inr hp
      exact ⟨⟨x, sub _ hx, hl, hi⟩, y, sub _ hy, hk⟩

theorem electedExact_node {n k : Nat} {l : List Entry} {i : Nat} {h : List Model.State}
    (e : electedExact n k l i h = true) : n ∈ (histNodes h).map (·.1) := by
  obtain ⟨⟨x, hx, -⟩, -⟩ := electedExact_mem e
  exact List.mem_map.mpr ⟨_, hx, rfl⟩

theorem electedExact_term {n k : Nat} {l : List Entry} {i : Nat} {h : List Model.State}
    (e : electedExact n k l i h = true) : k ∈ (histNodes h).map (·.2.currentTerm) := by
  obtain ⟨-, y, hy, hk⟩ := electedExact_mem e
  exact List.mem_map.mpr ⟨_, hy, hk⟩

theorem electedExact_log {n k : Nat} {l : List Entry} {i : Nat} {h : List Model.State}
    (e : electedExact n k l i h = true) : l ∈ (histNodes h).map (·.2.log) := by
  obtain ⟨⟨x, hx, hl, -⟩, -⟩ := electedExact_mem e
  exact List.mem_map.mpr ⟨_, hx, hl⟩

theorem electedExact_idx {n k : Nat} {l : List Entry} {i : Nat} {h : List Model.State}
    (e : electedExact n k l i h = true) : i ∈ (histNodes h).map (·.2.commitIndex) := by
  obtain ⟨⟨x, hx, -, hi⟩, -⟩ := electedExact_mem e
  exact List.mem_map.mpr ⟨_, hx, hi⟩

theorem canonAt_mem {b : NodeID} {k : Nat} {l : List Entry} :
    ∀ {h : List Model.State}, canonAt b k l h = true →
      ∃ p, p ∈ histNodes h ∧ p.2.currentTerm = k ∧ p.2.log = l
  | [] => by simp [canonAt]
  | s :: rest => by
    rw [canonAt, Bool.or_eq_true]
    rintro (e | e)
    · simp only [List.any_eq_true, Prod.exists, Bool.and_eq_true, decide_eq_true_eq] at e
      obtain ⟨a, st, hp, ⟨-, hk, hl⟩, -⟩ := e
      exact ⟨(a, st), mem_histNodes (by simp) hp, hk, hl⟩
    · obtain ⟨p, hp, hk, hl⟩ := canonAt_mem e
      refine ⟨p, ?_, hk, hl⟩
      simp only [histNodes, List.flatMap_cons, List.mem_append] at hp ⊢
      exact Or.inr hp

theorem canonAt_term {b : NodeID} {k : Nat} {l : List Entry} {h : List Model.State}
    (e : canonAt b k l h = true) : k ∈ (histNodes h).map (·.2.currentTerm) := by
  obtain ⟨p, hp, hk, -⟩ := canonAt_mem e
  exact List.mem_map.mpr ⟨_, hp, hk⟩

theorem canonAt_log {b : NodeID} {k : Nat} {l : List Entry} {h : List Model.State}
    (e : canonAt b k l h = true) : l ∈ (histNodes h).map (·.2.log) := by
  obtain ⟨p, hp, -, hl⟩ := canonAt_mem e
  exact List.mem_map.mpr ⟨_, hp, hl⟩

public def historicalPrefixes (hist : List Model.State) : List (List Entry) :=
  [] :: (histNodes hist).flatMap (prefixes ·.2.log)

theorem anchored_prefix_bound {bootstrap : NodeID} {h : List Model.State} {log : List Entry}
    (anchor : ∀ i, 0 < i → i ≤ log.length →
      ∃ l, canonAt bootstrap (termAt log i) l h = true ∧
        i ≤ l.length ∧ log.take i = l.take i) :
    log ∈ historicalPrefixes h := by
  by_cases empty : log = []
  · simp [historicalPrefixes, empty]
  obtain ⟨l, canon, _, eq⟩ :=
    anchor log.length (List.length_pos_iff.mpr empty) (Nat.le_refl _)
  obtain ⟨q, hq, _, rfl⟩ := canonAt_mem canon
  have sub : log <+: q.2.log := by
    rw [← List.take_length (l := log), eq]
    exact List.take_prefix _ _
  exact List.mem_cons_of_mem _ (List.mem_flatMap.mpr ⟨q, hq, guard_prefix sub⟩)

theorem electedExact_iff (n k : Nat) (l : List Entry) (i : Nat) (h : List Model.State) :
    electedExact n k l i h = true ↔ Historical.Elected h n k l i := by
  induction h with
  | nil => simp [electedExact, Historical.Elected]
  | cons t h ih =>
    cases h with
    | nil =>
      simp only [electedExact, Bool.false_eq_true, false_iff, Historical.Elected]
      rintro ⟨_, _, _, suf, _⟩
      have := suf.length_le; simp at this
    | cons s rest =>
      rw [electedExact, Bool.or_eq_true, electionExact_iff, ih]
      unfold Historical.Elected
      simp only [Historical.edge_cons, List.cons.injEq]
      grind

/-! ## Snapshot with the recorded event and its outputs -/

/-- The `View` of `GuardedDomain` plus the recorded event and its outgoing messages. -/
public structure XView where
  base : View
  event : Event
  outputs : Outputs NodeID Message Notification
  committedBefore : List (Nat × List Entry)
  committedAfter : List (Nat × List Entry)

def XView.sent (x : XView) : List Model.Envelope := x.outputs.outgoing

def voteStamps (hist : List Model.State) : VoteFacts.Ghost :=
  hist.foldr (fun s votes => VoteFacts.advance votes s) []

theorem frame_votes [Config.InitialConfiguration] (s : Model.State) (hist : List Model.State) :
    (StateCoverage.frame s hist).votes = voteStamps (s :: hist) := by
  induction hist generalizing s with
  | nil => rfl
  | cons old rest ih =>
    change VoteFacts.advance (StateCoverage.frame old rest).votes s =
      VoteFacts.advance (voteStamps (old :: rest)) s
    rw [ih]

def eventOf : Model.Action → Event
  | .local _ i => .internal i
  | .deliver e => .receive e.source e.payload

def outputsOf (actor : NodeID) (pre : NodeState) (event : Event) :
    Outputs NodeID Message Notification :=
  match (Model.Node.step (Capabilities.record actor) actor pre event).run {} with
  | some (_, out) => out
  | none => {}

private def packX (v : View) (e : Event) : XView :=
  ⟨v, e, outputsOf v.actor v.pre e,
    CommitKeys.keys v.bootstrap (v.before :: v.past),
    CommitKeys.keys v.bootstrap (v.after :: v.before :: v.past)⟩

public def ofXAction (cfg : FullProfile.Configuration) (before after : Model.State)
    (past : List Model.State) (act : Model.Action) : Option XView := do
  let v ← ofAction cfg before after past act
  return packX v (eventOf act)

def XView.Matches [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (x : XView) (c : Ctx f t) : Prop :=
  x.base.Matches c ∧ x.event = c.event ∧ x.outputs = c.tr.outputs ∧
    f.votes = voteStamps (x.base.before :: x.base.past) ∧
    x.committedBefore = CommitKeys.keys x.base.bootstrap (x.base.before :: x.base.past) ∧
    x.committedAfter = CommitKeys.keys x.base.bootstrap (x.base.after :: x.base.before :: x.base.past)

theorem ofXAction_matches (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    ∃ x, ofXAction s.cfg s.before s.after s.past s.act = some x ∧ x.Matches s.context := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := ofAction_matches s
  have action := (s.context_eq s.context).mpr rfl
  have ev : eventOf s.act = s.context.event := by
    rw [← action]
    change eventOf (ActionContext.encode _ s.context.tr.event) = s.context.tr.event
    generalize s.context.tr.event = e
    cases e <;> rfl
  have outputs : outputsOf v.actor v.pre s.context.event = s.context.tr.outputs := by
    rw [← View.actor_eq ok, ← View.pre_eq ok]
    unfold outputsOf
    rw [s.context.tr.ran]
  refine ⟨packX v (eventOf s.act), ?_, ok, ev, ?_, ?_, rfl, rfl⟩
  · simp [ofXAction, made]
  · change outputsOf v.actor v.pre (eventOf s.act) = _
    rw [ev, outputs]
  · change s.frame.votes = voteStamps (v.before :: v.past)
    rw [show v.before = s.before from (View.before_eq ok).symm.trans s.current_eq]
    have history : v.past = s.past := by
      change ((nodeState s.before (actionActor s.act)).bind fun pre =>
        (nodeState s.after (actionActor s.act)).bind fun post =>
          some (pack (s.cfg.min?.getD 0) s.before s.after s.past (actionActor s.act) pre post)) =
        some v at made
      cases hp : nodeState s.before (actionActor s.act) <;>
        cases hq : nodeState s.after (actionActor s.act) <;> simp [hp, hq] at made
      rw [← made]
      rfl
    rw [history]
    exact frame_votes s.before s.past

/-! ## Rewrite rules from frame atoms to snapshot data -/

section Rules
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State}
  {x : XView} {c : Ctx f t} (ok : x.Matches c)
include ok

theorem X.event_eq : c.event = x.event := ok.2.1.symm
theorem X.tr_event_eq : c.tr.event = x.event := ok.2.1.symm
theorem X.outputs_eq : c.tr.outputs = x.outputs := ok.2.2.1.symm
theorem X.sent_eq : c.sent = x.sent := congrArg Outputs.outgoing (X.outputs_eq ok)
theorem X.tr_sent_eq : c.tr.outputs.outgoing = x.sent := X.sent_eq ok
theorem X.votes_before : f.votes = voteStamps (x.base.before :: x.base.past) := ok.2.2.2.1
theorem X.votes_after :
    (f.advance t).votes = voteStamps (x.base.after :: x.base.before :: x.base.past) := by
  change VoteFacts.advance f.votes t = VoteFacts.advance _ x.base.after
  rw [X.votes_before ok, View.after_eq ok.1]
  rfl
theorem X.tr_actor_eq : c.tr.actor = x.base.actor := View.actor_eq ok.1
theorem X.tr_pre_eq : c.tr.pre = x.base.pre := View.pre_eq ok.1
theorem X.tr_post_eq : c.tr.post = x.base.post := View.post_eq ok.1

theorem X.run_for {e : Event} (same : e = x.event) :
    (Model.Node.step (Capabilities.record x.base.actor) x.base.actor x.base.pre e).run {} =
      some (x.base.post, x.outputs) := by
  rw [same, ← X.tr_actor_eq ok, ← X.tr_pre_eq ok, ← X.tr_event_eq ok, ← X.tr_post_eq ok,
    ← X.outputs_eq ok]
  exact c.tr.ran

theorem X.run_eq :
    (Model.Node.step (Capabilities.record x.base.actor) x.base.actor x.base.pre x.event).run {} =
      some (x.base.post, x.outputs) := X.run_for ok rfl

theorem X.send_ok (e : Model.Envelope) (h : e ∈ x.sent) :
    SendOK x.base.actor x.base.pre x.event x.base.post e := by
  have mem : e ∈ c.sent := (X.sent_eq ok).symm ▸ h
  rw [← X.tr_actor_eq ok, ← X.tr_pre_eq ok, ← X.tr_event_eq ok, ← X.tr_post_eq ok]
  exact @Summary.sends _ _ _ _ _ c.sum e mem

theorem X.logs_before : f.logs = Historical.logFacts (x.base.before :: x.base.past) := by
  rw [ok.1.2, View.before_eq ok.1]

theorem X.logs_after :
    (f.advance t).logs = Historical.logFacts (x.base.after :: x.base.before :: x.base.past) := by
  have logs : (f.advance t).logs = Historical.logFacts (t :: f.current :: x.base.past) := by
    change LogFacts.advance _ f.logs _ _ = _
    rw [ok.1.2]
    rfl
  rw [logs, View.before_eq ok.1, View.after_eq ok.1]

theorem X.bootstrap : x.base.bootstrap = Config.INITIAL_PRIMARY := congrArg View.bootstrap ok.1.1

theorem X.current_after : (f.advance t).current = x.base.after := View.after_eq ok.1

theorem X.now_before (n : NodeID) (st : NodeState) :
    Now f n st ↔ (n, st) ∈ x.base.before.nodes := by
  unfold Now; rw [View.before_eq ok.1]

theorem X.now_after (n : NodeID) (st : NodeState) :
    Now (f.advance t) n st ↔ (n, st) ∈ x.base.after.nodes := by
  change (n, st) ∈ t.nodes ↔ _; rw [View.after_eq ok.1]

theorem X.pre_mem : (x.base.actor, x.base.pre) ∈ x.base.before.nodes := by
  rw [← View.actor_eq ok.1, ← View.pre_eq ok.1, ← X.now_before ok]
  exact c.pre_now

theorem X.post_mem : (x.base.actor, x.base.post) ∈ x.base.after.nodes := by
  rw [← View.actor_eq ok.1, ← View.post_eq ok.1, ← X.now_after ok]
  exact c.post_now

theorem X.pending_before (e : Model.Envelope) : Pending f e ↔ e ∈ x.base.before.network := by
  unfold Pending; rw [View.before_eq ok.1]

theorem X.pending_after (e : Model.Envelope) :
    Pending (f.advance t) e ↔ e ∈ x.base.after.network := by
  change e ∈ t.network ↔ _; rw [View.after_eq ok.1]

theorem X.seen_before (n k : Nat) (l : List Entry) :
    f.logs.seen n k l ↔ Observation.mk k l ∈ observations (x.base.before :: x.base.past) n := by
  rw [X.logs_before ok]; exact seen_mem _ n ⟨k, l⟩

theorem X.seen_after (n k : Nat) (l : List Entry) :
    (f.advance t).logs.seen n k l ↔
      Observation.mk k l ∈ observations (x.base.after :: x.base.before :: x.base.past) n := by
  rw [X.logs_after ok]; exact seen_mem _ n ⟨k, l⟩

theorem X.led_before (n k : Nat) :
    f.logs.led Config.INITIAL_PRIMARY n k ↔ k ∈ ledTerms x.base.bootstrap (x.base.before :: x.base.past) n := by
  rw [X.logs_before ok, led_mem, X.bootstrap ok]

theorem X.led_after (n k : Nat) :
    (f.advance t).logs.led Config.INITIAL_PRIMARY n k ↔
      k ∈ ledTerms x.base.bootstrap (x.base.after :: x.base.before :: x.base.past) n := by
  rw [X.logs_after ok, led_mem, X.bootstrap ok]

theorem X.canon_before (k : Nat) (l : List Entry) :
    f.logs.canon k l ↔ canonAt x.base.bootstrap k l (x.base.before :: x.base.past) = true := by
  rw [X.logs_before ok, ← canonAt_true, X.bootstrap ok]

theorem X.canon_after (k : Nat) (l : List Entry) :
    (f.advance t).logs.canon k l ↔
      canonAt x.base.bootstrap k l (x.base.after :: x.base.before :: x.base.past) = true := by
  rw [X.logs_after ok, ← canonAt_true, X.bootstrap ok]

theorem X.committed_before (k : Nat) (l : List Entry) :
    f.logs.committed k l ↔ (k, l) ∈ x.committedBefore := by
  rw [X.logs_before ok, ok.2.2.2.2.1, X.bootstrap ok, CommitKeys.mem_historical,
    (Historical.logFacts_correct _).committed]

theorem X.committed_after (k : Nat) (l : List Entry) :
    (f.advance t).logs.committed k l ↔ (k, l) ∈ x.committedAfter := by
  rw [X.logs_after ok, ok.2.2.2.2.2, X.bootstrap ok, CommitKeys.mem_historical,
    (Historical.logFacts_correct _).committed]

theorem X.grant_before (v n k : Nat) (r : RequestVoteRequest) :
    f.logs.grant v n k r ↔ grantedIn (x.base.before :: x.base.past) v n k r = true := by
  rw [X.logs_before ok, grantedIn_iff, (Historical.logFacts_correct _).grant]

theorem X.grant_after (v n k : Nat) (r : RequestVoteRequest) :
    (f.advance t).logs.grant v n k r ↔
      grantedIn (x.base.after :: x.base.before :: x.base.past) v n k r = true := by
  rw [X.logs_after ok, grantedIn_iff, (Historical.logFacts_correct _).grant]

theorem X.elected_before (n k : Nat) (l : List Entry) (i : Nat) :
    f.logs.elected n k l i ↔ electedExact n k l i (x.base.before :: x.base.past) = true := by
  rw [X.logs_before ok, electedExact_iff, (Historical.logFacts_correct _).elected]

theorem X.elected_after (n k : Nat) (l : List Entry) (i : Nat) :
    (f.advance t).logs.elected n k l i ↔
      electedExact n k l i (x.base.after :: x.base.before :: x.base.past) = true := by
  rw [X.logs_after ok, electedExact_iff, (Historical.logFacts_correct _).elected]

theorem X.advanced_logs :
    LogFacts.advance Config.INITIAL_PRIMARY f.logs (some x.base.before) x.base.after =
      (f.advance t).logs := by
  have prev := View.before_eq ok.1
  have next := View.after_eq ok.1
  rw [← prev, ← next]
  rfl

theorem X.elected_advanced (n k : Nat) (l : List Entry) (i : Nat) :
    (LogFacts.advance Config.INITIAL_PRIMARY f.logs (some x.base.before) x.base.after).elected
      n k l i ↔ electedExact n k l i (x.base.after :: x.base.before :: x.base.past) = true := by
  rw [X.advanced_logs ok]
  exact X.elected_after ok n k l i

theorem X.canon_advanced (k : Nat) (l : List Entry) :
    (LogFacts.advance Config.INITIAL_PRIMARY f.logs (some x.base.before) x.base.after).canon
      k l ↔ canonAt x.base.bootstrap k l (x.base.after :: x.base.before :: x.base.past) = true := by
  rw [X.advanced_logs ok]
  exact X.canon_after ok k l

theorem X.committed_advanced (k : Nat) (l : List Entry) :
    (LogFacts.advance Config.INITIAL_PRIMARY f.logs (some x.base.before) x.base.after).committed
      k l ↔ (k, l) ∈ x.committedAfter := by
  rw [X.advanced_logs ok]
  exact X.committed_after ok k l

/-- A fresh election uses one joint key: the actor and its recorded endpoints. -/
theorem X.elect_now (n k : Nat) (l : List Entry) (i : Nat) :
    ElectStep f t n k l i ↔
      n = x.base.actor ∧ k = x.base.post.currentTerm ∧ l = x.base.pre.log ∧
      i = x.base.pre.commitIndex ∧
      electionExact x.base.after x.base.before x.base.past x.base.actor
        x.base.post.currentTerm x.base.pre.log x.base.pre.commitIndex = true := by
  have logs : (f.advance x.base.after).logs = (f.advance t).logs :=
    congrArg (fun s => (f.advance s).logs) (View.after_eq ok.1).symm
  have grants v a term req : (f.advance x.base.after).logs.grant v a term req ↔
      Historical.Granted (x.base.after :: x.base.before :: x.base.past) v a term req := by
    rw [logs, X.logs_after ok, (Historical.logFacts_correct _).grant]
  have edge : ElectStep f t n k l i ↔
      Historical.ElectStep x.base.after x.base.before x.base.past n k l i := by
    simp only [ElectStep, LogFacts.ElectionAt, Historical.ElectStep, grants,
      View.before_eq ok.1, View.after_eq ok.1, LogFacts.requestAt, Historical.vals]
  constructor
  · intro step
    obtain ⟨actor, log, commit, _, term, _, _, _⟩ := c.electStep step
    rw [View.actor_eq ok.1] at actor
    rw [View.pre_eq ok.1] at log commit
    rw [View.post_eq ok.1] at term
    refine ⟨actor, term.symm, log.symm, commit.symm, ?_⟩
    have yes := (electionExact_iff ..).2 (edge.mp step)
    rwa [actor, ← term, ← log, ← commit] at yes
  · rintro ⟨rfl, rfl, rfl, rfl, yes⟩
    exact edge.mpr ((electionExact_iff ..).mp yes)

end Rules

theorem obs_eta (o : Safety.Observation) : Observation.mk o.currentTerm o.log = o := rfl

theorem XView.Matches.base_ok [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) : x.base.Matches c := ok.1

theorem X.before_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) : f.current = x.base.before := View.before_eq ok.1

theorem X.after_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) : t = x.base.after := View.after_eq ok.1

theorem X.sent_of_new [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) {e : Model.Envelope}
    (yes : e ∈ x.base.after.network) (no : e ∉ x.base.before.network) : e ∈ x.sent := by
  rw [← X.after_eq ok] at yes
  rw [← X.before_eq ok] at no
  rcases c.tr.mem_network yes with old | sent
  · exact (no old).elim
  · exact X.tr_sent_eq ok ▸ sent

section Frame
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State}
  {x : XView} {c : Ctx f t} (ok : x.Matches c)
include ok

theorem X.unchanged_iff : c.pre = c.post ↔ x.base.changed = false := by
  rw [← View.old_post ok.1]
  exact ⟨fun h => h ▸ c.pre_now, fun h => (c.now_pre h).symm⟩

theorem X.keep {n : NodeID} {st : NodeState} (h : Now f n st) (ne : ¬ n = c.actor) :
    Now (f.advance t) n st := by
  change (n, st) ∈ t.nodes
  rw [c.tr.nodesEq]
  simp only [Concrete.replaceNode, List.mem_map]
  exact ⟨(n, st), h, by simp [ne]⟩

/-- Conditional: a present entry of the next table is in the previous one
unless it is the actor's and the actor changed. -/
theorem X.before_of_after {n : NodeID} {st : NodeState} (h : (n, st) ∈ x.base.after.nodes) :
    (n, st) ∈ x.base.before.nodes ↔ ¬ n = x.base.actor ∨ x.base.changed = false := by
  rw [← X.now_after ok] at h
  rw [← X.now_before ok, next_now c h, ← X.unchanged_iff ok, ← View.actor_eq ok.1]

theorem X.after_of_before {n : NodeID} {st : NodeState} (h : (n, st) ∈ x.base.before.nodes) :
    (n, st) ∈ x.base.after.nodes ↔ ¬ n = x.base.actor ∨ x.base.changed = false := by
  rw [← X.now_before ok] at h
  rw [← X.now_after ok, ← X.unchanged_iff ok, ← View.actor_eq ok.1]
  constructor
  · intro a
    exact (next_now c a).mp h
  · rintro (ne | same)
    · exact X.keep ok h ne
    · by_cases eq : n = c.actor
      · subst eq
        have := c.now_pre h
        subst this
        rw [same]
        exact c.post_now
      · exact X.keep ok h eq

end Frame

/-! ## Guards used by the compiler -/

theorem guard_subst {α : Sort u} {p : α → Prop} (e : α) (bounded : ∀ x, p x → x = e) :
    (∃ x, p x) ↔ p e :=
  ⟨fun ⟨x, h⟩ => bounded x h ▸ h, fun h => ⟨e, h⟩⟩

theorem guard_forall_subst {α : Sort u} {p : α → Prop} (e : α) (bounded : ∀ x, ¬ x = e → p x) :
    (∀ x, p x) ↔ p e := by
  refine ⟨fun h => h e, fun h x => ?_⟩
  by_cases eq : x = e
  · exact eq ▸ h
  · exact bounded x eq

theorem guard_forall {α : Type u} (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (bounded : ∀ x, ¬ x ∈ xs → p x)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.attach.all fun x => test x.1 x.2) = true ↔ ∀ x, p x := by
  rw [List.all_eq_true]
  constructor
  · intro h x
    by_cases mem : x ∈ xs
    · exact (pointwise x mem).mp (h ⟨x, mem⟩ (List.mem_attach ..))
    · exact bounded x mem
  · intro h ⟨x, mem⟩ _
    exact (pointwise x mem).mpr (h x)

theorem guard_any_unique {α : Type u} [BEq α] [LawfulBEq α] (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (bounded : ∀ x, p x → x ∈ xs)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.eraseDups.attach.any fun x => test x.1 (List.mem_eraseDups.mp x.2)) = true ↔ ∃ x, p x :=
  guard_any xs.eraseDups p (fun x h => test x (List.mem_eraseDups.mp h))
    (fun x h => List.mem_eraseDups.mpr (bounded x h)) (fun x h => pointwise x (List.mem_eraseDups.mp h))

theorem guard_forall_unique {α : Type u} [BEq α] [LawfulBEq α] (xs : List α) (p : α → Prop)
    (test : (x : α) → x ∈ xs → Bool)
    (bounded : ∀ x, ¬ x ∈ xs → p x)
    (pointwise : ∀ x h, test x h = true ↔ p x) :
    (xs.eraseDups.attach.all fun x => test x.1 (List.mem_eraseDups.mp x.2)) = true ↔ ∀ x, p x :=
  guard_forall xs.eraseDups p (fun x h => test x (List.mem_eraseDups.mp h))
    (fun x h => bounded x (fun mem => h (List.mem_eraseDups.mpr mem)))
    (fun x h => pointwise x (List.mem_eraseDups.mp h))

theorem keyed_snd {α β : Type} {L : List (α × β)} {a : α} {q : α × β} (h : q ∈ L) (e : q.1 = a) :
    (a, q.2) ∈ L := by
  obtain ⟨x, y⟩ := q
  cases e
  exact h

theorem keyed_fst {α β : Type} {L : List (α × β)} {b : β} {q : α × β} (h : q ∈ L) (e : q.2 = b) :
    (q.1, b) ∈ L := by
  obtain ⟨x, y⟩ := q
  cases e
  exact h

theorem guard_keyed_snd {α β : Type} [DecidableEq α] (L : List (α × β)) (a : α) (p : β → Prop)
    (test : (q : α × β) → (a, q.2) ∈ L → Bool)
    (bounded : ∀ b, p b → (a, b) ∈ L)
    (pointwise : ∀ q h, test q h = true ↔ p q.2) :
    (L.attach.any fun q => if e : q.1.1 = a then test q.1 (keyed_snd q.2 e) else false) = true ↔
      ∃ b, p b := by
  constructor
  · intro yes
    obtain ⟨⟨q, mem⟩, _, pass⟩ := List.any_eq_true.mp yes
    split at pass
    · exact ⟨_, (pointwise _ _).mp pass⟩
    · exact absurd pass Bool.false_ne_true
  · rintro ⟨b, hb⟩
    refine List.any_eq_true.mpr ⟨⟨(a, b), bounded b hb⟩, List.mem_attach .., ?_⟩
    split
    · exact (pointwise (a, b) _).mpr hb
    · next e => exact absurd rfl e

theorem guard_keyed_fst {α β : Type} [DecidableEq β] (L : List (α × β)) (b : β) (p : α → Prop)
    (test : (q : α × β) → (q.1, b) ∈ L → Bool)
    (bounded : ∀ a, p a → (a, b) ∈ L)
    (pointwise : ∀ q h, test q h = true ↔ p q.1) :
    (L.attach.any fun q => if e : q.1.2 = b then test q.1 (keyed_fst q.2 e) else false) = true ↔
      ∃ a, p a := by
  constructor
  · intro yes
    obtain ⟨⟨q, mem⟩, _, pass⟩ := List.any_eq_true.mp yes
    split at pass
    · exact ⟨_, (pointwise _ _).mp pass⟩
    · exact absurd pass Bool.false_ne_true
  · rintro ⟨a, ha⟩
    refine List.any_eq_true.mpr ⟨⟨(a, b), bounded a ha⟩, List.mem_attach .., ?_⟩
    split
    · exact (pointwise (a, b) _).mpr ha
    · next e => exact absurd rfl e

theorem guard_forall_keyed_snd {α β : Type} [DecidableEq α] (L : List (α × β)) (a : α)
    (p : β → Prop)
    (test : (q : α × β) → (a, q.2) ∈ L → Bool)
    (bounded : ∀ b, ¬ (a, b) ∈ L → p b)
    (pointwise : ∀ q h, test q h = true ↔ p q.2) :
    (L.attach.all fun q => if e : q.1.1 = a then test q.1 (keyed_snd q.2 e) else true) = true ↔
      ∀ b, p b := by
  rw [List.all_eq_true]
  constructor
  · intro h b
    by_cases mem : (a, b) ∈ L
    · have := h ⟨(a, b), mem⟩ (List.mem_attach ..)
      simp only [dite_true] at this
      exact (pointwise (a, b) _).mp this
    · exact bounded b mem
  · intro h ⟨q, mem⟩ _
    split
    · exact (pointwise _ _).mpr (h _)
    · rfl

theorem guard_forall_keyed_fst {α β : Type} [DecidableEq β] (L : List (α × β)) (b : β)
    (p : α → Prop)
    (test : (q : α × β) → (q.1, b) ∈ L → Bool)
    (bounded : ∀ a, ¬ (a, b) ∈ L → p a)
    (pointwise : ∀ q h, test q h = true ↔ p q.1) :
    (L.attach.all fun q => if e : q.1.2 = b then test q.1 (keyed_fst q.2 e) else true) = true ↔
      ∀ a, p a := by
  rw [List.all_eq_true]
  constructor
  · intro h a
    by_cases mem : (a, b) ∈ L
    · have := h ⟨(a, b), mem⟩ (List.mem_attach ..)
      simp only [dite_true] at this
      exact (pointwise (a, b) _).mp this
    · exact bounded a mem
  · intro h ⟨q, mem⟩ _
    split
    · exact (pointwise _ _).mpr (h _)
    · rfl

theorem bool_mem (b : Bool) : b ∈ [false, true] := by cases b <;> simp

theorem role_mem (r : Role) : r ∈ [Role.none, .follower, .preVoteCandidate, .candidate, .primary] := by
  cases r <;> simp

theorem option_some_mem {α : Type u} {a : α} {o : Option α} (h : a ∈ o.toList) : o = some a :=
  Option.mem_toList.mp h

theorem option_some_mem' {α : Type u} {a : α} {o : Option α} (h : a ∈ o.toList) : some a = o :=
  (Option.mem_toList.mp h).symm

theorem exists_mem_iff {α : Type u} (l : List α) : (∃ x, x ∈ l) ↔ l ≠ [] :=
  ⟨fun ⟨_, h⟩ => List.ne_nil_of_mem h, List.exists_mem_of_ne_nil _⟩

/-- The queue left by the step: the delivered envelope removed, if any. -/
def pendingOf (x : XView) : List Model.Envelope :=
  match x.event with
  | .internal _ => x.base.before.network
  | .receive src msg => removeOne ⟨src, x.base.actor, msg⟩ x.base.before.network

theorem X.pending_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) : c.tr.pending = pendingOf x := by
  rw [ActionContext.pending_eq, pendingOf, X.tr_event_eq ok, X.tr_actor_eq ok,
    ← View.before_eq ok.1]
  generalize x.event = e
  cases e <;> rfl

theorem mem_flatMap_of {α β : Type} {l : List α} {f : α → List β} {a : α} {b : β}
    (ha : a ∈ l) (hb : b ∈ f a) : b ∈ l.flatMap f := List.mem_flatMap.mpr ⟨a, ha, hb⟩

theorem commitFacts_iff [Config.InitialConfiguration] {g : LogFacts.Ghost} {l : List Entry} {t base i : Nat} :
    CommitFacts g l t base i ↔
      g.canon t l ∧ Rooted Config.GENESIS l ∧ l.Pairwise (fun x y => x.term ≤ y.term) ∧ 2 ≤ t ∧
      base ≤ i ∧ i ≤ l.length ∧ isSignatureAt l i = true ∧ termAt l i = t ∧
      ∃ xs, hasQuorum ((activeConfigurations l base).filter (·.index ≤ i)) xs ∧
        ∀ x ∈ xs, ∃ p, g.seen x t p ∧ l.take i <+: p :=
  ⟨fun ⟨a, b, c, d, e, f, g, h, i⟩ => ⟨a, b, c, d, e, f, g, h, i⟩,
   fun ⟨a, b, c, d, e, f, g, h, i⟩ => ⟨a, b, c, d, e, f, g, h, i⟩⟩

theorem appendEvidence_iff [Config.InitialConfiguration] {h : Frame} {source target : NodeID}
    {r : AppendEntriesRequest} {log : List Entry} :
    AppendEvidence h source target r log ↔
      target ≠ source ∧ Led h source r.term ∧ Canon h r.term log ∧ r.prevLogIndex ≤ log.length ∧
      r.prevLogTerm = termAt log r.prevLogIndex ∧ r.entries <+: log.drop r.prevLogIndex ∧
      Backed h log r.primaryCommit r.term :=
  ⟨fun ⟨a, b, c, d, e, f, g⟩ => ⟨a, b, c, d, e, f, g⟩,
   fun ⟨a, b, c, d, e, f, g⟩ => ⟨a, b, c, d, e, f, g⟩⟩

theorem copyLog_iff [Config.InitialConfiguration] {g : LogFacts.Ghost} {term : Nat} {log : List Entry} :
    CopyLog g term log ↔
      Rooted Config.GENESIS log ∧ (∀ e ∈ log, e.term ≤ term) ∧ log.Pairwise (fun x y => x.term ≤ y.term) ∧
      ∀ i, 0 < i → i ≤ log.length → ∃ l, g.canon (termAt log i) l ∧ i ≤ l.length ∧
        log.take i = l.take i :=
  ⟨fun ⟨a, b, c, d⟩ => ⟨a, b, c, d⟩, fun ⟨a, b, c, d⟩ => ⟨a, b, c, d⟩⟩

end ConsensusCoverage.ReadersAtoms
