module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCF.Function
public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.Historical
import all ConsensusCoverage.CommitMonitor
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ReadersShapes

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage.ReadersAtoms ConsensusCoverage.GuardedDomain

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

theorem cons_prefix_bound {α : Type} {head : α} {tail rest : List α}
    (h : head :: tail <+: rest) : tail ∈ prefixes (rest.drop 1) := by
  obtain ⟨more, eq⟩ := h
  rw [← eq]
  exact guard_prefix ⟨more, rfl⟩

theorem common_extension_iff {α : Type u} (p q : List α) :
    (∃ r, p <+: r ∧ q <+: r) ↔ p <+: q ∨ q <+: p := by
  constructor
  · rintro ⟨_, hp, hq⟩
    exact List.prefix_or_prefix_of_prefix hp hq
  · rintro (pq | qp)
    · exact ⟨q, pq, by simp⟩
    · exact ⟨p, by simp, qp⟩

theorem backed_prefix_agreement {α : Type u} (xs : List α) (keys : List (Nat × List α))
    (bound : Nat) :
    (∀ (ys : List α) (i : Nat), i ≤ xs.length →
      (i = 0 ∨ ∃ t p, (t, p) ∈ keys ∧ t < bound ∧ xs.take i <+: p) →
      (∀ t p, (t, p) ∈ keys → t < bound → p <+: ys) →
      xs.take i = ys.take i) ↔ True := by
  refine ⟨fun _ => trivial, ?_⟩
  rintro _ ys i le (rfl | ⟨t, p, mem, term, sub⟩) all
  · simp
  · have agree := List.prefix_iff_eq_take.mp (sub.trans (all t p mem term))
    simpa [List.length_take, Nat.min_eq_left le] using agree

theorem append_right_value {α : Type u} {pref tail whole : List α}
    (h : whole = pref ++ tail) : tail = whole.drop pref.length := by
  rw [h]
  simp

theorem append_left_value {α : Type u} {pref tail whole : List α}
    (h : whole = pref ++ tail) : pref = whole.take (whole.length - tail.length) := by
  rw [h]
  simp

theorem exist_or {α : Sort u} {P Q : α → Prop} :
    (∃ x, P x ∨ Q x) ↔ (∃ x, P x) ∨ (∃ x, Q x) :=
  ⟨fun ⟨x, h⟩ => h.elim (fun p => .inl ⟨x, p⟩) (fun q => .inr ⟨x, q⟩),
    fun h => h.elim (fun ⟨x, p⟩ => ⟨x, .inl p⟩) (fun ⟨x, q⟩ => ⟨x, .inr q⟩)⟩

theorem exists_false_iff {α : Sort u} : (∃ _ : α, False) ↔ False :=
  ⟨fun ⟨_, no⟩ => no, False.elim⟩

theorem exists_vacuous {α : Sort u} (witness : α) (p : Prop) :
    (∃ _ : α, p) ↔ p :=
  ⟨fun ⟨_, h⟩ => h, fun h => ⟨witness, h⟩⟩

theorem sat_take_sub {α : Type} (l : List α) (k : Nat) {x w B : Nat}
    (bound : k + l.length ≤ B) (hw : w = min x B) :
    l.take (x - k) = l.take (w - k) := by
  subst w
  by_cases h : x ≤ B
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right (by omega)]
    have hx : l.length ≤ x - k := by omega
    have hy : l.length ≤ B - k := by omega
    rw [List.take_of_length_le hx, List.take_of_length_le hy]

theorem sat_drop_sub {α : Type} (l : List α) (k : Nat) {x w B : Nat}
    (bound : k + l.length ≤ B) (hw : w = min x B) :
    l.drop (x - k) = l.drop (w - k) := by
  subst w
  by_cases h : x ≤ B
  · rw [Nat.min_eq_left h]
  · rw [Nat.min_eq_right (by omega)]
    have hx : l.length ≤ x - k := by omega
    have hy : l.length ≤ B - k := by omega
    rw [List.drop_eq_nil_of_le hx, List.drop_eq_nil_of_le hy]

public def nodeFieldsEq (a b : NodeState) : Bool :=
  a.role == b.role && a.currentTerm == b.currentTerm && a.log == b.log &&
    a.commitIndex == b.commitIndex && a.isNewFollower == b.isNewFollower &&
    a.votedFor == b.votedFor && a.primaryKnown == b.primaryKnown &&
    decide (a.votesGranted = b.votesGranted) && decide (a.preVotesGranted = b.preVotesGranted) &&
    a.retiredCommittedIndex == b.retiredCommittedIndex

theorem node_eq_iff (a b : NodeState) :
    a = b ↔ nodeFieldsEq a b = true ∧
      a.sentIndex = b.sentIndex ∧ a.matchIndex = b.matchIndex :=
  ⟨fun h => by subst b; exact ⟨by simp [nodeFieldsEq], rfl, rfl⟩,
    fun ⟨fields, sent, matched⟩ => LeaderEffect.eq_of_fields fields sent matched⟩

theorem view_same [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) :
    x.base.pre = x.base.post ↔ x.base.changed = false := by
  rw [← X.tr_pre_eq ok, ← X.tr_post_eq ok]
  exact X.unchanged_iff ok

theorem view_same' [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) :
    x.base.post = x.base.pre ↔ x.base.changed = false :=
  Eq.comm.trans (view_same ok)

theorem wins_of_origin {self : NodeID} {before after : NodeState} {event : Event}
    (origin : (before.role = .primary ∧ after.currentTerm = before.currentTerm) ∨
      Wins self before event after) :
    Wins self before event after ↔
      ¬(before.role = .primary ∧ after.currentTerm = before.currentTerm) := by
  constructor
  · rintro ⟨w, ⟨_, _, _, fresh | existing⟩, _, advance⟩ ⟨preRole, sameTerm⟩
    · have term := advance.term
      change after.currentTerm = w.currentTerm at term
      have next := fresh.2.1
      omega
    · cases preRole.symm.trans existing.1
  · intro no
    exact origin.resolve_left no

theorem campaign_no_advance [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {c : Ctx f t} {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate) :
    highestCommittableIndex (primaryState candidate) c.actor ≤ (primaryState candidate).commitIndex := by
  apply Nat.le_of_not_gt
  intro ahead
  obtain ⟨_, sig, term, _⟩ := highestCommittableIndex_spec _ _ ahead
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue sig
  have mem := (primaryState_log_prefix candidate).subset (Ledger.entryAt_mem found)
  obtain ⟨_, log, _, history⟩ := campaign
  rw [log] at mem
  unfold termAt at term
  rw [found] at term
  change entry.term = candidate.currentTerm at term
  rcases history with fresh | existing
  · have le := c.inv.terms c.actor c.pre c.pre_now entry mem
    have eq := fresh.2.1
    omega
  · have lt := (c.inv.candidate c.actor c.pre c.pre_now existing.1).2.2.2.2 entry mem
    have eq := existing.2.1
    omega

theorem wins_recorded [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    Wins c.actor c.pre c.event c.post ↔
      c.post.role = .primary ∧ ¬(c.pre.role = .primary ∧ c.post.currentTerm = c.pre.currentTerm) := by
  constructor
  · intro wins
    have primary : c.post.role = .primary := by
      obtain ⟨_, campaign, _, eq | adv⟩ := wins
      · rw [eq]
        rfl
      · have bound := campaign_no_advance campaign
        obtain ⟨_, _, _, _, _, _, grows, highest, _⟩ := adv
        rw [highest] at grows
        exact (Nat.not_lt_of_le bound grows).elim
    exact ⟨primary, (wins_of_origin (@Summary.leader _ _ _ _ _ c.sum primary)).mp wins⟩
  · rintro ⟨primary, fresh⟩
    exact (wins_of_origin (@Summary.leader _ _ _ _ _ c.sum primary)).mpr fresh

theorem wins_view [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) :
    Wins x.base.actor x.base.pre x.event x.base.post ↔
      x.base.post.role = .primary ∧
        ¬(x.base.pre.role = .primary ∧ x.base.post.currentTerm = x.base.pre.currentTerm) := by
  rw [← X.tr_actor_eq ok, ← X.tr_pre_eq ok, ← X.tr_event_eq ok, ← X.tr_post_eq ok]
  exact wins_recorded c

theorem update_eq_iff {α β : Type} [DecidableEq α] (f : α → β) (key : α) (v : β) :
    (fun x => if x = key then v else f x) = f ↔ v = f key := by
  constructor
  · intro h
    simpa using congrFun h key
  · intro h
    funext x
    by_cases eq : x = key
    · subst x; simpa
    · simp [eq]

theorem update_eq_self {α β : Type} [DecidableEq α] (f : α → β) (key : α) (v : β) :
    Function.update f key v = f ↔ v = f key := by
  constructor
  · intro h
    simpa using congrFun h key
  · intro h
    funext x
    by_cases eq : x = key
    · subst x; simpa using h
    · simp [Function.update_of_ne eq]

theorem eq_update_self {α β : Type} [DecidableEq α] (f : α → β) (key : α) (v : β) :
    f = Function.update f key v ↔ v = f key :=
  Eq.comm.trans (update_eq_self f key v)

def inputs : Event → List Input
  | .internal input => [input]
  | .receive _ _ => []

theorem guard_input {event : Event} {input : Input} (h : event = .internal input) :
    input ∈ inputs event := by
  subst event
  simp [inputs]

theorem input_mem {event : Event} {input : Input} (h : input ∈ inputs event) :
    event = .internal input := by
  cases event <;> simp_all [inputs]

theorem and_under_cert {p q : Prop} {a b : Bool}
    (ha : a = true ↔ p) (hb : p → (b = true ↔ q)) :
    (a && b) = true ↔ p ∧ q := by
  rw [Bool.and_eq_true, ha]
  exact ⟨fun ⟨hp, yes⟩ => ⟨hp, (hb hp).mp yes⟩,
    fun ⟨hp, hq⟩ => ⟨hp, (hb hp).mpr hq⟩⟩

theorem proof_cert {p : Prop} (h : p) : true = true ↔ p :=
  ⟨fun _ => h, fun _ => rfl⟩

theorem envelope_value {e : Model.Envelope} {s t : NodeID} {msg : Model.Node.Message}
    (src : e.source = s) (dst : e.target = t) (payload : e.payload = msg) :
    e = ⟨s, t, msg⟩ := by
  cases e
  cases src
  cases dst
  cases payload
  rfl

theorem message_before [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) {env : Model.Envelope}
    (mem : env ∈ x.base.before.network) : MessageOK f env :=
  c.inv.messages env ((X.pending_before ok env).mpr mem)

theorem message_after [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) {env : Model.Envelope}
    (mem : env ∈ x.base.after.network) : MessageOK (f.advance t) env :=
  c.inv_step.messages env ((X.pending_after ok env).mpr mem)

theorem grant_voter_bound {hist : List Model.State} {v c k : Nat} {r : RequestVoteRequest}
    (yes : grantedIn hist v c k r = true) : v ∈ (histNodes hist).map Prod.fst := by
  obtain ⟨after, before, _, suffix, ⟨_, post, _, mem, _, _, _⟩, _⟩ :=
    (grantedIn_iff hist v c k r).mp yes
  have member : after ∈ hist := suffix.subset List.mem_cons_self
  exact List.mem_map.mpr ⟨(v, post), mem_histNodes member mem, rfl⟩

theorem grant_term_bound {hist : List Model.State} {v c k : Nat} {r : RequestVoteRequest}
    (yes : grantedIn hist v c k r = true) :
    k ∈ (histNodes hist).map (fun p => p.2.currentTerm) := by
  obtain ⟨after, before, _, suffix, ⟨_, post, _, mem, _, term, _⟩, _⟩ :=
    (grantedIn_iff hist v c k r).mp yes
  have member : after ∈ hist := suffix.subset List.mem_cons_self
  exact List.mem_map.mpr ⟨(v, post), mem_histNodes member mem, term⟩

theorem grant_candidate_bound {hist : List Model.State} {v c k : Nat} {r : RequestVoteRequest}
    (yes : grantedIn hist v c k r = true) :
    c ∈ (histNodes hist).flatMap (fun p => p.2.votedFor.toList) := by
  obtain ⟨after, before, _, suffix, ⟨_, post, _, mem, _, _, vote, _⟩, _⟩ :=
    (grantedIn_iff hist v c k r).mp yes
  have member : after ∈ hist := suffix.subset List.mem_cons_self
  exact mem_flatMap_of (mem_histNodes member mem) (guard_some_left vote)

private theorem quorum_mono {cs : List Node.Configuration} {a b : Finset NodeID}
    (sub : a ⊆ b) (h : hasQuorum cs a) : hasQuorum cs b := by
  refine ⟨h.1, List.all_eq_true.mpr fun c mem => decide_eq_true ?_⟩
  have ab : a ∩ c.nodes ⊆ b ∩ c.nodes := fun _ hv =>
    Finset.mem_inter.mpr ⟨sub (Finset.mem_inter.mp hv).1, (Finset.mem_inter.mp hv).2⟩
  have le := Finset.card_le_card ab
  have gt := of_decide_eq_true (List.all_eq_true.mp h.2 c mem)
  unfold hasConfigurationMajority at gt ⊢
  omega

theorem quorum_required (cs : List Node.Configuration) (required : List NodeID) {P : NodeID → Prop}
    (test : NodeID → Bool) (correct : ∀ v, test v = true ↔ P v) :
    (CommitMonitor.quorum cs test && required.all test) = true ↔
      ∃ vs : Finset NodeID, (hasQuorum cs vs ∧ ∀ v ∈ vs, P v) ∧ ∀ r ∈ required, r ∈ vs := by
  rw [Bool.and_eq_true, quorum_cert cs test correct, List.all_eq_true]
  simp only [correct]
  constructor
  · rintro ⟨⟨vs, votes, good⟩, h⟩
    let extra := Finset.ofList required
    refine ⟨vs ∪ extra, ⟨quorum_mono (fun v mem => Finset.mem_union.mpr (Or.inl mem)) votes, ?_⟩, ?_⟩
    · intro v mem
      exact (Finset.mem_union.mp mem).elim (good v) (fun r => h v (Finset.mem_ofList.mp r))
    · exact fun _ mem => Finset.mem_union.mpr (Or.inr (Finset.mem_ofList.mpr mem))
  · rintro ⟨vs, facts, hits⟩
    exact ⟨⟨vs, facts⟩, fun r mem => facts.2 r (hits r mem)⟩

theorem quorum_all_required (cs : List Node.Configuration) (required : List NodeID) {P : NodeID → Prop}
    (test : NodeID → Bool) (correct : ∀ v, test v = true ↔ P v) :
    ((cs.isEmpty || CommitMonitor.quorum cs test) && required.all test) = true ↔
      ∃ vs : Finset NodeID,
        ((cs.all fun c => decide (hasConfigurationMajority vs c)) = true ∧ ∀ v ∈ vs, P v) ∧
          ∀ r ∈ required, r ∈ vs := by
  by_cases empty : cs = []
  · subst cs
    simp only [List.isEmpty_nil, Bool.true_or, Bool.true_and, List.all_nil, true_and, List.all_eq_true, correct]
    refine ⟨fun yes => ⟨Finset.ofList required, ?_, ?_⟩, ?_⟩
    · exact fun v mem => yes v (Finset.mem_ofList.mp mem)
    · exact fun _ mem => Finset.mem_ofList.mpr mem
    · rintro ⟨vs, pass, contains⟩ v mem
      exact pass v (contains v mem)
  · have ne : cs.isEmpty = false := by simpa using empty
    rw [ne, Bool.false_or, quorum_required cs required test correct]
    simp only [hasQuorum, ne_eq, empty, not_false_eq_true, true_and]

theorem quorum_hits (cs : List Node.Configuration) {P : NodeID → Prop}
    (test : NodeID → Bool) (correct : ∀ v, test v = true ↔ P v) :
    (!CommitMonitor.quorum cs (fun v => !test v)) = true ↔
      ∀ xs, hasQuorum cs xs → ∃ v, v ∈ xs ∧ P v := by
  classical
  have excluded : CommitMonitor.quorum cs (fun v => !test v) = true ↔
      ∃ xs, hasQuorum cs xs ∧ ∀ v ∈ xs, ¬ P v := by
    rw [CommitMonitor.quorum_iff]
    have bit (v) : (!test v) = true ↔ ¬ P v := by
      rw [← correct v]
      cases test v <;> decide
    simp only [bit]
  constructor
  · intro hn xs q
    apply Classical.byContradiction
    intro none
    have yes := excluded.mpr ⟨xs, q, fun v mem p => none ⟨v, mem, p⟩⟩
    rw [yes] at hn
    contradiction
  · intro h
    cases eq : CommitMonitor.quorum cs (fun v => !test v)
    · rfl
    · obtain ⟨xs, q, none⟩ := excluded.mp eq
      obtain ⟨v, hv, p⟩ := h xs q
      exact (none v hv p).elim

end ConsensusCoverage.ReadersShapes
