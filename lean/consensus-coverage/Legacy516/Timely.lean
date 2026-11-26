module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

/-!
# Is the commit evidence ahead of the protocol?

A certificate whose base does not exceed the certifying node's own commit
index is already a committed key of the proof ghost on initialized runs. `check` tests
this on one replayed snapshot and its strict history (newest first).
-/

namespace ConsensusCoverage.Timely

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Ledger

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

@[expose] public def check (bootstrap : NodeID) (s : Model.State) (history : List Model.State) : Bool :=
  (CommitKeys.here bootstrap s history fun st base => decide (base ≤ st.commitIndex)).all
    (CommitKeys.keys bootstrap (s :: history)).contains

/-- Certificates based at or below their node's protocol commit index are committed. -/
public def Holds [Config.InitialConfiguration] (f : FullProfile.ProofFrame) : Prop :=
  ∀ n st k b i, CommitStep f n st k b i → b ≤ st.commitIndex →
    Committed f k (st.log.take i)

/-- The executable test specifies this predicate even on non-initialized histories. -/
private theorem check_iff (cfg : FullProfile.Configuration) (s : Model.State) (history : List Model.State) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    check (cfg.min?.getD 0) s history = true ↔ Holds (StateCoverage.frame s history) := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  let f := StateCoverage.frame s history
  have current : f.current = s := StateCoverage.frame_current s history
  have logs : f.logs = Historical.logFacts (s :: history) := StateCoverage.frame_logs s history
  have step_iff (n st k b i) :
      CommitStep f n st k b i ↔ Historical.CommitStep (s :: history) n st k b i := by
    unfold CommitStep
    rw [current, logs]
    apply Historical.commitAt_iff _ (Historical.logFacts_correct (s :: history)).seen
    intro n st k
    simp only [LogFacts.Ghost.canonNow, LogFacts.Ghost.led, Historical.CanonNow, Historical.Led,
      Historical.Now, (Historical.logFacts_correct (s :: history)).elected]
  change check Config.INITIAL_PRIMARY s history = true ↔ _
  simp only [check, List.all_eq_true, List.contains_iff_mem, Prod.forall, CommitKeys.mem_here,
    decide_eq_true_eq, CommitKeys.mem_iff]
  change (∀ k p, (∃ n st b i, Historical.CommitStep (s :: history) n st k b i ∧
      p = st.log.take i ∧ b ≤ st.commitIndex) → (Historical.logFacts (s :: history)).committed k p) ↔ Holds f
  rw [← logs]
  constructor
  · intro test n st k b i cert le
    exact test k _ ⟨n, st, b, i, (step_iff ..).mp cert, rfl, le⟩
  · rintro invariant k p ⟨n, st, b, i, cert, rfl, le⟩
    exact invariant n st k b i ((step_iff ..).mpr cert) le

private abbrev bounded (l : List Entry) (b i : Nat) :=
  (activeConfigurations l b).filter (·.index ≤ i)

private theorem bounded_append (pre extra : List Entry) {b i : Nat} (le : b ≤ i) (hi : i ≤ pre.length) :
    bounded (pre ++ extra) b i = bounded pre b i := by
  obtain ⟨rest, eq, later⟩ := configurationHistory_split (pre ++ extra) pre.length
  rw [List.take_append_of_le_length (Nat.le_refl _), List.take_length] at eq
  have len : ((configurationHistory (pre ++ extra)).filter (·.index ≤ b)).length =
      ((configurationHistory pre).filter (·.index ≤ b)).length := by
    rw [eq, filter_index_append (Nat.le_trans le hi) later]
  have drop : ((configurationHistory pre).filter (·.index ≤ b)).length - 1 ≤
      (configurationHistory pre).length := by
    have := List.length_filter_le (fun cfg : Node.Configuration => decide (cfg.index ≤ b))
      (configurationHistory pre)
    omega
  unfold bounded activeConfigurations
  dsimp only
  rw [len, eq, List.drop_append_of_le_length drop, filter_index_append hi later]

private theorem majority_mono {cfg : Node.Configuration} {xs ys : Finset NodeID}
    (sub : xs ⊆ ys) (majority : hasConfigurationMajority xs cfg) :
    hasConfigurationMajority ys cfg := by
  have incl : xs ∩ cfg.nodes ⊆ ys ∩ cfg.nodes := by
    intro v hv
    obtain ⟨a, b⟩ := Finset.mem_inter.mp hv
    exact Finset.mem_inter.mpr ⟨sub a, b⟩
  have := Finset.card_le_card incl
  unfold hasConfigurationMajority at *
  omega

private theorem earlier_or_later {l : List Entry} {old base index commit : Nat}
    (le : base ≤ commit) {cfg : Node.Configuration} (mem : cfg ∈ bounded l old index) :
    cfg ∈ bounded l old commit ∨ cfg ∈ bounded l base index := by
  obtain ⟨active, cut⟩ := List.mem_filter.mp mem
  by_cases earlier : cfg.index ≤ commit
  · exact .inl (List.mem_filter.mpr ⟨active, decide_eq_true earlier⟩)
  · apply Or.inr
    refine List.mem_filter.mpr ⟨?_, cut⟩
    have lmem := (activeConfigurations_sublist l old).subset active
    obtain ⟨j, hj, eq⟩ := List.mem_iff_getElem.mp lmem
    let d := ((configurationHistory l).filter (·.index ≤ base)).length - 1
    have low : d ≤ j := by
      by_cases yes : d ≤ j
      · exact yes
      have h : j < ((configurationHistory l).filter (·.index ≤ base)).length := by
        dsimp [d] at yes
        omega
      have within := getElem_le_of_lt_length_filter (configurationHistory_sorted l) h
      rw [eq] at within
      omega
    change cfg ∈ (configurationHistory l).drop d
    apply List.mem_iff_getElem.mpr
    refine ⟨j - d, by rw [List.length_drop]; omega, ?_⟩
    rw [List.getElem_drop]
    have idx : d + (j - d) = j := by omega
    simpa only [idx] using eq

private theorem bounded_subset {l : List Entry} {old base index : Nat} (le : old ≤ base) :
    bounded l base index ⊆ bounded l old index := by
  have size (hist : List Node.Configuration) :
      (hist.filter (·.index ≤ old)).length ≤ (hist.filter (·.index ≤ base)).length := by
    induction hist with
    | nil => simp
    | cons hd tl ih =>
      by_cases a : hd.index ≤ old
      · simp [a, Nat.le_trans a le, ih]
      · by_cases b : hd.index ≤ base <;> simp [a, b] <;> omega
  let d (b : Nat) := ((configurationHistory l).filter (·.index ≤ b)).length - 1
  have dd : d old + (d base - d old) = d base := by
    have := size (configurationHistory l)
    dsimp [d]
    omega
  have sub : (activeConfigurations l base).Sublist (activeConfigurations l old) := by
    change ((configurationHistory l).drop (d base)).Sublist ((configurationHistory l).drop (d old))
    rw [← dd, ← List.drop_drop]
    exact List.drop_sublist _ _
  exact (sub.filter _).subset

section Fold

variable [Config.InitialConfiguration] {f : Frame} {after : Model.State}

private theorem commit_of_backed {n st k b i} (cert : CommitStep (f.advance after) n st k b i)
    (old : Backed f st.log b k) : Committed (f.advance after) k (st.log.take i) :=
  .inr ⟨n, st, b, i, cert, rfl, old⟩

/-- In the leader advance, the newly committed frontier either already had a
certificate on the pre-log, or was beyond that log and used only the actor.
In the latter case the actor can still vote at the target index, so the two
quorums can be joined at the old base. -/
private theorem leader_advance (c : Ctx f after) (ih : Holds f)
    (preLeader : c.pre.role = .primary) (sameTerm : c.post.currentTerm = c.pre.currentTerm)
    (prefixLog : c.pre.log <+: c.post.log)
    {k b i : Nat} (cert : CommitStep (f.advance after) c.actor c.post k b i)
    (le : b ≤ c.post.commitIndex)
    (advance : c.pre.commitIndex < c.post.commitIndex →
      isSignatureAt c.post.log c.post.commitIndex = true ∧
      termAt c.post.log c.post.commitIndex = c.post.currentTerm ∧
      ∃ vs, hasQuorum (bounded c.post.log c.pre.commitIndex c.post.commitIndex) vs ∧
        ∀ v ∈ vs, v ≠ c.actor → c.post.commitIndex ≤ c.pre.log.length ∧
          ∃ l, f.logs.seen v c.post.currentTerm l ∧ c.post.log.take c.post.commitIndex <+: l) :
    Committed (f.advance after) k (c.post.log.take i) := by
  have preNot : c.pre.role ≠ .candidate := by simp [preLeader]
  have preLed := c.pre_led preLeader
  have termEq := cert.1.2.1
  have agree (j : Nat) (bound : j ≤ c.pre.log.length) :
      c.post.log.take j = c.pre.log.take j := take_eq_of_prefix prefixLog bound
  have old : Backed f c.post.log c.pre.commitIndex k := by
    rw [← termEq, sameTerm]
    exact ((c.inv.commit_backed _ _ c.pre_now).2 preNot preLed).transfer (agree _ c.frontier_pre)
  by_cases small : b ≤ c.pre.commitIndex
  · exact commit_of_backed cert (old.shorten small)
  have grew : c.pre.commitIndex < c.post.commitIndex := by omega
  obtain ⟨sig, signed, va, qa, ack⟩ := advance grew
  by_cases within : c.post.commitIndex ≤ c.pre.log.length
  · have eq := agree _ within
    have preBounded : bounded c.post.log c.pre.commitIndex c.post.commitIndex =
        bounded c.pre.log c.pre.commitIndex c.post.commitIndex := by
      obtain ⟨extra, eqLog⟩ := prefixLog
      rw [← eqLog]
      exact bounded_append _ _ (Nat.le_of_lt grew) within
    have sig' := isSignatureAt_take_of_le (Nat.le_refl c.post.commitIndex) sig
    rw [eq] at sig'
    have preCert : CommitStep f c.actor c.pre c.pre.currentTerm
        c.pre.commitIndex c.post.commitIndex := by
      refine ⟨⟨c.pre_now, rfl, preNot, preLed⟩, Nat.le_of_lt grew, within,
        isSignatureAt_of_prefix (List.take_prefix _ _) sig', ?_, va, ?_, ?_⟩
      · rw [← termAt_of_prefix prefixLog within, signed, sameTerm]
      · change hasQuorum (bounded c.pre.log c.pre.commitIndex c.post.commitIndex) va
        rw [← preBounded]
        exact qa
      · intro v mem
        by_cases self : v = c.actor
        · subst v
          exact ⟨c.pre.log, c.inv.observed _ _ c.pre_now, List.take_prefix _ _⟩
        · obtain ⟨_, l, h, sub⟩ := ack v mem self
          exact ⟨l, sameTerm ▸ h, eq ▸ sub⟩
    have prior := ih _ _ _ _ _ preCert (Nat.le_refl _)
    apply commit_of_backed cert
    exact .inr ⟨c.pre.currentTerm, _, prior, by omega,
      (take_prefix_take c.post.log le).trans (eq ▸ List.prefix_refl _)⟩
  · obtain ⟨now, bi, len, sign, atI, vb, qb, voters⟩ := cert
    have low : c.pre.commitIndex ≤ b := by omega
    let vs := va ∪ vb
    have qaSub : va ⊆ vs := fun _ h => Finset.mem_union.mpr (.inl h)
    have qbSub : vb ⊆ vs := fun _ h => Finset.mem_union.mpr (.inr h)
    have quorum : hasQuorum (bounded c.post.log c.pre.commitIndex i) vs := by
      refine ⟨fun no => qb.1 (List.eq_nil_of_subset_nil (no ▸ bounded_subset (index := i) low)),
        List.all_eq_true.mpr (fun cfg mem => decide_eq_true ?_)⟩
      rcases earlier_or_later le mem with a | b
      · exact majority_mono qaSub (hasQuorum_majority qa a)
      · exact majority_mono qbSub (hasQuorum_majority qb b)
    have rebased : CommitStep (f.advance after) c.actor c.post k c.pre.commitIndex i := by
      refine ⟨now, Nat.le_trans low bi, len, sign, atI, vs, quorum, ?_⟩
      intro v mem
      rcases Finset.mem_union.mp mem with a | b
      · have self : v = c.actor := by
          by_cases self : v = c.actor
          · exact self
          · exact (within (ack v a self).1).elim
        subst v
        exact ⟨c.post.log, termEq ▸ c.post_seen, List.take_prefix _ _⟩
      · exact voters v b
    exact commit_of_backed rebased old

private theorem advance_quorum (c : Ctx f after) {mid : NodeState}
    (advance : Advance c.actor mid c.post) (grew : mid.commitIndex < c.post.commitIndex) :
    isSignatureAt c.post.log c.post.commitIndex = true ∧
    termAt c.post.log c.post.commitIndex = c.post.currentTerm ∧
    ∃ vs, hasQuorum (bounded c.post.log mid.commitIndex c.post.commitIndex) vs ∧
      ∀ v ∈ vs, v = c.actor ∨ c.post.commitIndex ≤ mid.matchIndex v := by
  rcases advance with same | ⟨log, term, _, _, _, _, _, eq, _⟩
  · exact (Nat.lt_irrefl _ (same ▸ grew)).elim
  have ⟨_, sig, signed, quorum⟩ := highestCommittableIndex_spec mid c.actor (eq ▸ grew)
  refine ⟨by rw [log, eq]; exact sig, by rw [log, eq, term]; exact signed,
    _, by rw [log, eq]; exact quorum, ?_⟩
  intro v mem
  rw [eq]
  exact (Finset.mem_filter.mp mem).2

private theorem acked_prefix (c : Ctx f after) (leader : c.pre.role = .primary) {v j}
    (acked : Acked f v c.pre.currentTerm j) :
    j ≤ c.pre.log.length ∧ ∃ l, f.logs.seen v c.pre.currentTerm l ∧ c.pre.log.take j <+: l := by
  obtain ⟨st, l, seen, term, canon, bound, sub⟩ := acked
  have inLog :=
    (c.inv.canon_mono c.actor c.pre c.pre_now (by simp [leader]) (c.pre_led leader)).1 l canon
  exact ⟨Nat.le_trans bound inLog.length_le, st.log, term ▸ seen,
    (take_eq_of_prefix inLog bound).symm ▸ sub⟩

private theorem append_case (c : Ctx f after) (ih : Holds f) (entries : List Entry)
    (sent : NodeID → Nat) (leader : c.pre.role = .primary)
    (adv : Advance c.actor { c.pre with log := c.pre.log ++ entries, sentIndex := sent } c.post)
    {k b i} (cert : CommitStep (f.advance after) c.actor c.post k b i) (le : b ≤ c.post.commitIndex) :
    Committed (f.advance after) k (c.post.log.take i) := by
  obtain ⟨log, term, _⟩ := Advance.facts adv
  have prefixLog : c.pre.log <+: c.post.log := by rw [log]; exact List.prefix_append _ _
  apply leader_advance c ih leader term prefixLog cert le
  intro grew
  obtain ⟨sig, signed, vs, q, voters⟩ := advance_quorum c adv grew
  refine ⟨sig, signed, vs, q, ?_⟩
  intro v mem diff
  have idx : c.post.commitIndex ≤ c.pre.matchIndex v := (voters v mem).resolve_left diff
  have ack := c.inv.match_ack c.actor c.pre v c.pre_now leader diff (by omega)
  obtain ⟨bound, l, seen, sub⟩ := acked_prefix c leader ack
  have within := Nat.le_trans idx bound
  refine ⟨within, l, term.symm ▸ seen, ?_⟩
  rw [take_eq_of_prefix prefixLog within]
  exact (take_prefix_take _ idx).trans sub

private theorem ack_case (c : Ctx f after) (ih : Holds f) {source : NodeID}
    {response : AppendEntriesResponse}
    (received : c.event = .receive source (.appendEntriesResponse response))
    (leader : c.pre.role = .primary) (success : response.success = true)
    (responseTerm : response.term = c.pre.currentTerm)
    (adv : Advance c.actor
      { c.pre with matchIndex :=
          Function.update c.pre.matchIndex source (max (c.pre.matchIndex source) response.lastLogIndex) }
      c.post)
    {k b i} (cert : CommitStep (f.advance after) c.actor c.post k b i) (le : b ≤ c.post.commitIndex) :
    Committed (f.advance after) k (c.post.log.take i) := by
  obtain ⟨log, term, _⟩ := Advance.facts adv
  apply leader_advance c ih leader term (log ▸ List.prefix_refl _) cert le
  intro grew
  obtain ⟨sig, signed, vs, q, voters⟩ := advance_quorum c adv grew
  refine ⟨sig, signed, vs, q, ?_⟩
  intro v mem diff
  have idx := (voters v mem).resolve_left diff
  dsimp only at idx
  have finish (j : Nat) (bound : c.post.commitIndex ≤ j) (ack : Acked f v c.pre.currentTerm j) :
      c.post.commitIndex ≤ c.pre.log.length ∧ ∃ l, f.logs.seen v c.post.currentTerm l ∧
        c.post.log.take c.post.commitIndex <+: l := by
    obtain ⟨len, l, seen, sub⟩ := acked_prefix c leader ack
    refine ⟨Nat.le_trans bound len, l, term.symm ▸ seen, ?_⟩
    rw [log]
    exact (take_prefix_take _ bound).trans sub
  have matchAck (bound : c.post.commitIndex ≤ c.pre.matchIndex v) :
      Acked f v c.pre.currentTerm (c.pre.matchIndex v) :=
    c.inv.match_ack c.actor c.pre v c.pre_now leader diff (by omega)
  by_cases fromSource : v = source
  · subst source
    rw [Function.update_self] at idx
    rcases Std.max_eq_or (a := c.pre.matchIndex v) (b := response.lastLogIndex) with choice | choice
    · rw [choice] at idx
      exact finish _ idx (matchAck idx)
    · rw [choice] at idx
      obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
      simp only [MessageOK, payload] at ok
      have ack := ok success
      rw [sourceEq, responseTerm] at ack
      exact finish _ idx ack
  · rw [Function.update_of_ne fromSource] at idx
    exact finish _ idx (matchAck idx)

private theorem holds_advance (c : Ctx f after) (ih : Holds f) : Holds (f.advance after) := by
  intro n st k b i cert le
  have canon := cert.1
  have term := canon.2.1
  have led := canon.2.2.2
  rcases c.now_after canon.1 with ⟨rfl, rfl⟩ | ⟨different, now⟩
  · cases Summary.kind c.sum with
    | same log commit =>
      apply commit_of_backed cert
      have small : b ≤ c.pre.commitIndex := by rwa [commit] at le
      rcases c.led_after led with old | ⟨l, j, election⟩
      · rw [← term] at old
        rcases c.inv.led_cur c.actor c.pre _ c.pre_now old with lt | ⟨same, role⟩
        · have := c.term_le
          omega
        · rw [same] at old
          have backed := ((c.inv.commit_backed _ _ c.pre_now).2 role old).shorten small
          have eq : k = c.pre.currentTerm := term.symm.trans same
          simpa only [log, eq] using backed
      · have ⟨_, logEq, commitEq, _, postTerm, _⟩ := c.electStep election
        have backed := c.elect_backed election
        rw [← logEq, ← commitEq] at backed
        rw [log]
        exact (backed.shorten small).weaken (by omega)
    | append entries sent leader _ adv => exact append_case c ih entries sent leader adv cert le
    | ack source response received leader success responseTerm adv =>
      exact ack_case c ih received leader success responseTerm adv cert le
    | accept source request received accepted =>
      exfalso
      obtain ⟨_, evidence, _⟩ := c.accept_shape received accepted
      have eq := accepted.1.trans term
      exact evidence.different
        (c.election_safety source c.actor request.term (evidence.led.mono after) (eq.symm ▸ led)).symm
    | elect wins =>
      exfalso
      obtain ⟨candidate, camp, _, log, postTerm, _⟩ := Wins.facts wins
      have sub : c.post.log <+: c.pre.log :=
        log ▸ (camp.2.1 ▸ primaryState_log_prefix candidate)
      obtain ⟨e, found, _⟩ := isSignatureAtTrue cert.2.2.2.1
      have member := sub.subset (entryAt_mem found)
      have eq : e.term = k := by
        have atI := cert.2.2.2.2.1
        simpa [termAt, found] using atI
      rcases (c.campaign_three camp).2 with lt | ⟨same, preRole⟩
      · have bound := c.inv.terms _ _ c.pre_now _ member
        omega
      · have bound := (c.inv.candidate _ _ c.pre_now preRole).2.2.2.2 _ member
        omega
    | install entries initialized positive signature fresh log commit installTerm role =>
      exfalso
      rcases c.led_after led with old | ⟨_, _, election⟩
      · have floor := c.inv.leader_floor old
        have zero : c.pre.currentTerm = 0 := fresh.2.1
        rcases c.inv.led_cur c.actor c.pre _ c.pre_now old with lt | ⟨same, _⟩ <;> omega
      · rcases (c.electStep election).2.2.2.2.2.1 with elected | elected <;> simp [role] at elected
  · apply commit_of_backed cert
    have old := c.led_other different led
    rw [← term] at old
    have backed := ((c.inv.commit_backed _ _ now).2 canon.2.2.1 old).shorten le
    simpa only [← term] using backed

end Fold

/-- Timely is an invariant of the initialized proof-frame fold. -/
public theorem folded {cfg nodes f} (run : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    Holds f := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  change Holds f
  induction run with
  | initial init =>
    intro n st k b i cert _
    have state := initial_state init cert.1.1
    have ⟨_, eq⟩ := led_single cert.1.2.2.2
    have sig := cert.2.2.2.1
    rw [state, eq] at sig
    cases i with
    | zero => simp [isSignatureAt, entryAt?] at sig
    | succ i => cases i <;> simp [initialLocal, isSignatureAt, entryAt?] at sig
  | step prior ran ih =>
    obtain ⟨tr⟩ := LocalTransition.ofStep ran
    exact holds_advance (Ctx.mk tr prior.invariant) ih

end ConsensusCoverage.Timely
