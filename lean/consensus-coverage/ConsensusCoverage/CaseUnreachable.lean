module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import ConsensusCoverage.ReachPath
meta import ConsensusCoverage.PathPremises
import all ConsensusCoverage.CampaignLookup
public import ConsensusCoverage.EvidenceSupport
public import ConsensusCoverage.EventSupport
public import ConsensusCoverage.ReducedQuestions
public import ConsensusCoverage.SolvedWitnesses
public import ConsensusCoverage.VoteRequestRoute
import all ConsensusCoverage.RetiredRoleOrigin
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

/-! Universally false proof cases. The search motivates which proofs to try;
its finite budget is not a hypothesis of these theorems. -/

namespace ConsensusCoverage.CaseUnreachable

open ActionProfile
open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

private def noSupport (b : Classes.StepBranch) : Bool :=
  (EventSupport.allowed b).isEmpty || decide ([] ∈ EvidenceSupport.supports b)

private theorem support_false (s : Step) (b : Classes.StepBranch)
    (h : noSupport b = true) : label s (.step b) = false := by
  simp only [noSupport, Bool.or_eq_true] at h
  rcases h with noEvent | noEvidence
  · apply EventSupport.label_false
    simp [List.isEmpty_iff.mp noEvent]
  · exact EvidenceSupport.label_false s b <|
      List.any_eq_true.mpr ⟨[], of_decide_eq_true noEvidence, rfl⟩

public theorem retained_false (s : Step) :
    label s (.step .mem_network_mem_append_inl) = false :=
  (ReducedQuestions.answer_eq s .retained).symm

-- The nested act/nominateSuccessor proof paths all enter through a fresh
-- actor record. A successful nomination can send, but leaves that record intact.
private theorem no_nomination_reach [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {self pre post outputs}
    (reach : (reach% SolvedWitnesses.step_act_input_nominateSuccessor[0,0])
      f t c self pre (.internal .nominateSuccessor) post outputs) :
    False := by
  obtain ⟨_, _, _, fresh, _, _, actual, _, _⟩ := reach
  have ran := c.tr.ran
  change (Node.step (Capabilities.record c.actor) c.actor c.pre c.tr.event).run {} =
    some (c.post, c.tr.outputs) at ran
  rw [← actual] at ran
  obtain ⟨_, _, same, _, _⟩ := nominate_sends c.actor c.pre {} _ _ ran
  exact fresh (same.symm ▸ c.pre_now)

private theorem solved_false (s : Step) (b : Classes.StepBranch)
    (no : ¬ @SolvedWitnesses.sig ⟨s.cfg⟩ s.frame s.after s.context b) :
    label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  exact Bool.eq_false_iff.mpr fun yes =>
    no ((SolvedWitnesses.sig_iff s.context b).mp ((label_true s _).mp yes))

public theorem commit_backed_other_false (s : Step) :
    label s (.step .commit_backed_now_after_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_commit_backed_now_after_inr s.frame s.after s.context
  rintro ⟨n, st, reach, ⟨different, _⟩, _⟩
  reach_unfold SolvedWitnesses.step_commit_backed_now_after_inr[0] at reach
  repeat' first | exact different reach.1 | obtain ⟨_, reach⟩ := reach

-- Election safety makes the old leader the actor. Its term/role invariant
-- then rules out both ways this actor could newly win in the same term.
private theorem no_repeat_election [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n m k l i} (e : ElectStep f t n k l i) (old : Led f m k) : False := by
  obtain rfl := c.new_old_unique e old
  obtain ⟨actor, _, _, campaign, _⟩ := c.electStep e
  subst n
  rcases c.inv.led_cur c.actor c.pre k c.pre_now old with lt | ⟨eq, notCandidate⟩
  · rcases campaign with newer | ⟨same, _⟩ <;> omega
  · rcases campaign with newer | ⟨_, candidate⟩
    · omega
    · exact notCandidate candidate

local macro "certificate_paths " c:term:arg h:term:arg : tactic => `(tactic|
  (rcases ($h) with h | h | h | h | h | h | h | h | h | h | h | h | h | h | h | h
   all_goals
     first
     | obtain ⟨_, _, _, _, _, _, _, reach, _⟩ := h
       exact no_repeat_election $c reach.2.2.2.2.1 reach.2.2.2.2.2.1
     | obtain ⟨_, _, _, _, _, _, reach, _⟩ := h
       exact no_repeat_election $c reach.2.2.2.2.1 reach.2.2.2.2.2.1
     | obtain ⟨_, _, _, _, _, _, _, reach, _⟩ := h
       rcases reach with r | r <;> exact no_repeat_election $c r.2.2.2.2.1 r.2.2.2.2.2.1
     | obtain ⟨_, _, _, _, _, _, reach, _⟩ := h
       rcases reach with r | r <;> exact no_repeat_election $c r.2.2.2.2.1 r.2.2.2.2.2.1))

public theorem certificates_zero_false (s : Step) :
    label s (.step .certificates_agree_backing_inl) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_certificates_agree_backing_inl s.frame s.after s.context
  intro h
  certificate_paths s.context h

public theorem certificates_committed_false (s : Step) :
    label s (.step .certificates_agree_backing_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_certificates_agree_backing_inr s.frame s.after s.context
  intro h
  certificate_paths s.context h

-- A copied or retained entry has a pre-step canonical log in its term.
-- Appending in that term instead needs a pre-step leader in the term.
private theorem no_election_entry [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n k l i j} (e : ElectStep f t n k l i)
    (pos : 0 < j) (bound : j ≤ c.post.log.length) (term : termAt c.post.log j = k) : False := by
  have noCanon {log} (old : Canon f k log) : False := by
    obtain ⟨_, led⟩ := c.inv.owner old
    exact no_repeat_election c e led
  rcases c.post_log with sub | ⟨_, _, _, primary, same, _⟩ | ⟨log, size, copy, _, eq⟩
  · obtain ⟨_, anchor, _⟩ := c.inv.anchor _ _ j c.pre_now pos (Nat.le_trans bound sub.length_le)
    rw [termAt_of_prefix sub bound, term] at anchor
    exact noCanon anchor
  · have sameTerm := (c.electStep e).2.2.2.2.1
    exact no_repeat_election c e ((same.symm.trans sameTerm) ▸ c.pre_led primary)
  · have sub : c.post.log <+: log := eq ▸ List.take_prefix _ _
    obtain ⟨_, anchor, _⟩ := copy.anchor j pos (Nat.le_trans bound sub.length_le)
    rw [termAt_of_prefix sub bound, term] at anchor
    exact noCanon anchor

private theorem no_election_commit [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n k l i st b j} (e : ElectStep f t n k l i)
    (cert : CommitStep (f.advance t) n st k b j) : False := by
  obtain rfl := (c.electStep e).1
  obtain rfl := c.now_post cert.1.1
  exact no_election_entry c e (signature_pos cert.2.2.2.1) cert.2.2.1 cert.2.2.2.2.1

public theorem new_in_elected_fresh_leader_false (s : Step) :
    label s (.step .new_in_elected_led_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_new_in_elected_led_inr s.frame s.after s.context
  rintro (h | h | h | h | h)
  all_goals repeat' first
    | exact no_election_commit s.context h.1 h.2.1
    | obtain ⟨_, h⟩ := h

public theorem rv_stable_actor_false (s : Step) :
    label s (.step .rv_stable_now_after_inl) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_rv_stable_now_after_inl s.frame s.after s.context
  rintro ⟨_, request, reach, _⟩
  obtain ⟨out, _, _, _, _, _, _, _, _, _, _, received, rest⟩ := reach
  have target : s.context.actor = out.target := by
    repeat' first | exact rest.1 | obtain ⟨_, rest⟩ := rest
  obtain ⟨packet, queued, source, dest, payload⟩ := s.context.received received
  exact VoteRequestRoute.folded s.folded queued payload (source.trans (target.symm.trans dest.symm))

public theorem led_cur_retired_false (s : Step) :
    label s (.step .led_cur_role_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  apply solved_false
  change ¬ SolvedWitnesses.step_led_cur_role_inr s.frame s.after c
  rintro ⟨_, _, _, _, _, _, election, rest⟩
  have gone : c.post.role = .none := by
    repeat' first | exact rest.1 | obtain ⟨_, rest⟩ := rest
  rcases RetiredRoleOrigin.step c gone with ⟨role, term⟩ | ⟨_, pos, bound, atJ⟩ |
      ⟨_, _, arrived, same⟩
  · rcases (c.electStep election).2.2.2.1 with fresh | ⟨_, candidate⟩
    · omega
    · simp [role] at candidate
  · exact no_election_entry c election pos bound atJ
  · obtain ⟨_, ok, _, _, payload⟩ := c.received_ok arrived
    simp only [MessageOK, payload] at ok
    obtain ⟨_, evidence⟩ := ok
    exact no_repeat_election c election (same ▸ evidence.led)

public theorem act_nomination_false (s : Step) :
    label s (.step .act_input_nominateSuccessor) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ (reach% SolvedWitnesses.step_act_input_nominateSuccessor[0])
    s.frame s.after s.context .nominateSuccessor
  rintro ⟨_, _, _, _, _, reach, internal, _⟩
  exact no_nomination_reach s.context (internal ▸ reach)

private theorem no_nomination_successor [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {self pre}
    (reach : (reach% SolvedWitnesses.step_nominateSuccessor_successor_some[0]) f t c self pre) :
    False := by
  obtain ⟨⟨_, _, _, introReach, internal, _⟩, _⟩ := reach
  exact no_nomination_reach c (internal ▸ introReach)

public theorem nomination_some_false (s : Step) :
    label s (.step .nominateSuccessor_successor_some) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_nominateSuccessor_successor_some s.frame s.after s.context
  rintro ⟨_, _, reach, _⟩
  exact no_nomination_successor s.context reach

public theorem nomination_none_false (s : Step) :
    label s (.step .nominateSuccessor_successor_none) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_nominateSuccessor_successor_none s.frame s.after s.context
  rintro ⟨_, _, reach, _⟩
  exact no_nomination_successor s.context reach

private def individual : List Classes.StepBranch :=
  [.mem_network_mem_append_inl, .act_input_nominateSuccessor,
    .nominateSuccessor_successor_some, .nominateSuccessor_successor_none,
    .commit_backed_now_after_inr, .certificates_agree_backing_inl,
    .certificates_agree_backing_inr, .new_in_elected_led_inr, .rv_stable_now_after_inl,
    .led_cur_role_inr, .led_cur_now_after_inr, .persist_now_after_inr, .seen_after_now_after_inr,
    .facts_advance_inr_2, .facts_role_inl, .facts_role_inr,
    .certificates_agree_le_total_inl, .certificates_agree_le_total_inr,
    .vals_upToDate_lt_or_eq_of_le_inl, .termAt_le_of_mem_found_none,
    .termAt_mono_eq_zero_or_pos_inl]

private theorem old_seen_other [Config.InitialConfiguration] {f : Frame} {t : State}
    (c : Ctx f t) {n o} (other : n ≠ c.actor) (h : Seen (f.advance t) n o) : Seen f n o := by
  rcases c.seen_after h with old | ⟨eq, _⟩
  · exact old
  · exact (other eq).elim

private theorem persist_delta_actor [Config.InitialConfiguration] {f : Frame} {t : State}
    (c : Ctx f t) {n st o i}
    (r : (reach% SolvedWitnesses.step_persist_now_after_inr[0]) f t c c n st o i) :
    n = c.actor := by
  apply Classical.byContradiction
  intro different
  obtain ⟨now, seen, sig, fresh, _⟩ := r
  rcases c.now_after now with ⟨eq, _⟩ | ⟨_, old⟩
  · exact different eq
  · exact fresh ⟨old, old_seen_other c different seen, sig⟩

public theorem led_cur_other_false (s : Step) : label s (.step .led_cur_now_after_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_led_cur_now_after_inr _ _ _
  rintro ⟨_, _, _, r, ⟨other, old⟩, _⟩
  exact r.2.2.1 ⟨old, s.context.led_other other r.2.1⟩

public theorem persist_other_false (s : Step) : label s (.step .persist_now_after_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_persist_now_after_inr _ _ _
  rintro ⟨_, _, _, _, r, ⟨other, _⟩, _⟩
  exact other (persist_delta_actor s.context r)

public theorem seen_other_false (s : Step) : label s (.step .seen_after_now_after_inr) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  change ¬ SolvedWitnesses.step_seen_after_now_after_inr _ _ _
  rintro (h | h)
  all_goals obtain ⟨n, o, r, _, st, _, _, _, _, _, ⟨other, _⟩, _⟩ := h
  · obtain ⟨_, now, seen, fresh, _⟩ := r
    rcases s.context.now_after now with ⟨eq, _⟩ | ⟨_, old⟩
    · exact other eq
    · exact fresh ⟨old, old_seen_other s.context other seen⟩
  · rcases r with ⟨_, _, _, _, _, _, _, _, _, eq⟩ | ⟨_, _, r, _⟩
    · exact other eq
    · exact other (persist_delta_actor s.context r)

private theorem no_winning_advance [Config.InitialConfiguration] {f : Frame} {t : State}
    (c : Ctx f t) (middle : NodeState) (win : Wins c.actor c.pre c.event c.post)
    (log : c.post.log = middle.log) (term : c.post.currentTerm = middle.currentTerm)
    (lt : middle.commitIndex < c.post.commitIndex)
    (eq : c.post.commitIndex = highestCommittableIndex middle c.actor) : False := by
  obtain ⟨bound, signed, stamp, _⟩ := highestCommittableIndex_spec middle c.actor (eq ▸ lt)
  exact no_election_entry c (c.wins_elect win) (signature_pos signed)
    (log.symm ▸ bound) (by rw [log, term]; exact stamp)

local macro "winning_advance_paths " c:term:arg h:term:arg : tactic => `(tactic|
  (rcases ($h) with h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h|h
   all_goals
     obtain ⟨self, pre, ev, post, origin, candidate, rest⟩ := h
     have pins : self = ($c).actor ∧ pre = ($c).pre ∧ ev = ($c).event ∧ post = ($c).post := by
       path_premise origin
     obtain ⟨hs, hp, he, ht⟩ := pins
     subst self; subst pre; subst ev; subst post
     apply no_winning_advance $c (primaryState candidate)
     all_goals path_premise rest))

public theorem winning_advance_false (s : Step) (b : Classes.StepBranch)
    (arm : b = .facts_advance_inr_2 ∨ b = .facts_role_inl ∨ b = .facts_role_inr) :
    label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  rcases arm with rfl | rfl | rfl
  all_goals
    first | change ¬ SolvedWitnesses.step_facts_advance_inr_2 _ _ _
          | change ¬ SolvedWitnesses.step_facts_role_inl _ _ _
          | change ¬ SolvedWitnesses.step_facts_role_inr _ _ _
    intro h
    winning_advance_paths s.context h

public theorem certificate_order_false (s : Step) (b : Classes.StepBranch)
    (arm : b = .certificates_agree_le_total_inl ∨ b = .certificates_agree_le_total_inr) :
    label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply solved_false
  rcases arm with rfl | rfl
  all_goals
    first | change ¬ SolvedWitnesses.step_certificates_agree_le_total_inl _ _ _
          | change ¬ SolvedWitnesses.step_certificates_agree_le_total_inr _ _ _
    rintro (h|h|h|h|h|h|h|h)
    all_goals
      obtain ⟨n, m, k, l, i, _, _, r, _⟩ := h
      apply no_repeat_election s.context (n := n) (m := m) (k := k) (l := l) (i := i)
      all_goals path_premise r

public theorem self_vote_strict_rank_false (s : Step) :
    label s (.step .vals_upToDate_lt_or_eq_of_le_inl) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have frontier : c.pre.commitIndex ≤ maxCommittableIndex c.pre.log := by
    rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | pos
    · exact zero ▸ Nat.zero_le _
    · exact Ledger.signatureIndex_le_maxCommittableIndex ((c.inv.frontier _ _ c.pre_now).2 pos)
  apply solved_false
  change ¬ SolvedWitnesses.step_vals_upToDate_lt_or_eq_of_le_inl _ _ c
  rintro (h|h|h|h|h|h|h|h|h|h)
  all_goals
    obtain ⟨st, r, strict, _⟩ := h
    have pin : st = c.pre := by path_premise r
    rw [pin, Nat.max_eq_right frontier] at strict
    exact Nat.lt_irrefl _ strict

/-- Cases refuted by the generic support checks or individual proofs below. -/
public def refuted : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b => noSupport b || decide (b ∈ individual)

public theorem count : refuted.Nodup ∧ refuted.length = 21 := by decide +kernel

public theorem label_false {b : Classes.StepBranch} (mem : b ∈ refuted) :
    ∀ s : Step, label s (.step b) = false := by
  intro s
  have h := (List.mem_filter.mp mem).2
  simp only [Bool.or_eq_true] at h
  rcases h with unsupported | direct
  · exact support_false s b unsupported
  · have mem := of_decide_eq_true direct
    simp only [individual, List.mem_cons, List.not_mem_nil, or_false] at mem
    rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    · exact retained_false s
    · exact act_nomination_false s
    · exact nomination_some_false s
    · exact nomination_none_false s
    · exact commit_backed_other_false s
    · exact certificates_zero_false s
    · exact certificates_committed_false s
    · exact new_in_elected_fresh_leader_false s
    · exact rv_stable_actor_false s
    · exact led_cur_retired_false s
    · exact led_cur_other_false s
    · exact persist_other_false s
    · exact seen_other_false s
    all_goals first
      | exact winning_advance_false s _ (by decide)
      | exact certificate_order_false s _ (by decide)
      | exact self_vote_strict_rank_false s
      | exact CampaignLookup.lookup_false s
      | exact CampaignLookup.mono_false s

end ConsensusCoverage.CaseUnreachable
