module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallB.MessageFloorGate

open Consensus Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersElection

set_option maxHeartbeats 0
set_option maxRecDepth 8192

private def anyRank : Pairs.Test := fun _ _ _ _ _ _ => true

/-- The expensive floor test only needs evaluating on an installation or
    when the simpler signed committed/elected-pair reader has a candidate. -/
public def relevant (s : Step) : Bool :=
  decide (EventSupport.actionTag s.act = .initAsBackup) ||
    Pairs.reader anyRank s.cfg s.before s.act s.after s.past

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Installing := ∃ es, c.event = .internal (.initAsBackup es)

private theorem source {n k}
    (root : (reach% step_leader_floor_led_inl[0]) f t c n k ∨
      (reach% step_leader_floor_led_inl[1]) f t c n k ∨
      (reach% step_leader_floor_led_inl[2]) f t c n k ∨
      (reach% step_leader_floor_led_inl[3]) f t c n k ∨
      (reach% step_leader_floor_led_inl[4]) f t c n k ∨
      (reach% step_leader_floor_led_inl[5]) f t c n k ∨
      (reach% step_leader_floor_led_inl[6]) f t c n k ∨
      (reach% step_leader_floor_led_inl[7]) f t c n k ∨
      (reach% step_leader_floor_led_inl[8]) f t c n k) :
    Installing c ∨ Pairs.Evidence c anyRank := by
  rcases root with h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨_, _, _, es, ev, _, _, _, _, _, _, _, _⟩ := h
      exact .inl ⟨es, ev⟩
    | obtain ⟨es, ev, _, _, _⟩ := h.2.2.2.1
      exact .inl ⟨es, ev⟩
    | obtain ⟨_, es, ev, _, _, _, _, _, _, _, _⟩ := h
      exact .inl ⟨es, ev⟩
    | obtain ⟨st, b, i, raw, _⟩ := h
      have ticket := (Pairs.ticket_iff c).mp raw
      obtain ⟨laterNode, later, l, commit, elect, lt, _⟩ := ticket.2.2
      exact .inr ⟨st.log, k, b, i, l, commit,
        .inr ⟨n, st, laterNode, later, ticket, rfl, elect, lt⟩, rfl⟩

private theorem needed (h : sig c .leader_floor_led_inl ∨ sig c .leader_floor_led_inr) :
    Installing c ∨ Pairs.Evidence c anyRank := by
  rcases h with h | h
  · repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      apply source c (n := Config.INITIAL_PRIMARY) (k := Model.BOOTSTRAP_TERM)
      repeat' first | exact h.1 | exact Or.inl h.1 | apply Or.inr
  · repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨n, k, root, _⟩ := h
      apply source c (n := n) (k := k)
      repeat' first | exact root | exact Or.inl root | apply Or.inr

end

public theorem positive_relevant (s : Step)
    (yes : label s (.step .leader_floor_led_inl) = true ∨
      label s (.step .leader_floor_led_inr) = true) : relevant s = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have spec (q : Classes.StepBranch) := (label_true s (.step q)).trans (sig_iff s.context q)
  obtain ⟨es, ev⟩ | pair := needed s.context (yes.imp (spec _).mp (spec _).mp)
  · have tag := EventSupport.actionTag_eq s.context
    rw [(s.context_eq s.context).mpr rfl] at tag
    change EventSupport.actionTag s.act = EventSupport.eventTag s.context.event at tag
    rw [ev] at tag
    simp [relevant, tag, EventSupport.eventTag, EventSupport.inputTag]
  · have read := (Pairs.reader_iff s anyRank).mpr pair
    simp [relevant, read]

public theorem negative (s : Step) (no : relevant s = false) :
    label s (.step .leader_floor_led_inl) = false ∧
      label s (.step .leader_floor_led_inr) = false := by
  constructor <;> apply Bool.eq_false_iff.mpr <;> intro yes
  · exact Bool.noConfusion (no.symm.trans (positive_relevant s (.inl yes)))
  · exact Bool.noConfusion (no.symm.trans (positive_relevant s (.inr yes)))

end ConsensusCoverage.ClauseSmallB.MessageFloorGate
