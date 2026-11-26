module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.DeepBatchCases
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor

namespace ConsensusCoverage.HandReadersA.Batch

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile SolvedWitnesses
open Lean Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 1000000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def column (later : Bool) : Classes.StepBranch :=
  if later then .appendBatch_summary_mem_append_inr else .appendBatch_summary_mem_append_inl

def reader := Append.reader

run_cmd liftTermElabM do
  for n in #[``step_appendBatch_summary_mem_append_inl,``step_appendBatch_summary_mem_append_inr,
      ``step_appendBatch_summary_role_inl] do
    HandReadersBFactor.compile n

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private theorem on_append {xs} (ev : c.event = .internal (.append xs)) :
    (step_appendBatch_summary_mem_append_inl f t c ∧ step_appendBatch_summary_mem_append_inr f t c) ∧
      step_appendBatch_summary_role_inl f t c := by
  have ran : (appendBatch (Capabilities.record c.actor) c.actor c.pre xs).run {} = some (c.post,c.tr.outputs) := by
    change (step _ _ _ (.internal (.append xs))).run {} = _
    rw [←ev]
    exact c.tr.ran
  have guard : c.pre.role = .primary ∧ ¬c.pre.isRetiredCommitted c.actor ∧ xs ≠ [] := by
    apply Classical.byContradiction
    intro no
    simp [appendBatch,_root_.guard,no,Bind.bind,StateT.bind,StateT.run,failure,StateT.failure] at ran
  obtain ⟨_,_,grow⟩ := LeaderEffect.appendBatch_grows c.actor c.pre xs _ _ _ ran
  have fresh : ¬Now f c.actor c.post := fun h => (Nat.lt_irrefl _) ((c.now_pre h) ▸ grow)
  have rt := DeepInputCases.summary c fresh
  have path : (reach% step_appendBatch_summary_mem_append_inl[15]) f t c c.actor c.pre xs :=
    ⟨c.event,⟨_,c.tr,rt,rfl,rfl,rfl⟩,_,ev,ev,rfl⟩
  exact ⟨DeepBatchCases.member _ _ _ path guard,(DeepBatchCases.roles _ _ _ path guard c.pre (.inl rfl)).1 rfl⟩
end

private theorem iff_append (s : Step) (later : Bool) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    sig s.context (column later) ↔ ∃ xs, s.context.event = .internal (.append xs) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have no := HandReadersBGate.quiet s
  constructor
  · intro h
    cases later
    all_goals
      first
      | have p := ((HandReadersBFactor.Exact.step_appendBatch_summary_mem_append_inl _ _ _ no).mp h).2
      | have p := ((HandReadersBFactor.Exact.step_appendBatch_summary_mem_append_inr _ _ _ no).mp h).2
      obtain ⟨_,_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩ := p
      exact ⟨xs,ev⟩
  · rintro ⟨xs,ev⟩
    cases later <;> first | exact (on_append s.context ev).1.1 | exact (on_append s.context ev).1.2

def exactReader (later : Bool) : Exact (column later) where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [show reader = (Append.exactReader .cons).eval from rfl,← (Append.exactReader .cons).eq_label s]
    apply Bool.eq_iff_iff.mpr
    rw [label_true,label_true,holds,holds,sig_iff,sig_iff,iff_append,Append.iff_append]

def retained : Exact .appendBatch_summary_role_inl where
  eval := reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    rw [show reader = (Append.exactReader .cons).eval from rfl,← (Append.exactReader .cons).eq_label s]
    apply Bool.eq_iff_iff.mpr
    rw [label_true,label_true,holds,holds,sig_iff,sig_iff,Append.iff_append]
    constructor
    · intro h
      have p := ((HandReadersBFactor.Exact.step_appendBatch_summary_role_inl _ _ _ (HandReadersBGate.quiet s)).mp h).2
      rcases p with p | p | p
      all_goals
        obtain ⟨_,_,xs,⟨_,⟨rfl,rfl,rfl⟩,_,ev,_,rfl⟩,_⟩ := p
        exact ⟨xs,ev⟩
    · rintro ⟨_,ev⟩; exact (on_append s.context ev).2

end ConsensusCoverage.HandReadersA.Batch
