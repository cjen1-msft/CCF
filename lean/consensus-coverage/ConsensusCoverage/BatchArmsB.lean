module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.BatchArmsB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private structure Seed {f : Frame} {t : Model.State} (c : Ctx f t) where
  self : NodeID
  before : NodeState
  contents : List AppendEntryInput
  entered : (reach% step_push_mem_append_inl[6,0,1]) f t c self before contents
  erased : (reach% step_appendEntry_batch_peers_none[31,1]) f t c
  guards : before.role = .primary ∧ ¬ before.isRetiredCommitted self ∧ contents ≠ []

private def items : Event → List AppendEntryInput
  | .internal (.append xs) => xs
  | _ => []

private theorem seedOf {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .internal (.append (items x.event)))
    (guards : x.base.pre.role = .primary ∧ ¬ x.base.pre.isRetiredCommitted x.base.actor ∧ items x.event ≠ []) :
    Nonempty (Seed c) := by
  have summary := ReceiveCasesB.changedSummary ok changed
  exact ⟨⟨x.base.actor, x.base.pre, items x.event,
    ⟨x.event, ⟨t, c.tr, summary, (X.tr_actor_eq ok).symm, (X.tr_pre_eq ok).symm,
      (X.tr_event_eq ok).symm⟩, _, ev, ev, rfl⟩,
    ⟨x.event, ⟨t, c.tr, summary, (X.tr_event_eq ok).symm⟩, _, ev, ev, _, rfl⟩, guards⟩⟩

private def plain := EntryContent.transaction 1 {}
private def configured := EntryContent.transaction 1 {configuration := some {0,1,2,3}}

private theorem peers (seed : Seed c) :
    step_appendEntry_batch_peers_none f t c ∧ step_appendEntry_batch_peers_some f t c := by
  have entry (v : EntryContent) : (reach% step_appendEntry_batch_peers_none[31]) f t c v :=
    Or.inr ⟨seed.erased, {content := v}, rfl⟩
  constructor <;> iterate 81 right
  · exact Or.inl ⟨plain, entry _, by decide, by decide, rfl⟩
  · exact Or.inl ⟨configured, entry _, by decide, by decide, _, rfl⟩

private theorem start (s : Seed c) : BatchState s.self s.before s.before [] :=
  ⟨⟨[], s.before.sentIndex, by simp, by simp⟩, by simp⟩

private theorem itemCaller (s : Seed c) (content : EntryContent) {state sent}
    (batch : BatchState s.self s.before state sent) :
    (reach% step_push_mem_append_inl[6,0]) f t c s.self s.before state sent content :=
  Or.inr ⟨s.contents, s.entered, s.guards, s.guards.1, s.guards.2, s.guards,
    {content}, batch, start s, rfl⟩

private theorem pushed (s : Seed c) :
    step_push_mem_append_inl f t c ∧ step_push_mem_append_inr f t c := by
  let e := ({term := s.before.currentTerm, content := plain} : Entry)
  let state := {s.before with log := s.before.log ++ [e]}
  have terms : ∀ e' ∈ [e], e'.term = s.before.currentTerm := by simp [e]
  have batch : BatchState s.self s.before state [] :=
    ⟨⟨[e], s.before.sentIndex, rfl, terms⟩, by simp⟩
  have origin : (reach% step_push_mem_append_inl[6]) f t c s.self s.before state [] plain := by
    iterate 6 right
    exact Or.inl ⟨itemCaller s plain batch, by decide, by decide, rfl, rfl, batch⟩
  constructor <;> iterate 6 right
  all_goals exact Or.inl ⟨_, _, _, _, _, origin, batch.1, batch.2, [e],
    ⟨s.before.sentIndex, rfl, terms⟩, s.before.sentIndex, ⟨rfl, terms⟩, rfl, terms, batch.2,
    e, .head _, .head _, batch⟩

private theorem folded (s : Seed c) : step_foldlM__items_cons_2 f t c := by
  let action := fun state (item : NodeID × Nat) =>
    sendEntries (CCF.Capabilities.record s.self) s.self state item.1 item.2
  let I := BatchState s.self s.before
  have entry : (reach% step_foldlM__items_cons_2[6]) f t c (NodeID × Nat) I action :=
    Or.inr (.inl ⟨s.self, s.before, s.contents, s.entered, s.guards, s.guards.1, s.guards.2,
      s.guards, s.before, [], start s, s.before, [], start s, start s, rfl, rfl, HEq.rfl⟩)
  iterate 6 right
  left
  refine ⟨_, I, action, entry, [], ?_, ?_⟩
  · intro init sent valid
    exact Sends.pure' (by simpa using valid)
  · intro state sent item valid
    exact sendEntries_batch s.self s.before state sent item.1 item.2 valid

end

public def questions : List Classes.StepBranch := [.appendEntry_batch_peers_none,
  .appendEntry_batch_peers_some, .push_mem_append_inl, .push_mem_append_inr, .foldlM__items_cons_2]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {b : Classes.StepBranch} (mem : b ∈ questions) (seed : Seed c) : sig c b := by
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl
  · exact (peers seed).1
  · exact (peers seed).2
  · exact (pushed seed).1
  · exact (pushed seed).2
  · exact folded seed

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample batch 0 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  obtain ⟨seed⟩ := seedOf (c := a.s.context) (x := a.x) a.ok
    (by decide +kernel) (by decide +kernel) (by decide +kernel)
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr (casesOf mem seed))⟩

end ConsensusCoverage.BatchArmsB
