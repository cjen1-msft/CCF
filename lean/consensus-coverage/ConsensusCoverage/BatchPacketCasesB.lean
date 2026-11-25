module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.DeepSchedulesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.BatchPacketCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

private def initial (s : NodeState) := {s with log := s.log ++ [], sentIndex := fun _ => 0}
private def nodes : CCF.Finset NodeID := {0,1,2,3}

public def questions : List Classes.StepBranch := [.appendEntry_batch_mem_append_inl,
  .appendEntry_batch_mem_append_inr, .sendEntries_batch_mem_append_inl, .sendEntries_batch_mem_append_inr]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) (m : NodeState) (eq : m = initial s.before)
    (newNodes : nodes ≠ latestConfigurationMembers (configurationHistory m.log))
    (peer : s.self + 1 ∈ eligiblePeers m s.self) (live : ¬ m.isRetiredCommitted s.self)
    {b : Classes.StepBranch} (mem : b ∈ questions) : sig c b := by
  subst m
  let m := initial s.before
  let old := SelfQuorumCasesB.heartbeat s.self m
  let new : Model.Envelope := ⟨s.self, s.self + 1, .appendEntriesRequest (makeAppendEntriesRequest m (s.self+1) 0)⟩
  have packets : ∀ e ∈ [old], AEFrom s.self s.before.currentTerm s.before.commitIndex m.log e :=
    SelfQuorumCasesB.singleton (SelfQuorumCasesB.beat s.self m)
  have terms : ∀ e ∈ ([] : List Entry), e.term = s.before.currentTerm := by simp
  have valid : BatchState s.self s.before m [old] := ⟨⟨[], fun _ => 0, rfl, terms⟩, packets⟩
  have guards := And.intro (show nodes.Nonempty by decide) newNodes
  have send := And.intro s.guards.1 (And.intro peer (And.intro (Nat.le_refl 0)
    (And.intro (Nat.zero_le m.log.length) (And.intro
      (show ((messageEntries m.log 0 0).all fun e => e.term == termAt m.log 0) = true by
        simp [messageEntries]) (Or.inl (b := 0+1 < 0) live)))))
  have origin : (reach% step_sendEntries_batch_mem_append_inl[6]) f t c s.self s.before m [old] (s.self+1) 0 :=
    Or.inr ⟨s.contents, s.entered, s.guards, s.guards.1, s.guards.2, s.guards, s.before, [],
      BatchArmsB.start s, s.before, [], BatchArmsB.start s, valid, BatchArmsB.start s⟩
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  all_goals first
    | (iterate 81 right
       left
       exact ⟨s.self, s.before, m, [old], BatchArmsB.configured,
        BatchArmsB.itemCaller s _ valid, by decide, by decide, nodes, rfl, rfl, guards,
        valid.1, packets, [], ⟨fun _ => 0, rfl, terms⟩, fun _ => 0, ⟨rfl, terms⟩,
        rfl, terms, guards, packets, [old], packets, old, .head _, .head _, valid⟩)
    | (iterate 6 right
       left
       refine ⟨s.self, s.before, m, [old], s.self+1, 0, origin,
        send, send.1, send.2.1, send.2.2.1, send.2.2.2.1, send.2.2.2.2, valid.1, packets,
        [], ⟨fun _ => 0, rfl, terms⟩, fun _ => 0, ⟨rfl, terms⟩, rfl, terms,
        send, send.1, send.2.1, send.2.2.1, send.2.2.2.1, send.2.2.2.2, rfl,
        packets, ?_⟩)
  · exact ⟨old, .head _, .head _, valid⟩
  · exact ⟨new, .tail _ (.head _), .head _, valid⟩

private theorem fromView [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    (x : XView) (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .internal (.append (BatchArmsB.items x.event)))
    (guards : x.base.pre.role = .primary ∧ ¬ x.base.pre.isRetiredCommitted x.base.actor ∧
      BatchArmsB.items x.event ≠ [])
    (config : nodes ≠ latestConfigurationMembers (configurationHistory (initial x.base.pre).log))
    (peer : x.base.actor+1 ∈ eligiblePeers (initial x.base.pre) x.base.actor)
    (live : ¬ (initial x.base.pre).isRetiredCommitted x.base.actor)
    {b : Classes.StepBranch} (mem : b ∈ questions) : sig c b :=
  casesOf (BatchArmsB.seedOf ok changed ev guards) (initial x.base.pre) rfl config peer live mem

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample batch 0 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  have witness := fromView (c := a.s.context) a.x a.ok (by decide +kernel)
    (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel) mem
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr witness)⟩

end ConsensusCoverage.BatchPacketCasesB
