module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.BatchPacketCasesB
import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
import CCF.Proofs.Finset

namespace ConsensusCoverage.HandReadersTrunkA.Batch

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

private def configure (n : NodeID) : EntryContent :=
  .transaction 0 {configuration := some {n}}

/-- The last configuration is active even when every historical configuration has committed. -/
private theorem lastPeer (m : NodeState) (peer self : NodeID) (ne : peer ≠ self)
    (hist : List Node.Configuration) (i : Nat)
    (h : configurationHistory m.log = hist ++ [⟨i,{peer}⟩]) : peer ∈ eligiblePeers m self := by
  apply Finset.mem_erase.mpr
  refine ⟨ne, Finset.mem_union.mpr (.inl ?_)⟩
  unfold NodeState.activeMembers NodeState.activeConfigurations activeConfigurations configurationMembers
  rw [h]
  have le := List.length_filter_le (fun c : Node.Configuration => decide (c.index ≤ m.commitIndex))
    (hist ++ [⟨i,{peer}⟩])
  simp only [List.length_append, List.length_cons, List.length_nil] at le
  rw [List.drop_append_of_le_length (by omega), List.foldl_append]
  exact Finset.mem_union.mpr (.inr (Finset.mem_singleton.mpr rfl))

private theorem packetCases [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) {b : Classes.StepBranch} (mem : b ∈ BatchPacketCasesB.questions) : sig c b := by
  let peer := s.self + 1
  let a : Entry := ⟨s.before.currentTerm,.signature⟩
  let z : Entry := ⟨s.before.currentTerm,configure peer⟩
  let xs := [a,z]
  let ix := s.before.log.length
  let m := {s.before with log := s.before.log ++ xs, sentIndex := fun _ => ix}
  have ne : peer ≠ s.self := Nat.succ_ne_self _
  have hist : configurationHistory m.log = configurationHistory s.before.log ++ [⟨(1+ix)+1,{peer}⟩] := by
    simp [m, xs, a, z, configure, configurationHistory, List.zipIdx_append, ix,
      EntryContent.metadata]
  have peerMem := lastPeer m peer s.self ne _ _ hist
  have term : ∀ v ∈ xs, v.term = s.before.currentTerm := by simp [xs,a,z]
  have bound : ix+2 ≤ m.log.length := by simp [m,ix,xs]
  have stamp : termAt m.log (ix+2) = s.before.currentTerm := by
    obtain ⟨e,mem,eq⟩ := termAt_append_right (front := s.before.log) (back := xs)
      (index := ix+2) (by dsimp [ix]; omega) bound
    exact eq.trans (term e mem)
  have sendsame : ((messageEntries m.log ix (ix+2)).all fun e => e.term == termAt m.log (ix+2)) = true := by
    simp [messageEntries, m, ix, stamp, xs, a, z]
  have send := And.intro s.guards.1 (And.intro peerMem (And.intro (show ix ≤ ix+2 by omega)
    (And.intro bound (And.intro sendsame (Or.inr (a := ¬m.isRetiredCommitted s.self)
      (show ix+1 < ix+2 by omega))))))
  let old := SelfQuorumCasesB.heartbeat s.self m
  have packets : ∀ e ∈ [old], AEFrom s.self s.before.currentTerm s.before.commitIndex m.log e :=
    SelfQuorumCasesB.singleton (SelfQuorumCasesB.beat s.self m)
  have valid : BatchState s.self s.before m [old] := ⟨⟨xs,fun _ => ix,rfl,term⟩,packets⟩
  have origin : (reach% step_sendEntries_batch_mem_append_inl[6]) f t c s.self s.before m [old] peer (ix+2) :=
    .inr ⟨s.contents,s.entered,s.guards,s.guards.1,s.guards.2,s.guards,s.before,[],
      BatchArmsB.start s,s.before,[],BatchArmsB.start s,valid,BatchArmsB.start s⟩
  have distinct : ({s.self} : Finset Nat) ≠ latestConfigurationMembers (configurationHistory m.log) := by
    rw [hist]
    simpa [latestConfigurationMembers] using fun (eq : ({s.self} : Finset Nat) = {peer}) =>
      ne (Finset.mem_singleton.mp (eq ▸ (Finset.mem_singleton.mpr (rfl : s.self = s.self)))).symm
  have guards := And.intro (show ({s.self} : Finset Nat).Nonempty from ⟨_, Finset.mem_singleton.mpr rfl⟩) distinct
  simp only [BatchPacketCasesB.questions,List.mem_cons,List.not_mem_nil,or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl
  case inl | inr.inl =>
    iterate 81 right
    left
    exact ⟨s.self,s.before,m,[old],configure s.self,BatchArmsB.itemCaller s _ valid,Bool.noConfusion,
      (by change ¬(∅ : Finset Nat).Nonempty; decide),{s.self},rfl,rfl,guards,valid.1,packets,xs,⟨fun _ => ix,rfl,term⟩,
      fun _ => ix,⟨rfl,term⟩,rfl,term,guards,packets,[old],packets,old,.head _,.head _,valid⟩
  all_goals
    iterate 6 right
    left
    refine ⟨s.self,s.before,m,[old],peer,ix+2,origin,send,send.1,send.2.1,send.2.2.1,
      send.2.2.2.1,send.2.2.2.2,valid.1,packets,xs,⟨fun _ => ix,rfl,term⟩,
      fun _ => ix,⟨rfl,term⟩,rfl,term,send,send.1,send.2.1,send.2.2.1,send.2.2.2.1,
      send.2.2.2.2,rfl,packets,?_⟩
  · exact ⟨old,.head _,.head _,valid⟩
  · let new : Model.Envelope := ⟨s.self,peer,.appendEntriesRequest (makeAppendEntriesRequest m peer (ix+2))⟩
    exact ⟨new,.tail _ (.head _),.head _,valid⟩

def entryOld := exactOfSeed .appendEntry_batch_mem_append_inl (by decide +kernel) (packetCases · (by decide))
def entryNew := exactOfSeed .appendEntry_batch_mem_append_inr (by decide +kernel) (packetCases · (by decide))
def sendOld := exactOfSeed .sendEntries_batch_mem_append_inl (by decide +kernel) (packetCases · (by decide))
def sendNew := exactOfSeed .sendEntries_batch_mem_append_inr (by decide +kernel) (packetCases · (by decide))

end ConsensusCoverage.HandReadersTrunkA.Batch
