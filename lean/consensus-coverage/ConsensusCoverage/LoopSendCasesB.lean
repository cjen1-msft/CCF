module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.LoopSendCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

public def questions : List Classes.StepBranch :=
  [.forIn__items_nil, .forIn__items_cons, .forIn__step_done, .forIn__step_yield,
   .forIn__mem_append_inl, .forIn__mem_append_inr]

private theorem casesOf [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}
    {b : Classes.StepBranch} (mem : b ∈ questions) (s : SelfQuorumCasesB.Seed c) : sig c b := by
  let items := (eligiblePeers s.leader s.self).sort
  let sendOne (n : NodeID) (_ : PUnit) : NodeEffect (ForInStep PUnit) := do
    (CCF.Capabilities.record s.self : Caps).send (.appendEntriesRequest (makeAppendEntriesRequest s.leader n s.leader.log.length)) n
    pure (.yield .unit)
  let packet := AEFrom s.self s.leader.currentTerm s.leader.commitIndex s.leader.log
  let allPackets := fun (_ : ForInStep PUnit) (sent : List Model.Envelope) => ∀ e ∈ sent, packet e
  have adv : Advance s.self s.leader s.leader := Or.inl rfl
  have empty {P : Model.Envelope → Prop} : ∀ e ∈ ([] : List Model.Envelope), P e :=
    fun _ h => (List.not_mem_nil h).elim
  have entry : (reach% step_forIn__items_cons[6]) f t c items sendOne packet := by
    iterate 5 right
    left
    exact ⟨s.self, s.fresh, s.promotion, s.leader, [], ⟨adv, empty⟩, adv, empty, rfl, rfl, rfl⟩
  have one (n : NodeID) (v : PUnit) (other : n ≠ s.self) : Sends allPackets (sendOne n v) := by
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    intro e member
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst e
    have index : s.leader.sentIndex n = s.leader.log.length := rfl
    refine ⟨rfl, other, _, rfl, rfl, ?_, rfl, ?_, Nat.le_refl _⟩ <;>
      simp [makeAppendEntriesRequest, index, messageEntries]
  have each (n : NodeID) (v : PUnit) (h : n ∈ items) : Sends allPackets (sendOne n v) := by
    exact one n v (CCF.Finset.mem_erase.mp (CCF.Finset.mem_sort.mp h)).1
  let n := s.self + 1
  have head (i : NodeID) (v : PUnit) (h : i ∈ [n]) : Sends allPackets (sendOne i v) := by
    have same := List.mem_singleton.mp h
    exact same ▸ one n v (Nat.succ_ne_self _)
  let e := SelfQuorumCasesB.heartbeat s.self s.leader
  have good : ∀ a ∈ [e], packet a := SelfQuorumCasesB.singleton (SelfQuorumCasesB.beat _ _)
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals iterate 6 right
  all_goals left
  · exact ⟨_, _, _, entry, fun _ _ h => (List.not_mem_nil h).elim, each⟩
  all_goals refine ⟨_, _, _, entry, n, [], fun h => Sends.forIn' h, head, ?_⟩
  · exact each
  · exact ⟨[], empty, each⟩
  · exact ⟨[], empty, each⟩
  · exact ⟨[e], good, [], empty, e, .head _, .head _, each⟩
  · exact ⟨[], empty, [e], good, e, .head _, .head _, each⟩

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample soloCampaign 5 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  obtain ⟨s⟩ := SelfQuorumCasesB.seedOf (c := a.s.context) (x := a.x) a.ok
    (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel)
  exact ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr (casesOf mem s))⟩

end ConsensusCoverage.LoopSendCasesB
