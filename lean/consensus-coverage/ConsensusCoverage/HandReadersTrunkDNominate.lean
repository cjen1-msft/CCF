module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDNominateRoute
import all ConsensusCoverage.HandReadersTrunkDNominateBound
import all ConsensusCoverage.HandReadersTrunkDNominateLog
import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersTrunkDLeaderQuery
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Nominate

open Consensus Model Model.Node Proofs Safety SolvedWitnesses ActionProfile HandReadersA HandReadersTrunkC
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def test (want : Bool) (n : NodeID) (s : NodeState) (ev : Event) (_ : NodeState) := match ev with
  | .internal .nominateSuccessor => decide (s.role = Role.primary ∧ (findSuccessor s n).isSome = want)
  | .internal (.append _) => decide (Pick want n (canon n s want))
  | .receive src (.appendEntriesResponse r) => decide (src ∈ eligiblePeers s n ∧ s.role = Role.primary ∧
      r.success = true ∧ r.term = s.currentTerm ∧ Pick want n (Match.ack s src r))
  | _ => false

private instance (p n s) : Decidable (Pick p n s) := by unfold Pick Leader.Growth; infer_instance

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)
private theorem batch_iff (want : Bool) : Leader.Batch c (Pick want) ↔ Leader.App c ∧
    Pick want c.actor (canon c.actor c.pre want) := by
  constructor
  · rintro ⟨⟨xs,ev⟩,es,si,_,h⟩
    have primary : c.pre.role = .primary := (HandReadersTrunkA.Batch.seed c ev).guards.1
    exact ⟨⟨xs,ev⟩,normalize c primary want h⟩
  · rintro ⟨app,pick⟩
    refine ⟨app,suffix c.actor c.pre.currentTerm want,c.pre.sentIndex,?_,pick⟩
    intro e h
    simp only [suffix,List.mem_cons,List.not_mem_nil,or_false] at h
    rcases h with rfl | rfl | rfl | rfl <;> rfl

private abbrev Direct (want : Bool) := c.event = .internal .nominateSuccessor ∧ Body want c.actor c.pre

private theorem standalone (want : Bool) : HandReadersTrunkBFactor.Tail.Standalone f t c want ↔ Direct c want := by
  constructor
  · rintro ⟨n,s,⟨ev,⟨rfl,rfl,rfl⟩,ne⟩,h⟩
    exact ⟨ne,h⟩
  · rintro ⟨ev,h⟩
    exact ⟨c.actor,c.pre,⟨c.event,⟨rfl,rfl,rfl⟩,ev⟩,h⟩

private theorem iff_test (want : Bool) : (Direct c want ∨ Leader.Batch c (Pick want) ∨ Leader.Ack c (Pick want)) ↔
    test want c.actor c.pre c.event c.post = true := by
  rw [batch_iff]; unfold Leader.Ack Leader.App Direct
  cases c.event with
  | internal input => cases input <;> simp [test,Body]
  | receive n m => cases m <;> simp [test] <;> grind
end

private def column (want : Bool) : ConsensusCoverage.Classes.StepBranch :=
  if want then .nominate_sends_successor_some else .nominate_sends_successor_none

def exactReader (want : Bool) : Exact (column want) where
  eval := SummaryRows.gated (test want)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c:=s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff]
    have h : sig c (column want) ↔ Standalone s.frame s.after c want ∨
        Leader.Working s.frame s.after c (Pick want) := by cases want <;> first | exact none_iff .. | exact some_iff ..
    rw [h,HandReadersTrunkBFactor.Exact.Standalone _ _ _ want (HandReadersBGate.quiet s),standalone,
      Leader.working_iff s _ (fun _ _ h=>h.1),SummaryRows.gated,Bool.and_eq_true,actorRead_at,HandReadersBGate.live,
      ←iff_test]
    grind only

end ConsensusCoverage.HandReadersTrunkD.Nominate
