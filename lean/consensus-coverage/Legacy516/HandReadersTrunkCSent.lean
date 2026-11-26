module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkCSentRoute
import all ConsensusCoverage.HandReadersTrunkBPrimary
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkC.Sent

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA HandReadersTrunkB ActionProfile

set_option maxRecDepth 16384
set_option maxHeartbeats 1200000

private abbrev Peer (n : NodeID) (st : NodeState) := ∃ p, p ∈ (eligiblePeers (primaryState st) n).sort

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem tailPeer : HandReadersTrunkBFactor.Tail.step_sentIndex_advance_inl f t c ↔
    HandReadersTrunkBFactor.Tail.Promotion f t c Peer := by
  constructor
  · rintro (h | h | h | h)
    all_goals obtain ⟨_,_,⟨cand,entry,_,_,_,_,p,hp,_,_,_,rfl⟩,_⟩ := h
    all_goals first | left; exact ⟨_,_,entry,p,hp⟩ | right; left; exact ⟨_,_,entry,p,hp⟩
                    | right; right; left; exact ⟨_,_,entry,p,hp⟩ | right; right; right; exact ⟨_,_,entry,p,hp⟩
  · rintro (⟨n,cand,entry,p,hp⟩ | ⟨n,cand,entry,p,hp⟩ | ⟨n,cand,entry,p,hp⟩ | ⟨n,cand,entry,p,hp⟩)
    all_goals
      let m := primaryState cand
      have a : Advance n m m := .inl rfl
      have empty : ∀ msg ∈ ([] : List Model.Envelope), msg.source = n ∧ msg.payload = .proposeRequestVoteRequest m.currentTerm := by simp
      have ne := (Finset.mem_erase.mp (Finset.mem_sort.mp hp)).1
      first | left; exact ⟨n,m,⟨cand,entry,[],⟨a,empty⟩,a,empty,p,hp,_,.head _,ne,rfl⟩,a⟩
            | right; left; exact ⟨n,m,⟨cand,entry,[],⟨a,empty⟩,a,empty,p,hp,_,.head _,ne,rfl⟩,a⟩
            | right; right; left; exact ⟨n,m,⟨cand,entry,[],⟨a,empty⟩,a,empty,p,hp,_,.head _,ne,rfl⟩,a⟩
            | right; right; right; exact ⟨n,m,⟨cand,entry,[],⟨a,empty⟩,a,empty,p,hp,_,.head _,ne,rfl⟩,a⟩

private theorem extract (R : NodeID → NodeState → Prop)
    (pin : ∀ n st, R n st → (Peer n st ↔ Peer c.actor c.pre)) :
    (∃ n st, R n st ∧ Peer n st) ↔ (∃ n st, R n st ∧ Primary.localGuard false n st) ∧ Peer c.actor c.pre := by
  constructor
  · rintro ⟨n,st,h,hp⟩
    exact ⟨⟨n,st,h,Primary.always ..⟩,(pin n st h).mp hp⟩
  · rintro ⟨⟨n,st,h,_⟩,hp⟩
    exact ⟨n,st,h,(pin n st h).mpr hp⟩

omit [Config.InitialConfiguration] in
private theorem distribute {a b d e p : Prop} :
    ((a ∨ b ∨ d ∨ e) ∧ p) ↔ (a ∧ p) ∨ (b ∧ p) ∨ (d ∧ p) ∨ (e ∧ p) := by grind

private theorem pinned : HandReadersTrunkBFactor.Tail.Promotion f t c Peer ↔
    HandReadersTrunkBFactor.Tail.Promotion f t c (Primary.localGuard false) ∧ Peer c.actor c.pre := by
  unfold HandReadersTrunkBFactor.Tail.Promotion
  rw [distribute]
  apply or_congr
  · apply extract c
    rintro _ _ ⟨⟨_,_,_,⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,_,_,_,rfl⟩,_⟩
    rfl
  apply or_congr
  · apply extract c
    rintro _ _ ⟨⟨_,⟨_,⟨⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩
    rfl
  apply or_congr
  · apply extract c
    rintro _ _ ⟨⟨_,⟨_,⟨_,_,⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,_,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩
    rfl
  · apply extract c
    rintro _ _ ⟨⟨_,⟨_,⟨_,⟨_,⟨rfl,rfl,_⟩,_⟩,_,_,_,rfl⟩,_⟩,rfl⟩,_⟩
    rfl

end

def identity : Exact .sentIndex_advance_inl where
  eval := fun cfg pre act post past => (Primary.exactReader false).eval cfg pre act post past &&
    actorRead (fun n st _ _ => !(eligiblePeers (primaryState st) n).sort.isEmpty) cfg pre act post past
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have h := HandReadersBGate.quiet s
    apply Bool.eq_iff_iff.mpr
    rw [Bool.and_eq_true,←(Primary.exactReader false).eq_label s,actorRead_at,label_true,label_true,
      holds,holds,sig_iff,sig_iff,Primary.query_eq,HandReadersTrunkBFactor.Exact.Promotion _ _ _ _ h]
    change step_sentIndex_advance_inl _ _ _ ↔ _
    rw [HandReadersTrunkBFactor.Exact.step_sentIndex_advance_inl _ _ _ h,tailPeer,pinned,and_assoc]
    apply and_congr_right; intro _
    apply and_congr_right; intro _
    unfold Peer
    cases (eligiblePeers (primaryState s.context.pre) s.context.actor).sort <;> simp

end ConsensusCoverage.HandReadersTrunkC.Sent
