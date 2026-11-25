module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDRecordSupply
import all ConsensusCoverage.HandReadersTrunkDRecordRoute
import all ConsensusCoverage.HandReadersTrunkDRecordSample
import all ConsensusCoverage.HandReadersTrunkDLeader
import all ConsensusCoverage.HandReadersTrunkCMatch
import all ConsensusCoverage.HandReadersTrunkALoop
import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersTrunkABatch
import all ConsensusCoverage.HandReadersOtherFoldDirect
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersAAppend
import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkD.Record

open Consensus Model Model.Node Proofs Safety ActionProfile SolvedWitnesses HandReadersA HandReadersTrunkC
open HandReadersOther HandReadersTrunkA
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def select (b : Bool) (n : NodeID) (m : NodeState) :=
  decide (Leader.Growth n m) && cut b n m (highestCommittableIndex m n)

private def directTest (b : Bool) (n : NodeID) (st : NodeState) (ev : Event) :=
  Fold.appends ev || (Fold.ack n st ev).any (select b n) ||
    (Promotion.candidate n st ev).any (fun z=> decide (Promotion.elects n z) && select b n (primaryState z))

private def ackTest (b : Bool) (n : NodeID) (st : NodeState) (ev : Event) (_ : NodeState) := match ev with
  | .receive src (.appendEntriesResponse r) => decide (src ∈ eligiblePeers st n ∧ st.role = Role.primary ∧
      r.success = true ∧ r.term = st.currentTerm) && select b n (Match.ack st src r)
  | _ => false

def reader (b : Bool) : Reader := fun cfg pre act post past =>
  Loop.cons.eval cfg pre act post past || Promotion.gated (directTest b) cfg pre act post past ||
    SummaryRows.gated (ackTest b) cfg pre act post past

private theorem pick_iff {n m b} : select b n m = true ↔ Pick b n m := by
  simp only [select,Pick,Bool.and_eq_true,decide_eq_true_eq]

section
variable [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t)

private theorem fresh {xs} (ev : c.event = .internal (.append xs)) : ¬Now f c.actor c.post := by
  have ran := c.tr.ran
  rw [show c.tr.event = .internal (.append xs) from ev] at ran
  obtain ⟨_,_,gt⟩ := LeaderEffect.appendBatch_grows c.actor c.pre xs _ _ _ ran
  exact fun old => Nat.lt_irrefl _ ((c.now_pre old) ▸ gt)

private theorem directSupply {m n b} (call : Fold.LeftCall c m n ∨ Fold.RightCall c m n)
    (fr : Direct.CommitFrontier m) (p : Pick b n m) : DirectCase c b := by
  refine ⟨m,n,?_,p⟩
  have ng := Nat.not_le_of_gt p.1
  rcases call with call | call <;>
    by_cases ret : (m.recordCommit n (highestCommittableIndex m n)).isRetiredCommitted n <;> by_cases role : m.role = .primary
  all_goals first
    | left
      repeat' first | exact ⟨call,ng,ret,role,fr⟩ | exact Or.inl ⟨call,ng,ret,role,fr⟩
                    | exact ⟨call,ng,ret,fr⟩ | exact Or.inl ⟨call,ng,ret,fr⟩ | apply Or.inr
      done
    | right
      repeat' first | exact ⟨call,ng,ret,role,fr⟩ | exact Or.inl ⟨call,ng,ret,role,fr⟩
                    | exact ⟨call,ng,ret,fr⟩ | exact Or.inl ⟨call,ng,ret,fr⟩ | apply Or.inr

private theorem onAppend (b : Bool) (a : Leader.App c) : DirectCase c b := by
  obtain ⟨xs,ev⟩ := a
  obtain ⟨m,p,fr⟩ := sample c.actor b
  obtain ⟨e,z,out,co,eq,ran,f0,run⟩ := (Promotion.input_iff c (st := c.pre) (self := c.actor)).mpr
    ⟨fresh c ev,rfl,rfl,ev⟩
  exact directSupply c (.inl (.inl ⟨_,⟨_,e,z,out,co,eq,ran,f0,run⟩,xs,rfl,rfl,fr⟩)) fr p

private theorem direct_iff (b : Bool) : DirectCase c b ↔ ¬Now f c.actor c.post ∧ directTest b c.actor c.pre c.event := by
  constructor
  · rintro ⟨m,n,site,p⟩
    have call : Fold.LeftCall c m n ∨ Fold.RightCall c m n := by
      repeat' (change _ ∨ _ at site; rcases site with site | site)
      all_goals first | exact .inl site.1 | exact .inr site.1
    rcases call with (⟨_,co,xs,rfl,_⟩ | ⟨z,src,_,rfl⟩) | ack
    · obtain ⟨fr,rfl,ev⟩ := Fold.inputs c co
      exact ⟨fr,by simp [directTest,ev,Fold.appends]⟩
    · obtain ⟨fr,rfl,eq,e⟩ := (Promotion.primary_iff c).mp (.inr src)
      exact ⟨fr,by simp [directTest,eq,e,pick_iff.mpr p]⟩
    · rcases Fold.from_ack c ack with ⟨fr,rfl,eq⟩ | ⟨z,src,rfl⟩
      · exact ⟨fr,by simp [directTest,eq,pick_iff.mpr p]⟩
      · obtain ⟨fr,rfl,eq,e⟩ := (Promotion.primary_iff c).mp src
        exact ⟨fr,by simp [directTest,eq,e,pick_iff.mpr p]⟩
  · rintro ⟨fr,h⟩
    simp only [directTest,Bool.or_eq_true,Option.any_eq_true,Bool.and_eq_true,decide_eq_true_eq,pick_iff] at h
    rcases h with (app | ⟨m,eq,g⟩) | ⟨z,eq,e,g⟩
    · cases ev : c.event with
      | internal i => cases i <;> simp only [ev,Fold.appends] at app <;> try contradiction
                      exact onAppend c b ⟨_,ev⟩
      | receive => simp [ev,Fold.appends] at app
    · obtain ⟨call,fm⟩ := Fold.to_ack c fr eq
      exact directSupply c (.inr call) fm g
    · obtain ⟨_,fz⟩ := Promotion.cast_of c fr eq
      obtain call | call := (Promotion.primary_iff c).mpr ⟨fr,rfl,eq,e⟩
      · exact directSupply c (.inr (.inr ⟨z,call,fz,rfl⟩)) (fz.promotedLog.of_log rfl rfl) g
      · exact directSupply c (.inl (.inr ⟨z,call,fz,rfl⟩)) (fz.promotedLog.of_log rfl rfl) g

private theorem ack_iff (b : Bool) : ackTest b c.actor c.pre c.event c.post = true ↔ Leader.Ack c (Pick b) := by
  unfold Leader.Ack
  cases c.event with
  | internal => simp [ackTest]
  | receive n m => cases m <;> simp [ackTest,pick_iff] <;> grind
end

def exactReader (b : Bool) : Exact (column b) where
  eval := reader b
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    have live := Bool.eq_iff_iff.mp (Loop.cons.eq_label s)
    rw [label_true,holds,sig_iff] at live
    change step_fromLeader_loop_entries_cons _ _ c ↔ _ at live
    rw [Loop.Equiv.step_fromLeader_loop_entries_cons] at live
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.or_eq_true,Bool.or_eq_true,←live,Promotion.gated_iff,←direct_iff,
      SummaryRows.gated,Bool.and_eq_true,HandReadersBGate.live,actorRead_at,ack_iff]
    have h : sig c (column b) ↔ Tickets c b := by
      cases b <;> first | exact positive_iff .. | exact negative_iff ..
    rw [h,show Tickets c b ↔ Classes c b from ⟨necessary c b,sufficient c b⟩,Classes,
      Leader.working_iff s (Pick b) (fun _ _ h=>h.1)]
    constructor
    · rintro (lo | direct | ⟨yes,⟨app,_⟩ | ack⟩)
      · exact .inl (.inl lo)
      · exact .inl (.inr direct)
      · exact .inl (.inr (onAppend c b app))
      · exact .inr ⟨ack,yes⟩
    · rintro ((lo | direct) | ⟨ack,yes⟩)
      · exact .inl lo
      · exact .inr (.inl direct)
      · exact .inr (.inr ⟨yes,.inr ack⟩)

end ConsensusCoverage.HandReadersTrunkD.Record
