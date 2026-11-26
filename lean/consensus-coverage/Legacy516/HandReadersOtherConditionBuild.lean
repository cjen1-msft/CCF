module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherConditionOnly
import all ConsensusCoverage.HandReadersOtherConditionBase
import all ConsensusCoverage.HandReadersOtherPromotion
import all ConsensusCoverage.AckAdvance
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.AssistReplyA
import all ConsensusCoverage.AssistConflictA
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersOther.Condition

open CCF Consensus Model Model.Node Proofs Safety Direct ActionProfile HandReadersA SolvedWitnesses
set_option maxRecDepth 8192
set_option maxHeartbeats 1400000

private theorem good (pos : Bool) {p : Prop} {m n : NodeEffect NodeState}
    (cut : Picks pos p) (keeps : if pos then Keeps CommitFrontier m else Keeps CommitFrontier n) :
    (p → Keeps CommitFrontier m) ∧ (¬p → Keeps CommitFrontier n) := by
  cases pos
  · exact ⟨fun h => (cut h).elim,fun _ => keeps⟩
  · exact ⟨fun _ => keeps,fun h => (h cut).elim⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev Remote (p : Prop) (m n : NodeEffect NodeState) := (reach% step_ite__condition_pos[0]) f t c p m n
private abbrev Here (p : Prop) (m n : NodeEffect NodeState) := (reach% step_ite__condition_pos[1]) f t c p m n

private theorem make {p m n} (r : Remote c p m n ∨ Here c p m n) (pos : Bool) (cut : Picks pos p)
    (keeps : if pos then Keeps CommitFrontier m else Keeps CommitFrontier n) : sig c (column pos) := by
  have g := good pos cut keeps
  cases pos <;> rcases r with r | r
  all_goals first | exact .inl ⟨p,m,n,r,cut,g⟩ | exact .inr ⟨p,m,n,r,cut,g⟩

private theorem receiveOuter {src msg} (fresh : Fresh c) (ev : c.event = .receive src msg)
    (pos : Bool) (cut : Picks pos (blocked c.actor c.pre src msg)) : sig c (column pos) := by
  let caps : Caps := Capabilities.record c.actor
  have co : Receive c caps c.actor c.pre src msg := (receive_iff c).mpr ⟨fresh,rfl,rfl,ev,rfl⟩
  have fr := c.inv.frontier _ _ c.pre_now
  have seen : CommitFrontier (observeTerm c.pre msg) := fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
  apply make c (pos := pos) (cut := cut)
  · left; unfold Remote
    iterate 7 right
    left; exact ⟨caps,c.actor,c.pre,src,msg,co,fr,seen,rfl,rfl,rfl⟩
  · cases pos
    · have h := fr.receive caps c.actor src msg
      unfold Model.Node.receive at h
      change Keeps CommitFrontier (if blocked c.actor c.pre src msg then _ else _) at h
      rwa [ite_eq_right cut] at h
    · exact Keeps.pure' fr

private theorem receiveInner {src msg} (fresh : Fresh c) (ev : c.event = .receive src msg)
    (pass : ¬blocked c.actor c.pre src msg) (yes : inner c.actor c.pre msg) : sig c (column true) := by
  let caps : Caps := Capabilities.record c.actor
  have co : Receive c caps c.actor c.pre src msg := (receive_iff c).mpr ⟨fresh,rfl,rfl,ev,rfl⟩
  have fr := c.inv.frontier _ _ c.pre_now
  have seen : CommitFrontier (observeTerm c.pre msg) := fr.of_log (Concrete.observeTerm_log ..) (Concrete.observeTerm_commitIndex ..)
  cases msg <;> simp only [inner,decide_eq_true_eq] at yes <;> try contradiction
  case appendEntriesResponse r =>
    let z := observeTerm c.pre (.appendEntriesResponse r)
    by_cases primary : z.role = .primary
    · have success := yes.resolve_left (not_not_intro primary)
      have role : ¬(z.role != .primary) = true := by simp [primary]
      apply make c (pos := true) (p := r.success = true) (cut := success)
      · left; unfold Remote; right; left
        exact ⟨caps,_,_,src,_,co,pass,r,rfl,pass,role,fr,seen,rfl,rfl,rfl⟩
      · change Keeps CommitFrontier (if r.term = z.currentTerm then _ else _)
        split
        · exact (seen.of_log (after := AckAdvance.middle z src r) rfl rfl).advanced c.actor caps
        · exact Keeps.pure' seen
    · have b : (z.role != .primary) = true := bne_iff_ne.mpr primary
      apply make c (pos := true) (p := (z.role != .primary) = true) (cut := b)
      · left; unfold Remote; iterate 2 right
        left; exact ⟨caps,_,_,src,_,co,pass,r,rfl,pass,fr,seen,rfl,rfl,rfl⟩
      · exact Keeps.pure' seen
  case requestVoteResponse r =>
    apply make c (pos := true) (p := _) (cut := yes)
    · left; unfold Remote; iterate 3 right
      left; exact ⟨caps,_,_,src,_,co,pass,r,rfl,pass,fr,seen,rfl,rfl,rfl⟩
    · exact (seen.of_log (after := Promotion.ballot (observeTerm c.pre (.requestVoteResponse r)) src) rfl rfl).electIfQuorum caps c.actor
  case requestPreVoteResponse r =>
    apply make c (pos := true) (p := _) (cut := yes)
    · left; unfold Remote; iterate 5 right
      left; exact ⟨caps,_,_,src,_,co,pass,r,rfl,pass,fr,seen,rfl,rfl,rfl⟩
    · change Keeps CommitFrontier (if _ then _ else _)
      split
      · exact (seen.of_log rfl rfl).becomeCandidate caps c.actor
      · exact Keeps.pure' (seen.of_log rfl rfl)
  case proposeRequestVoteRequest k =>
    apply make c (pos := true) (p := _) (cut := yes)
    · left; unfold Remote; iterate 6 right
      left; exact ⟨caps,_,_,src,_,co,pass,k,rfl,pass,fr,seen,rfl,rfl,rfl⟩
    · exact seen.becomeCandidate caps c.actor
  case appendEntriesRequest r =>
    let z := observeTerm c.pre (.appendEntriesRequest r)
    let w := AssistReplyA.prepared z r
    have ready : CommitFrontier w := by unfold w AssistReplyA.prepared; split <;> exact seen
    have req : (reach% step_ite__condition_pos[0,2]) f t c c.actor z r caps src :=
      ⟨c.pre,_,co,pass,rfl,pass,fr,seen,rfl⟩
    by_cases bad : reject z r
    · apply make c (pos := true) (p := reject z r) (cut := bad)
      · left; unfold Remote; iterate 12 right
        left; exact ⟨_,z,r,caps,src,req,seen,ready,rfl,rfl,rfl⟩
      · have h := seen.handleAppendEntriesRequest (self := c.actor) (request := r) caps src
        unfold Model.Node.handleAppendEntriesRequest at h
        rwa [ite_eq_left bad] at h
    · have b := yes.resolve_left bad
      apply make c (pos := true) (p := AssistConflictA.Bad z r) (cut := b)
      · left; unfold Remote; iterate 11 right
        left; exact ⟨_,z,r,caps,src,req,bad,seen,ready,rfl,rfl,rfl⟩
      · exact Keeps.pure' (ready.of_log rfl rfl)

private theorem atAppend {xs} (fresh : Fresh c) (ev : c.event = .internal (.append xs))
    (pos : Bool) : sig c (column pos) := by
  let caps : Caps := Capabilities.record c.actor
  have co : Local c caps c.actor (.append xs) := (local_iff c).mpr ⟨fresh,rfl,ev,rfl⟩
  have fr := c.inv.frontier _ _ c.pre_now
  let content : EntryContent := if pos then .signature else .transaction 0 {}
  have call : (reach% step_ite__condition_pos[1,0]) f t c caps c.actor c.pre content :=
    ⟨_,co,xs,rfl,rfl,⟨content,[]⟩,fr,rfl⟩
  have cut : Picks pos (content.isSignature = true) := by cases pos <;> decide
  apply make c (pos := pos) (cut := cut)
  · right; unfold Here; iterate 2 right
    left; exact ⟨caps,_,_,content,call,fr,rfl,rfl,rfl⟩
  · have h := fr.appendEntry caps c.actor content
    unfold Model.Node.appendEntry at h
    cases pos
    · simpa only [content,Bool.false_eq_true,ite_false,EntryContent.isSignature,pure_bind] using h
    · simpa only [content,ite_true,EntryContent.isSignature,pure_bind] using h

private theorem atTime (fresh : Fresh c) (ev : c.event = .internal (.timeout .election))
    (pos : Bool) (yes : test pos c.actor c.pre (.internal (.timeout .election))) : sig c (column pos) := by
  let caps : Caps := Capabilities.record c.actor
  have co : Timeout c caps c.actor c.pre := (timeout_iff c).mpr ⟨fresh,rfl,rfl,ev,rfl⟩
  have fr := c.inv.frontier _ _ c.pre_now
  by_cases q : Picks pos (timeQuorum c.actor c.pre)
  · apply make c (pos := pos) (cut := q)
    · right; unfold Here; iterate 6 right
      left; exact ⟨caps,_,_,co,fr,rfl,rfl,rfl⟩
    · cases pos
      · exact Keeps.seq' fun _ => Keeps.pure' (fr.of_log (after := firstVote c.actor c.pre) rfl rfl)
      · exact (fr.of_log (after := firstVote c.actor c.pre) rfl rfl).becomeCandidate caps c.actor
  · cases pos
    case true => exact (q (of_decide_eq_true yes)).elim
    case false =>
      have quorum := Classical.not_not.mp q
      have lose := (of_decide_eq_true yes).resolve_left q
      let z := firstVote c.actor c.pre
      let cand := freshCandidate c.actor z
      have co' : (reach% step_ite__condition_pos[1,3]) f t c caps c.actor cand :=
        ⟨z,⟨c.pre,co,quorum,fr,rfl⟩,fr,rfl⟩
      apply make c (pos := false) (p := Promotion.elects c.actor cand) (cut := lose)
      · right; unfold Here; iterate 7 right
        exact ⟨caps,_,cand,co',fr,rfl,rfl,rfl⟩
      · exact Keeps.pure' fr

theorem sufficient (pos : Bool) (a : Answer c pos) : sig c (column pos) := by
  obtain ⟨fresh,h⟩ := a
  cases ev : c.event with
  | internal i =>
    rw [ev] at h
    cases i <;> try contradiction
    case append => exact atAppend c fresh ev pos
    case timeout k => cases k <;> first | exact atTime c fresh ev pos h | contradiction
  | receive n m =>
    rw [ev] at h
    cases pos
    case false => exact receiveOuter c fresh ev false (of_decide_eq_true h)
    case true =>
      rcases Bool.or_eq_true_iff.mp h with b | inner
      · exact receiveOuter c fresh ev true (of_decide_eq_true b)
      · by_cases b : blocked c.actor c.pre n m
        · exact receiveOuter c fresh ev true b
        · exact receiveInner c fresh ev b inner
end

def exactReader (pos : Bool) : Exact (column pos) where
  eval := Promotion.gated (test pos)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,Promotion.gated_iff]
    exact ⟨necessary s.context pos,sufficient s.context pos⟩

end ConsensusCoverage.HandReadersOther.Condition
