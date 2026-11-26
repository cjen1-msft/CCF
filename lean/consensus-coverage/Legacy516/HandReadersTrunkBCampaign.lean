module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkBCandidate
import all ConsensusCoverage.HandReadersTrunkBCampaignOrigin
import all ConsensusCoverage.HandReadersTrunkBCampaignPack
import all ConsensusCoverage.HandReadersTrunkBElect
import all ConsensusCoverage.HandReadersASummary
import all ConsensusCoverage.HandReadersTrunkBFactor
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersTrunkBFactor
public meta import ConsensusCoverage.ProofWalk
public meta import ConsensusCoverage.PinnedClasses

namespace ConsensusCoverage.HandReadersTrunkB.CampaignRows

open Consensus Model Model.Node Proofs Safety ActionProfile HandReadersA HandReadersBGate SolvedWitnesses
open Lean Elab Command

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 3000000
set_option maxRecDepth 16384

inductive Kind where | wait | fresh | kept | win | role | nominate | ping | ballot

def column : Kind → Classes.StepBranch
  | .wait => .campaign_summary_result_inl
  | .fresh => .campaign_summary_campaign_inl
  | .kept => .campaign_summary_campaign_inr
  | .win => .campaign_summary_result_inr
  | .role => .campaign_summary_role_inl
  | .nominate => .campaign_summary_started_inl
  | .ping => .campaign_summary_started_inr_inl
  | .ballot => .campaign_summary_started_inr_inr

def needsWin : Kind → Bool | .wait | .fresh | .kept => false | _ => true
def admitsFresh : Kind → Bool | .kept => false | _ => true
def admitsKept : Kind → Bool | .fresh | .ballot => false | _ => true

def test (k : Kind) (self : NodeID) (st : NodeState) (ev : Event) (post : NodeState) : Bool :=
  (admitsFresh k && Candidate.test (needsWin k) self st ev post) ||
    (admitsKept k && Elect.test (needsWin k) self st ev post)

private def packed : Kind → Effect
  | .wait => Packed.step_campaign_summary_result_inl
  | .fresh => Packed.step_campaign_summary_campaign_inl
  | .kept => Packed.step_campaign_summary_campaign_inr
  | .win => Packed.step_campaign_summary_result_inr
  | .role => Packed.step_campaign_summary_role_inl
  | .nominate => Packed.step_campaign_summary_started_inl
  | .ping => Packed.step_campaign_summary_started_inr_inl
  | .ballot => Packed.step_campaign_summary_started_inr_inr

private theorem packed_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) (k : Kind) :
    sig c (column k) ↔ CampaignCall f t c (packed k) := by
  cases k
  all_goals first | apply PackIff.step_campaign_summary_result_inl | apply PackIff.step_campaign_summary_result_inr
                  | apply PackIff.step_campaign_summary_campaign_inl | apply PackIff.step_campaign_summary_campaign_inr
                  | apply PackIff.step_campaign_summary_role_inl | apply PackIff.step_campaign_summary_started_inl
                  | apply PackIff.step_campaign_summary_started_inr_inl | apply PackIff.step_campaign_summary_started_inr_inr

private def eligible (k : Kind) (before cand : NodeState) :=
  (before.currentTerm < cand.currentTerm → admitsFresh k = true) ∧
  (cand.currentTerm = before.currentTerm → admitsKept k = true) ∧
  (needsWin k = true → hasQuorum cand.activeConfigurations cand.votesGranted)

open Meta Elab.Term in
private meta partial def project (p h goal : Expr) : MetaM Expr := do
  let p := p.consumeMData.headBeta
  if p.isAppOf ``onCandidate then return ←project (←whnf p) h goal
  if p.getAppFn.constName? == goal.getAppFn.constName? && (←isDefEq p goal) then return h
  if p.isAppOf ``And then
    let (l,r) := ProofWalk.conjuncts p h
    return ← project l.1 l.2 goal <|> project r.1 r.2 goal
  if p.isAppOf ``Or then
    let arm (a : Expr) := withLocalDeclD `h a fun x => do mkLambdaFVars #[x] (←project a x goal)
    return ProofWalk.casesOr p h goal (←arm (p.getArg! 0)) (←arm p.appArg!)
  if p.isAppOf ``Exists then
    let f ←withLocalDeclD `x (p.getArg! 0) fun x => do
      let a := p.appArg!.beta #[x]
      withLocalDeclD `h a fun h => do mkLambdaFVars #[x,h] (←project a h goal)
    return ProofWalk.casesExists p h goal f
  throwError "no matching campaign guard"

open Meta Elab.Term in
local elab "from_guard% " h:ident : term <= t => do
  let val ← elabTerm h none
  project (←whnf (←inferType val)) val t

private theorem necessary {self before cand next ev sent} (k : Kind)
    (h : packed k self before cand next ev sent) : eligible k before cand := by
  cases k
  case wait => exact ⟨fun _ => rfl,fun _ => rfl,fun no => Bool.noConfusion no⟩
  case fresh =>
    have inc : cand.currentTerm = before.currentTerm + 1 := from_guard% h
    exact ⟨fun _ => rfl,fun same => (Nat.succ_ne_self _ (inc.symm.trans same)).elim,fun no => Bool.noConfusion no⟩
  case kept =>
    have same : cand.currentTerm = before.currentTerm := from_guard% h
    exact ⟨fun lt => (Nat.ne_of_lt lt same.symm).elim,fun _ => rfl,fun no => Bool.noConfusion no⟩
  case ballot =>
    have lt : before.currentTerm < cand.currentTerm := from_guard% h
    exact ⟨fun _ => rfl,fun same => (Nat.ne_of_lt lt same.symm).elim,fun _ => from_guard% h⟩
  all_goals exact ⟨fun _ => rfl,fun _ => rfl,fun _ => from_guard% h⟩

private theorem sufficient {self before cand ev} (k : Kind) (camp : Campaign self before ev cand)
    (ok : eligible k before cand) :
    ∃ next sent, CampaignResult self before cand next sent ∧ packed k self before cand next ev sent := by
  let pred := fun (e : Model.Envelope) => e.source = self ∧
    e.payload = .requestVoteRequest (makeRequestVoteRequest cand) ∧ before.currentTerm < cand.currentTerm
  have alts := camp.2.2.2
  have le : before.currentTerm ≤ cand.currentTerm := by rcases alts with h | h <;> have eq := h.2.1 <;> omega
  have active : Engaged before := by rcases alts with h | h; exact h.1; simp [Engaged,h.1]
  have notLeader : before.role = .primary → cand.currentTerm = before.currentTerm → False := by
    rcases alts with h | h
    · intro _ same; have incr := h.2.1; omega
    · simp [h.1]
  have preserve : cand.currentTerm = before.currentTerm → ∀ n, before.votedFor = some n → cand.votedFor = some n := by
    rcases alts with h | h
    · intro same; have incr := h.2.1; omega
    · rcases h.2.2.1 with eq | no <;> simp [*]
  have empty : ∀ e ∈ [], pred e := by simp
  have wait : CampaignResult self before cand cand [] := .inl ⟨rfl,empty⟩
  cases k
  · exact ⟨cand,[],wait,rfl,empty,empty,camp,wait,le,active,notLeader,preserve⟩
  · have fresh := alts.resolve_right (fun h => Bool.noConfusion (ok.2.1 h.2.1))
    exact ⟨cand,[],wait,.inl ⟨rfl,empty,empty,camp,le,notLeader,preserve,empty,fresh,camp,wait,active,notLeader,preserve⟩⟩
  · have kept := alts.resolve_left (fun h => Bool.noConfusion (ok.1 (h.2.1 ▸ Nat.lt_succ_self _)))
    exact ⟨cand,[],wait,.inl ⟨rfl,empty,empty,camp,le,notLeader,preserve,empty,kept,camp,wait,active,notLeader,preserve⟩⟩
  all_goals
    let leader := primaryState cand
    let nom := SelfQuorumCasesB.successor self cand.currentTerm
    let ping := SelfQuorumCasesB.heartbeat self leader
    have nq : LeaderStart self cand.currentTerm leader nom := .inl ⟨rfl,rfl⟩
    have beat := SelfQuorumCasesB.beat self leader
    have pq : LeaderStart self cand.currentTerm leader ping := .inr beat
    have adv : Advance self leader leader := .inl rfl
    have won : Wins self before ev leader := ⟨cand,camp,ok.2.2 rfl,adv⟩
    have notCand : leader.role ≠ .candidate := fun h => Role.noConfusion h
    have send : ∀ e ∈ [nom,ping], LeaderStart self cand.currentTerm leader e ∨ pred e := by
      intro e mem
      simp only [List.mem_cons,List.not_mem_nil,or_false] at mem
      rcases mem with rfl | rfl
      · exact .inl nq
      · exact .inl pq
    have ready := And.intro (ok.2.2 rfl) (And.intro adv send)
    have result : CampaignResult self before cand leader [nom,ping] := .inr ready
  · exact ⟨leader,_,result,ready,ready.1,ready.2,adv,send,camp,result,le,active,notLeader,preserve⟩
  · obtain ⟨req,payload,valid⟩ := beat.ok
    exact ⟨leader,_,result,.inr (.inl ⟨ready,ready.1,ready.2,adv,send,ping,.tail _ (.head _),pq,beat,
      req,⟨payload,valid⟩,payload,valid,rfl,camp,result,le,active,notLeader,preserve,adv,rfl,won⟩)⟩
  · exact ⟨leader,_,result,ready,ready.1,ready.2,adv,send,nom,.head _,nq,⟨rfl,rfl⟩,rfl,rfl,camp,result,le,
      active,notLeader,preserve,adv,rfl,won,notCand⟩
  · exact ⟨leader,_,result,ready,ready.1,ready.2,adv,send,ping,.tail _ (.head _),pq,beat,camp,result,le,
      active,notLeader,preserve,adv,rfl,won,notCand⟩
  · let ballot := SelfQuorumCasesB.ballot self cand
    have lt := Nat.lt_of_le_of_ne le (fun eq => Bool.noConfusion (ok.2.1 eq.symm))
    have v : pred ballot := ⟨rfl,rfl,lt⟩
    have s : ∀ e ∈ [ballot], LeaderStart self cand.currentTerm leader e ∨ pred e :=
      SelfQuorumCasesB.singleton (.inr v)
    have r := And.intro (ok.2.2 rfl) (And.intro adv s)
    have result' : CampaignResult self before cand leader [ballot] := .inr r
    exact ⟨leader,_,result',r,r.1,r.2,adv,s,ballot,.head _,v,v.1,v.2,v.2.1,v.2.2,camp,result',le,
      active,notLeader,preserve,adv,rfl,won,notCand⟩

private theorem site_test (k : Kind) (self before ev post) :
    (∃ cand, Origin self before ev cand ∧ eligible k before cand) ↔ test k self before ev post = true := by
  rw [test,Bool.or_eq_true,Bool.and_eq_true,Bool.and_eq_true,←Candidate.guard_iff,←Elect.guard_iff]
  constructor
  · rintro ⟨cand,o,ok⟩
    cases o with
    | fresh h => exact .inl ⟨ok.1 (Nat.lt_succ_self _),h,ok.2.2⟩
    | kept n q ev peer g => exact .inr ⟨ok.2.1 rfl,n,q,ev,peer,g,ok.2.2⟩
  · rintro (⟨admit,h,w⟩ | ⟨admit,n,q,ev,peer,g,w⟩)
    · exact ⟨_,.fresh h,fun _ => admit,fun h => (Nat.succ_ne_self _ h).elim,w⟩
    · exact ⟨_,.kept n q ev peer g,fun h => (Nat.lt_irrefl _ h).elim,fun _ => admit,w⟩

def exactReader (k : Kind) : Exact (column k) where
  eval := SummaryRows.gated (test k)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    apply Bool.eq_iff_iff.mpr
    rw [label_true,show holds s (.step (column k)) ↔ sig c (column k) from sig_iff _ _,packed_iff,
      HandReadersTrunkBFactor.Exact.CampaignCall _ _ _ _ (quiet s),origin_iff,
      SummaryRows.gated,Bool.and_eq_true,actorRead_at,live,and_comm,←site_test]
    constructor
    · rintro ⟨⟨cand,o,_,_,_,h⟩,src⟩
      exact ⟨⟨cand,o,necessary k h⟩,src⟩
    · rintro ⟨⟨cand,o,ok⟩,src⟩
      exact ⟨⟨cand,o,sufficient k o.campaign ok⟩,src⟩

end ConsensusCoverage.HandReadersTrunkB.CampaignRows
