module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CampaignCasesB
import all ConsensusCoverage.CampaignCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.SelfQuorumCasesB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 500000

private def pre (self : NodeID) (s : NodeState) :=
  {s with role := .preVoteCandidate, primaryKnown := false, preVotesGranted := {self}}

private def successor (self : NodeID) (term : Nat) : Model.Envelope :=
  ⟨self, self+1, .proposeRequestVoteRequest term⟩

private def ballot (self : NodeID) (s : NodeState) : Model.Envelope :=
  ⟨self, self+1, .requestVoteRequest (makeRequestVoteRequest s)⟩

private def heartbeat (self : NodeID) (s : NodeState) : Model.Envelope :=
  ⟨self, self+1, .appendEntriesRequest ⟨s.currentTerm, 0, termAt s.log 0, [], 0⟩⟩

private theorem beat (self : NodeID) (s : NodeState) :
    AEFrom self s.currentTerm s.commitIndex s.log (heartbeat self s) :=
  ⟨rfl, Nat.succ_ne_self _, _, rfl, rfl, Nat.zero_le _, rfl, List.nil_prefix, Nat.zero_le _⟩

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private structure Seed (c : Ctx f t) where
  self : NodeID
  before : NodeState
  timeout : (reach% step_canStartElection_engaged_can_inl[6,1]) f t c self before
  can : canStartElection before self
  quorum : hasQuorum before.activeConfigurations {self}

private theorem seedOf {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .internal (.timeout .election))
    (can : canStartElection x.base.pre x.base.actor) (q : hasQuorum x.base.pre.activeConfigurations {x.base.actor}) :
    Nonempty (Seed c) := by
  exact ⟨⟨x.base.actor, x.base.pre, ⟨x.event, CampaignCasesB.entry ok changed, _, ev, ev, rfl⟩, can, q⟩⟩

private abbrev Seed.state (s : Seed c) := pre s.self s.before
private abbrev Seed.fresh (s : Seed c) := freshCandidate s.self s.state
private abbrev Seed.leader (s : Seed c) := primaryState s.fresh

private theorem Seed.entry (s : Seed c) :
    (reach% step_becomeCandidate_result_started_inl[6]) f t c s.self s.state s.before :=
  Or.inr (.inl ⟨s.timeout, s.can, s.can, s.can, s.quorum, canStartElection_engaged s.can, rfl⟩)

private theorem Seed.campaign (s : Seed c) :
    (reach% step_becomeCandidate_sends_mem_append_inl[6]) f t c s.self s.state :=
  ⟨s.before, s.entry, rfl⟩

private theorem Seed.promotion (s : Seed c) :
    (reach% step_becomePrimary_sends_mem_append_inl[6]) f t c s.self s.fresh :=
  ⟨Or.inr ⟨s.state, s.campaign, rfl⟩, rfl, s.quorum, s.can.2.2⟩

omit [Config.InitialConfiguration] in
private theorem singleton {α : Type} {e : α} {P : α → Prop}
    (h : P e) : ∀ a ∈ [e], P a := by simpa using h

-- The postcondition quantifies output lists; it does not assert that these
-- same lists were the recorded outgoing messages. Supply one of each kind.
local macro "outputs " s:ident : tactic => `(tactic|
  (let nom := successor ($s).self ($s).fresh.currentTerm
   let vote := ballot ($s).self ($s).fresh
   let ping := heartbeat ($s).self ($s).leader
   have adv : Advance ($s).self ($s).leader ($s).leader := Or.inl rfl
   have nomOK : ∀ e ∈ [nom], e.source = ($s).self ∧
       e.payload = .proposeRequestVoteRequest ($s).fresh.currentTerm := singleton ⟨rfl, rfl⟩
   have start : ∀ e ∈ [nom], LeaderStart ($s).self ($s).fresh.currentTerm ($s).leader e :=
     fun e h => Or.inl (nomOK e h)
   have vs : ∀ e ∈ [vote], e.source = ($s).self ∧ ¬e.target = ($s).self ∧
       e.payload = .requestVoteRequest (makeRequestVoteRequest ($s).fresh) :=
     singleton ⟨rfl, Nat.succ_ne_self _, rfl⟩
   have ae : ∀ e ∈ [ping], AEFrom ($s).self ($s).leader.currentTerm
     ($s).leader.commitIndex ($s).leader.log e := singleton (beat _ _)
   iterate 6 right
   left
   first
   | (refine ⟨($s).self, ($s).fresh, ($s).promotion, ($s).leader, [nom], ⟨adv, nomOK⟩,
        adv, nomOK, [ping], ae, ?_⟩
      first | exact ⟨nom, .head _, .head _⟩ | exact ⟨ping, .tail _ (.head _), .head _⟩)
   | (have done := And.intro (show ($s).fresh.role = .candidate from rfl)
        (And.intro ($s).quorum (And.intro adv start))
      refine ⟨($s).self, ($s).state, ($s).campaign, ($s).leader, [nom], Or.inr done,
        [vote], vs, done, done.1, done.2, done.2.1, done.2.2, adv, start, ?_⟩
      first | exact ⟨nom, .head _, .head _⟩ | exact ⟨vote, .tail _ (.head _), .head _⟩)))

private theorem output_cases (s : Seed c) :
    step_becomeCandidate_sends_mem_append_inl f t c ∧ step_becomeCandidate_sends_mem_append_inr f t c ∧
    step_becomePrimary_sends_mem_append_inl f t c ∧ step_becomePrimary_sends_mem_append_inr f t c := by
  refine ⟨?_, ?_, ?_, ?_⟩ <;> outputs s

private theorem result_cases (s : Seed c) :
    step_becomeCandidate_result_done_inl f t c ∧ step_becomeCandidate_result_done_inr f t c ∧
    step_becomeCandidate_result_started_inl f t c ∧ step_becomeCandidate_result_started_inr f t c := by
  let nom := successor s.self s.fresh.currentTerm
  let req := ballot s.self s.fresh
  let vote (e : Model.Envelope) := e.source = s.self ∧ e.payload = .requestVoteRequest (makeRequestVoteRequest s.fresh)
  have v : vote req := ⟨rfl, rfl⟩
  have start : LeaderStart s.self s.fresh.currentTerm s.leader nom := Or.inl ⟨rfl, rfl⟩
  have both : ∀ e ∈ [nom, req], LeaderStart s.self s.fresh.currentTerm s.leader e ∨ vote e := by
    intro e h
    simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl
    · exact Or.inl start
    · exact Or.inr v
  have adv : Advance s.self s.leader s.leader := Or.inl rfl
  have ready := And.intro s.quorum (And.intro adv both)
  have noVotes : ∀ e ∈ [], vote e := fun _ h => False.elim (List.not_mem_nil h)
  have lt : s.before.currentTerm < s.fresh.currentTerm := Nat.lt_succ_self _
  refine ⟨?_, ?_, ?_, ?_⟩
  all_goals iterate 6 right
  all_goals left
  · exact ⟨s.self, s.state, s.before, s.entry, [], Or.inl noVotes, noVotes, noVotes, rfl, lt⟩
  all_goals refine ⟨s.self, s.state, s.before, s.entry, s.leader, [nom, req], Or.inr ready,
    ready, ready.1, ready.2, adv, both, ?_⟩
  · exact ⟨rfl, lt⟩
  · exact ⟨nom, .head _, start, rfl, lt⟩
  · exact ⟨req, .tail _ (.head _), v, v.1, v.2, rfl, lt⟩

private theorem Seed.summary (s : Seed c) {next : NodeState} {sent : List Model.Envelope}
    (result : CampaignResult s.self s.before s.fresh next sent) :
    (reach% step_campaign_summary_result_inr[6]) f t c s.self s.before s.fresh next
      (.internal (.timeout .election)) sent :=
  Or.inr (.inl ⟨s.timeout, s.can, s.can, s.can, s.quorum, sent, result,
    canStartElection_engaged s.can, rfl, rfl, rfl⟩)

private theorem summaries (s : Seed c) :
    step_campaign_summary_result_inl f t c ∧ step_campaign_summary_campaign_inl f t c ∧
    step_campaign_summary_result_inr f t c ∧ step_campaign_summary_role_inl f t c ∧
    step_campaign_summary_started_inl f t c ∧ step_campaign_summary_started_inr_inl f t c ∧
    step_campaign_summary_started_inr_inr f t c := by
  let ev : Event := .internal (.timeout .election)
  let nom := successor s.self s.fresh.currentTerm
  let ping := heartbeat s.self s.leader
  let req := ballot s.self s.fresh
  let vote (e : Model.Envelope) := e.source = s.self ∧
    e.payload = .requestVoteRequest (makeRequestVoteRequest s.fresh) ∧ s.before.currentTerm < s.fresh.currentTerm
  have active := canStartElection_engaged s.can
  have camp : Campaign s.self s.before ev s.fresh := fresh_campaign active rfl rfl rfl
  have le : s.before.currentTerm ≤ s.fresh.currentTerm := Nat.le_succ _
  have ne : s.fresh.currentTerm ≠ s.before.currentTerm := Nat.succ_ne_self _
  have notLeader : s.before.role = .primary → s.fresh.currentTerm = s.before.currentTerm → False := fun _ => ne
  have keep : s.fresh.currentTerm = s.before.currentTerm → ∀ n, s.before.votedFor = some n →
      s.fresh.votedFor = some n := fun h => (ne h).elim
  have v : vote req := ⟨rfl, rfl, Nat.lt_succ_self _⟩
  have n : LeaderStart s.self s.fresh.currentTerm s.leader nom := Or.inl ⟨rfl, rfl⟩
  have p : LeaderStart s.self s.fresh.currentTerm s.leader ping := Or.inr (beat _ _)
  have sends : ∀ e ∈ [nom, ping, req], LeaderStart s.self s.fresh.currentTerm s.leader e ∨ vote e := by
    intro e h
    simp only [List.mem_cons, List.not_mem_nil, or_false] at h
    rcases h with rfl | rfl | rfl
    · exact Or.inl n
    · exact Or.inl p
    · exact Or.inr v
  have adv : Advance s.self s.leader s.leader := Or.inl rfl
  have ready := And.intro s.quorum (And.intro adv sends)
  have won : CampaignResult s.self s.before s.fresh s.leader [nom, ping, req] := Or.inr ready
  have wins : Wins s.self s.before ev s.leader := ⟨s.fresh, camp, s.quorum, adv⟩
  have notCand : s.leader.role ≠ .candidate := fun h => Role.noConfusion h
  have empty : ∀ e ∈ [], vote e := fun _ h => False.elim (List.not_mem_nil h)
  have waiting : CampaignResult s.self s.before s.fresh s.fresh [] := Or.inl ⟨rfl, empty⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals first | (guard_target =ₛ step_campaign_summary_role_inl f t c; iterate 25 right) | skip
  all_goals iterate 6 right
  all_goals left
  · exact ⟨_, _, _, ev, [], s.summary waiting, empty, empty, camp, waiting, le, active, notLeader, keep⟩
  · refine ⟨_, _, _, ev, [], s.summary waiting, empty, empty, ?_⟩
    repeat' first | assumption | rfl | apply And.intro
  all_goals refine ⟨_, _, _, _, ev, _, s.summary won, ready, ready.1, ready.2, adv, sends, ?_⟩
  · exact ⟨camp, won, le, active, notLeader, keep⟩
  · obtain ⟨request, payload, ok⟩ := (beat s.self s.leader).ok
    exact ⟨ping, .tail _ (.head _), p, beat _ _, request, ⟨payload, ok⟩, payload, ok,
      rfl, camp, won, le, active, notLeader, keep, adv, rfl, wins⟩
  · exact ⟨nom, .head _, n, ⟨rfl, rfl⟩, rfl, rfl, camp, won, le, active, notLeader,
      keep, adv, rfl, wins, notCand⟩
  · exact ⟨ping, .tail _ (.head _), p, beat _ _, camp, won, le, active, notLeader,
      keep, adv, rfl, wins, notCand⟩
  · exact ⟨req, .tail _ (.tail _ (.head _)), v, v.1, v.2, v.2.1, v.2.2, camp, won,
      le, active, notLeader, keep, adv, rfl, wins, notCand⟩

end

public def questions : List Classes.StepBranch :=
  [.becomeCandidate_sends_mem_append_inl, .becomeCandidate_sends_mem_append_inr,
   .becomePrimary_sends_mem_append_inl, .becomePrimary_sends_mem_append_inr,
   .becomeCandidate_result_done_inl, .becomeCandidate_result_done_inr,
   .becomeCandidate_result_started_inl, .becomeCandidate_result_started_inr,
   .campaign_summary_result_inl, .campaign_summary_campaign_inl, .campaign_summary_result_inr,
   .campaign_summary_role_inl, .campaign_summary_started_inl, .campaign_summary_started_inr_inl,
   .campaign_summary_started_inr_inr]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample soloCampaign 5 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  let c := a.s.context
  have ⟨seed⟩ := seedOf (c := c) (x := a.x) a.ok (by decide +kernel) (by decide +kernel)
    (by decide +kernel) (by decide +kernel)
  obtain ⟨l, r, nl, nr⟩ := output_cases seed
  obtain ⟨cl, cr, sl, sr⟩ := result_cases seed
  obtain ⟨rl, fl, rr, role, nom, ping, vote⟩ := summaries seed
  refine ⟨a.s, (label_true a.s (.step b)).mpr ((sig_iff c b).mpr ?_)⟩
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    assumption

end ConsensusCoverage.SelfQuorumCasesB
