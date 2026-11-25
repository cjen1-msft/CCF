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
  entry : (reach% step_becomeCandidate_result_started_inl[6]) f t c self (pre self before) before
  quorum : hasQuorum before.activeConfigurations {self}
  member : ¬before.isRetiredCommitted self

private theorem seedOf {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
    (ev : x.event = .internal (.timeout .election))
    (can : canStartElection x.base.pre x.base.actor) (q : hasQuorum x.base.pre.activeConfigurations {x.base.actor}) :
    Nonempty (Seed c) := by
  refine ⟨⟨x.base.actor, x.base.pre, ?_, q, can.2.2⟩⟩
  right; left
  exact ⟨⟨x.event, CampaignCasesB.entry ok changed, _, ev, ev, rfl⟩,
    can, can, can, q, canStartElection_engaged can, rfl⟩

private abbrev Seed.state (s : Seed c) := pre s.self s.before
private abbrev Seed.fresh (s : Seed c) := freshCandidate s.self s.state
private abbrev Seed.leader (s : Seed c) := primaryState s.fresh

private theorem Seed.campaign (s : Seed c) :
    (reach% step_becomeCandidate_sends_mem_append_inl[6]) f t c s.self s.state :=
  ⟨s.before, s.entry, rfl⟩

private theorem Seed.promotion (s : Seed c) :
    (reach% step_becomePrimary_sends_mem_append_inl[6]) f t c s.self s.fresh :=
  ⟨Or.inr ⟨s.state, s.campaign, rfl⟩, rfl, s.quorum, s.member⟩

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

end

public def questions : List Classes.StepBranch :=
  [.becomeCandidate_sends_mem_append_inl, .becomeCandidate_sends_mem_append_inr,
   .becomePrimary_sends_mem_append_inl, .becomePrimary_sends_mem_append_inr,
   .becomeCandidate_result_done_inl, .becomeCandidate_result_done_inr,
   .becomeCandidate_result_started_inl, .becomeCandidate_result_started_inr]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  let a := ReceiveCasesB.asSample soloCampaign 5 (by decide +kernel) (by decide +kernel)
  letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
  let c := a.s.context
  have ⟨seed⟩ := seedOf (c := c) (x := a.x) a.ok (by decide +kernel) (by decide +kernel)
    (by decide +kernel) (by decide +kernel)
  obtain ⟨l, r, nl, nr⟩ := output_cases seed
  obtain ⟨cl, cr, sl, sr⟩ := result_cases seed
  refine ⟨a.s, (label_true a.s (.step b)).mpr ((sig_iff c b).mpr ?_)⟩
  simp only [questions, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> assumption

end ConsensusCoverage.SelfQuorumCasesB
