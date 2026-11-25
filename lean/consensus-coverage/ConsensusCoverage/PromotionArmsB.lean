module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.SelfQuorumCasesB
import all ConsensusCoverage.ReceiveCasesB
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.PromotionArmsB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile ReadersAtoms SolvedWitnesses DeepSchedulesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} {c : Ctx f t}

private theorem selfCases (s : SelfQuorumCasesB.Seed c) :
    step_becomeCandidate_sends_elected_inl f t c ∧ step_becomeCandidate_sends_elected_inr f t c := by
  have empty {P : Model.Envelope → Prop} : ∀ e ∈ ([] : List Model.Envelope), P e :=
    fun _ h => (List.not_mem_nil h).elim
  have adv : Advance s.self s.leader s.leader := Or.inl rfl
  have elected := And.intro (show s.fresh.role = .candidate from rfl)
    (And.intro s.quorum (And.intro adv (empty (P := LeaderStart s.self s.fresh.currentTerm s.leader))))
  constructor
  all_goals iterate 6 right
  all_goals left
  · exact ⟨_, _, s.campaign, Or.inl trivial, [], empty⟩
  · exact ⟨_, _, s.campaign, s.leader, [], Or.inr elected, [], empty, elected⟩

private abbrev candidate (s : NodeState) (n : NodeID) := {s with votesGranted := insert n s.votesGranted}

private theorem responseCases {x : XView} (ok : x.Matches c) (changed : x.base.changed = true)
    (n : NodeID) (q : RequestVoteResponse) (ev : x.event = .receive n (.requestVoteResponse q))
    (peer : n ∈ eligiblePeers x.base.pre x.base.actor)
    (g : x.base.pre.role = .candidate ∧ q.term = x.base.pre.currentTerm ∧ q.voteGranted = true)
    (quorum : hasQuorum (candidate x.base.pre n).activeConfigurations (candidate x.base.pre n).votesGranted)
    (live : ¬(candidate x.base.pre n).isRetiredCommitted x.base.actor)
    (canSend : n ∈ (eligiblePeers (primaryState (candidate x.base.pre n)) x.base.actor).sort)
    (other : n ≠ x.base.actor) :
    step_elect_result_elected_inl f t c ∧ step_elect_result_elected_inr f t c ∧ step_sentIndex_advance_inl f t c := by
  let self := x.base.actor
  let before := x.base.pre
  let mid := candidate before n
  let leader := primaryState mid
  let event := Event.receive n (.requestVoteResponse q)
  have caller : (reach% step_elect_result_elected_inl[6,1]) f t c self before n q :=
    ⟨x.event, ⟨t, c.tr, ReceiveCasesB.changedSummary ok changed, (X.tr_actor_eq ok).symm,
      (X.tr_pre_eq ok).symm, (X.tr_event_eq ok).symm⟩, _, ev, ev, rfl⟩
  have pass : ¬(True ∧ ¬n ∈ eligiblePeers before self) := fun h => h.2 peer
  obtain raised | obs := observe_bumping before (message := .requestVoteResponse q) trivial
  · exact absurd raised.1 (Nat.not_lt_of_ge (Nat.le_of_eq g.2.1))
  have camp : Campaign self before event mid := by
    refine ⟨g.1, rfl, rfl, Or.inr ⟨g.1, rfl, Or.inl rfl, ?_⟩⟩
    intro voter got
    rcases CCF.Finset.mem_insert.mp got with rfl | old
    · exact Or.inr ⟨q, rfl, g.2⟩
    · exact Or.inl old
  have empty {P : Model.Envelope → Prop} : ∀ e ∈ ([] : List Model.Envelope), P e :=
    fun _ h => (List.not_mem_nil h).elim
  have adv : Advance self leader leader := Or.inl rfl
  have win := And.intro g.1 (And.intro quorum (And.intro adv (empty (P := LeaderStart self mid.currentTerm leader))))
  have wait : (reach% step_elect_result_elected_inl[6]) f t c self mid mid [] :=
    Or.inr ⟨before, n, q, caller, pass, obs, obs.1, obs.2, g, Or.inl ⟨rfl, rfl⟩, camp, rfl⟩
  have won : (reach% step_elect_result_elected_inl[6]) f t c self mid leader [] :=
    Or.inr ⟨before, n, q, caller, pass, obs, obs.1, obs.2, g, Or.inr win, camp, rfl⟩
  have primary : (reach% step_sentIndex_advance_inl[6,1]) f t c self mid :=
    ⟨Or.inl ⟨before, n, q, caller, pass, obs, obs.1, obs.2, g, camp, rfl⟩, g.1, quorum, live⟩
  refine ⟨?_, ?_, ?_⟩
  all_goals iterate 6 right
  all_goals left
  · exact ⟨self, mid, wait, Or.inl trivial⟩
  · exact ⟨self, mid, leader, [], won, win, win.1, win.2, quorum, win.2.2, adv, empty, Or.inr win⟩
  · exact ⟨self, leader, Or.inr (.inl ⟨mid, primary, [], ⟨adv, empty⟩, adv, empty, n, canSend,
      _, .head _, other, rfl⟩), adv⟩

end

public def questions : List Classes.StepBranch :=
  [.becomeCandidate_sends_elected_inl, .becomeCandidate_sends_elected_inr,
   .elect_result_elected_inl, .elect_result_elected_inr, .sentIndex_advance_inl]

public theorem occurs {b : Classes.StepBranch} (mem : b ∈ questions) :
    ∃ s : Step, label s (.step b) = true := by
  change b ∈ [_, _] ++ [_, _, _] at mem
  rcases List.mem_append.mp mem with self | vote
  · let a := ReceiveCasesB.asSample soloCampaign 5 (by decide +kernel) (by decide +kernel)
    letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
    obtain ⟨s⟩ := SelfQuorumCasesB.seedOf (c := a.s.context) (x := a.x) a.ok
      (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel)
    obtain ⟨l, r⟩ := selfCases s
    refine ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr ?_)⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at self
    rcases self with rfl | rfl <;> assumption
  · let a := ReceiveCasesB.asSample campaign 5 (by decide +kernel) (by decide +kernel)
    letI : Config.InitialConfiguration := ⟨a.s.cfg⟩
    obtain ⟨l, r, sent⟩ := responseCases (c := a.s.context) (x := a.x) a.ok (by decide +kernel)
      0 (ReceiveCasesB.response (ReceiveCasesB.msg a.x.event))
      (by decide +kernel) (by decide +kernel) (by decide +kernel) (by decide +kernel)
      (by decide +kernel) (by decide +kernel) (by decide +kernel)
    refine ⟨a.s, (label_true a.s _).mpr ((sig_iff a.s.context _).mpr ?_)⟩
    simp only [List.mem_cons, List.not_mem_nil, or_false] at vote
    rcases vote with rfl | rfl | rfl <;> assumption

end ConsensusCoverage.PromotionArmsB
