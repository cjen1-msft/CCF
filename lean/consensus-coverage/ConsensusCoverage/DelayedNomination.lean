module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.DelayedNominationRead
public import ConsensusCoverage.DelayedNominationSuccessor
import all ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.DelayedNominationPrune
import all ConsensusCoverage.DelayedNominationArms
import all ConsensusCoverage.DelayedNominationWitnesses
import all ConsensusCoverage.NominationArms
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DelayedNomination

open ActionProfile FullProfile
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Every step coordinate; the queued-envelope and successor coordinates
intentionally distinguish finding a successor from sending a new value. -/
@[expose] public def signature (successor fresh : Bool) : Classes.StepBranch → Bool
  | .sorted_now_after_inl | .sorted_post_log_inl | .sorted_post_log_inr_inl
  | .sorted_post_log_inr_inr | .sorted_now_after_inr
  | .rooted_now_after_inl | .rooted_post_log_inl | .rooted_post_log_inr_inl
  | .rooted_post_log_inr_inr | .rooted_now_after_inr
  | .commitChains_step_committed_inr | .commitChains_step_led_inl | .commitChains_step_backing_inr
  | .advance_chain_fresh | .advance_chain_backed
  | .post_log_kind_same | .post_log_kind_append | .post_log_role_inl | .facts_advance_inl
  | .prefix_small_inl | .prefix_small_inr | .mem_replaceNode_here_pos | .mem_replaceNode_here_neg
  | .summary_event_internal | .summary_input_nominateSuccessor | .quiet_summary_either_inl => true
  | .messages_mem_network_inr | .mem_network_mem_append_inr | .new_message_h_proposeRequestVoteRequest => fresh
  | .nominate_sends_successor_some => successor
  | .nominate_sends_successor_none => !successor
  | _ => false

public theorem signature_counts :
    stepBranches.size = 516 ∧
      (stepBranches.toList.filter (signature true false)).length = 27 ∧
      (stepBranches.toList.filter (signature true true)).length = 30 := by decide +kernel

public theorem shape (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    (label s).step = signature (sends s.before s.act) (ReducedQuestions.answer s.before s.after .message) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let c := s.context
  have st : Stable s.frame s.after c := stable s h
  have key := newKey s h
  obtain ⟨node, state, ne, now⟩ := another s h
  obtain ⟨zero, prior⟩ := BackingStutter.nomination_answers s ((test_iff s).mp h).1
  have commit := ((test_iff s).mp h).2.1
  have priorAnswer := prior.symm.trans commit
  have commits := commitPositive st ((label_true s (.step .commitChains_step_backing_inr)).mp priorAnswer)
  have out := (ReducedQuestions.answer_eq s .outgoing).symm.trans
    (show ReducedQuestions.answer s.before s.after .outgoing = _ from rfl)
  have keep : label s (.step .mem_network_mem_append_inl) = false :=
    (ReducedQuestions.answer_eq s .retained).symm
  have internal := (summaryPositive st key).1
  have nomination := (summaryPositive st key).2
  have pos (b : Classes.StepBranch) (hb : SolvedWitnesses.sig c b) : label s (.step b) = true :=
    (label_true s _).mpr ((SolvedWitnesses.sig_iff c b).mpr hb)
  have neg (b : Classes.StepBranch) (hb : ¬ SolvedWitnesses.sig c b) : label s (.step b) = false :=
    Bool.eq_false_iff.mpr (fun yes => hb ((SolvedWitnesses.sig_iff c b).mp ((label_true s _).mp yes)))
  have excluded (b : Classes.StepBranch) (no : possible b = false) : label s (.step b) = false := by
    apply neg
    intro yes
    exact Bool.noConfusion (no.symm.trans (possible_of_sig _ _ _ _ st yes))
  have someAnswer : label s (.step .nominate_sends_successor_some) = sends s.before s.act := by
    apply Bool.eq_iff_iff.mpr
    rw [sends_iff s st]
    refine ⟨fun yes => ?_, fun yes => pos _ (successorSome st key yes)⟩
    classical
    by_cases has : ∃ n, findSuccessor c.pre c.actor = some n
    · exact has
    exact (no_successor_some _ _ c st.event has ((SolvedWitnesses.sig_iff c _).mp ((label_true s _).mp yes))).elim
  have noneAnswer : label s (.step .nominate_sends_successor_none) = !sends s.before s.act := by
    apply Bool.eq_iff_iff.mpr
    rw [Bool.not_eq_true', ← Bool.not_eq_true, sends_iff s st]
    refine ⟨fun yes has => ?_, fun no => pos _ (successorNone st key no)⟩
    exact NominationArms.step_nominate_sends_successor_none_on_nomination _ _ c st.event has
      ((SolvedWitnesses.sig_iff c _).mp ((label_true s _).mp yes))
  funext b
  change label s (.step b) = signature _ _ b
  cases b <;> first
    | exact excluded _ rfl
    | exact commit
    | exact pos _ commits.1
    | exact pos _ commits.2.1
    | exact pos _ commits.2.2
    | exact priorAnswer
    | exact zero
    | exact someAnswer
    | exact noneAnswer
    | exact (ReducedQuestions.answer_eq s .message).symm
    | exact out
    | exact keep
    | exact proposal_answer s st
    | exact pos _ (rootPositive st key).1
    | exact pos _ (rootPositive st key).2
    | exact pos _ (sortedPositive st key).1
    | exact pos _ (sortedPositive st key).2
    | exact pos _ (otherPositive st key ne now).1
    | exact pos _ (otherPositive st key ne now).2
    | exact pos _ (rootAppend st key)
    | exact pos _ (sortedAppend st key)
    | exact pos _ (rootCopy st key)
    | exact pos _ (sortedCopy st key)
    | exact pos _ (kindSame st key)
    | exact pos _ (kindAppend st key)
    | exact pos _ (roleSame st key)
    | exact pos _ (advancePositive st key)
    | exact pos _ (prefixPositive st key).1
    | exact pos _ (prefixPositive st key).2
    | exact pos _ (replacePositive key)
    | exact pos _ (replaceOther st key ne now)
    | exact pos _ internal
    | exact pos _ nomination
    | exact pos _ (quietPositive st key)
    | exact neg _ (NominationArms.quiet_summary_either_inr st.event)

/-- Exact replay test in terms of the full step signature and the two
evidence tests not assumed to be functions of that signature. -/
public theorem replay_iff (s : Step) :
    test s.cfg s.before s.act s.after s.past = true ↔
      (∃ fresh, (label s).step = signature true fresh) ∧
      GrantFrontier.noNewGrant s.after (s.before :: s.past) = true ∧
      hasElection (s.after :: s.before :: s.past) = false := by
  constructor
  · intro pass
    refine ⟨⟨_, by simpa only [sends_of_test s pass] using shape s pass⟩, ?_⟩
    have last := Bool.and_eq_true_iff.mp pass
    exact ⟨(Bool.and_eq_true_iff.mp last.1).2, by simpa only [Bool.not_eq_true'] using last.2⟩
  · rintro ⟨⟨fresh, sig⟩, noGrant, noElection⟩
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    have input : label s (.step .summary_input_nominateSuccessor) = true := congrFun sig _
    have action := EventSupport.sig_support s.context _ ((label_true s _).mp input)
    rw [(s.context_eq s.context).mpr rfl] at action
    have nom : EventSupport.actionTag s.act = .nominateSuccessor := List.mem_singleton.mp action
    have committed := (CommitKeys.fresh_answer s).trans
      (show label s (.step .commitChains_step_committed_inr) = true from congrFun sig _)
    unfold test
    simp only [nom, committed, noGrant, noElection, decide_true, Bool.not_false, Bool.and_self]

public def row (zero successor fresh : Bool) : Profile
  | .pre b | .post b => ProofContexts.answers (zero, true) b
  | .step b => signature successor fresh b

public theorem row_eq (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    label s = row (StateCoverage.read s.cfg s.before s.past).1 true
      (ReducedQuestions.answer s.before s.after .message) := by
  have pair : StateCoverage.read s.cfg s.before s.past = ((StateCoverage.read s.cfg s.before s.past).1, true) :=
    Prod.ext rfl (backed s h)
  have pre := (pre_answers s).trans (congrArg ProofContexts.answers pair)
  funext q
  cases q with
  | pre b => exact congrFun pre b
  | post b => exact congrFun ((endpoints s h).symm.trans pre) b
  | step b => exact congrFun (by simpa only [sends_of_test s h] using shape s h) b

/-- The two reachable step signatures, split by proposal freshness. -/
public theorem shape_cases (s : Step) (h : test s.cfg s.before s.act s.after s.past = true) :
    (label s).step = signature true true ∨ (label s).step = signature true false := by
  obtain ⟨fresh, eq⟩ := ((replay_iff s).mp h).1
  cases fresh
  · exact .inr eq
  · exact .inl eq

/-- Replay side, with both reachable step signatures explicit. -/
public theorem replay_cases_iff (s : Step) :
    test s.cfg s.before s.act s.after s.past = true ↔
      ((label s).step = signature true true ∨ (label s).step = signature true false) ∧
      GrantFrontier.noNewGrant s.after (s.before :: s.past) = true ∧
      hasElection (s.after :: s.before :: s.past) = false := by
  constructor
  · intro pass
    exact ⟨shape_cases s pass, ((replay_iff s).mp pass).2⟩
  · rintro ⟨(a | b), evidence⟩
    · exact (replay_iff s).mpr ⟨⟨true, a⟩, evidence⟩
    · exact (replay_iff s).mpr ⟨⟨false, b⟩, evidence⟩

/-- The four witnessed rows: each endpoint context has
one fresh-envelope row and one repeated-envelope row. -/
public def rows : List Profile :=
  [row true true true, row true true false, row false true true, row false true false]

private def rowKey (p : Profile) : Bool × Bool :=
  (p (.pre .committed_logs_comparable_left_backed_inl), p (.step .messages_mem_network_inr))

private theorem occurrence (ws : List Step) (k f : Bool)
    (seen : ws.getLast?.map observe = some ((k, true), true, true, f)) :
    ∃ s : Step, test s.cfg s.before s.act s.after s.past = true ∧ label s = row k true f := by
  obtain ⟨s, _, same⟩ := Option.map_eq_some_iff.mp seen
  have zero : (StateCoverage.read s.cfg s.before s.past).1 = k :=
    congrArg (fun x => x.1.1) same
  have pass : test s.cfg s.before s.act s.after s.past = true :=
    congrArg (fun x => x.2.1) same
  have fresh : ReducedQuestions.answer s.before s.after .message = f :=
    congrArg (fun x => x.2.2.2) same
  exact ⟨s, pass, by rw [row_eq s pass, zero, fresh]⟩

/-- Exact full profiles of initialized delayed-commit nominations before the first election. -/
public theorem exact :
    rows.Nodup ∧ rows.length = 4 ∧
    ∀ p : Profile, p ∈ rows ↔
      ∃ s : Step, test s.cfg s.before s.act s.after s.past = true ∧ label s = p := by
  have distinct : (rows.map rowKey).Nodup := by decide +kernel
  have nodup : rows.Nodup :=
    (List.pairwise_map.mp distinct).imp (fun ne eq => ne (congrArg rowKey eq))
  refine ⟨nodup, rfl, fun p => ⟨?_, ?_⟩⟩
  · intro mem
    simp only [rows, List.mem_cons, List.not_mem_nil, or_false] at mem
    rcases mem with rfl | rfl | rfl | rfl
    · exact occurrence _ _ _ coldFresh
    · exact occurrence _ _ _ coldRepeated
    · exact occurrence _ _ _ warmFresh
    · exact occurrence _ _ _ warmRepeated
  · rintro ⟨s, h, rfl⟩
    rw [row_eq s h]
    cases (StateCoverage.read s.cfg s.before s.past).1 <;>
      cases ReducedQuestions.answer s.before s.after .message <;> simp [rows]

end ConsensusCoverage.DelayedNomination
