module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ZeroRows
public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.GrantFrontier
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.GrantFrontier
public import ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ProofContexts
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.ZeroRows
import all Consensus.Proofs.SafetyInvariant

/-! The three diagonal labels are exactly the reachable labels with no true
step answer. The replay gate allows queue removals, but checks that the log
fold adds no evidence even on signed prefixes. -/

namespace ConsensusCoverage.SignedQuiet

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile FullProfile StutterProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- On an unchanged node table, only grants and committed prefixes can add
log evidence. Both checks use the strict past when testing for an old fact. -/
@[expose] public def evidence (cfg : FullProfile.Configuration) (before after : Model.State)
    (past : List Model.State) : Bool :=
  GrantFrontier.noNewGrant after (before :: past) &&
    CommitKeys.noNew (cfg.min?.getD 0) after (before :: past)

private theorem stable (s : Step) (nodes : s.after.nodes = s.before.nodes)
    (passes : evidence s.cfg s.before s.after s.past = true) :
    @StableLogs ⟨s.cfg⟩ s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨grants, noNew⟩ := Bool.and_eq_true_iff.mp passes
  have nodeEq := nodes.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  have logsEq := advance_logs_nodes (f := s.frame) nodeEq
  change (s.frame.advance s.after).logs = s.frame.logs
  apply logs_ext
  · exact (congrArg LogFacts.Ghost.seen logsEq).trans (frozenSeen s.folded.invariant)
  · exact (GrantFrontier.step_grant_eq s).mp grants
  · exact (congrArg LogFacts.Ghost.elected logsEq).trans (frozenElection s.folded.invariant)
  · exact (congrArg LogFacts.Ghost.canon logsEq).trans (frozenCanon s.folded)
  · funext k l
    apply propext
    exact ⟨(CommitKeys.step_noNew s).mp noNew k l, Or.inl⟩

public theorem evidence_iff (s : Step) (nodes : s.after.nodes = s.before.nodes) :
    evidence s.cfg s.before s.after s.past = true ↔ @StableLogs ⟨s.cfg⟩ s.frame s.after := by
  refine ⟨stable s nodes, fun eq => Bool.and_eq_true_iff.mpr ⟨?_, ?_⟩⟩
  · exact (GrantFrontier.step_grant_eq s).mpr (congrArg LogFacts.Ghost.grant eq)
  · apply (CommitKeys.step_noNew s).mpr
    intro k l post
    exact Eq.mp (congrFun (congrFun (congrArg LogFacts.Ghost.committed eq) k) l) post

/-- Reuse any proof that no support is new; the remaining evidence is a
Boolean test on the recorded replay. -/
public theorem label_eq_of_noNewSupport (s : Step) (support : NoNewSupport s.before s.after)
    (passes : evidence s.cfg s.before s.after s.past = true) :
    label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  StutterProfile.label_eq_of_noNewSupport s support (stable s support.1 passes)

public theorem label_eq_of_support (s : Step) (support : SameSupport s.before s.after)
    (passes : evidence s.cfg s.before s.after s.past = true) :
    label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  label_eq_of_noNewSupport s support.noNew passes

/-- Reject new envelopes, but allow removals, reordering and duplication.
On a validated action, only the actor can have changed its node record. -/
@[expose] public def test (v : Option GuardedDomain.View) (s t : Model.State) (logsStable : Bool) : Bool :=
  v.any (fun x => !x.changed) && t.network.all s.network.contains && logsStable

@[expose] public def gate (cfg : FullProfile.Configuration) (before : Model.State) (a : Model.Action)
    (after : Model.State) (past : List Model.State) : Bool :=
  test (GuardedDomain.ofAction cfg before after past a) before after
    (evidence cfg before after past)

/-- For a passing, successfully replayed action, return the whole
label using only the pre-state answer key. -/
public theorem gate_sound (s : Step)
    (passes : gate s.cfg s.before s.act s.after s.past = true) :
    label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  simp only [gate, test, made, Option.any_some, Bool.not_eq_true', Bool.and_eq_true] at passes
  obtain ⟨⟨unchanged, forward⟩, logs⟩ := passes
  have same := s.context.now_pre ((GuardedDomain.View.old_post ok).mpr unchanged)
  change s.context.tr.post = s.context.tr.pre at same
  have nodes : s.after.nodes = s.before.nodes := by
    rw [← s.current_eq, s.context.tr.nodesEq, same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  apply label_eq_of_noNewSupport s ⟨nodes, fun e h => List.contains_iff_mem.mp
    (List.all_eq_true.mp forward e h)⟩
  exact logs

public theorem evidence_of_negatives (s : Step)
    (grant : label s (.step .grantFactsBefore_grant_inr) = false)
    (commit : label s (.step .commitChains_step_committed_inr) = false) :
    evidence s.cfg s.before s.after s.past = true := by
  apply Bool.and_eq_true_iff.mpr
  constructor
  · cases h : GrantFrontier.noNewGrant s.after (s.before :: s.past) with
    | false => exact Bool.noConfusion (grant.symm.trans (GrantFrontier.fresh_implies_grant_arm s h))
    | true => rfl
  · simpa only [Bool.not_eq_false'] using (CommitKeys.fresh_answer s).trans commit

/-- Four negative proof answers suffice on *any* successful action, even a
delivery or a step taken after an election. -/
public theorem gate_of_four (s : Step)
    (node : label s (.step .commit_backed_now_after_inl) = false)
    (msg : label s (.step .messages_mem_network_inr) = false)
    (grant : label s (.step .grantFactsBefore_grant_inr) = false)
    (commit : label s (.step .commitChains_step_committed_inr) = false) :
    gate s.cfg s.before s.act s.after s.past = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
  have old : Now s.frame s.context.actor s.context.post := by
    apply Classical.byContradiction
    intro new
    have hit := (SolvedWitnesses.sig_iff s.context .commit_backed_now_after_inl).mpr
      (Or.inl ⟨⟨s.context.post_now, new, rfl⟩, s.context.post_now⟩)
    exact Bool.noConfusion (node.symm.trans ((label_true s _).mpr hit))
  have queue := (ReducedQuestions.answer_eq s .message).trans msg
  have subset : s.after.network.all s.before.network.contains = true := by
    simpa [ReducedQuestions.answer, ReducedQuestions.answerFrom, ReducedQuestions.freshPayloads,
      List.all_eq_true, List.any_eq_false] using queue
  simp [gate, test, made, (GuardedDomain.View.old_post ok).mp old, subset, evidence_of_negatives s grant commit]

/-- Total slice membership: a failing gate refutes the all-false signature;
there is no need to evaluate the other 429 coordinates. -/
public theorem gate_iff (s : Step) :
    gate s.cfg s.before s.act s.after s.past = true ↔ (label s).step = fun _ => false :=
  ⟨fun h => congrArg Profile.step (gate_sound s h),
    fun h => gate_of_four s (congrFun h _) (congrFun h _) (congrFun h _) (congrFun h _)⟩

private def appendResult (nodes : List NodeID) : Option Model.State :=
  (transitionSystem {0} nodes).step (StateCoverage.initial nodes)
    (.local 0 (.append [{content := .signature}]))

private def signed (nodes : List NodeID) (ok : (appendResult nodes).isSome) : Model.State :=
  (appendResult nodes).get ok

private def nominate (nodes : List NodeID) (distinct : nodes.Nodup)
    (ok : (appendResult nodes).isSome)
    (ran : (transitionSystem {0} nodes).step (signed nodes ok) (.local 0 .nominateSuccessor) =
      some (signed nodes ok)) : Step :=
  ⟨{0}, nodes, signed nodes ok, [StateCoverage.initial nodes], .local 0 .nominateSuccessor,
    signed nodes ok, .step (.initial (StateCoverage.init _ distinct)) (Option.some_get _).symm, ran⟩

private def two : Step := nominate [0, 1] (by decide) (by decide +kernel) (by rfl)
private def one : Step := nominate [0] (by decide) (by decide +kernel) (by rfl)

private theorem checked_label (s : Step) (r : StateCoverage.Row)
    (passes : gate s.cfg s.before s.act s.after s.past = true)
    (key : StateCoverage.read s.cfg s.before s.past = r) :
    label s = diagonal (ProofContexts.answers r) := by
  rw [gate_sound s passes, key]

/-- The signature commits at the only voter but the nonvoting deployed node
still has commit index zero. The following nomination stutters. -/
public theorem two_node_witness :
    ∃ s : Step, s.cfg = {0} ∧ s.nodes = [0, 1] ∧ s.act = .local 0 .nominateSuccessor ∧
      s.after = s.before ∧ label s = diagonal (ProofContexts.answers (true, true)) :=
  ⟨two, rfl, rfl, rfl, rfl, checked_label two _ (by decide +kernel) (by decide +kernel)⟩

/-- The singleton deployment has no remaining zero commit index before the
stuttering nomination. -/
public theorem one_node_witness :
    ∃ s : Step, s.cfg = {0} ∧ s.nodes = [0] ∧ s.act = .local 0 .nominateSuccessor ∧
      s.after = s.before ∧ label s = diagonal (ProofContexts.answers (false, true)) :=
  ⟨one, rfl, rfl, rfl, rfl, checked_label one _ (by decide +kernel) (by decide +kernel)⟩

private theorem realized (r : StateCoverage.Row) (mem : r ∈ StateCoverage.activeTable) :
    Realized (diagonal (ProofContexts.answers r)) := by
  simp only [StateCoverage.activeTable, List.mem_cons, List.not_mem_nil, or_false] at mem
  rcases mem with rfl | rfl | rfl
  · obtain ⟨s, _, _, _, _, _, _, _, _, eq⟩ := InertProfile.duplicate_heartbeat_witness
    exact ⟨s, eq⟩
  · obtain ⟨s, _, _, _, _, eq⟩ := two_node_witness
    exact ⟨s, eq⟩
  · obtain ⟨s, _, _, _, _, eq⟩ := one_node_witness
    exact ⟨s, eq⟩

/-- An exact table for the all-false-step slice of the full recorded-action
labels. This does not assume every member of that slice is a stutter. -/
public theorem exact (p : Profile) :
    p ∈ ZeroRows.table ↔ Realized p ∧ p.step = fun _ => false := by
  constructor
  · intro mem
    obtain ⟨pre, preMem, rfl⟩ := List.mem_map.mp (show p ∈ ProofContexts.table.map diagonal from mem)
    obtain ⟨r, rowMem, rfl⟩ := List.mem_map.mp
      (show pre ∈ StateCoverage.activeTable.map ProofContexts.answers from preMem)
    exact ⟨realized r rowMem, rfl⟩
  · rintro ⟨⟨s, rfl⟩, zero⟩
    exact ZeroRows.mem_of_zero s zero

end ConsensusCoverage.SignedQuiet
