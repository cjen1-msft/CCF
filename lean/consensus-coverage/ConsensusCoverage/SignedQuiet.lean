module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ZeroRows
public import ConsensusCoverage.CommitKeys
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ProofContexts
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.ZeroRows
import all Consensus.Proofs.SafetyInvariant

/-! The three diagonal labels are exactly the reachable labels with no true
step answer. Signed witnesses preserve the old commit evidence rather than
assuming that a repeated snapshot is always idempotent on the ghost. -/

namespace ConsensusCoverage.SignedQuiet

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ActionProfile FullProfile StutterProfile

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Check the log-evidence hypotheses other than preservation of the node
table. Unlike the unsigned gate, this can accept signed prefixes. -/
@[expose] public def evidence (cfg : FullProfile.Configuration) (before after : Model.State)
    (past : List Model.State) : Bool :=
  before.nodes.all (fun (_, st) => st.votedFor.isNone) &&
    CommitKeys.noNew (cfg.min?.getD 0) after (before :: past)

private theorem frozenGrant [Config.InitialConfiguration] {f : Frame}
    (quiet : ∀ n st, Now f n st → st.votedFor = none) :
    (f.advance f.current).logs.grant = f.logs.grant := by
  funext v n k r
  apply propext
  refine ⟨?_, Or.inl⟩
  rintro (old | ⟨_, eq, atStep, _⟩)
  · exact old
  · cases eq
    obtain ⟨_, y, _, mem, _, _, vote, _⟩ := atStep
    rw [quiet v y mem] at vote
    contradiction

private theorem stable (s : Step) (nodes : s.after.nodes = s.before.nodes)
    (passes : evidence s.cfg s.before s.after s.past = true) :
    @StableLogs ⟨s.cfg⟩ s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨unvoted, noNew⟩ := Bool.and_eq_true_iff.mp passes
  have nodeEq := nodes.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  have logsEq := advance_logs_nodes (f := s.frame) nodeEq
  have quiet (n st) (mem : Now s.frame n st) : st.votedFor = none := by
    change (n, st) ∈ (FullProfile.current s.frame).nodes at mem
    rw [s.current_eq] at mem
    exact Option.isNone_iff_eq_none.mp (List.all_eq_true.mp unvoted (n, st) mem)
  change (s.frame.advance s.after).logs = s.frame.logs
  apply logs_ext
  · exact (congrArg LogFacts.Ghost.seen logsEq).trans (frozenSeen s.folded.invariant)
  · exact (congrArg LogFacts.Ghost.grant logsEq).trans (frozenGrant quiet)
  · exact (congrArg LogFacts.Ghost.elected logsEq).trans (frozenElection s.folded.invariant)
  · exact (congrArg LogFacts.Ghost.canon logsEq).trans (frozenCanon s.folded)
  · funext k l
    apply propext
    exact ⟨(CommitKeys.step_noNew s).mp noNew k l, Or.inl⟩

/-- Reuse any proof of support preservation; the remaining evidence is a
Boolean test on the recorded replay. -/
public theorem label_eq_of_support (s : Step) (support : SameSupport s.before s.after)
    (passes : evidence s.cfg s.before s.after s.past = true) :
    label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) :=
  StutterProfile.label_eq_of_support s support (stable s support.1 passes)

/-- Completes the support check for nominations. On a validated nomination
the node table cannot change, but a newly queued proposal would fail the
queue check. This gate is not an enabledness test. -/
@[expose] public def gate (cfg : FullProfile.Configuration) (before : Model.State) (a : Model.Action)
    (after : Model.State) (past : List Model.State) : Bool :=
  match a with
  | .local _ .nominateSuccessor => (after.network == before.network) && evidence cfg before after past
  | _ => false

private theorem nominate_nodes {cfg ns before after src past}
    (run : StateCoverage.Run cfg ns before past)
    (ran : (transitionSystem cfg ns).step before (.local src .nominateSuccessor) = some after) :
    after.nodes = before.nodes := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  obtain ⟨pre, post, outputs, found, acted, result⟩ := Concrete.step_local ran
  obtain ⟨_, _, postEq, _, _⟩ := nominate_sends src pre _ _ _ acted
  have distinct := (@StateCoverage.run_inv ‹_› _ _ _ run).distinct
  have nodes : (before.nodes.map Prod.fst).Nodup := by
    simpa only [StateCoverage.frame_current] using distinct
  rw [result, postEq]
  exact InertProfile.replace_eq nodes found

/-- For a passing, successfully replayed nomination, return the whole
457-coordinate label using only the pre-state answer key. -/
public theorem gate_sound (s : Step)
    (passes : gate s.cfg s.before s.act s.after s.past = true) :
    label s = diagonal (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) := by
  cases action : s.act with
  | deliver => simp [gate, action] at passes
  | «local» node input =>
    cases input <;> simp only [gate, action, Bool.false_eq_true] at passes
    case nominateSuccessor =>
      have ran := s.ran
      rw [action] at ran
      obtain ⟨net, quiet⟩ := Bool.and_eq_true_iff.mp passes
      have queues := beq_iff_eq.mp net
      exact label_eq_of_support s ⟨nominate_nodes s.run ran, fun e => queues ▸ Iff.rfl⟩ quiet

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
