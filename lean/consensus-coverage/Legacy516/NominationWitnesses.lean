module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.NominationProfile
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.MessageWitnesses
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.PairWitnesses
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.ZeroRows

namespace ConsensusCoverage.NominationRows

open ActionProfile FrontierRows Consensus

-- Fork the same two-node replication schedule before any signature, after
-- backing first exists, and after the follower learns the committed index.
private def lastNomination (n : Nat) : Option Step := do
  let base := JointWitnesses.replication
  let r := {base with schedule := base.schedule.take n ++ [.input 0 .nominateSuccessor]}
  let steps ← JointWitnesses.recorded r MessageWitnesses.replication.valid
  return (← steps.getLast?).val

private def witnesses : List Step := [0, 3, 6].filterMap lastNomination

private def observation (s : Step) : StateCoverage.Row × Bool :=
  (StateCoverage.read s.cfg s.before s.past, test s.cfg s.before s.act s.after s.past)

set_option maxRecDepth 8192 in
private theorem observed : witnesses.map observation =
    StateCoverage.activeTable.map (fun k => (k, true)) := by decide +kernel

public theorem occurs {r : StateCoverage.Row} (mem : r ∈ StateCoverage.activeTable) :
    ∃ s : Step, StateCoverage.read s.cfg s.before s.past = r ∧ test s.cfg s.before s.act s.after s.past = true := by
  have hit : (r, true) ∈ witnesses.map observation := by
    rw [observed]
    exact List.mem_map.mpr ⟨r, mem, rfl⟩
  obtain ⟨s, _, h⟩ := List.mem_map.mp hit
  exact ⟨s, congrArg Prod.fst h, congrArg Prod.snd h⟩

open FullProfile

private def row (bits : Classes.StepBranch → Bool) (atState : ProofContexts.Answers) : Profile
  | .pre b | .post b => atState b
  | .step b => bits b

private theorem row_eq (s : Step) {bits : Classes.StepBranch → Bool} (shape : (label s).step = bits)
    (terms : bits .terms_now_after_inl = false) (commit : bits .commitChains_step_committed_inr = false) :
    label s = row bits (ProofContexts.answers (StateCoverage.read s.cfg s.before s.past)) := by
  have same := ZeroRows.endpoints s ((congrFun shape _).trans terms) ((congrFun shape _).trans commit)
  funext q
  cases q with
  | pre b => exact congrFun (pre_answers s) b
  | step b => exact congrFun shape b
  | post b => exact congrFun (same.symm.trans (pre_answers s)) b

/-- Every action with this step shape is covered, not just the nominations
used to witness the rows. The two negative coordinates rule out a change of
endpoint, and each of the three pre-state contexts has a nomination witness. -/
private theorem exact_shape {bits : Classes.StepBranch → Bool}
    (shape : ∀ s : Step, test s.cfg s.before s.act s.after s.past = true → (label s).step = bits)
    (terms : bits .terms_now_after_inl = false) (commit : bits .commitChains_step_committed_inr = false) :
    let rows := ProofContexts.table.map (row bits)
    rows.Nodup ∧ rows.length = 3 ∧ ∀ p : Profile, p ∈ rows ↔ Realized p ∧ p.step = bits := by
  have inj : Function.Injective (row bits) := fun _ _ h => funext fun b => congrFun h (.pre b)
  refine ⟨ProofContexts.count.1.map _ (fun _ _ h eq => h (inj eq)),
    by simpa only [List.length_map] using ProofContexts.count.2, fun p => ⟨?_, ?_⟩⟩
  · intro mem
    obtain ⟨_, pre, rfl⟩ := List.mem_map.mp mem
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp (show _ ∈ StateCoverage.activeTable.map ProofContexts.answers from pre)
    obtain ⟨s, key, pass⟩ := occurs hr
    exact ⟨⟨s, key ▸ row_eq s (shape s pass) terms commit⟩, rfl⟩
  · rintro ⟨⟨s, rfl⟩, bitsEq⟩
    let k := StateCoverage.read s.cfg s.before s.past
    have mem : k ∈ StateCoverage.activeTable := (StateCoverage.exact k).2.mpr
      ⟨_, _, _, _, s.run, rfl, fun _ => FrontierRows.no_step_without_nodes s.ran⟩
    exact List.mem_map.mpr ⟨_, List.mem_map.mpr ⟨_, mem, rfl⟩, (row_eq s bitsEq terms commit).symm⟩

public def table : List Profile := ProofContexts.table.map (row bits)

public theorem exact : table.Nodup ∧ table.length = 3 ∧
    ∀ p : Profile, p ∈ table ↔ Realized p ∧ p.step = bits :=
  exact_shape shape rfl rfl

private def duplicateAfterElection : Option Step := do
  let election := FrontierRows.runs[1]
  let run := {election with schedule := election.schedule ++
    [.input 0 .nominateSuccessor, .input 0 .nominateSuccessor]}
  let steps ← JointWitnesses.recorded run (by
    change ({0, 1} : CCF.Finset Model.Node.NodeID).Nonempty ∧ ([0, 1] : List Model.Node.NodeID).Nodup
    decide)
  return (← steps.getLast?).val

private def votedCheck (s : Step) : Bool :=
  decide (EventSupport.actionTag s.act = .nominateSuccessor) &&
    !(s.before.nodes.all fun (_, st) => st.votedFor.isNone) &&
    SignedQuiet.gate s.cfg s.before s.act s.after s.past

set_option maxRecDepth 8192 in
private theorem votedCheck_passes : duplicateAfterElection.any votedCheck = true := by decide +kernel

/-- Votes are present, but none is new. The duplicate nomination after the
election has an all-false step signature, just like a pre-election duplicate. -/
public theorem voted_stutter :
    ∃ s : Step, EventSupport.actionTag s.act = .nominateSuccessor ∧
      s.before.nodes.all (fun (_, st) => st.votedFor.isNone) = false ∧
      (label s).step = fun _ => false := by
  obtain ⟨s, _, pass⟩ := (Option.any_eq_true _ _).mp votedCheck_passes
  simp only [votedCheck, Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at pass
  exact ⟨s, pass.1.1, pass.1.2, (SignedQuiet.gate_iff s).mp pass.2⟩

private def quietNominations := duplicateAfterElection.toList ++ [SignedQuiet.two, SignedQuiet.one]

private def quietKey (s : Step) : Option StateCoverage.Row :=
  if EventSupport.actionTag s.act = .nominateSuccessor ∧ SignedQuiet.gate s.cfg s.before s.act s.after s.past = true
  then some (StateCoverage.read s.cfg s.before s.past) else none

set_option maxRecDepth 8192 in
private theorem quietKeys : quietNominations.filterMap quietKey = StateCoverage.activeTable := by decide +kernel

/-- Every row has an actual nomination witness. Conversely, no other full
label occurs on a nomination that adds neither a grant nor a committed key. -/
public theorem exact_stable :
    let rows := ZeroRows.table ++ table
    rows.Nodup ∧ rows.length = 6 ∧ ∀ p : Profile, p ∈ rows ↔ ∃ s : Step,
      EventSupport.actionTag s.act = .nominateSuccessor ∧ SignedQuiet.evidence s.cfg s.before s.after s.past = true ∧
      label s = p := by
  refine ⟨List.pairwise_append.mpr ⟨ZeroRows.count.1, exact.1, ?_⟩, ?_, fun p => ⟨?_, ?_⟩⟩
  · rintro a ha _ hb rfl
    have zero := congrFun ((SignedQuiet.exact a).mp ha).2 .messages_mem_network_inr
    have fresh := congrFun ((exact.2.2 a).mp hb).2 .messages_mem_network_inr
    exact Bool.noConfusion (zero.symm.trans fresh)
  · rw [List.length_append, ZeroRows.count.2, exact.2.1]
  · intro mem
    rcases List.mem_append.mp mem with hz | hn
    · obtain ⟨pre, hpre, rfl⟩ := List.mem_map.mp (show p ∈ ProofContexts.table.map StutterProfile.diagonal from hz)
      obtain ⟨r, hr, rfl⟩ := List.mem_map.mp (show pre ∈ StateCoverage.activeTable.map ProofContexts.answers from hpre)
      obtain ⟨s, _, key⟩ := List.mem_filterMap.mp (quietKeys ▸ hr : r ∈ quietNominations.filterMap quietKey)
      simp only [quietKey] at key
      split at key
      · rename_i pass
        have zero := (SignedQuiet.gate_iff s).mp pass.2
        exact ⟨s, pass.1, (stable_iff s pass.1).mpr (.inl zero),
          (Option.some.inj key) ▸ SignedQuiet.gate_sound s pass.2⟩
      · cases key
    · obtain ⟨⟨s, rfl⟩, h⟩ := (exact.2.2 p).mp hn
      have pass := (test_iff s).mpr h
      have both := Bool.and_eq_true_iff.mp (Bool.and_eq_true_iff.mp pass).1
      exact ⟨s, of_decide_eq_true both.1, both.2, rfl⟩
  · rintro ⟨s, tag, stable, rfl⟩
    rcases (stable_iff s tag).mp stable with hz | hn
    · exact List.mem_append_left _ (ZeroRows.mem_of_zero s hz)
    · exact List.mem_append_right _ ((exact.2.2 _).mpr ⟨⟨s, rfl⟩, hn⟩)

end ConsensusCoverage.NominationRows
