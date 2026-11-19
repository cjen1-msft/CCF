module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BackingStutter
public import ConsensusCoverage.ConsecutiveStutter
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.SignedQuiet
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.RepeatedInput

open CCF CCF.MultiNodeTransitionSystem
open ActionProfile FullProfile Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs

/-- Repeat the recorded action immediately, extending its actual history. -/
public def again (s : Step) {t : Model.State} (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t) :
    Step :=
  ⟨s.cfg, s.nodes, s.after, s.before :: s.past, s.act, t, .step s.run s.ran, ran⟩

/-- Repeating the same successful local input on the same node table sends
the same envelopes. Their multiplicities can increase; none is a new value. -/
private theorem noNewSupport (s : Step) {t : Model.State} {n i}
    (input : s.act = .local n i) (nodes : s.before.nodes = s.after.nodes)
    (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t) :
    StutterProfile.NoNewSupport s.after t := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have first := s.ran
  rw [input] at first ran
  obtain ⟨x, y, out, loc, action, result⟩ := Concrete.step_local first
  obtain ⟨x', y', out', loc', action', result'⟩ := Concrete.step_local ran
  have same : nodeState s.before n = nodeState s.after n := by simp only [nodeState, nodes]
  obtain rfl := Option.some.inj (loc.symm.trans (same.trans loc'))
  obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj (action.symm.trans action'))
  constructor
  · exact (congrArg (fun a : Model.State => a.nodes) result').trans
      ((congrArg (fun ns => Concrete.replaceNode ns n y) nodes.symm).trans
        (congrArg (fun a : Model.State => a.nodes) result).symm)
  · have old := congrArg (fun a : Model.State => a.network) result
    rw [result']
    intro e mem
    exact (List.mem_append.mp mem).elim id (fun sent => old ▸ List.mem_append_right _ sent)

/-- On the repeat there is only one possible source of a nonzero step
signature: a new committed key. This class allows signed logs and votes. -/
public theorem diagonal_iff (s : Step) {t : Model.State} {n i}
    (input : s.act = .local n i) (nodes : s.before.nodes = s.after.nodes)
    (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t) :
    label (again s ran) = StutterProfile.diagonal (ProofContexts.answers
      (StateCoverage.read s.cfg s.after (s.before :: s.past))) ↔
      CommitKeys.noNew (s.cfg.min?.getD 0) t (s.after :: s.before :: s.past) = true := by
  let w := again s ran
  have support := noNewSupport s input nodes ran
  constructor
  · intro eq
    have no := congrFun eq (.step .commitChains_step_committed_inr)
    change label w (.step .commitChains_step_committed_inr) = false at no
    simpa only [Bool.not_eq_false', w, again] using (CommitKeys.fresh_answer w).trans no
  · intro quiet
    exact SignedQuiet.label_eq_of_noNewSupport w support
      ((ConsecutiveStutter.evidence_eq w rfl nodes support.1.symm).trans quiet)

/-- No commit on the first input is enough; the next action with identical
inputs cannot restart the chain of delayed commits. -/
public theorem frozen (s : Step) {t : Model.State} {n i}
    (input : s.act = .local n i) (nodes : s.before.nodes = s.after.nodes)
    (quiet : CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true)
    (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t) :
    label (again s ran) = StutterProfile.diagonal (ProofContexts.answers
      (StateCoverage.read s.cfg s.after (s.before :: s.past))) :=
  (diagonal_iff s input nodes ran).mpr (ConsecutiveStutter.noNewCommit (again s ran) rfl
    (noNewSupport s input nodes ran).1.symm quiet)

/-- No stable-evidence hypothesis is needed before the very first certificate:
the second consecutive nomination by the same actor has one possible full label. -/
public theorem unbacked_nomination (s : Step) {t : Model.State} {n}
    (input : s.act = .local n .nominateSuccessor)
    (unbacked : (StateCoverage.read s.cfg s.before s.past).2 = false)
    (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t) :
    label (again s ran) = StutterProfile.diagonal (ProofContexts.answers (true, false)) := by
  have tag : EventSupport.actionTag s.act = .nominateSuccessor := input ▸ rfl
  have nodes := (NominationRows.run_nomination s tag).2.2.1.trans
    (congrArg (fun x : Model.State => x.nodes) s.current_eq)
  have key := (StateCoverage.exact (StateCoverage.read s.cfg s.before s.past)).2.mpr
    ⟨_, _, _, _, s.run, rfl, fun _ => FrontierRows.no_step_without_nodes s.ran⟩
  have pre : StateCoverage.read s.cfg s.before s.past = (true, false) := by
    simp only [StateCoverage.activeTable, List.mem_cons, List.not_mem_nil, or_false] at key
    rcases key with h | h | h <;> first | exact h | simp [h] at unbacked
  rw [frozen s input nodes.symm (BackingStutter.no_first_commit s nodes.symm unbacked) ran,
    ← post_answers, ← BackingStutter.endpoints s nodes.symm, pre_answers, pre]

/-- The first input preserves node records and adds no key. There is no
assumption about the second input's evidence or the earlier history. -/
public def Occurs (p : Profile) : Prop :=
  ∃ (s : Step) (t : Model.State) (n : NodeID) (i : Input)
    (ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some t),
    s.act = .local n i ∧ s.before.nodes = s.after.nodes ∧
      CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true ∧ label (again s ran) = p

private def beforeFirstCommit : Step :=
  let init := StateCoverage.initial [0]
  ⟨{0}, [0], init, [], .local 0 .nominateSuccessor, init, .initial (StateCoverage.init _ (by decide)), rfl⟩

private theorem witness (s : Step) (r : StateCoverage.Row) (input : s.act = .local 0 .nominateSuccessor)
    (same : s.after = s.before) (quiet : CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true)
    (key : StateCoverage.read s.cfg s.after (s.before :: s.past) = r) :
    Occurs (StutterProfile.diagonal (ProofContexts.answers r)) := by
  have ran : (transitionSystem s.cfg s.nodes).step s.after s.act = some s.after := by
    simpa only [same] using s.ran
  have nodes := congrArg (fun t : Model.State => t.nodes) same.symm
  exact ⟨s, s.after, _, _, ran, input, nodes, quiet, key ▸ frozen s input nodes quiet ran⟩

/-- Exactly three full labels across this family of local repeats. In
particular, repeating a nomination witnesses each of the three. -/
public theorem exact : ZeroRows.table.Nodup ∧ ZeroRows.table.length = 3 ∧
    ∀ p : Profile, p ∈ ZeroRows.table ↔ Occurs p := by
  refine ⟨ZeroRows.count.1, ZeroRows.count.2, fun p => ⟨?_, ?_⟩⟩
  · intro mem
    change p ∈ ((StateCoverage.activeTable.map ProofContexts.answers).map StutterProfile.diagonal) at mem
    obtain ⟨_, pre, rfl⟩ := List.mem_map.mp mem
    obtain ⟨r, hr, rfl⟩ := List.mem_map.mp pre
    simp only [StateCoverage.activeTable, List.mem_cons, List.not_mem_nil, or_false] at hr
    rcases hr with rfl | rfl | rfl
    · exact witness beforeFirstCommit _ rfl rfl (by decide +kernel) (by decide +kernel)
    · exact witness SignedQuiet.two _ rfl rfl (by decide +kernel) (by decide +kernel)
    · exact witness SignedQuiet.one _ rfl rfl (by decide +kernel) (by decide +kernel)
  · rintro ⟨s, _, _, _, ran, input, nodes, quiet, rfl⟩
    exact ZeroRows.mem_of_zero _ (congrArg Profile.step (frozen s input nodes quiet ran))

end ConsensusCoverage.RepeatedInput
