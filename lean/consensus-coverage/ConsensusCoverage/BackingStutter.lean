module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.EventSupport
import ConsensusCoverage.BackingRead
import all ConsensusCoverage.BackingArms
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.NominationRows
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.BackingStutter

open ActionProfile
open Consensus Consensus.Model Consensus.Proofs Consensus.Proofs.Safety

private theorem commitStep_iff_of_nodes [Config.InitialConfiguration] {f : Frame}
    {t : Model.State} (inv : Inv f) (nodes : t.nodes = f.current.nodes) {n st k b i} :
    CommitStep (f.advance t) n st k b i ↔ CommitStep f n st k b i := by
  have logs := StutterProfile.advance_logs_nodes nodes
  have seen := (congrArg LogFacts.Ghost.seen logs).trans (StutterProfile.frozenSeen inv)
  have elected := (congrArg LogFacts.Ghost.elected logs).trans (StutterProfile.frozenElection inv)
  change (f.advance t).logs.commitAt _ t n st k b i ↔ f.logs.commitAt _ f.current n st k b i
  simp only [LogFacts.Ghost.commitAt, LogFacts.Ghost.canonNow, LogFacts.Ghost.led, nodes, seen, elected]

/-- The fold installing the current snapshot records its zero-base certificates,
even at initialization: this arm never needs a key from the strict past. -/
private theorem committed_of_zero {cfg nodes f} (folded : FullProfile.Folded cfg nodes f) :
    letI : Config.InitialConfiguration := ⟨cfg⟩
    ∀ {n st k i}, CommitStep f n st k 0 i → Committed f k (st.log.take i) := by
  cases folded <;> exact fun cert => .inr ⟨_, _, 0, _, cert, rfl, .inl rfl⟩

/-- On an initialized recorded step with unchanged node records, no new
committed key can have a base-zero certificate. The network may change. -/
public theorem zero_answer (s : Step) (nodes : s.before.nodes = s.after.nodes) :
    label s (.step .commitChains_step_backing_inl) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have same : s.after.nodes = s.frame.current.nodes :=
    nodes.symm.trans (congrArg (fun t : Model.State => t.nodes) s.current_eq).symm
  apply Bool.eq_false_iff.mpr
  intro yes
  obtain ⟨n, st, k, i, cert, fresh⟩ :=
    (BackingArms.zero_iff s.context).mp ((label_true s _).mp yes)
  exact fresh (committed_of_zero s.folded ((commitStep_iff_of_nodes s.folded.invariant same).mp cert))

/-- With the zero-base arm excluded, a fresh commit is exactly a fresh
certificate backed by a strictly earlier committed key. -/
public theorem committed_eq_prior (s : Step) (nodes : s.before.nodes = s.after.nodes) :
    label s (.step .commitChains_step_committed_inr) =
      label s (.step .commitChains_step_backing_inr) := by
  simpa only [CommitKeys.fresh_answer, BackingRead.zero_answer, BackingRead.prior_answer,
    zero_answer s nodes, Bool.false_or] using (BackingRead.any_eq s).symm

private theorem old_of_prior (s : Step)
    (yes : label s (.step .commitChains_step_backing_inr) = true) :
    (StateCoverage.read s.cfg s.before s.past).2 = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨_, _, _, _, _, _, _, k, part, old, _, _⟩ :=
    (BackingArms.prior_iff s.context).mp ((label_true s _).mp yes)
  exact (StateCoverage.read_iff _ _ s.folded.invariant).2.mpr
    ((StateCoverage.backed_iff _ s.folded.invariant).mpr ⟨List.ne_nil_of_mem s.context.pre_now, k, part, old⟩)

public theorem no_first_commit (s : Step) (nodes : s.before.nodes = s.after.nodes)
    (unbacked : (StateCoverage.read s.cfg s.before s.past).2 = false) :
    CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) = true := by
  cases h : CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past) with
  | true => rfl
  | false =>
    have yes := (CommitKeys.fresh_answer s).symm.trans (congrArg Bool.not h)
    exact Bool.noConfusion (unbacked.symm.trans (old_of_prior s (committed_eq_prior s nodes ▸ yes)))

/-- A node-preserving action can establish another key, but not the first.
All twelve state answers therefore stay fixed, even if the step answers change. -/
public theorem endpoints (s : Step) (nodes : s.before.nodes = s.after.nodes) :
    (label s).pre = (label s).post := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have inv := s.context.inv
  have after := s.context.inv_step
  rw [pre_answers, post_answers]
  congr 1
  apply Prod.ext
  · simp only [StateCoverage.read, nodes]
  · apply Bool.eq_iff_iff.mpr
    refine (StateCoverage.read_iff _ _ inv).2.trans
      (Iff.trans ?_ (StateCoverage.read_iff s.after (s.before :: s.past) after).2.symm)
    change StateBasis.Backing s.frame ↔ StateBasis.Backing (s.frame.advance s.after)
    rw [StateCoverage.backed_iff _ inv, StateCoverage.backed_iff _ after]
    refine ⟨fun ⟨_, k, p, old⟩ => ⟨List.ne_nil_of_mem s.context.post_now, k, p, Or.inl old⟩, ?_⟩
    rintro ⟨_, k, p, post⟩
    refine ⟨List.ne_nil_of_mem s.context.pre_now, ?_⟩
    by_cases old : Committed s.frame k p
    · exact ⟨k, p, old⟩
    · have yes := (label_true s (.step .commitChains_step_committed_inr)).mpr
        ((CommitKeys.fresh_iff s.context).mpr ⟨k, p, post, old⟩)
      have pre := old_of_prior s (committed_eq_prior s nodes ▸ yes)
      exact ((StateCoverage.backed_iff _ inv).mp ((StateCoverage.read_iff _ _ inv).2.mp pre)).2

/-- A recorded successor nomination preserves every node record, regardless
of its outgoing messages or whether any commit key is new. -/
public theorem nomination_answers (s : Step) (tag : EventSupport.actionTag s.act = .nominateSuccessor) :
    label s (.step .commitChains_step_backing_inl) = false ∧
      label s (.step .commitChains_step_committed_inr) =
        label s (.step .commitChains_step_backing_inr) := by
  have nodes := (NominationRows.run_nomination s tag).2.2.1.trans
    (congrArg (fun t : Model.State => t.nodes) s.current_eq)
  exact ⟨zero_answer s nodes.symm, committed_eq_prior s nodes.symm⟩

end ConsensusCoverage.BackingStutter
