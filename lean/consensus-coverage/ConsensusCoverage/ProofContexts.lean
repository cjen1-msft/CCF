module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.PairWitnesses
import all ConsensusCoverage.StateCoverage
import all ConsensusCoverage.StateBasis
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ProofContexts

open Consensus Consensus.Model Consensus.Model.Node
open StateCoverage (Row Run Holds)

public abbrev Answers := Classes.StateBranch → Bool

/-- In the order of the generated questions, not a subset of chosen probes. -/
@[expose] public def answers (r : Row) : Answers
  | .committed_logs_comparable_left_backed_inl => r.1
  | .committed_logs_comparable_right_backed_inl => r.1 && r.2
  | _ => r.2

public theorem faithful {cfg ns s past} (run : Run cfg ns s past) (b : Classes.StateBranch) :
    answers (StateCoverage.read cfg s past) b = true ↔ Holds cfg s past b := by
  letI : Proofs.Config.InitialConfiguration := ⟨cfg⟩
  have inv := StateCoverage.run_inv run
  obtain ⟨zero, backed⟩ := @StateCoverage.read_iff ‹_› s past inv
  change ((StateCoverage.read cfg s past).1 = true ↔ _) at zero
  change ((StateCoverage.read cfg s past).2 = true ↔ _) at backed
  unfold StateCoverage.Holds
  rw [StateBasis.ctx_iff_decode _ inv.commitChains]
  cases b <;> simp only [answers, StateBasis.decode, Bool.and_eq_true, zero, backed]

public def table : List Answers := StateCoverage.activeTable.map answers

public theorem count : table.Nodup ∧ table.length = 3 := by
  have inj : Function.Injective answers := by
    intro r q h
    exact Prod.ext (congrFun h .committed_logs_comparable_left_backed_inl)
      (congrFun h .committed_logs_comparable_left_backed_inr)
  exact ⟨StateCoverage.counts.2.2.1.map answers (fun _ _ h e => h (inj e)), rfl⟩

public def Realized (cfg : CCF.Finset NodeID) (ns : List NodeID) (p : Answers) : Prop :=
  ∃ s past, Run cfg ns s past ∧ s.nodes ≠ [] ∧ ∀ b, p b = true ↔ Holds cfg s past b

private theorem mem_of_realized {cfg ns p} (h : Realized cfg ns p) : p ∈ table := by
  obtain ⟨s, past, run, nonempty, holds⟩ := h
  have mem := (StateCoverage.exact (StateCoverage.read cfg s past)).2.mpr
    ⟨cfg, ns, s, past, run, rfl, fun _ => nonempty⟩
  exact List.mem_map.mpr ⟨_, mem, funext fun b => Bool.eq_iff_iff.mpr ((faithful run b).trans (holds b).symm)⟩

private abbrev cfg : CCF.Finset NodeID := {0, 1, 2}
private abbrev nodes : List NodeID := [0, 1, 2]

private def replication : FrontierRows.Run :=
  ⟨cfg, nodes, [FrontierRows.signature, .input 0 (.sendEntries 1 2), .deliver 0 1, .deliver 1 0,
    .input 0 (.sendEntries 1 2), .deliver 0 1, .input 0 (.sendEntries 2 2), .deliver 0 2]⟩

private def observed : FrontierRows.Observe Row := fun c s t past => StateCoverage.read c t (s :: past)

private def witnessRows := FrontierRows.replay observed replication (FrontierRows.initial replication) [] replication.schedule

set_option maxRecDepth 8192 in
private theorem witnessed :
    (witnessRows.map fun rs => StateCoverage.activeTable.all (· ∈ rs)) = some true := by decide +kernel

/-- All three *complete* answer vectors occur even with a fixed three-voter
bootstrap, with all three nodes present, on one replication schedule. -/
public theorem exact_three (p : Answers) : p ∈ table ↔ Realized {0, 1, 2} [0, 1, 2] p := by
  refine ⟨?_, mem_of_realized⟩
  rintro mem
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp mem
  have hw := witnessed
  cases h : witnessRows with
  | none => simp [h] at hw
  | some rs =>
    have all := Option.some.inj (show some (StateCoverage.activeTable.all (· ∈ rs)) = some true by simpa [h] using hw)
    have picked := of_decide_eq_true (List.all_eq_true.mp all _ hr)
    apply FrontierRows.replay_sound (observe := observed) (r := replication)
      (P := fun x => Realized cfg nodes (answers x))
      (.initial (FrontierRows.initialized replication (by unfold FrontierRows.Run.valid; decide))) _ h _ picked
    intro s t past a run step
    have next := StateCoverage.Run.step run step
    obtain ⟨tr⟩ := @Proofs.Safety.LocalTransition.ofStep ⟨cfg⟩ nodes s t a step
    exact ⟨t, s :: past, next, List.ne_nil_of_mem tr.post_mem, faithful next⟩

/-- Allowing other nonempty deployments adds no state-answer vector. -/
public theorem exact (p : Answers) : p ∈ table ↔ ∃ cfg ns, Realized cfg ns p :=
  ⟨fun h => ⟨_, _, (exact_three p).mp h⟩, fun ⟨_, _, h⟩ => mem_of_realized h⟩

end ConsensusCoverage.ProofContexts
