module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BackingRead
public import ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.MessageWitnesses

namespace ConsensusCoverage.BackingRows

open ActionProfile FullProfile

set_option maxRecDepth 8192

/-- In proof-column order: fresh committed key, base-zero reason, prior-key reason. -/
public def project (p : Profile) : Bool × Bool × Bool :=
  (p (.step .commitChains_step_committed_inr), p (.step .commitChains_step_backing_inl),
    p (.step .commitChains_step_backing_inr))

public def table : List (Bool × Bool × Bool) :=
  [(false, false, false), (true, true, false), (true, false, true), (true, true, true)]

private def row (reasons : Bool × Bool) := (reasons.1 || reasons.2, reasons)

private theorem project_eq (s : Step) :
    project (label s) = row (BackingRead.read (s.cfg.min?.getD 0) s.after (s.before :: s.past)) := by
  simp only [project, row, ← BackingRead.zero_answer, ← BackingRead.prior_answer,
    BackingRead.any_eq, CommitKeys.fresh_answer]

public theorem complete (s : Step) : project (label s) ∈ table := by
  rw [project_eq]
  exact (by decide : ∀ a b, row (a, b) ∈ table) _ _

open JointWitnesses

private def observed (r : MultiRun) :=
  (recorded r.val r.property.1).map fun ws => ws.map fun w =>
    row (BackingRead.read (w.val.cfg.min?.getD 0) w.val.after (w.val.before :: w.val.past))

private theorem occurs {r : MultiRun} {xs} (ran : observed r = some xs) {k} (mem : k ∈ xs) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  unfold observed at ran
  cases h : recorded r.val r.property.1 with
  | none => simp [h] at ran
  | some ws =>
    simp only [h, Option.map_some, Option.some.injEq] at ran
    subst xs
    obtain ⟨w, _, rfl⟩ := List.mem_map.mp mem
    exact ⟨w.val, w.property.symm ▸ r.property.2, project_eq _⟩

-- The delivery establishes the shorter prefix from base zero. The following
-- nomination establishes the longer one using only the now-available key.
private theorem delayed :
    observed delayedCommit = some [(false, false, false), (true, true, false),
      (true, false, true), (false, false, false)] := by decide +kernel

private def successor : MultiRun :=
  ⟨MessageWitnesses.laggingSuccessor.run, MessageWitnesses.laggingSuccessor.valid,
    0, by decide, 1, by decide, by decide⟩

private theorem both : (observed successor).bind (·[14]?) = some (true, true, true) := by decide +kernel

public theorem count : table.Nodup ∧ table.length = 4 := by decide

/-- Every listed triple has an initialized multi-node witness; `complete`
also excludes unlisted triples on singleton deployments. -/
public theorem exact (k : Bool × Bool × Bool) :
    k ∈ table ↔ ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  constructor
  · intro h
    rcases List.mem_cons.mp h with rfl | h
    · exact occurs delayed (by decide)
    rcases List.mem_cons.mp h with rfl | h
    · exact occurs delayed (by decide)
    rcases List.mem_cons.mp h with rfl | h
    · exact occurs delayed (by decide)
    obtain rfl := List.mem_singleton.mp h
    have h := both
    cases obs : observed successor with
    | none => simp [obs] at h
    | some xs =>
      simp only [obs, Option.bind_some] at h
      exact occurs obs (List.mem_of_getElem? h)
  · rintro ⟨s, _, rfl⟩
    exact complete s

end ConsensusCoverage.BackingRows
