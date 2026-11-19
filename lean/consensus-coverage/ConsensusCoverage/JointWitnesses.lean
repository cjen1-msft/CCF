module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.MessageWitnesses
import ConsensusCoverage.CommitKeys
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.MessageWitnesses
import all ConsensusCoverage.PairWitnesses

/-!
# Joint witnesses from initialized action schedules

Refine the joint endpoint/leader/message key with the guarded questions and
the fresh committed-key question. Replay produces witnesses, not exclusions:
the schedules need not enumerate all reachable actions.
-/

namespace ConsensusCoverage.JointWitnesses

open ActionProfile FullProfile Consensus Consensus.Model Consensus.Model.Node

set_option maxRecDepth 8192

public abbrev Key := Nat × Bool × List Bool

public def project (p : Profile) : Key :=
  (MessageWitnesses.project p, p (.step .commitChains_step_committed_inr),
    GuardedQuestions.covered.map fun b => p (.step b))

private def read (s : Step) : Option Key := do
  let view ← GuardedDomain.ofAction s.cfg s.before s.after s.past s.act
  let bits ← GuardedQuestions.covered.mapM (GuardedQuestions.answer view)
  return (MessageWitnesses.read s.cfg s.before s.after s.past,
    !CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past), bits)

private theorem guard_bits (s : Step) (v : GuardedDomain.View)
    (view : GuardedDomain.ofAction s.cfg s.before s.after s.past s.act = some v)
    (bs : List Classes.StepBranch) (covered : bs ⊆ GuardedQuestions.covered) :
    bs.mapM (GuardedQuestions.answer v) = some (bs.map fun b => label s (.step b)) := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    have eq := GuardedQuestions.read?_at s (covered (List.mem_cons_self ..))
    have eq : GuardedQuestions.answer v b = some (label s (.step b)) := by
      change (GuardedDomain.ofAction _ _ _ _ _ >>= fun w => GuardedQuestions.answer w b) = _ at eq
      rw [view] at eq
      exact eq
    simp [List.mapM_cons, eq, ih (fun _ h => covered (List.mem_cons_of_mem _ h))]

private theorem read_eq (s : Step) : read s = some (project (label s)) := by
  obtain ⟨v, made, _⟩ := GuardedDomain.ofAction_matches s
  unfold read project
  rw [made]
  simp only [Option.bind_eq_bind, Option.bind_some, guard_bits s v made _ (fun _ h => h),
    ← MessageWitnesses.project_eq, CommitKeys.fresh_answer]
  rfl

open FrontierRows

-- The state-only frontier replay does not pass the recorded action to its
-- observer. Here the resolved action is retained in each initialized Step.
private def replay (r : Run) (s : Model.State) (past : List Model.State)
    (reach : StateCoverage.Run r.cfg r.nodes s past) :
    List Command → Option (List { w : Step // w.nodes = r.nodes })
  | [] => some []
  | cmd :: rest => do
    let act ← cmd.resolve s
    match ran : (transitionSystem r.cfg r.nodes).step s act with
    | none => none
    | some t =>
      let tail ← replay r t (s :: past) (.step reach ran) rest
      return ⟨⟨r.cfg, r.nodes, s, past, act, t, reach, ran⟩, rfl⟩ :: tail

private def recorded (r : Run) (valid : r.valid) :
    Option (List { w : Step // w.nodes = r.nodes }) :=
  replay r (initial r) [] (.initial (initialized r valid)) r.schedule

private def observed (r : Run) (valid : r.valid) : List Key :=
  ((recorded r valid).getD []).filterMap fun w => read w.val

private theorem observed_occurs {r : Run} {valid : r.valid} {k : Key}
    (mem : k ∈ observed r valid) :
    ∃ s : Step, s.nodes = r.nodes ∧ project (label s) = k := by
  obtain ⟨w, _, found⟩ := List.mem_filterMap.mp mem
  exact ⟨w.val, w.property, Option.some.inj ((read_eq _).symm.trans found)⟩

private abbrev MultiRun := { r : Run // r.valid ∧ LeaderCoverage.MultiNode r.nodes }

private def replication := runs[2]

private def onTwo (schedule : List Command) : MultiRun := by
  refine ⟨{ replication with schedule }, MessageWitnesses.replication.valid, ?_⟩
  change LeaderCoverage.MultiNode replication.nodes
  exact ⟨0, by decide, 1, by decide, by decide⟩

private def unsigned : Command := .input 0 (.append [{content := .transaction 1 {}}])
private def heartbeat : Command := .input 0 (.sendEntries 1 0)

-- Fork just before replication, once backed but before the leader's ack,
-- after the leader commits, and after the follower learns the commit.
private def appendForks : List MultiRun :=
  [0, 3, 4, 6].flatMap fun i => [signature, unsigned].map fun cmd =>
    onTwo (replication.schedule.take i ++ [cmd])

private def emptyBackup : MultiRun :=
  ⟨{ runs[3] with schedule := [.input 2 (.initAsBackup [])] },
    MessageWitnesses.spareNode.valid, ⟨0, by decide, 1, by decide, by decide⟩⟩

private def nominationForks : List MultiRun :=
  [0, 3, 6].map fun n => onTwo (replication.schedule.take n ++ [.input 0 .nominateSuccessor])

private def nominate : Command := .input 0 .nominateSuccessor

-- Only the shorter prefix reaches the old quorum. Its certificate can back
-- a longer prefix under the new configuration, but not until the next step.
private def delayedCommit : MultiRun := onTwo [
  .input 0 (.append [{content := .transaction 1 {configuration := some {0}}},
    {content := .signature, flushes := [(1, 3)]}, {content := .signature}]),
  .deliver 0 1, nominate, nominate]

private def chainedCommit : MultiRun :=
  ⟨{runs[3] with schedule := [
    .input 0 (.append [{content := .transaction 1 {configuration := some {0, 2}}},
      {content := .signature, flushes := [(1, 3)]},
      {content := .transaction 2 {configuration := some {0}}},
      {content := .signature}, {content := .signature}]),
    .deliver 0 2, .deliver 2 0, .input 0 (.sendEntries 2 5), .deliver 0 2,
    .deliver 0 1, nominate, nominate, nominate]},
    MessageWitnesses.spareNode.valid, ⟨0, by decide, 1, by decide, by decide⟩⟩

/-- In the second run, two successive nominations each add a committed key;
the third does not. These bits are part of the recorded action label (`read_eq`). -/
private theorem delayed_commit_answers :
    (observed delayedCommit.val delayedCommit.property.1).map (·.2.1) =
      [false, true, true, false] ∧
    (observed chainedCommit.val chainedCommit.property.1).map (·.2.1) =
      [false, false, false, false, false, true, true, true, false] := by decide +kernel

private def multiRuns : List MultiRun :=
  (MessageWitnesses.multiSchedules.map fun c => ⟨c.val.run, c.val.valid, c.property⟩) ++
  appendForks ++ nominationForks ++ [onTwo [heartbeat, heartbeat], emptyBackup, delayedCommit, chainedCommit]

private def soloObserved : List Key :=
  observed MessageWitnesses.solo.run MessageWitnesses.solo.valid

private def multiObserved : List Key :=
  multiRuns.flatMap fun r => observed r.val r.property.1

public def multiKeys : List Key := multiObserved.eraseDups
public def keys : List Key := (soloObserved ++ multiObserved).eraseDups

public theorem multi_occurs {k : Key} (mem : k ∈ multiKeys) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  obtain ⟨r, _, found⟩ := List.mem_flatMap.mp (List.mem_eraseDups.mp mem)
  obtain ⟨s, nodes, key⟩ := observed_occurs found
  exact ⟨s, nodes ▸ r.property.2, key⟩

public theorem occurs {k : Key} (mem : k ∈ keys) :
    ∃ s : Step, project (label s) = k := by
  rcases List.mem_append.mp (List.mem_eraseDups.mp mem) with solo | multi
  · obtain ⟨s, _, key⟩ := observed_occurs solo
    exact ⟨s, key⟩
  · obtain ⟨s, _, key⟩ := multi_occurs (List.mem_eraseDups.mpr multi : k ∈ multiKeys)
    exact ⟨s, key⟩

-- These checks reduce the replay, including the guarded answers and deduplication.
-- No expected keys are enumerated by hand.
private theorem all_replayed :
    soloObserved.length = MessageWitnesses.solo.run.schedule.length ∧
      (multiRuns.all fun r => (observed r.val r.property.1).length == r.val.schedule.length) =
        true := by decide +kernel

private theorem sample_size :
    1 + multiRuns.length = 22 ∧ soloObserved.length + multiObserved.length = 121 := by decide +kernel

public theorem multi_count : multiKeys.Nodup ∧ multiKeys.length = 46 := by decide +kernel
public theorem count : keys.Nodup ∧ keys.length = 48 := by decide +kernel

/-- Every list covering the full recorded-action labels has at least 48 rows. -/
public theorem full_lower_bound (rows : List Profile) (complete : ∀ s, label s ∈ rows) :
    48 ≤ rows.length := by
  simpa only [count.2] using
    (projected_lower_bound project count.1 (fun _ => occurs) complete)

/-- Each key here has a witness with at least two distinct deployed node IDs. -/
public theorem multi_lower_bound (rows : List Profile)
    (complete : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) :
    46 ≤ rows.length := by
  have sub : multiKeys ⊆ rows.map project := by
    intro k hk
    obtain ⟨s, multi, eq⟩ := multi_occurs hk
    exact List.mem_map.mpr ⟨_, complete s multi, eq⟩
  simpa only [multi_count.2, List.length_map] using multi_count.1.length_le_of_subset sub

end ConsensusCoverage.JointWitnesses
