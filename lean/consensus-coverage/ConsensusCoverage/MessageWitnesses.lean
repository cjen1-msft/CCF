module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionFrontier
public import ConsensusCoverage.LeaderCoverage
public import ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.LeaderCoverage
import all ConsensusCoverage.LeaderRefinement
import all ConsensusCoverage.LeaderWitnesses
import all ConsensusCoverage.ReducedQuestions

/-!
# Joint message and leader witnesses

For each successful action of the existing leader-witness schedules, pack the
six bits of the endpoint/leader key followed by all sixteen pinned message
answers. Distinct packed keys certify distinct full action labels. No exclusion
is inferred from replay.
-/

namespace ConsensusCoverage.MessageWitnesses

open Consensus Consensus.Model Consensus.Model.Node
open ActionProfile FullProfile FrontierRows

private def pack (key : LeaderWitnesses.Key) (messages : List Bool) : Nat :=
  ([key.1.zeroBefore, key.1.backedBefore, key.1.wonPrimary,
    key.1.zeroAfter, key.1.backedAfter, key.2] ++ messages).foldl
      (fun bits b => 2 * bits + b.toNat) 0

public def project (p : Profile) : Nat :=
  pack (ActionFrontier.project p)
    (ReducedQuestions.columns.map fun k => p (.step k.branch))

private def read (cfg : CCF.Finset NodeID) (s t : Model.State) (past : List Model.State) : Nat :=
  pack (LeaderWitnesses.read cfg s t past) (ReducedQuestions.columns.map (ReducedQuestions.answer s t))

private theorem project_eq (s : Step) : project (label s) = read s.cfg s.before s.after s.past := by
  have messages := List.map_congr_left (l := ReducedQuestions.columns)
    (fun k _ => (ReducedQuestions.answer_eq s k).symm)
  unfold project read
  rw [ActionFrontier.project_eq, messages]
  rfl

private def recorded (r : FrontierRows.Run) : Option (List Nat) :=
  replay read r (initial r) [] r.schedule

private theorem recorded_occurs {r : FrontierRows.Run} (valid : r.valid)
    {keys : List Nat} (checked : recorded r = some keys) :
    ∀ k ∈ keys, ∃ s : Step, s.nodes = r.nodes ∧ project (label s) = k := by
  refine replay_sound (.initial (initialized r valid)) ?_ checked
  intro s t past act path ran
  exact ⟨⟨r.cfg, r.nodes, s, past, act, t, path, ran⟩, rfl, project_eq _⟩

private structure Certificate where
  run : FrontierRows.Run
  observed : List Nat
  valid : run.valid
  checked : recorded run = some observed

local instance (r : FrontierRows.Run) : Decidable r.valid :=
  inferInstanceAs (Decidable (r.cfg.Nonempty ∧ r.nodes.Nodup))

-- Each certificate replays just one schedule. The low four hex digits are
-- the message answers in ReducedQuestions.columns order.
set_option maxRecDepth 8192 in
private def solo : Certificate :=
  ⟨runs[0], [0x230000, 0x130000], by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def extraNode : Certificate :=
  ⟨LeaderWitnesses.extraNode, [0x270000], by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def committedAppend : Certificate :=
  ⟨LeaderWitnesses.committedAppend,
   [0x250000, 0x25D810, 0x269400, 0x370000, 0x36D810, 0x329400, 0x130000],
   by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def election : Certificate :=
  ⟨runs[1], [0x250000, 0x240000, 0x24D082, 0x24D041, 0x24D208, 0x24D104, 0x2DD810],
   by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def replication : Certificate :=
  ⟨runs[2],
   [0x250000, 0x25D810, 0x269400, 0x370000, 0x36D810, 0x329400, 0x120000,
    0x120000, 0x12D082, 0x12D041, 0x12D208, 0x12D104, 0x1BD810],
   by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def spareNode : Certificate :=
  ⟨runs[3],
   [0x250000, 0x25D810, 0x269400, 0x370000, 0x36D810, 0x369400, 0x360000,
    0x360000, 0x36D082, 0x36D041, 0x36D208, 0x36D104, 0x3FD810],
   by decide, by decide +kernel⟩

set_option maxRecDepth 8192 in
private def laggingSuccessor : Certificate :=
  ⟨LeaderWitnesses.laggingSuccessor,
   [0x250000, 0x25D810, 0x269400, 0x370000, 0x360000, 0x36D082, 0x36D041, 0x36D208,
    0x36D104, 0x3FD810, 0x370000, 0x37D810, 0x369400, 0x370000, 0x369400, 0x330000],
   by decide, by decide +kernel⟩

private abbrev MultiCertificate := {c : Certificate // LeaderCoverage.MultiNode c.run.nodes}

private def withTwo (c : Certificate) (zero : 0 ∈ c.run.nodes) (one : 1 ∈ c.run.nodes) :
    MultiCertificate :=
  ⟨c, 0, zero, 1, one, by decide⟩

private def multiSchedules : List MultiCertificate :=
  [withTwo extraNode (by decide) (by decide),
   withTwo committedAppend (by decide) (by decide),
   withTwo election (by decide) (by decide),
   withTwo replication (by decide) (by decide),
   withTwo spareNode (by decide) (by decide),
   withTwo laggingSuccessor (by decide) (by decide)]

private def multiObserved : List Nat := multiSchedules.flatMap fun c => c.val.observed

public def multiKeys : List Nat := multiObserved.eraseDups
public def keys : List Nat := (solo.observed ++ multiObserved).eraseDups

-- Deduplication reduces only lists of integer literals, not the replays.
public theorem multi_count : multiKeys.Nodup ∧ multiKeys.length = 29 := by decide
public theorem count : keys.Nodup ∧ keys.length = 30 := by decide

public theorem multi_occurs {k : Nat} (mem : k ∈ multiKeys) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k := by
  have seen : k ∈ multiObserved := List.mem_eraseDups.mp mem
  obtain ⟨c, _, observed⟩ := List.mem_flatMap.mp seen
  obtain ⟨s, nodes, key⟩ := recorded_occurs c.val.valid c.val.checked k observed
  exact ⟨s, nodes ▸ c.property, key⟩

public theorem occurs {k : Nat} (mem : k ∈ keys) :
    ∃ s : Step, project (label s) = k := by
  have seen : k ∈ solo.observed ++ multiObserved := List.mem_eraseDups.mp mem
  rcases List.mem_append.mp seen with h | h
  · obtain ⟨s, _, key⟩ := recorded_occurs solo.valid solo.checked k h
    exact ⟨s, key⟩
  · obtain ⟨s, _, key⟩ := multi_occurs (List.mem_eraseDups.mpr h : k ∈ multiKeys)
    exact ⟨s, key⟩

-- Neither step sends a fresh message; their generated log-entry answers differ.
private theorem split {rows : List Profile} {ks : List Nat} (distinct : ks.Nodup)
    (covered : ∀ k ∈ ks, ∃ p ∈ rows, project p = k)
    (multi : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) :
    ks.length < rows.length := by
  let d := LeaderRefinement.down
  let b := LeaderRefinement.backup
  apply LeaderRefinement.split_bound (project := project) distinct covered
    (multi d ⟨0, by decide, 1, by decide, by decide⟩)
    (multi b ⟨0, by decide, 1, by decide, by decide⟩)
  · intro same
    exact Bool.noConfusion (LeaderRefinement.down_yes.symm.trans ((congrFun same _).trans LeaderRefinement.backup_no))
  · rw [project_eq, project_eq]
    decide +kernel

/-- Thirty witnessed projected keys, and a collision on a full log-entry question. -/
public theorem full_lower_bound (rows : List Profile) (complete : ∀ s, label s ∈ rows) :
    31 ≤ rows.length := by
  have h := split count.1 (rows := rows) (fun k hk => by
    obtain ⟨s, eq⟩ := occurs hk
    exact ⟨_, complete s, eq⟩) (fun s _ => complete s)
  simpa only [count.2, Nat.lt_iff_add_one_le] using h

/-- Twenty-nine projected keys and the same collision occur on multi-node deployments. -/
public theorem multi_lower_bound (rows : List Profile)
    (complete : ∀ s, LeaderCoverage.MultiNode s.nodes → label s ∈ rows) :
    30 ≤ rows.length := by
  have h := split multi_count.1 (rows := rows) (fun k hk => by
    obtain ⟨s, multi, key⟩ := multi_occurs hk
    exact ⟨_, complete s multi, key⟩) complete
  simpa only [multi_count.2, Nat.lt_iff_add_one_le] using h

end ConsensusCoverage.MessageWitnesses
