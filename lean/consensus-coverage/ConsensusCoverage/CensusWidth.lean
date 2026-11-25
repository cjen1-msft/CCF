module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.BoundedWitnesses
public import ConsensusCoverage.ReadersGenerated
import all Consensus.Proofs.VoteFacts
import all ConsensusCoverage.BoundedWitnesses
import all ConsensusCoverage.ActorLogRows
import all ConsensusCoverage.Classes
import all ConsensusCoverage.ExploredWitnesses
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.ReadersIndex
import all ConsensusCoverage.ReadersVoteReply
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.CensusWidth

open Consensus Consensus.Proofs ActionProfile FullProfile FrontierRows
open ExploredWitnesses (append deliver down elect flush nom project send sig tx)

set_option maxRecDepth 8192
set_option maxHeartbeats 0

@[noinline] private def coordinate (s : Step) (b : Classes.StepBranch) : Option Bool :=
  (ReadersAtoms.ofXAction s.cfg s.before s.after s.past s.act).bind fun x =>
    @ReadersCompiler.readView ⟨s.cfg⟩ x b

private theorem coordinate_correct (s : Step) (b : Classes.StepBranch) {v : Bool}
    (eq : coordinate s b = some v) : label s (.step b) = v := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x, made, ok⟩ := ReadersAtoms.ofXAction_matches s
  simp only [coordinate, made, Option.bind_some] at eq
  have iff := ReadersCompiler.picked_some eq
    (@ReadersCompiler.readView_correct ⟨s.cfg⟩ s.frame s.after s.context b x ok)
  exact Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans ((SolvedWitnesses.sig_iff s.context b).trans iff.symm))

private def onTwo (cmds : List Command) : Run := ⟨{0, 1}, [0, 1], cmds⟩

private def lastStep (cmds : List Command) : Option {s : Step // s.nodes = [0, 1]} := do
  let r := onTwo cmds
  let valid : r.valid := by change (onTwo []).cfg.Nonempty ∧ (onTwo []).nodes.Nodup; decide
  (← JointWitnesses.recordedAt r valid []).getLast?

private def reads (k : Nat) (b : Classes.StepBranch) (v : Bool) (s : Step) : Bool :=
  decide ((JointWitnesses.read s).map ExploredWitnesses.encode = some k ∧ coordinate s b = some v)

private def Hit (k : Nat) (b : Classes.StepBranch) (v : Bool) : Prop :=
  ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ project (label s) = k ∧ label s (.step b) = v

private theorem checked {cmds k b v}
    (test : (lastStep cmds).any (fun w => reads k b v w.val) = true) : Hit k b v := by
  cases last : lastStep cmds with
  | none => simp [last] at test
  | some w =>
    simp only [last, Option.any_some, reads, decide_eq_true_eq] at test
    refine ⟨w.val, ?_, ?_, coordinate_correct _ _ test.2⟩
    · rw [w.property]
      exact ⟨0, by decide, 1, by decide, by decide⟩
    · simpa only [JointWitnesses.read_eq, Option.map_some, Option.some.injEq, project] using test.1

private structure Split where
  key : Nat
  branch : Classes.StepBranch
  hit : ∀ v, Hit key branch v

private def splitAt (k : Nat) (b : Classes.StepBranch) (no yes : List Command)
    (zero : (lastStep no).any (fun w => reads k b false w.val) = true)
    (one : (lastStep yes).any (fun w => reads k b true w.val) = true) : Split :=
  ⟨k, b, fun v => by cases v <;> first | exact checked zero | exact checked one⟩

local macro "splitOn " k:term:arg b:term:arg no:term:arg yes:term:arg : term =>
  `(splitAt $k $b $no $yes (by decide +kernel) (by decide +kernel))

-- BEGIN GENERATED SPLITS
private def splits : List Split :=
  [splitOn 618475535097 .canon_mono_elected_after_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, down 0]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1],
    splitOn 646460979961 .canon_mono_elected_after_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, down 0, elect 0]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1, elect 1],
    splitOn 646665445497 .post_two_active_inr_inr_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, nom 0, deliver 0 1]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1, deliver 1 0, elect 1, deliver 1 0, deliver 0 1],
    splitOn 1256814804992 .accept_shape_eq_zero_or_pos_inl
      [send 0 1 1, deliver 0 1, deliver 1 0, send 0 1 1, deliver 0 1]
      [send 0 1 0, deliver 0 1, deliver 1 0, send 0 1 0, deliver 0 1],
    splitOn 1256815009792 .accept_shape_eq_zero_or_pos_inl
      [append 0 [tx], send 0 1 1, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1]
      [send 0 1 1, deliver 0 1],
    splitOn 1256815009864 .accept_shape_eq_zero_or_pos_inl
      [append 0 [sig], send 0 1 1, deliver 0 1, deliver 1 0, down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1]
      [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 2, deliver 0 1],
    splitOn 1271310565113 .commit_backed_kind_append
      [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, send 0 1 1, deliver 0 1, deliver 1 0]
      [append 0 [sig], down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0],
    splitOn 1325534748748 .accept_shape_eq_zero_or_pos_inl
      [send 0 1 1, deliver 0 1, deliver 1 0, append 0 [flush 1 2], deliver 0 1]
      [append 0 [flush 1 2], deliver 0 1],
    splitOn 1855426116345 .canon_mono_elected_after_inl
      [append 0 [flush 1 2], deliver 0 1, down 0]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1],
    splitOn 1875290340473 .accept_backed_max_eq_or_inr
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0]
      [append 0 [flush 1 2], deliver 0 1, down 0, deliver 1 0, elect 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0],
    splitOn 1883411561209 .canon_mono_elected_after_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1, down 1, elect 1],
    splitOn 1883616026745 .post_two_active_inr_inr_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, elect 1, deliver 1 0, deliver 0 1],
    splitOn 1889785854713 .canon_mono_elected_after_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0]
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, nom 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0, deliver 0 1],
    splitOn 2193663196281 .freshCert_backing_inl
      [append 0 [flush 1 2], deliver 0 1, deliver 1 0, down 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0]
      [append 0 [flush 1 2], deliver 0 1, down 0, deliver 1 0, elect 0, deliver 0 1, deliver 1 0, deliver 0 1, deliver 1 0]]
-- END GENERATED SPLITS

private def lookup (k : Nat) := splits.find? (·.key == k)

-- This projection retains just one of the additional total coordinates at
-- each split key; it does not need to compute or enumerate full profiles.
private def refineKey (p : Profile) : Nat × Bool :=
  let k := project p
  (k, (lookup k).any fun c => p (.step c.branch))

private def keys (base : List Nat) :=
  base.map (·, false) ++ splits.map (fun c => (c.key, true))

private theorem hit_lookup {k : Nat} {c : Split} (found : lookup k = some c) (v : Bool) :
    ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ refineKey (label s) = (k, v) := by
  have eq : c.key = k := beq_iff_eq.mp (List.find?_some (p := fun x : Split => x.key == k) found)
  obtain ⟨s, multi, narrow, value⟩ := c.hit v
  exact ⟨s, multi, by simp only [refineKey, narrow, eq, found, Option.any_some, value]⟩

private theorem occurs {base : List Nat} {scope : Step → Prop}
    (multi : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → scope s)
    (old : ∀ k ∈ base, ∃ s : Step, scope s ∧ project (label s) = k)
    {w : Nat × Bool} (mem : w ∈ keys base) : ∃ s : Step, scope s ∧ refineKey (label s) = w := by
  rcases List.mem_append.mp mem with zero | one
  · obtain ⟨k, hk, rfl⟩ := List.mem_map.mp zero
    cases found : lookup k with
    | none =>
      obtain ⟨s, hs, narrow⟩ := old k hk
      exact ⟨s, hs, by simp only [refineKey, narrow, found, Option.any_none]⟩
    | some c =>
      obtain ⟨s, hs, eq⟩ := hit_lookup found false
      exact ⟨s, multi s hs, eq⟩
  · obtain ⟨c, hc, rfl⟩ := List.mem_map.mp one
    have found : (lookup c.key).isSome := List.find?_isSome.mpr ⟨c, hc, by simp⟩
    obtain ⟨_, eq⟩ := Option.isSome_iff_exists.mp found
    obtain ⟨s, hs, yes⟩ := hit_lookup eq true
    exact ⟨s, multi s hs, yes⟩

private theorem count : (keys BoundedWitnesses.keys).Nodup ∧
    (keys BoundedWitnesses.keys).length = 250 := by decide +kernel
private theorem multi_count : (keys BoundedWitnesses.multiKeys).Nodup ∧
    (keys BoundedWitnesses.multiKeys).length = 247 := by decide +kernel

private def extra : List Classes.StepBranch :=
  FullProfile.stepBranches.toList.filter fun b =>
    ReadersCompiler.generatedColumns.contains b && !ReplayAnswers.unconditional.contains b

/-- The old key paired with the new total coordinates, in constructor order. -/
public def wide (p : Profile) : Nat × List Bool :=
  (project p, extra.map (fun b => p (.step b)))

private def reduceKey (w : Nat × List Bool) : Nat × Bool :=
  (w.1, (lookup w.1).any fun c => ((extra.zip w.2).lookup c.branch).getD false)

private theorem lookup_zip {b : Classes.StepBranch} {xs : List Classes.StepBranch} (h : b ∈ xs)
    (f : Classes.StepBranch → Bool) : (xs.zip (xs.map f)).lookup b = some (f b) := by
  induction xs with
  | nil => cases h
  | cons a xs ih =>
    by_cases e : b = a
    · subst a; simp
    · simpa only [List.map_cons, List.zip_cons_cons, List.lookup, beq_false_of_ne e] using
        ih (by simpa [e] using h)

private theorem included : splits.all (fun c => extra.contains c.branch) = true := by decide +kernel

private theorem reduce_wide (p : Profile) : reduceKey (wide p) = refineKey p := by
  simp only [reduceKey, wide, refineKey]
  cases e : lookup (project p) with
  | none => rfl
  | some c =>
    have mem : c ∈ splits := List.mem_of_find?_eq_some e
    have h := List.contains_iff_mem.mp (List.all_eq_true.mp included c mem)
    simp only [Option.any_some, lookup_zip h, Option.getD_some]

private theorem bound {base : List Nat} {scope : Step → Prop}
    (multi : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → scope s)
    (old : ∀ k ∈ base, ∃ s : Step, scope s ∧ project (label s) = k)
    (distinct : (keys base).Nodup) (rows : List (Nat × List Bool))
    (complete : ∀ s : Step, scope s → wide (label s) ∈ rows) : (keys base).length ≤ rows.length := by
  have sub : keys base ⊆ rows.map reduceKey := by
    intro k hk
    obtain ⟨s, hs, eq⟩ := occurs multi old hk
    exact List.mem_map.mpr ⟨_, complete s hs, (reduce_wide _).trans eq⟩
  simpa only [List.length_map] using distinct.length_le_of_subset sub

/-- Fourteen old projection keys split on further total answers. This is a
lower bound across all deployments, not the cardinality of a bounded model. -/
public theorem wider_lower_bound (rows : List (Nat × List Bool)) (complete : ∀ s, wide (label s) ∈ rows) :
    250 ≤ rows.length := by
  have old k (hk : k ∈ BoundedWitnesses.keys) :
      ∃ s : Step, True ∧ project (label s) = k := by
    obtain ⟨s, eq⟩ := BoundedWitnesses.occurs hk
    exact ⟨s, trivial, eq⟩
  simpa only [count.2] using bound (scope := fun _ => True) (fun _ _ => trivial) old count.1 rows
    (fun s _ => complete s)

public theorem multi_wider_lower_bound (rows : List (Nat × List Bool))
    (complete : ∀ s : Step, LeaderCoverage.MultiNode s.nodes → wide (label s) ∈ rows) :
    247 ≤ rows.length := by
  simpa only [multi_count.2] using bound (fun _ h => h) (fun _ h => BoundedWitnesses.multi_occurs h)
    multi_count.1 rows complete

end ConsensusCoverage.CensusWidth
