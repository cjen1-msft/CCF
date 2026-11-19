module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.EventSupport
public import ConsensusCoverage.LeaderCoverage
public import ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ActionFrontier
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.LeaderWitnesses
import all ConsensusCoverage.Projection
import all ConsensusCoverage.ReducedQuestions

/-! A symbolic upper cover for the *full* recorded-action labels. Reconstruct
the endpoints and three leader bits from a leader key, all sixteen queue bits
from the fresh message kinds, and only vary the remaining bits permitted by
the recorded event. Different tags can cover the same label. Neither these
overlaps nor infeasible assignments are counted as reachability witnesses. -/

namespace ConsensusCoverage.ActionCover

open ActionProfile FullProfile ReducedQuestions EventSupport
open Consensus.Model.Node (Message)

set_option maxRecDepth 8192

private def kinds : List MessageKind := (constructors% MessageKind).toList

private theorem allKinds (k : MessageKind) : k ∈ kinds := by cases k <;> simp [kinds]

private def acceptsKind : Column → MessageKind → Bool
  | .message | .outgoing => fun _ => true
  | .retained => fun _ => false
  | .sentKind k => fun k' => decide (k' = k)
  | .termKind k => fun k' => decide (k' = k.message)
  | .bumping => fun k => match k with
    | .appendEntriesResponse | .proposeRequestVoteRequest => false
    | _ => true

private def freshKinds (ms : List Message) : List MessageKind :=
  kinds.filter fun k => ms.any (hasKind k)

private theorem mem_freshKinds {k : MessageKind} {ms : List Message} :
    k ∈ freshKinds ms ↔ ∃ m ∈ ms, messageKind m = k := by
  simp [freshKinds, allKinds, List.any_eq_true, hasKind]

private theorem kind_answer (ms : List Message) (col : Column) :
    (freshKinds ms).any (acceptsKind col) = answerFrom ms col := by
  have seen (test : MessageKind → Bool) :
      (freshKinds ms).any test = ms.any (fun m => test (messageKind m)) := by
    apply Bool.eq_iff_iff.mpr
    simp only [List.any_eq_true, mem_freshKinds]
    constructor
    · rintro ⟨_, ⟨m, mem, rfl⟩, yes⟩
      exact ⟨m, mem, yes⟩
    · rintro ⟨m, mem, yes⟩
      exact ⟨_, ⟨m, mem, rfl⟩, yes⟩
  rw [seen]
  cases col with
  | retained => simp [acceptsKind, answerFrom]
  | bumping =>
    have eq (m : Message) : acceptsKind .bumping (messageKind m) = bumping m := by cases m <;> rfl
    simp only [eq, answerFrom]
  | _ => rfl

private def leaders (k : LeaderWitnesses.Key) : Question → Bool
  | .pre b => ProofContexts.answers (k.1.zeroBefore, k.1.backedBefore) b
  | .post b => ProofContexts.answers (k.1.zeroAfter, k.1.backedAfter) b
  | .step .leader_led_leader_inr => k.1.wonPrimary
  | .step .leader_led_now_after_inl => k.2
  | .step .leader_led_leader_inl => k.2 && !k.1.wonPrimary
  | _ => false

private theorem leaders_correct (s : Step) (q : Question) (h : ActionFrontier.selected q = true) :
    leaders (ActionFrontier.project (label s)) q = label s q := by
  cases q with
  | pre b =>
    rw [ActionFrontier.project_eq]
    exact (congrFun (pre_answers s) b).symm
  | post b =>
    rw [ActionFrontier.project_eq]
    exact (congrFun (post_answers s) b).symm
  | step b =>
    cases b <;> first | rfl | exact (ActionFrontier.incumbent_eq s).symm | contradiction

/-- Step coordinates not reconstructed from the leader/queue facts and not
excluded by the event. Membership says nothing about reachability. -/
public def free (tag : Tag) : List Classes.StepBranch :=
  stepBranches.toList.filter fun b =>
    !ActionFrontier.selected (.step b) && decide (b ∉ covered) && decide (tag ∈ allowed b)

private def decode (k : LeaderWitnesses.Key) (ks : List MessageKind) (yes : List Classes.StepBranch) :
    Profile := fun q =>
  if ActionFrontier.selected q then leaders k q else
    match q with
    | .pre _ | .post _ => false
    | .step b =>
      match columns.find? (fun col => decide (col.branch = b)) with
      | some col => ks.any (acceptsKind col)
      | none => yes.contains b

private theorem decode_step (s : Step) :
    let ms := freshPayloads s.before s.after.network
    let yes := (free (actionTag s.act)).filter fun b => label s (.step b)
    decode (ActionFrontier.project (label s)) (freshKinds ms) yes = label s := by
  funext q
  unfold decode
  split
  · exact leaders_correct s q (by assumption)
  next unselected =>
    cases q with
    | pre | post => contradiction
    | step b =>
      dsimp only
      cases found : columns.find? (fun col => decide (col.branch = b)) with
      | some col =>
        have eq : col.branch = b := of_decide_eq_true (List.find?_some (p := fun c : Column => decide (c.branch = b)) found)
        exact (kind_answer _ col).trans ((answer_eq s col).trans (congrArg (fun x => label s (.step x)) eq))
      | none =>
        have notCovered : b ∉ covered := by
          rintro mem
          obtain ⟨col, h, eq⟩ := List.mem_map.mp (show b ∈ columns.map Column.branch from mem)
          simpa [eq] using List.find?_eq_none.mp found col h
        have listed : b ∈ stepBranches.toList := by
          rw [← step_get b]
          exact Array.getElem_mem_toList ..
        apply Bool.eq_iff_iff.mpr
        simp only [List.contains_iff_mem, List.mem_filter]
        refine ⟨And.right, fun pos => ⟨?_, pos⟩⟩
        have tag : actionTag s.act ∈ allowed b :=
          Classical.byContradiction fun no => Bool.noConfusion (pos.symm.trans (label_false s b no))
        simp [free, listed, unselected, notCovered, tag]

private def subsets : List α → List (List α)
  | [] => [[]]
  | x :: xs => let rest := subsets xs; rest ++ rest.map (x :: ·)

private theorem filter_mem (xs : List α) (test : α → Bool) : xs.filter test ∈ subsets xs := by
  induction xs with
  | nil => exact List.mem_cons_self
  | cons x xs ih =>
    simp only [subsets, List.filter_cons, List.mem_append, List.mem_map]
    split
    · exact .inr ⟨_, ih, rfl⟩
    · exact .inl ih

private theorem subsets_length (xs : List α) : (subsets xs).length = 2 ^ xs.length := by
  induction xs with
  | nil => rfl
  | cons x xs ih => simp only [subsets, List.length_append, List.length_map, ih,
      List.length_cons, Nat.pow_succ, Nat.mul_two]

public def tags : List Tag := inputs ++ messages

-- Only `capacity` is evaluated. The symbolic covering list is never built.
private def candidates (keys : List LeaderWitnesses.Key) : List Profile :=
  tags.flatMap fun tag => keys.flatMap fun k => (subsets kinds).flatMap fun ks =>
    (subsets (free tag)).map fun yes => decode k ks yes

public def capacity (keyCount : Nat) : Nat :=
  (tags.map fun tag => keyCount * (2 ^ kinds.length * 2 ^ (free tag).length)).sum

private theorem constant_sum (xs : List α) (n : Nat) : (xs.map (fun _ => n)).sum = xs.length * n := by
  induction xs with
  | nil => simp
  | cons x xs ih => simp [ih, Nat.add_mul, Nat.add_comm]

private theorem candidates_length (keys : List LeaderWitnesses.Key) :
    (candidates keys).length = capacity keys.length := by
  simp only [candidates, capacity, List.length_flatMap, List.length_map, subsets_length, constant_sum]

private theorem cover (keys : List LeaderWitnesses.Key) (s : Step)
    (mem : ActionFrontier.project (label s) ∈ keys) : label s ∈ candidates keys := by
  apply List.mem_flatMap.mpr
  refine ⟨_, allTag (actionTag s.act), List.mem_flatMap.mpr ⟨_, mem, List.mem_flatMap.mpr ?_⟩⟩
  exact ⟨_, filter_mem kinds _, List.mem_map.mpr ⟨_, filter_mem (free (actionTag s.act)) _, decode_step s⟩⟩

/-- Bounds *distinct full labels*, not schedules, observations or independent
branch answers. Does not require the table being bounded to be exhaustive. -/
public theorem upper {rows : List Profile} (distinct : rows.Nodup) (real : ∀ p ∈ rows, Realized p) :
    rows.length ≤ capacity 15 := by
  let keys := LeaderCoverage.remaining :: LeaderWitnesses.table
  have sub : rows ⊆ candidates keys := by
    intro p hp
    obtain ⟨s, rfl⟩ := real p hp
    apply cover
    exact (LeaderCoverage.upper s).elim (List.mem_cons_of_mem _) (fun eq => eq ▸ List.mem_cons_self)
  simpa only [candidates_length, show keys.length = 15 from rfl] using distinct.length_le_of_subset sub

public theorem multi_upper {rows : List Profile} (distinct : rows.Nodup)
    (real : ∀ p ∈ rows, ∃ s : Step, LeaderCoverage.MultiNode s.nodes ∧ label s = p) :
    rows.length ≤ capacity 13 := by
  have sub : rows ⊆ candidates LeaderCoverage.multiTable := by
    intro p hp
    obtain ⟨s, multi, rfl⟩ := real p hp
    exact cover _ s ((LeaderCoverage.multi_exact _).mpr ⟨s, multi, rfl⟩)
  simpa only [candidates_length, LeaderCoverage.multi_count.2] using distinct.length_le_of_subset sub

public theorem free_counts : tags.map (fun tag => (free tag).length) =
    [267, 237, 272, 241, 238, 302, 269, 260, 282, 254, 285, 281] := by decide +kernel

public theorem ceiling : capacity 15 < 2 ^ 313 ∧ capacity 13 < 2 ^ 313 := by decide +kernel

end ConsensusCoverage.ActionCover
