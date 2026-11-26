module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseMatchAck
public import ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.HandReadersElectionBFind
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.SolvedWitnesses
public import ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.ReadersTotal
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseSmallB

open ActionProfile ClauseExactTables ClauseQuestions

public abbrev nonTrunk := ClauseMatchAck.nonTrunk

public noncomputable def nonTrunkLabel (c : Clause) (s : Step) : RestrictedProfile :=
  restrictedLabel (nonTrunk c) s

public def read (c : Clause) (s : Step) : RestrictedProfile :=
  ⟨(endpoints s).1, (nonTrunk c).map fun b =>
    (ReadersTotal.read s.cfg s.before s.act s.after s.past b).getD false, (endpoints s).2⟩

public theorem read_eq (c : Clause) (covered : ∀ b ∈ nonTrunk c, b ∈ ReadersTotal.covered)
    (s : Step) : read c s = nonTrunkLabel c s := by
  unfold read nonTrunkLabel restrictedLabel
  congr 1
  apply List.map_congr_left
  intro b mem
  rw [ReadersTotal.read_total s (covered b mem), Option.getD_some]

public theorem witnessed {c : Clause} (covered : ∀ b ∈ nonTrunk c, b ∈ ReadersTotal.covered)
    {steps : List Step} {rows : List RestrictedProfile} {r : RestrictedProfile}
    (checked : rows.all (steps.map (read c)).contains = true) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel c s = r := by
  obtain ⟨s, _, eq⟩ :=
    List.mem_map.mp (List.contains_iff_mem.mp (List.all_eq_true.mp checked r mem))
  exact ⟨s, (read_eq c covered s).symm.trans eq⟩

public def row (e : Endpoints) (bits : List Bool) : RestrictedProfile :=
  ⟨e.1, bits, e.2⟩

public abbrev z : StateCoverage.Row := (true, false)
public abbrev b : StateCoverage.Row := (true, true)
public abbrev p : StateCoverage.Row := (false, true)

public theorem endpoints_mem (s : Step) : endpoints s ∈ endpointRows :=
  (endpoint_exact _).mpr ⟨s, rfl⟩

open Consensus Consensus.Proofs Safety in
public theorem lookup_false_diagonal (s : Step)
    (no : label s (.step .find_of_mem_here_pos) = false) :
    (endpoints s).1 = (endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have old : Now s.frame s.context.actor s.context.post := by
    classical
    by_cases h : Now s.frame s.context.actor s.context.post
    · exact h
    · have hit := HandReadersElectionB.Find.sufficient s.context (.inl h)
      have test := (label_true s (.step .find_of_mem_here_pos)).trans (SolvedWitnesses.sig_iff s.context _)
      exact (Bool.noConfusion (no.symm.trans (test.mpr hit)) : False).elim
  have same := s.context.now_pre old
  have nodes : s.after.nodes = s.before.nodes := by
    change s.context.tr.post = s.context.tr.pre at same
    rw [← s.current_eq, s.context.tr.nodesEq, same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  have eq := BackingStutter.endpoints s nodes.symm
  rw [pre_answers, post_answers] at eq
  exact Prod.ext (congrFun eq .committed_logs_comparable_left_backed_inl)
    (congrFun eq .committed_logs_comparable_left_backed_inr)

public def bits (text : String) : List Bool := text.toList.map (· == '1')

public def booleans : List Bool := [false, true]

public theorem bool_mem (x : Bool) : x ∈ booleans := by cases x <;> decide +kernel

public def vectors : Nat → List (List Bool)
  | 0 => [[]]
  | n + 1 => booleans.flatMap fun b => (vectors n).map (b :: ·)

public theorem vector_mem (xs : List Bool) : xs ∈ vectors xs.length := by
  induction xs with
  | nil => exact List.mem_cons_self
  | cons b bs ih => exact List.mem_flatMap.mpr ⟨b, bool_mem b, List.mem_map_of_mem ih⟩

public theorem vectors_length (n : Nat) : (vectors n).length = 2 ^ n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [vectors, booleans, ih, Nat.pow_succ, Nat.mul_two]

public theorem covered_of_check {c : Clause}
    (h : (nonTrunk c).all ReadersTotal.covered.contains = true) :
    ∀ b ∈ nonTrunk c, b ∈ ReadersTotal.covered :=
  fun b mem => List.contains_iff_mem.mp (List.all_eq_true.mp h b mem)

public theorem corpus_witness {c : Clause} (covered : ∀ b ∈ nonTrunk c, b ∈ ReadersTotal.covered)
    {i j : Nat} {r : RestrictedProfile}
    (checked : (ReadersCorpus.stepAt i j).map (read c) = some r) : ∃ s, nonTrunkLabel c s = r := by
  obtain ⟨s, _, h⟩ := Option.map_eq_some_iff.mp checked
  exact ⟨s, (read_eq c covered s).symm.trans h⟩

public abbrev Pick := RestrictedProfile × Nat × Nat

public def checkPick (c : Clause) (pick : Pick) : Bool :=
  let (r, i, j) := pick
  decide ((ReadersCorpus.stepAt i j).map (read c) = some r)

public theorem all_split {α : Type} {xs : List α} {f : α → Bool} (n : Nat)
    (first : (xs.take n).all f = true) (last : (xs.drop n).all f = true) : xs.all f = true := by
  rw [← List.take_append_drop n xs, List.all_append, first, last]
  rfl

public theorem replay_picks {c : Clause} (covered : ∀ b ∈ nonTrunk c, b ∈ ReadersTotal.covered)
    {ps : List Pick} (checked : ps.all (checkPick c) = true) {r : RestrictedProfile}
    (mem : r ∈ ps.map Prod.fst) : ∃ s, nonTrunkLabel c s = r := by
  obtain ⟨⟨_, i, j⟩, found, rfl⟩ := List.mem_map.mp mem
  have yes := List.all_eq_true.mp checked _ found
  exact corpus_witness covered (of_decide_eq_true yes)

public def patternsOf (rows : List RestrictedProfile) : List (List Bool) :=
  (rows.map RestrictedProfile.bits).eraseDups

public theorem pattern_witness {c : Clause} {rows : List RestrictedProfile}
    (lower : ∀ r ∈ rows, ∃ s, nonTrunkLabel c s = r) {bs} (mem : bs ∈ patternsOf rows) :
    ∃ s, (nonTrunkLabel c s).bits = bs := by
  obtain ⟨r, hr, rfl⟩ := List.mem_map.mp (List.mem_eraseDups.mp mem)
  obtain ⟨s, eq⟩ := lower r hr
  exact ⟨s, congrArg RestrictedProfile.bits eq⟩

/-- List the candidate rows for which no replay certificate was supplied. -/
public def unresolved (upper witnessed : List RestrictedProfile) : List RestrictedProfile :=
  upper.filter fun r => !witnessed.contains r

public theorem witnessed_or_unresolved {upper rows : List RestrictedProfile} {r : RestrictedProfile}
    (mem : r ∈ upper) : r ∈ rows ∨ r ∈ unresolved upper rows := by
  by_cases found : r ∈ rows
  · exact .inl found
  · exact .inr (List.mem_filter.mpr ⟨mem, by simpa using found⟩)

end ConsensusCoverage.ClauseSmallB
