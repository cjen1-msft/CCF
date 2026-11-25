module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.CensusWidth
import all ConsensusCoverage.HandReadersBSummary
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.ReadersTotal

namespace ConsensusCoverage.ClauseLowerBounds

open ClauseQuestions ClauseExactTables ActionProfile HandReadersBSummary

set_option maxRecDepth 8192
set_option maxHeartbeats 0

private def kinds : List Kind :=
  [.append, .send, .election, .quorum, .nominate, .install, .request, .ack, .vote,
   .ballot, .preVote, .preBallot, .propose]

private def hasDispatch (bs : List Classes.StepBranch) := kinds.all (fun k => bs.contains (column k))

private abbrev Key := Endpoints × Option Kind

private def project (bs : List Classes.StepBranch) (r : RestrictedProfile) : Key :=
  ((r.pre, r.post), kinds.find? fun k => ((bs.zip r.bits).lookup (column k)).getD false)

private def dispatchKey (s : Step) : Key :=
  (endpoints s, kinds.find? fun k => answer s.cfg s.before s.act s.after s.past k)

private theorem find_congr {xs : List α} {f g : α → Bool} (eq : ∀ x ∈ xs, f x = g x) :
    xs.find? f = xs.find? g := by
  induction xs with
  | nil => rfl
  | cons a xs ih =>
    simp only [List.find?_cons, eq a (by simp), ih (fun x h => eq x (List.mem_cons_of_mem _ h))]

private theorem project_eq (bs : List Classes.StepBranch) (all : hasDispatch bs) (s : Step) :
    project bs (restrictedLabel bs s) = dispatchKey s := by
  apply Prod.ext
  · rfl
  apply find_congr
  intro k hk
  have mem := List.contains_iff_mem.mp (List.all_eq_true.mp all k hk)
  change ((bs.zip (bs.map fun b => label s (.step b))).lookup (column k)).getD false = _
  rw [CensusWidth.lookup_zip mem, Option.getD_some, exact_answer]

/-- Short prefixes from the certified corpus. The pairs are schedule and
offset, not projected labels. Every successful lookup returns an actual Step. -/
private def picks : List (Nat × Nat) :=
  [(0,0),(0,1),(1,0),(2,0),(18,0),(20,1),(52,2),(45,2),(70,4),(44,0),
   (3,2),(3,3),(3,4),(3,5),(3,6),(25,4),(186,5),(168,5),(135,5),(135,6),
   (135,7),(135,8),(140,2),(25,1),(55,2),(30,3),(27,4),(128,5),(165,4),
   (166,5),(34,1),(110,11),(15,0),(20,2),(59,3),(18,1),(19,0),(21,1),(21,2),
   (90,7),(46,1),(59,4),(69,6),(70,5),(66,1),(131,3),(119,6)]

private def keys := picks.filterMap fun (i,j) => (ReadersCorpus.stepAt i j).map dispatchKey

private theorem count : keys.length = 47 ∧ keys.Nodup := by decide +kernel

private theorem dispatch_bound (bs : List Classes.StepBranch) (all : hasDispatch bs)
    (rows : List RestrictedProfile) (complete : ∀ s, restrictedLabel bs s ∈ rows) :
    47 ≤ rows.length := by
  have sub : keys ⊆ rows.map (project bs) := by
    intro k mem
    obtain ⟨⟨i,j⟩, _, hit⟩ := List.mem_filterMap.mp mem
    obtain ⟨s, _, rfl⟩ := Option.map_eq_some_iff.mp hit
    exact List.mem_map.mpr ⟨_, complete s, project_eq bs all s⟩
  simpa only [← count.1, List.length_map] using count.2.length_le_of_subset sub

public def lower (c : Clause) : Nat := if hasDispatch (questions c) then 47 else 6

public theorem lower_counts :
    Clause.all.filter (fun c => lower c != 47) = [.distinct,.frontier,.owners,.observed] ∧
      (Clause.all.filter (fun c => lower c == 47)).length = 26 := by decide +kernel

/-- Does not assume the table has already been made exact or duplicate-free. -/
public theorem clause_bound (c : Clause) (rows : List (ClauseProfile c))
    (complete : ∀ s, clauseLabel c s ∈ rows) : lower c ≤ rows.length := by
  unfold lower
  split
  · exact dispatch_bound _ ‹_› rows complete
  · have sub : endpointRows ⊆ rows.map (fun r => (r.pre,r.post)) := by
      intro p mem
      obtain ⟨s,rfl⟩ := (endpoint_exact p).mp mem
      exact List.mem_map.mpr ⟨_,complete s,rfl⟩
    simpa only [← endpoint_count.2, List.length_map] using endpoint_count.1.length_le_of_subset sub

end ConsensusCoverage.ClauseLowerBounds
