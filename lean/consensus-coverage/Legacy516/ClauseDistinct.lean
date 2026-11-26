module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.BackingStutter
import all ConsensusCoverage.ClauseExactTables
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.DeepActorCases
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersCorpus
import all ConsensusCoverage.SignedQuiet
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ClauseDistinct

open Consensus Consensus.Proofs Consensus.Proofs.Safety ActionProfile ClauseQuestions ClauseExactTables

set_option maxRecDepth 8192
set_option maxHeartbeats 0

private def row (p : Endpoints) (b : Bool) : RestrictedProfile := ⟨p.1,[b,b],p.2⟩

/-- Both bits are equal. If the endpoint changes, the true pair is forced.
On each diagonal, both the true and the false pair occur. -/
public def rows : List RestrictedProfile :=
  endpointRows.flatMap fun p => row p true :: (if p.1 = p.2 then [row p false] else [])

public theorem count : rows.Nodup ∧ rows.length = 9 := by decide +kernel

private def bit (s : Step) := DeepActorCases.check s .keyHere

private theorem hit (s : Step) (yes : bit s) : label s (.step .replaceNode_keys_here_pos) = true :=
  DeepActorCases.correct s .keyHere yes

private theorem false_diagonal (s : Step) (no : label s (.step .replaceNode_keys_here_pos) = false) :
    (endpoints s).1 = (endpoints s).2 := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨x,made,ok⟩ := ReadersAtoms.ofXAction_matches s
  have old : x.base.changed = false := Bool.eq_false_iff.mpr fun h => by
    have yes : bit s = true := by
      simp only [bit, DeepActorCases.check, made, Option.any_some, h, DeepActorCases.test, Bool.and_self]
    exact Bool.noConfusion (no.symm.trans (hit s yes))
  have same := s.context.now_pre ((GuardedDomain.View.old_post ok.1).mpr old)
  have nodes : s.after.nodes = s.before.nodes := by
    change s.context.tr.post = s.context.tr.pre at same
    rw [← s.current_eq, s.context.tr.nodesEq, same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  have eq := BackingStutter.endpoints s nodes.symm
  rw [pre_answers, post_answers] at eq
  exact Prod.ext (congrFun eq .committed_logs_comparable_left_backed_inl)
    (congrFun eq .committed_logs_comparable_left_backed_inr)

private theorem actual (s : Step) :
    clauseLabel .distinct s = row (endpoints s) (label s (.step .replaceNode_keys_here_pos)) := by
  rw [distinct_reduction, ← distinct_bits_eq s]
  rfl

private theorem complete (s : Step) : clauseLabel .distinct s ∈ rows := by
  rw [actual]
  apply List.mem_flatMap.mpr
  refine ⟨_, (endpoint_exact _).mpr ⟨s,rfl⟩, ?_⟩
  cases h : label s (.step .replaceNode_keys_here_pos) with
  | true => exact List.mem_cons_self
  | false => simp [false_diagonal s h]

private def sample (s : Step) : Option RestrictedProfile :=
  if bit s then some (row (endpoints s) true)
  else if SignedQuiet.gate s.cfg s.before s.act s.after s.past then some (row (endpoints s) false)
  else none

private theorem sound {s : Step} {p} (h : sample s = some p) : ClauseRealized .distinct p := by
  refine ⟨s, ?_⟩
  rw [actual]
  unfold sample at h
  split at h
  · rw [hit s ‹_›, Option.some.inj h]
  · split at h
    · have neg := congrFun ((SignedQuiet.gate_iff s).mp ‹_›) .replaceNode_keys_here_pos
      change label s (.step .replaceNode_keys_here_pos) = false at neg
      rw [neg, Option.some.inj h]
    · contradiction

private def picks : List (Nat × Nat) :=
  [(0,0),(0,1),(1,0),(2,0),(34,1),(46,1),(25,4),(25,1),(18,1)]

private def witnessed := picks.filterMap fun (i,j) => (ReadersCorpus.stepAt i j).bind sample

private theorem witnesses : rows.all witnessed.contains = true := by decide +kernel

/-- No total reader for the two `replaceNode_keys` bits is needed to prove
the exact joint table: the positive and negative witness tests need not
classify every *step* so long as they witness every *row*. -/
public theorem distinct_exact : ClauseExactTable .distinct rows := by
  refine ⟨count.1, fun p => ⟨?_, ?_⟩⟩
  · intro mem
    have hm := List.contains_iff_mem.mp (List.all_eq_true.mp witnesses p mem)
    obtain ⟨_,_,h⟩ := List.mem_filterMap.mp hm
    obtain ⟨_,_,test⟩ := Option.bind_eq_some_iff.mp h
    exact sound test
  · rintro ⟨s,rfl⟩
    exact complete s

end ConsensusCoverage.ClauseDistinct
