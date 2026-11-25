module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersBSummary
import all ConsensusCoverage.HandReadersBSummary

namespace ConsensusCoverage.HandReadersB

open Consensus Consensus.Model ActionProfile HandReadersBSummary

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def kinds : List Kind :=
  [.quorum, .nominate, .install, .receive, .request, .ack, .vote, .ballot, .preVote, .preBallot, .propose]

public def covered : List Classes.StepBranch := kinds.map column

public theorem covered_nodup : covered.Nodup := by decide
public theorem count : covered.length = 11 := by decide

public def read (cfg : FullProfile.Configuration) (before : State) (act : Action)
    (after : State) (past : List State) (b : Classes.StepBranch) : Option Bool :=
  (kinds.find? fun k => column k == b).map (answer cfg before act after past)

public theorem read_correct (s : Step) {b : Classes.StepBranch} {v : Bool}
    (h : read s.cfg s.before s.act s.after s.past b = some v) : label s (.step b) = v := by
  obtain ⟨k, found, rfl⟩ := Option.map_eq_some_iff.mp h
  have yes := List.find?_some (p := fun x => column x == b) found
  have eq : column k = b := beq_iff_eq.mp yes
  exact eq ▸ exact_answer s k

public theorem read_total (s : Step) {b : Classes.StepBranch} (mem : b ∈ covered) :
    (read s.cfg s.before s.act s.after s.past b).isSome := by
  change b ∈ kinds.map column at mem
  obtain ⟨k, member, rfl⟩ := (List.mem_map (f := column)).mp mem
  simp only [read, Option.isSome_map, List.isSome_find?, List.any_eq_true]
  exact ⟨k, member, beq_self_eq_true _⟩

end ConsensusCoverage.HandReadersB
