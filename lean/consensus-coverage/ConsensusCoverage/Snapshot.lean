module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.PairQuestions
import all ConsensusCoverage.PairQuestions

namespace ConsensusCoverage.PairQuestions

open Consensus Consensus.Model.Node

public structure Sample where
  id : NodeID
  primary : Bool
  currentTerm : Nat
  commitIndex : Nat

public def snapshot (s : Model.State) : List Sample :=
  s.nodes.map fun (id, st) => ⟨id, st.role == .primary, st.currentTerm, st.commitIndex⟩

public def snapshotLabel (before after : List Sample) : Bool × Bool × Bool :=
  let atZero (s : List Sample) := s.any fun n => n.commitIndex == 0
  let won := after.any fun n => n.primary && !(before.any fun old =>
    old.id == n.id && old.primary && old.currentTerm == n.currentTerm)
  (atZero before, won, atZero after)

/-- In particular, mutations to omitted fields cannot change this label, even off execution. -/
public theorem snapshotLabel_eq (s t : Model.State) :
    snapshotLabel (snapshot s) (snapshot t) = label s t := by
  change snapshotLabel _ _ = (zero s, newPrimary s t, zero t)
  simp [snapshotLabel, snapshot, zero, newPrimary, List.any_map, Function.comp_def]

end ConsensusCoverage.PairQuestions
