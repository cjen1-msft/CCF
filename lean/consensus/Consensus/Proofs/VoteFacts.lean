module

public import Consensus.Model

/-! The ballot ghost. Definitions only: the proofs about them are in `SafetyInvariant.lean`,
the module whose proof bodies the coverage generator reads. -/

namespace Consensus.Proofs.VoteFacts

open Model.Node

public structure Stamp where
  voter : NodeID
  term : Nat
  vote : Option NodeID
deriving DecidableEq

public abbrev Ghost := List Stamp

@[expose] public def stamp (n : NodeID) (s : NodeState) : Stamp := ⟨n, s.currentTerm, s.votedFor⟩

/-- Duplicate observations carry no information. No ordering or past snapshots are read. -/
@[expose] public def advance (g : Ghost) (s : Model.State) : Ghost :=
  ((s.nodes.map fun (n, st) => stamp n st) ++ g).eraseDups

end Consensus.Proofs.VoteFacts
