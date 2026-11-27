module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import MidTrace.Model
public import MidTrace.Properties.Certificate
public import Consensus.Replay.Interpreter
public import CCF.Execution

import MidTrace.Proofs.Certificate
import MidTrace.Proofs.Witnesses

@[expose] public section

/-!
Theorems about mid-trace certification, each paired with a witness that
satisfies its preconditions.
-/

namespace Consensus.MidTrace.Properties

open CCF (Finset)
open Model.Node (NodeID)
open Replay (Group Header ReplayState)

/-- Successful replay from the supplied cut justifies every observation in order
and yields a run of the consensus model. -/
theorem replayFrom_sound
    : forall (header : Header) (s0 : Model.State) (groups : Array Group)
              (final : ReplayState),
        Replay.replayFrom header { state := s0 } groups = .ok final
        -> exists actions,
            ValidInstructions header { state := s0 }
              (groups.toList.flatMap fun group => group.instructions.toList) actions final
            /\ CCF.Execution.Run (Model.transitionSystem header.bootstrap []) s0 actions
                final.state := by
  exact Proofs.Certificate.replayFrom_sound

/-- Witness: a nonempty replay with a signature append from bootstrap succeeds. -/
theorem replayFrom_sound_witness
    : exists (header : Header) (s0 : Model.State),
    exists (groups : Array Group) (final : ReplayState),
      header.bootstrap.Nonempty
      /\ header.declared ≠ []
      /\ groups ≠ #[]
      /\ Replay.replayFrom header { state := s0 } groups = .ok final := by
  exact Proofs.Witnesses.replayFrom_sound_witness

/-- The concrete cut checker accepts every reachable state with the original
bootstrap configuration or no bootstrap information. -/
theorem reachable_implies_initInvariant
    : forall (bootstrap : Finset NodeID) (nodes : List NodeID) (s0 : Model.State),
        (Model.transitionSystem bootstrap nodes).Reachable s0
        -> InitInvariant.check bootstrap s0 = .ok ()
            /\ InitInvariant.check ∅ s0 = .ok () := by
  exact Proofs.Certificate.reachable_implies_initInvariant

/-- Witness: a singleton bootstrap has a reachable state. -/
theorem reachable_implies_initInvariant_witness
    : exists (bootstrap : Finset NodeID) (nodes : List NodeID) (s0 : Model.State),
        bootstrap.Nonempty /\ (Model.transitionSystem bootstrap nodes).Reachable s0 := by
  exact Proofs.Witnesses.reachable_implies_initInvariant_witness

end Consensus.MidTrace.Properties
