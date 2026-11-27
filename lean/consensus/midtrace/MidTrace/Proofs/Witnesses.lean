module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter

import all Consensus.Replay.Interpreter

namespace Consensus.MidTrace.Proofs.Witnesses

open CCF (Finset)
open Model.Node (NodeID)
open Replay (Group Header ReplayState)

public theorem replayFrom_sound_witness
    : exists (header : Header) (s0 : Model.State),
    exists (groups : Array Group) (final : ReplayState),
      header.bootstrap.Nonempty
      /\ header.declared ≠ []
      /\ groups ≠ #[]
      /\ Replay.replayFrom header { state := s0 } groups = .ok final := by
  let header : Header := ⟨{0}, ["A"]⟩
  let groups : Array Group :=
    #[⟨"A", 0, 0, none,
      #[.action (.local "A" (.append [{ content := .signature }])) ⟨"", 0, "append"⟩]⟩]
  let start : ReplayState := { state := header.initial }
  let final := (Replay.replayFrom header start groups).toOption.getD start
  refine ⟨header, start.state, groups, final, ?_, by decide, ?_, rfl⟩
  · exact ⟨0, by decide +kernel⟩
  · intro empty
    have sizes : (1 : Nat) = 0 := congrArg Array.size empty
    exact Nat.noConfusion sizes

public theorem reachable_implies_initInvariant_witness
    : exists (bootstrap : Finset NodeID) (nodes : List NodeID) (s0 : Model.State),
        bootstrap.Nonempty /\ (Model.transitionSystem bootstrap nodes).Reachable s0 := by
  let s0 : Model.State := { nodes := [(0, Model.initialNodeState {0} 0)] }
  have nonempty : ({0} : Finset NodeID).Nonempty := ⟨0, by decide +kernel⟩
  refine ⟨{0}, [0], s0, nonempty, .initial ⟨nonempty, rfl, by decide, rfl, ?_⟩⟩
  rintro entry member
  simp only [s0, List.mem_singleton] at member
  subst entry
  rfl

end Consensus.MidTrace.Proofs.Witnesses
