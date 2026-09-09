-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import BoundedState
import TransactionMapping
import TraceInstructions

set_option autoImplicit false

/-!
# Leader writes from a full entry-state template

Every structural field is explicit. Transaction identifiers may refer to shared
unknowns, including identifiers already present in logs, packets, and submitted
transactions. The entry need not be reachable from bootstrap.
-/

namespace CCFRaft.BoundedTrace

open TraceInstructions

abbrev Bounds := BoundedState.Bounds
abbrev Template (holes : Nat) := State Node (TraceSmt.NatTerm holes)

def observationBounds (bounds : Bounds) : TraceInstructions.Bounds :=
  { transactionCount := bounds.transactionCount, logCapacity := bounds.logCapacity }

def Follows {holes : Nat}
    (bounds : Bounds) (assignment : Fin holes -> Nat) (state : State Node Nat) :
    List (Instruction holes) -> Prop
  | [] => BoundedState.WithinBounds bounds state
  | .observation observation :: rest =>
      BoundedState.WithinBounds bounds state /\
        observation.Holds (observationBounds bounds) assignment state /\
          Follows bounds assignment state rest
  | .clientRequest node transaction :: rest =>
      BoundedState.WithinBounds bounds state /\
        transaction.eval assignment < bounds.transactionCount /\
          Enabled state (.clientRequest node (transaction.eval assignment)) /\
            Follows bounds assignment
              (next state (.clientRequest node (transaction.eval assignment))) rest
  | .signCommittableMessages node :: rest =>
      BoundedState.WithinBounds bounds state /\
        Enabled state (.signCommittableMessages node) /\
          Follows bounds assignment (next state (.signCommittableMessages node)) rest
  | .changeConfiguration node configuration :: rest =>
      BoundedState.WithinBounds bounds state /\
        Enabled state (.changeConfiguration node configuration) /\
          Follows bounds assignment (next state (.changeConfiguration node configuration)) rest
  | .appendRetiredCommitted node :: rest =>
      BoundedState.WithinBounds bounds state /\
        Enabled state (.appendRetiredCommitted node) /\
          Follows bounds assignment (next state (.appendRetiredCommitted node)) rest

def Satisfiable {holes : Nat}
    (bounds : Bounds) (entry : Template holes) (trace : List (Instruction holes)) : Prop :=
  Exists fun assignment : Fin holes -> Nat =>
    (forall index, assignment index < bounds.transactionCount) /\
      Follows bounds assignment
        (TransactionMapping.mapState (TraceSmt.NatTerm.eval assignment) entry) trace

structure VerifiedEncoder (holes : Nat) where
  encode : Bounds -> Template holes -> List (Instruction holes) -> TraceSmt.Formula holes
  correct : forall bounds entry trace assignment,
    (encode bounds entry trace).Holds assignment <->
      (forall index, assignment index < bounds.transactionCount) /\
        Follows bounds assignment
          (TransactionMapping.mapState (TraceSmt.NatTerm.eval assignment) entry) trace

end CCFRaft.BoundedTrace
