-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Model

set_option autoImplicit false

namespace CCFRaft.TraceStateObservation

inductive Observation (Node : Type) where
  | preVoteStatus (node : Node) (value : PreVoteStatus)
  | membershipState (node : Node) (value : MembershipState)
  | retirementIndex (node : Node) (value : Option Nat)
  | retirementCommittableIndex (node : Node) (value : Option Nat)
  | retiredCommittedIndex (node : Node) (value : Option Nat)
  | retirementCompleted (observer retired : Node) (value : Bool)
  deriving DecidableEq, Repr

/--
Observe stored model fields, without inferring them from the log or requiring
allocation. Local fields at absent nodes use Model's fresh-node lookup.
-/
def Observation.Holds {Node TxId : Type} [DecidableEq Node]
    (state : State Node TxId) : Observation Node -> Prop
  | .preVoteStatus node value => state.preVoteStatus node = value
  | .membershipState node value => (state.nodes node).membershipState = value
  | .retirementIndex node value => (state.nodes node).retirementIndex = value
  | .retirementCommittableIndex node value =>
      (state.nodes node).retirementCommittableIndex = value
  | .retiredCommittedIndex node value => (state.nodes node).retiredCommittedIndex = value
  | .retirementCompleted observer retired value =>
      decide (retired ∈ state.retirementCompleted observer) = value

instance {Node TxId : Type} [DecidableEq Node]
    (state : State Node TxId) (observation : Observation Node) :
    Decidable (observation.Holds state) := by
  cases observation <;> unfold Observation.Holds <;> infer_instance

end CCFRaft.TraceStateObservation
