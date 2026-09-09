-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TraceStateObservationJson
import MachineGenerated.TraceStateObservationProofs
import Shared.Guarded
import Lean

set_option autoImplicit false

namespace CCFRaft.TraceStateObservation.Tests

open Lean TraceSmt TransactionMapping

private def node : Node := ⟨1, by decide⟩
private def absent : Node := ⟨14, by decide⟩
private def other : Node := ⟨2, by decide⟩
private def aliased : Fin 2 -> Nat := fun _ => 9
private def distinct : Fin 2 -> Nat := fun index => index.val

-- Stored retirement fields deliberately disagree with the empty log.
private def template (membership : MembershipState := .active)
    (preVote : PreVoteStatus := .capable) (index : Option Nat := none) :
    State Node (NatTerm 2) :=
  { (initialState : State Node (NatTerm 2)) with
    nodes := updateNode (initialState : State Node (NatTerm 2)).nodes node
      { (freshNodeState : NodeState Node (NatTerm 2)) with
        membershipState := membership
        retirementIndex := index
        retirementCommittableIndex := index
        retiredCommittedIndex := index }
    preVoteStatus := fun _ => preVote
    retirementCompleted := fun observer => if observer = absent then {node, absent} else {}
    submittedTxIds := {.unknown 0, .unknown 1} }

private def memberships : List (String × MembershipState) :=
  [("active", .active), ("retirementOrdered", .retirementOrdered),
   ("retirementSigned", .retirementSigned), ("retirementCompleted", .retirementCompleted),
   ("retiredCommitted", .retiredCommitted)]
private def preVotes : List (String × PreVoteStatus) :=
  [("capable", .capable), ("enabled", .enabled)]
private def indices : List (Option Nat) := [none, some 0, some 1, some 123]
private def indexFields : List (String × (Node -> Option Nat -> Observation Node)) :=
  [("retirementIndex", .retirementIndex),
   ("retirementCommittableIndex", .retirementCommittableIndex),
   ("retiredCommittedIndex", .retiredCommittedIndex)]

private def nodeJson (variableName : String) (value : Json) (nodeId : Nat := 1) : Json :=
  Json.mkObj [("kind", .str "observation"), ("variable", .str variableName),
    ("node", toJson nodeId), ("value", value)]

private def membershipJson (value : Bool) (observer : Nat := 14) (retired : Nat := 1) : Json :=
  Json.mkObj [("kind", .str "observation"), ("variable", .str "retirementCompleted"),
    ("observer", toJson observer), ("retired", toJson retired), ("value", .bool value)]

private def optionalJson : Option Nat -> Json
  | none => .null
  | some value => toJson value

-- All enum values, cross-value rejection, and the same arbitrary assignment.
#guard memberships.all fun (_, actual) =>
  memberships.all fun (text, expected) =>
    let state := template actual
    let observation := Observation.membershipState node expected
    (decode (nodeJson "membershipState" (.str text))).toOption == some observation &&
      decide (observation.Holds state) == decide (actual = expected) &&
      decide ((expression state observation).Holds aliased) == decide (actual = expected) &&
      decide ((expression state observation).Holds distinct) ==
        decide (observation.Holds (mapState (NatTerm.eval distinct) state))

#guard preVotes.all fun (_, actual) =>
  preVotes.all fun (text, expected) =>
    let state := template .active actual
    let observation := Observation.preVoteStatus absent expected
    (decode (nodeJson "preVoteStatus" (.str text) 14)).toOption == some observation &&
      decide (observation.Holds state) == decide (actual = expected) &&
      decide ((expression state observation).Holds aliased) ==
        decide (observation.Holds (mapState (NatTerm.eval aliased) state)) &&
      decide ((expression state observation).Holds distinct) == decide (actual = expected)

-- Null is absence, never zero. These tests impose no index or reachability bounds.
#guard indexFields.all fun (fieldName, constructor) =>
  indices.all fun actual =>
    indices.all fun expected =>
      let state := template .retiredCommitted .enabled actual
      let observation := constructor node expected
      (decode (nodeJson fieldName (optionalJson expected))).toOption == some observation &&
        decide (observation.Holds state) == decide (actual = expected) &&
        decide ((expression state observation).Holds aliased) ==
          decide (observation.Holds (mapState (NatTerm.eval aliased) state)) &&
        decide ((expression state observation).Holds distinct) == decide (actual = expected)

-- All local fields of an absent node use freshNodeState, not the allocated peer.
#guard !(template .retiredCommitted .enabled (some 123)).allocated absent
#guard memberships.all fun (_, value) =>
  decide ((Observation.membershipState absent value).Holds
    (template .retiredCommitted .enabled (some 123))) == decide (value = .active)
#guard indexFields.all fun (_, constructor) =>
  indices.all fun value =>
    decide ((constructor absent value).Holds (template .retiredCommitted .enabled (some 123))) ==
      decide (value = none)

-- Global tables can have meaningful rows for absent observers and retired nodes.
#guard [true, false].all fun value =>
  [node, absent, other].all fun retired =>
    let observation := Observation.retirementCompleted absent retired value
    (decode (membershipJson value 14 retired.val)).toOption == some observation &&
      decide (observation.Holds template) == decide ((retired != other) = value) &&
      decide ((expression template observation).Holds aliased) ==
        decide (observation.Holds (mapState (NatTerm.eval aliased) template))
#guard (Observation.retirementCompleted node absent false).Holds template
#guard !(Observation.retirementCompleted node absent true).Holds template
#guard (Observation.preVoteStatus absent .enabled).Holds (template .active .enabled)
#guard (mapState (NatTerm.eval aliased) template).submittedTxIds.card == 1
#guard (mapState (NatTerm.eval distinct) template).submittedTxIds.card == 2

private def distinctIndices : State Node (NatTerm 2) :=
  let state := template
  { state with
    nodes := updateNode state.nodes node
      { (state.nodes node) with
        retirementIndex := some 1
        retirementCommittableIndex := some 2
        retiredCommittedIndex := some 3 } }

#guard (Observation.retirementIndex node (some 1)).Holds distinctIndices
#guard (Observation.retirementCommittableIndex node (some 2)).Holds distinctIndices
#guard (Observation.retiredCommittedIndex node (some 3)).Holds distinctIndices
#guard !((expression distinctIndices (.retirementIndex node (some 2))).Holds aliased)
#guard !((expression distinctIndices (.retirementCommittableIndex node (some 3))).Holds aliased)
#guard !((expression distinctIndices (.retiredCommittedIndex node (some 1))).Holds aliased)

-- Strict decoding reuses the entry-state enum and optional decoders.
#guard ["unknown", "Enabled", "active"].all fun text =>
  (decode (nodeJson "preVoteStatus" (.str text))).toOption.isNone
#guard ["unknown", "RetiredCommitted", "enabled"].all fun text =>
  (decode (nodeJson "membershipState" (.str text))).toOption.isNone
#guard indexFields.all fun (fieldName, _) =>
  [Json.str "0", Json.str "none", Json.bool false, toJson (-1 : Int), Json.arr #[]].all
    fun invalid => (decode (nodeJson fieldName invalid)).toOption.isNone
#guard (decode (nodeJson "preVoteStatus" (.str "capable") 15)).toOption.isNone
#guard (decode (membershipJson true 15 1)).toOption.isNone
#guard (decode (membershipJson true 1 15)).toOption.isNone
#guard (decode (nodeJson "unknownField" .null)).toOption.isNone
#guard (decode (nodeJson "retirementCompleted" (.bool true))).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "action"), ("variable", .str "retirementIndex"),
   ("node", toJson (1 : Nat)), ("value", .null)])).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementIndex"),
   ("node", toJson (1 : Nat))])).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementIndex"),
   ("node", toJson (1 : Nat)), ("value", .null), ("extra", .null)])).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementCompleted"),
   ("observer", toJson (14 : Nat)), ("retired", toJson (1 : Nat)),
   ("value", toJson (1 : Nat))])).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementCompleted"),
   ("observer", toJson (14 : Nat)), ("value", .bool false)])).toOption.isNone
#guard (decode (Json.mkObj
  [("kind", .str "observation"), ("variable", .str "retirementIndex"),
   ("node", .str "14"), ("value", .null), ("provenance", .str "raw"),
   ("rule", .str "state")])).toOption == some (.retirementIndex absent none)

example {Node TxId OtherTxId : Type} [DecidableEq Node] [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId) (state : State Node TxId) (observation : Observation Node) :
    observation.Holds (mapState f state) ↔ observation.Holds state :=
  holds_map f state observation

example {holes : Nat} (assignment : Fin holes -> Nat)
    (state : State Node (NatTerm holes)) (observation : Observation Node) :
    (expression state observation).Holds assignment ↔
      observation.Holds (mapState (NatTerm.eval assignment) state) :=
  expression_correct assignment state observation

end CCFRaft.TraceStateObservation.Tests

run_cmd do
  for theoremName in [
      ``CCFRaft.TraceStateObservation.holds_map,
      ``CCFRaft.TraceStateObservation.expression_correct] do
    for axiomName in ← Lean.collectAxioms theoremName do
      unless axiomName == ``propext || axiomName == ``Classical.choice ||
          axiomName == ``Quot.sound do
        throwError "{theoremName} depends on unapproved axiom {axiomName}"
