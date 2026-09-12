-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeCampaignGuardEncoding
import Sparse.NativeArrayFixtureJson

set_option autoImplicit false
set_option warningAsError true

namespace CCFRaft.NativeCampaignGuardFixtures

open Lean NativeSmt NativeEncode NativeArrayFixtures

private instance : Bootstrap (Fin 3) :=
  { configuration := {0, 1}, leader := 0, leader_mem := by simp }

def decodeGuardInstruction (width : PNat) (names : Array String) (value : Json) :
    Except String (FrameInstruction width) := do
  let kind <- (<- field value "kind").getStr?
  if kind = "timeout" || kind = "becomePreVoteCandidate" then
    fields value ["kind", "node"]
    return .campaign (kind = "becomePreVoteCandidate") (<- resolve width names (<- field value "node"))
  decodeFrameInstruction width names value

def modelFixture (index : Nat) (item : Json) : Except String Json := do
  let input <- decodeDocumentWith decodeGuardInstruction (<- field item "trace")
  let program : EncodeM input.width Unit := do
    initialFrameDomains input.width
    for instruction in input.instructions do
      match instruction with
      | .campaign preVote node =>
        let state <- get
        let base <- fresh
        let _ <- fresh
        let _ <- fresh
        assertAll (campaignGuards state.toColumns state.bootstrap preVote node base)
        return ()
      | other => frameInstruction other
    throw "campaign guard fixture has no campaign instruction"
  let (_, final) <- program.run (initialEncoding input.width input.bootstrap)
  return Json.mkObj [("name", toJson s!"campaign-guard-model-{index}"),
    ("script", toJson (renderScript final.assertions.toList)), ("expected", <- field item "expected")]

def matrixCase (preVote present excluded completed : Bool) (role : Role)
    (membershipState : MembershipState) (status : PreVoteStatus) : Json :=
  let state : State (Fin 3) Nat :=
    { nodes := NodeStore.ofFinset (if present then {0, 1} else {1}) fun _ =>
        { (freshNodeState : NodeState (Fin 3) Nat) with
          role, membershipState, currentTerm := 10 ^ 30, commitIndex := 1
          log := if excluded then
            [{ term := 1, content := .reconfiguration {1} }, { term := 1, content := .signature }]
            else [] }
      preVoteStatus := fun _ => status
      retirementCompleted := fun _ => if completed then {0} else {}
      network := fun _ => [], submittedTxIds := {}, hasJoined := {} }
  let action := NativeArrayVote.campaignAction (T := Nat) preVote (0 : Fin 3)
  let observations := [
      Json.mkObj [("kind", toJson "allocated"), ("node", toJson "a"), ("value", toJson present)]] ++
    nodeObservations 0 (state.nodes 0) ++ globalObservations state []
  let event := Json.mkObj [
    ("kind", toJson (if preVote then "becomePreVoteCandidate" else "timeout")), ("node", toJson "a")]
  Json.mkObj [
    ("expected", toJson (if decide (CCFRaft.Enabled state action) then "sat" else "unsat")),
    ("trace", Json.mkObj [("nodes", toJson (["a", "b", "c"] : List String)),
      ("bootstrap", toJson (["a", "b"] : List String)),
      ("instructions", toJson (observations ++ [event]))])]

def cases (input : Json) : Except String (List Json) := do
  let matrix := [false, true].flatMap fun preVote =>
    [false, true].flatMap fun present =>
      [false, true].flatMap fun excluded =>
        [false, true].flatMap fun completed =>
          [.none, .follower, .preVoteCandidate, .candidate, .leader].flatMap fun role =>
            [.active, .retirementOrdered, .retirementSigned, .retirementCompleted, .retiredCommitted].flatMap
              fun membership =>
                [.capable, .enabled].map (matrixCase preVote present excluded completed role membership)
  let models := (<- input.getArr?).toList ++ matrix
  models.zipIdx.mapM fun (item, index) => modelFixture index item

end CCFRaft.NativeCampaignGuardFixtures

def main : IO Unit := do
  let input <- (<- IO.getStdin).readToEnd
  let result := do
    let input <- Lean.Json.parse input
    CCFRaft.NativeCampaignGuardFixtures.cases input
  match result with
  | .ok fixtures => IO.println (Lean.toJson fixtures).compress
  | .error error => throw (IO.userError error)
