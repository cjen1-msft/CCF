import Sparse.ObservationTraceEncoding
import Sparse.StateFrameInitial
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.FrameObservationFixtures

open Smt Lean
open StateFrameEncoding (refTerm)
open ModelInputSyntax (ObservationSyntax)

private def firstNode : Node := Fin.mk 0 (by decide +kernel)
private def lastNode : Node := Fin.mk 14 (by decide +kernel)
private def mask (node : Node) : Term .nodes := .nodes (NodeSetCodec.encodeNodes {node})
private def frame := StateFrameInitial.frame 1000 0 0

private def rejectionName : FrameObservationEncoding.Rejection -> String
  | .submitted => "submitted"
  | .firstMessage => "firstMessage"
  | .messageSummary => "messageSummary"
  | .queueLength => "queueLength"
  | .configurationSnapshot => "configurationSnapshot"
  | .action => "action"

private def fixture {n : Nat} (name : String) (input : SmtScript.Formula)
    (trace : ModelInputSyntax.Trace n) (expected : String) (canonical : Bool := false) : Json :=
  let encoded := if canonical then ObservationTraceEncoding.encode trace
    else FrameObservationEncoding.encodeChecked 0 frame trace
  match encoded with
  | .error reason => Json.mkObj [("name", toJson name), ("expected", toJson expected),
      ("rejection", toJson (rejectionName reason))]
  | .ok encoded =>
    let script := SmtScript.render (input ++ encoded)
    let checked := if canonical then ObservationTraceEncoding.render trace
      else FrameObservationEncoding.renderChecked 0 frame trace
    let checkedMatches := match checked with
      | .ok text => text == SmtScript.render encoded
      | .error _ => false
    Json.mkObj [
      ("name", toJson name), ("expected", toJson expected), ("script", toJson script),
      ("clauses", toJson encoded.length), ("instructions", toJson trace.length),
      ("source_count", toJson n),
      ("checked_matches", toJson checkedMatches),
      ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
      ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput
        (SmtScript.compile (input ++ encoded)))),
      ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

private def single (name : String) (input : SmtScript.Formula)
    (observation : ObservationSyntax 0) (expected : String) : Json :=
  fixture name input [.observation observation] expected

def leaves : List Json :=
  [firstNode, lastNode].flatMap fun node =>
    [false, true].flatMap fun active =>
      let row := frame.locals[node.val]
      let allocated := Term.equal (refTerm frame.allocated) (if active then mask node else .nodes 0)
      let localValue := fun value : Int => if active then value else -1000000
      let cases : List (String × SmtScript.Formula × ObservationSyntax 0 × ObservationSyntax 0) :=
        [("allocated", [], .allocated node (.literal active), .allocated node (.literal (!active))),
         ("joined", [.equal (refTerm frame.hasJoined) (mask node)],
          .joined node (.literal true), .joined node (.literal false)),
         ("role", [.equal (refTerm row.role) (.integer (localValue (StateFrame.roleCode .leader)))],
          .role node (if active then .leader else .none), .role node .candidate),
         ("term", [.equal (refTerm row.currentTerm) (.integer (localValue 7))],
          .currentTerm node (.literal (if active then 7 else 0)), .currentTerm node (.literal 8)),
         ("commit", [.equal (refTerm row.commitIndex) (.integer (localValue 9))],
          .commitIndex node (.literal (if active then 9 else 0)), .commitIndex node (.literal 10)),
         ("length", [.equal (refTerm row.log.length) (.integer (localValue 1000000))],
          .logLength node (.literal (if active then 1000000 else 0)), .logLength node (.literal 2)),
         ("pre-vote", [.equal (refTerm frame.preVoteEnabled[node.val]) (.boolean true)],
          .state (.preVoteStatus node .enabled), .state (.preVoteStatus node .capable)),
         ("membership", [.equal (refTerm row.membershipState)
            (.integer (localValue (StateFrame.membershipCode .retirementOrdered)))],
          .state (.membershipState node (if active then .retirementOrdered else .active)),
          .state (.membershipState node .retiredCommitted)),
         ("retirement", [.equal (refTerm row.retirementIndex) (.integer (localValue 1))],
          .state (.retirementIndex node (if active then some (.literal 0) else none)),
          .state (.retirementIndex node (some (.literal 4)))),
         ("committable", [.equal (refTerm row.retirementCommittableIndex) (.integer (localValue 3))],
          .state (.retirementCommittableIndex node (if active then some (.literal 2) else none)),
          .state (.retirementCommittableIndex node (some (.literal 4)))),
         ("retired", [.equal (refTerm row.retiredCommittedIndex) (.integer (localValue 4))],
          .state (.retiredCommittedIndex node (if active then some (.literal 3) else none)),
          .state (.retiredCommittedIndex node (some (.literal 4)))),
         ("completed", [.equal (refTerm frame.retirementCompleted[node.val]) (mask lastNode)],
          .state (.retirementCompleted node lastNode (.literal true)),
          .state (.retirementCompleted node lastNode (.literal false)))]
      cases.flatMap fun (kind, input, good, bad) =>
        [single s!"{kind}-{node.val}-{active}-sat" (allocated :: input) good "sat",
         single s!"{kind}-{node.val}-{active}-unsat" (allocated :: input) bad "unsat"]

def enumCases : List Json :=
  FrameObservationEncoding.Regression.roles.flatMap fun role =>
    FrameObservationEncoding.Regression.memberships.map fun membership =>
      fixture s!"enums-{StateFrame.roleCode role}-{StateFrame.membershipCode membership}"
        [.equal (refTerm frame.allocated) (mask firstNode),
         .equal (refTerm frame.locals[0].role) (.integer (StateFrame.roleCode role)),
         .equal (refTerm frame.locals[0].membershipState) (.integer (StateFrame.membershipCode membership))]
        ([.observation (.role firstNode role),
          .observation (.state (.membershipState firstNode membership))] : ModelInputSyntax.Trace 0)
        "sat"

def sharedCases : List Json :=
  [0, 2, 7].flatMap fun value =>
    [false, true].map fun wrong =>
      let joined := (value == 0) != wrong
      fixture s!"shared-{value}-{wrong}"
        [.equal (refTerm frame.allocated) (mask firstNode),
         .equal (refTerm frame.hasJoined) (if joined then mask firstNode else .nodes 0),
         .equal (.unknown .int 0) (.integer value),
         .equal (refTerm frame.locals[0].currentTerm) (.integer value),
         .equal (refTerm frame.locals[0].retirementIndex) (.integer (value + 1))]
        ([.observation (.currentTerm firstNode (.unknown 0)),
          .observation (.joined firstNode (.isZero (.unknown 0))),
          .observation (.state (.retirementIndex firstNode (some (.unknown 0)))),
          .observation (.currentTerm firstNode (.unknown 0))] : ModelInputSyntax.Trace 1)
        (if wrong then "unsat" else "sat")

def edgeCases : List Json :=
  [fixture "adjacent-conflict" []
    ([.observation (.commitIndex firstNode (.literal 1)),
      .observation (.commitIndex firstNode (.literal 2))] : ModelInputSyntax.Trace 0) "unsat",
   fixture "negative-unused-source" [.equal (.unknown .int 1) (.integer (-1))]
    ([] : ModelInputSyntax.Trace 2) "unsat",
   fixture "empty-trace" [] ([] : ModelInputSyntax.Trace 0) "sat",
   fixture "none-some-zero-conflict" [.equal (refTerm frame.allocated) (mask firstNode)]
    ([.observation (.state (.retirementIndex firstNode none)),
      .observation (.state (.retirementIndex firstNode (some (.literal 0))))] :
      ModelInputSyntax.Trace 0) "unsat"]

def rejectedCases : List Json :=
  let observations : List (ObservationSyntax 0) :=
    [.submitted (.literal 0) (.literal true), .firstMessage firstNode lastNode none,
     .messageSummary (.proposeVoteRequest { term := .literal 0, source := firstNode, destination := lastNode }),
     .queueLength firstNode (.literal 0), .configurationSnapshot firstNode []]
  (observations.zip ["submitted", "firstMessage", "messageSummary", "queueLength", "configurationSnapshot"]).map
    (fun (observation, name) => fixture s!"reject-{name}" []
      [.observation (.currentTerm firstNode (.literal 0)), .observation observation] name) ++
    [fixture "reject-action" []
      ([.observation (.currentTerm firstNode (.literal 0)), .action (.timeout firstNode)] :
        ModelInputSyntax.Trace 0) "action"]

def canonicalCases : List Json :=
  [fixture "canonical-empty" [] ([] : ModelInputSyntax.Trace 0) "sat" true,
   fixture "canonical-unused-names" [] ([] : ModelInputSyntax.Trace 2) "sat" true,
   fixture "canonical-absent-nonfresh" []
    ([.observation (.allocated firstNode (.literal false)),
      .observation (.currentTerm firstNode (.literal 1))] : ModelInputSyntax.Trace 0) "unsat" true,
   fixture "canonical-absent-globals" []
    ([.observation (.allocated firstNode (.literal false)),
      .observation (.joined firstNode (.literal true)),
      .observation (.state (.preVoteStatus firstNode .enabled)),
      .observation (.state (.retirementCompleted firstNode lastNode (.literal true)))] :
      ModelInputSyntax.Trace 0) "sat" true,
   fixture "canonical-shared-name" []
    ([.observation (.role firstNode .leader),
      .observation (.currentTerm firstNode (.unknown 0)),
      .observation (.currentTerm firstNode (.literal 2)),
      .observation (.joined firstNode (.isZero (.unknown 0))),
      .observation (.joined firstNode (.literal false))] : ModelInputSyntax.Trace 1) "sat" true,
   fixture "canonical-shared-conflict" []
    ([.observation (.currentTerm firstNode (.unknown 0)),
      .observation (.currentTerm firstNode (.literal 2)),
      .observation (.joined firstNode (.isZero (.unknown 0))),
      .observation (.joined firstNode (.literal true))] : ModelInputSyntax.Trace 1) "unsat" true,
   fixture "canonical-alias-names" []
    ([.observation (.role firstNode .leader),
      .observation (.currentTerm firstNode (.unknown 0)),
      .observation (.currentTerm firstNode (.unknown 1)),
      .observation (.currentTerm firstNode (.literal 7))] : ModelInputSyntax.Trace 2) "sat" true,
   fixture "canonical-million-log" []
    ([.observation (.logLength lastNode (.literal 1000000)),
      .observation (.commitIndex lastNode (.literal 2000000))] : ModelInputSyntax.Trace 0) "sat" true,
   fixture "canonical-adjacent-conflict" []
    ([.observation (.commitIndex firstNode (.literal 1)),
      .observation (.commitIndex firstNode (.literal 2))] : ModelInputSyntax.Trace 0) "unsat" true,
   fixture "canonical-reject-action" [] ([.action (.timeout firstNode)] : ModelInputSyntax.Trace 0)
    "action" true,
   fixture "canonical-reject-queue" []
    ([.observation (.queueLength firstNode (.literal 0))] : ModelInputSyntax.Trace 0)
    "queueLength" true]

end CCFRaft.Sparse.FrameObservationFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.FrameObservationFixtures.leaves ++
    CCFRaft.Sparse.FrameObservationFixtures.enumCases ++
    CCFRaft.Sparse.FrameObservationFixtures.sharedCases ++
    CCFRaft.Sparse.FrameObservationFixtures.edgeCases ++
    CCFRaft.Sparse.FrameObservationFixtures.rejectedCases ++
    CCFRaft.Sparse.FrameObservationFixtures.canonicalCases)).compress
