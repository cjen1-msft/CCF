-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.StateFrameInitial
import Sparse.StateFrameEncoding
import Sparse.QueueEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.StateFrameFixtures

private def sortName : Smt.Ty -> String
  | .bool => "bool"
  | .int => "int"
  | .nodes => "nodes"
  | .content => "content"
  | .entry => "entry"

private def symbolJson : Smt.Symbol -> Lean.Json
  | .constant ty id => Lean.Json.mkObj
      [("constant", Lean.toJson true), ("sort", Lean.toJson (sortName ty)), ("id", Lean.toJson id)]
  | .unary domain result id => Lean.Json.mkObj
      [("constant", Lean.toJson false), ("domain", Lean.toJson (sortName domain)),
       ("result", Lean.toJson (sortName result)), ("id", Lean.toJson id)]

def fixture (base prior versions : Nat) : IO Lean.Json := do
  let start <- IO.monoNanosNow
  let stored <- IO.mkRef (StateFrameInitial.frame base prior versions)
  let finish <- IO.monoNanosNow
  let frame <- stored.get
  let roots := List.ofFn fun node : Node =>
    match frame.locals[node.val].log.address with
    | .root id => Lean.Json.mkObj [("kind", Lean.toJson "root"), ("id", Lean.toJson id.val)]
    | .version id => Lean.Json.mkObj [("kind", Lean.toJson "version"), ("id", Lean.toJson id.val)]
  return Lean.Json.mkObj
    [("base", Lean.toJson base), ("prior", Lean.toJson prior), ("versions", Lean.toJson versions),
     ("high_water", Lean.toJson (StateFrameInitial.highWater base)),
     ("allocation_ns", Lean.toJson (finish - start)),
     ("symbols", Lean.toJson (frame.symbols.map symbolJson)), ("roots", Lean.toJson roots)]

private def domainCase {roots versions : Nat} (name : String) (frame : StateFrame.Frame roots versions)
    (input : SmtScript.Formula) (metadata : List (Prod String Lean.Json)) : Lean.Json :=
  let formula := input ++ StateFrameEncoding.encode frame
  let script := SmtScript.render formula
  Lean.Json.mkObj ([
    ("name", Lean.toJson name), ("script", Lean.toJson script),
    ("clauses", Lean.toJson (StateFrameEncoding.encode frame).length),
    ("parsed_script", Lean.toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", Lean.toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", Lean.toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def allocation (node : Node) (active : Bool) : BitVec NODE_COUNT :=
  if active then NodeSetCodec.encodeNodes {node} else if node.val == 0 then 16384 else 1

private def firstNode : Node := Fin.mk 0 (by decide +kernel)
private def lastNode : Node := Fin.mk 14 (by decide +kernel)

private def domainMetadata (node : Node) (active : Bool) (column : Nat) (value : Int) : List (Prod String Lean.Json) :=
  [("node", Lean.toJson node.val), ("active", Lean.toJson active),
   ("allocation", Lean.toJson (allocation node active).toNat),
   ("column", Lean.toJson column), ("value", Lean.toJson value)]

def domainFixtures : List Lean.Json :=
  let frame := StateFrameInitial.frame 1000 1000000000000 1000000000000
  [firstNode, lastNode].flatMap (fun node =>
    [false, true].flatMap fun active =>
      (List.ofFn fun column : Fin 39 =>
        let values : List Int := if column.val == 0 || column.val == 5 then [-1, 0, 4, 5]
          else if column.val == 4 then [-1, 0, 1, 15, 16] else [-1, 0, 1, 1000000]
        values.map fun value =>
          domainCase s!"field-{node.val}-{active}-{column.val}-{value}" frame
            [.equal (StateFrameEncoding.refTerm frame.allocated) (.nodes (allocation node active)),
             .equal (StateFrameEncoding.refTerm frame.hasJoined) (.nodes (~~~(allocation node active))),
             .equal (StateFrameEncoding.refTerm (StateFrameInitial.intRef 1000 node column)) (.integer value)]
            (domainMetadata node active column.val value)).flatten) ++
  [false, true].flatMap (fun active =>
    ([4, 5] : List Int).map fun value =>
      let row := frame.locals[0]
      let aliased := { frame with locals := Vector.ofFn fun node : Node =>
        if node.val == 0 then { row with role := row.currentTerm } else frame.locals[node.val] }
      domainCase s!"alias-{active}-{value}" aliased
        [.equal (StateFrameEncoding.refTerm frame.allocated) (.nodes (allocation firstNode active)),
         .equal (StateFrameEncoding.refTerm row.role) (.integer 0),
         .equal (StateFrameEncoding.refTerm row.currentTerm) (.integer value)]
        (domainMetadata firstNode active 0 value)) ++
  [domainCase "commit-beyond-empty-log" frame
     [.equal (StateFrameEncoding.refTerm frame.allocated) (.nodes 16384),
      .equal (StateFrameEncoding.refTerm frame.hasJoined) (.nodes 0),
      .equal (StateFrameEncoding.refTerm frame.locals[14].commitIndex) (.integer 1000000),
      .equal (StateFrameEncoding.refTerm frame.locals[14].log.length) (.integer 0)]
     [("expected", Lean.toJson "sat")],
   domainCase "independent-global-and-local-masks" frame
     [.equal (StateFrameEncoding.refTerm frame.allocated) (.nodes 0),
      .equal (StateFrameEncoding.refTerm frame.hasJoined) (.nodes 32767),
      .equal (StateFrameEncoding.refTerm frame.retirementCompleted[14]) (.nodes 32767),
      .equal (StateFrameEncoding.refTerm frame.preVoteEnabled[14]) (.boolean true),
      .equal (StateFrameEncoding.refTerm frame.locals[14].isNewFollower) (.boolean true),
      .equal (StateFrameEncoding.refTerm frame.locals[14].votesGranted) (.nodes 32767),
      .equal (StateFrameEncoding.refTerm frame.locals[14].role) (.integer (-1))]
     [("expected", Lean.toJson "sat")]]

end CCFRaft.Sparse.StateFrameFixtures

def main (args : List String) : IO UInt32 := do
  if args == ["--domains"] then
    IO.println (Lean.toJson CCFRaft.Sparse.StateFrameFixtures.domainFixtures).compress
    return 0
  unless args.isEmpty do
    ( <- IO.getStderr).putStrLn "usage: StateFrameFixtureMain.lean [--domains]"
    return 1
  let cases <- [(0, 0, 0), (1000, 7, 400), (1000000, 1000000, 1000000),
    (1000000000000, 1000000000000, 1000000000000)].mapM fun (base, prior, versions) =>
      CCFRaft.Sparse.StateFrameFixtures.fixture base prior versions
  IO.println (Lean.toJson cases).compress
  return 0
