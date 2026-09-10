import Sparse.QueueEncoding
import Sparse.QueueScalarEncoding
import Sparse.SmtScriptText
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueCountFixtures

open QueueEncoding QueueStream Smt Lean

private def formulaFields (formula : SmtScript.Formula) : List (Prod String Json) :=
  let script := SmtScript.render formula
  [("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText regressionInput script))]

private def fixture (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) : Json :=
  Json.mkObj ([("name", toJson name), ("expected", toJson expected),
    ("scope", toJson "count-read")] ++ formulaFields (encode input [] trace observations))

private def scalarFixture (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (length : InputInt) : Json :=
  Json.mkObj ([("name", toJson name), ("expected", toJson expected),
    ("scope", toJson "count-and-scalar"),
    ("count_range_end", toJson (freshBase input + QueueReadback.writeCount trace + 1)),
    ("scalar_base", toJson (QueueScalarEncoding.scalarBase input [] trace observations))] ++
    formulaFields (QueueScalarEncoding.encode input [] trace observations length))

private def sendOne : List (Event InputInt) := [.send (.literal 1)]
private def sendSymbol : List (Event InputInt) := [.send (.symbolic 0)]
private def popOne : List (Event InputInt) := [.pop (.literal 1)]
private def sameKeys : Term .bool := .equal (.unknown .int 0) (.unknown .int 1)

private def otherKey (expected : Int) : List (Observation sendOne) :=
  [{ version := 0, key := .literal 2, expected := .literal 7 },
   { version := 1, key := .literal 2, expected := .literal expected }]

private def aliasCounts : List (Observation []) :=
  [{ version := 0, key := .symbolic 0, expected := .literal 0 },
   { version := 0, key := .symbolic 1, expected := .literal 1 }]

private def storedAlias : List (Observation sendSymbol) :=
  [{ version := 0, key := .symbolic 0, expected := .literal 0 },
   { version := 0, key := .symbolic 1, expected := .literal 0 },
   { version := 1, key := .symbolic 1, expected := .literal 0 }]

private def symbolicExpected : List (Observation sendOne) :=
  [{ version := 0, key := .literal 1, expected := .literal 0 },
   { version := 1, key := .literal 1, expected := .symbolic 9 }]

def fixtures : List Json :=
  [
    fixture "duplicate-send" "sat" [] regressionTrace regressionObservations,
    fixture "duplicate-send-contradiction" "unsat" [] regressionTrace
      (regressionObservations ++
        [{ version := 2, key := .literal (-2), expected := .literal 2 }]),
    fixture "other-key-preserved" "sat" [] sendOne (otherKey 7),
    fixture "other-key-contradiction" "unsat" [] sendOne (otherKey 8),
    fixture "aliased-root-counts" "unsat" [sameKeys] [] aliasCounts,
    fixture "distinct-root-counts" "sat" [.not sameKeys] [] aliasCounts,
    fixture "aliased-store-hit" "unsat" [sameKeys] sendSymbol storedAlias,
    fixture "distinct-store-miss" "sat" [.not sameKeys] sendSymbol storedAlias,
    fixture "fresh-function-namespace" "sat"
      [.equal (.app .int .int 1 (.integer 1)) (.integer 99)] sendOne
      [{ version := 0, key := .literal 1, expected := .literal 0 },
       { version := 1, key := .literal 1, expected := .literal 1 }],
    fixture "symbolic-expected-count" "sat"
      [.equal (.unknown .int 9) (.integer 1)] sendOne symbolicExpected,
    fixture "symbolic-expected-contradiction" "unsat"
      [.equal (.unknown .int 9) (.integer 2)] sendOne symbolicExpected,
    fixture "count-only-allows-pop-underflow" "sat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 0 },
       { version := 1, key := .literal 1, expected := .literal (-1) }],
    fixture "count-only-does-not-check-fifo" "sat" []
      [.peek (.literal 1), .length 0]
      [{ version := 0, key := .literal 1, expected := .literal 0 }]
  ]

def scalarFixtures : List Json :=
  [
    scalarFixture "duplicate-send-and-pop" "sat" [] regressionTrace regressionObservations
      (.literal 0),
    scalarFixture "duplicate-send-wrong-length" "unsat" []
      [.send (.literal (-2)), .send (.literal (-2)), .pop (.literal (-2)), .length 1]
      [{ version := 0, key := .literal (-2), expected := .literal 0 }] (.literal 0),
    scalarFixture "empty-peek" "unsat" [] [.peek (.literal 1)] [] (.literal 0),
    scalarFixture "empty-pop" "unsat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 1 }] (.literal 0),
    scalarFixture "nonpositive-pop-count" "unsat" [] popOne
      [{ version := 0, key := .literal 1, expected := .literal 0 }] (.literal 1),
    scalarFixture "negative-initial-length" "unsat" [] [] [] (.literal (-1)),
    scalarFixture "unknown-million-initial-length" "sat" []
      [.length 1000000, .peek (.symbolic 0), .pop (.symbolic 0), .length 999999]
      [{ version := 0, key := .symbolic 0, expected := .literal 1 }] (.symbolic 10),
    scalarFixture "repeated-peeks-cannot-differ" "unsat" [.not sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] [] (.literal 1),
    scalarFixture "repeated-peeks-can-alias" "sat" [sameKeys]
      [.peek (.symbolic 0), .peek (.symbolic 1)] [] (.literal 1),
    scalarFixture "send-order-cannot-differ" "unsat" [.not sameKeys]
      [.send (.symbolic 0), .peek (.symbolic 1)]
      [{ version := 0, key := .symbolic 0, expected := .literal 0 }] (.literal 0),
    scalarFixture "send-order-can-alias" "sat" [sameKeys]
      [.send (.symbolic 0), .peek (.symbolic 1)]
      [{ version := 0, key := .symbolic 0, expected := .literal 0 }] (.literal 0),
    scalarFixture "initial-budget-still-missing" "sat" []
      [.length 0, .send (.literal 1), .length 0]
      [{ version := 0, key := .literal 1, expected := .literal 1 }] (.literal 0),
    scalarFixture "initial-histogram-still-missing" "sat" [] [.peek (.literal 1)]
      [{ version := 0, key := .literal 1, expected := .literal 0 }] (.literal 1),
    scalarFixture "unrendered-count-version-reserved" "sat"
      [.equal (.app .int .int 1 (.integer 0)) (.integer 44)] sendOne [] (.literal 0)
  ]

end CCFRaft.Sparse.QueueCountFixtures

def main (args : List String) : IO UInt32 := do
  let fixtures := match args with
    | [] => some CCFRaft.Sparse.QueueCountFixtures.fixtures
    | ["--scalar"] => some CCFRaft.Sparse.QueueCountFixtures.scalarFixtures
    | _ => none
  let some fixtures := fixtures |
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: QueueCountFixtureMain.lean [--scalar]"
    return 1
  IO.println (Lean.Json.arr fixtures.toArray).compress
  return 0
