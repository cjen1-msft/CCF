import Sparse.QueueEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueCountFixtures

open QueueEncoding QueueStream Smt Lean

private def fixture (name expected : String) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) : Json :=
  Json.mkObj [("name", toJson name), ("expected", toJson expected),
    ("scope", toJson "count-read"), ("script", toJson (render input [] trace observations))]

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

end CCFRaft.Sparse.QueueCountFixtures

def main (args : List String) : IO UInt32 := do
  unless args.isEmpty do
    let stderr <- IO.getStderr
    stderr.putStrLn "usage: QueueCountFixtureMain.lean"
    return 1
  IO.println (Lean.Json.arr CCFRaft.Sparse.QueueCountFixtures.fixtures.toArray).compress
  return 0
