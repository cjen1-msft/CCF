import Sparse.IntervalEncoding
import Sparse.SmtScriptText
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalEncodingFixtures

open IntervalEncoding VersionedIntervals Smt Lean

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def fixture {roots size : Nat} (name expected : String)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (observations : List (Observation roots size)) : Json :=
  let formula := encode input graph observations
  let script := SmtScript.render formula
  Json.mkObj [
    ("name", toJson name), ("expected", toJson expected),
    ("versions", toJson size), ("roots", toJson roots),
    ("demands", toJson (demands graph observations).length),
    ("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput
      (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

private def rootGraph : SymbolicGraph 1 1 := .push .empty (.root 0)

private def constantSplice : SymbolicGraph 0 3 :=
  .push (.push (.push .empty (.constant 7)) (.constant 9)) (.splice 0 1 0 1)

private def repeatedChild : (depth : Nat) -> SymbolicGraph 1 (depth + 1)
  | 0 => rootGraph
  | depth + 1 =>
    .push (repeatedChild depth) (.splice 0 1 (Fin.last depth) (Fin.last depth))

private def point {roots size : Nat} (address : IntervalReadback.Address roots size)
    (position : Nat) (value : Int) : Observation roots size :=
  { address, position, expected := .literal value }

def fixtures : List Json := [
  fixture "empty" "sat" [] (.empty : SymbolicGraph 0 0) [],
  fixture "input-contradiction" "unsat" [.boolean false]
    (.empty : SymbolicGraph 0 0) [],
  fixture "unknown-root" "sat" [fixed 0 1000000] rootGraph
    [point (.version 0) 0 (-17)],
  fixture "aliased-position-tokens" "unsat" [fixed 0 3, fixed 1 3] rootGraph
    [point (.version 0) 0 7, point (.root 0) 1 9],
  fixture "distinct-positions" "sat" [fixed 0 3, fixed 1 4] rootGraph
    [point (.version 0) 0 7, point (.root 0) 1 9],
  fixture "independent-roots" "sat" [fixed 0 3]
    (.empty : SymbolicGraph 2 0) [point (.root 0) 0 7, point (.root 1) 0 9],
  fixture "aliased-root-versions" "unsat" [fixed 0 3]
    (.push rootGraph (.root 0)) [point (.version 0) 0 7, point (.version 1) 0 9],
  fixture "constant-negative-value" "sat" [fixed 0 0]
    (.push (.empty : SymbolicGraph 0 0) (.constant (-7))) [point (.version 0) 0 (-7)],
  fixture "constant-contradiction" "unsat" [fixed 0 0]
    (.push (.empty : SymbolicGraph 0 0) (.constant (-7))) [point (.version 0) 0 7],
  fixture "negative-position" "unsat" [fixed 0 (-1)] rootGraph
    [point (.root 0) 0 7],
  fixture "negative-unused-endpoint" "unsat" [fixed 0 (-1)] constantSplice [],
  fixture "empty-splice" "sat" [fixed 0 3, fixed 1 3, fixed 2 3] constantSplice
    [point (.version 2) 2 9],
  fixture "reversed-splice" "sat" [fixed 0 9, fixed 1 3, fixed 2 5] constantSplice
    [point (.version 2) 2 9],
  fixture "unknown-endpoints" "sat" [fixed 2 4] constantSplice
    [point (.version 2) 2 7],
  fixture "unknown-endpoints-impossible-value" "unsat" [fixed 2 4] constantSplice
    [point (.version 2) 2 100],
  fixture "fresh-function-namespace" "sat"
    [fixed 0 3, .equal (.app .int .int 0 (.integer 3)) (.integer 99)] rootGraph
    [point (.root 0) 0 7],
  fixture "trillion-position" "sat" [fixed 0 1000000000000] rootGraph
    [point (.version 0) 0 7],
  fixture "million-root-domain" "sat" [fixed 0 1000000]
    (.push (.empty : SymbolicGraph 1000000 0) (.root 500000))
    [point (.version 0) 0 7],
  fixture "shared-400-sat" "sat" [fixed 2 1000000] (repeatedChild 399)
    [point (.root 0) 2 7, point (.version (Fin.last 399)) 2 7],
  fixture "shared-400-unsat" "unsat" [fixed 2 1000000] (repeatedChild 399)
    [point (.root 0) 2 7, point (.version (Fin.last 399)) 2 9]
]

def boundaryFixtures : List Json := Id.run do
  let mut result := []
  for lower in List.range 3 do
    for upper in List.range 3 do
      for position in List.range 4 do
        for expectedValue in [7, 9] do
          let actual : Int := if lower <= position && position < upper then 7 else 9
          let expected := if actual == expectedValue then "sat" else "unsat"
          result := result ++ [fixture s!"boundary-{lower}-{upper}-{position}-{expectedValue}"
            expected [fixed 0 lower, fixed 1 upper, fixed 2 position] constantSplice
            [point (.version 2) 2 expectedValue]]
  return result

end CCFRaft.Sparse.IntervalEncodingFixtures

def main : IO Unit := do
  IO.println (Lean.toJson (CCFRaft.Sparse.IntervalEncodingFixtures.fixtures ++
    CCFRaft.Sparse.IntervalEncodingFixtures.boundaryFixtures)).compress
