import Sparse.JointIntervalEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.JointEncodingFixtures

open IntervalEncoding IntervalPredicate Smt Lean

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def query {size : Nat} (version : Fin size) (value : Int) : Query size :=
  { lower := 0, upper := 1, predicate := .eq (.cell version) (.input (.literal value)) }

private def point {roots size : Nat} (address : IntervalReadback.Address roots size)
    (position : Nat) (value : Int) : Observation roots size :=
  { address, position, expected := .literal value }

private def fixture {roots size : Nat} (name expected : String)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) (observations : List (Observation roots size)) : Json :=
  let zeroID := JointIntervalEncoding.zeroId input graph queries observations
  let formula := JointIntervalEncoding.encode input graph queries observations
  let script := SmtScript.render formula
  Json.mkObj [
    ("name", toJson name), ("expected", toJson expected), ("zero_id", toJson zeroID),
    ("demands", toJson (JointIntervalEncoding.planned zeroID graph queries observations).length),
    ("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput
      (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

private def rootGraph : SymbolicGraph 1 1 := .push .empty (.root 0)

private def rootsGraph (aliases : Bool) : SymbolicGraph 2 2 :=
  .push (.push .empty (.root 0)) (.root (if aliases then 0 else 1))

private def spliceGraph : SymbolicGraph 1 3 :=
  .push (.push (.push .empty (.root 0)) (.constant 1)) (.splice 3 4 1 0)

def fixtures : List Json := [
  fixture "empty" "sat" [] (.empty : SymbolicGraph 0 0) [] [],
  fixture "point-only-negative-value" "sat" [fixed 2 0] rootGraph []
    [point (.root 0) 2 (-7)],
  fixture "query-only" "sat" [fixed 0 0, fixed 1 10] rootGraph [query 0 0] [],
  fixture "inside-conflict" "unsat" [fixed 0 0, fixed 1 10, fixed 2 5]
    rootGraph [query 0 0] [point (.root 0) 2 1],
  fixture "outside-preserved" "sat" [fixed 0 0, fixed 1 5, fixed 2 7]
    rootGraph [query 0 0] [point (.root 0) 2 1],
  fixture "upper-boundary-outside" "sat" [fixed 0 0, fixed 1 5, fixed 2 5]
    rootGraph [query 0 0] [point (.root 0) 2 1],
  fixture "lower-boundary-inside" "unsat" [fixed 0 0, fixed 1 5, fixed 2 0]
    rootGraph [query 0 0] [point (.root 0) 2 1],
  fixture "root-version-conflict" "unsat" [fixed 2 3] rootGraph []
    [point (.root 0) 2 0, point (.version 0) 2 1],
  fixture "aliased-position-conflict" "unsat" [fixed 2 3, fixed 3 3] rootGraph []
    [point (.root 0) 2 0, point (.root 0) 3 1],
  fixture "distinct-positions" "sat" [fixed 2 3, fixed 3 4] rootGraph []
    [point (.root 0) 2 0, point (.root 0) 3 1],
  fixture "repeated-equal-point" "sat" [fixed 2 3] rootGraph []
    [point (.root 0) 2 7, point (.root 0) 2 7],
  fixture "repeated-conflicting-point" "unsat" [fixed 2 3] rootGraph []
    [point (.root 0) 2 7, point (.root 0) 2 8],
  fixture "negative-symbolic-expectation" "sat" [fixed 2 3, fixed 1000 (-7)] rootGraph []
    [{ address := .root 0, position := 2, expected := .symbolic 1000 }],
  fixture "expected-symbol-reservation" "sat" [fixed 2 3]
    (.push (.empty : SymbolicGraph 0 0) (.constant 9)) []
    [{ address := .version 0, position := 2, expected := .symbolic 1000 }],
  fixture "negative-position" "unsat" [fixed 2 (-1)] rootGraph []
    [point (.root 0) 2 7],
  fixture "position-symbol-reservation" "sat" [] rootGraph []
    [point (.root 0) 1999 7],
  fixture "preserved-input-function" "sat"
    [fixed 2 0, .equal (.app .int .int 400 (.integer 0)) (.integer 9)] rootGraph []
    [point (.root 0) 2 7],
  fixture "independent-root-point" "sat" [fixed 0 0, fixed 1 10, fixed 2 5]
    (rootsGraph false) [query 0 0] [point (.root 1) 2 1],
  fixture "splice-inside-independent" "sat"
    [fixed 0 0, fixed 1 10, fixed 2 5, fixed 3 5, fixed 4 6]
    spliceGraph [query 0 0] [point (.version 2) 2 1],
  fixture "splice-outside-conflict" "unsat"
    [fixed 0 0, fixed 1 10, fixed 2 4, fixed 3 5, fixed 4 6]
    spliceGraph [query 0 0] [point (.version 2) 2 1],
  fixture "trillion-point-million-roots" "sat" [fixed 2 1000000000000]
    (.empty : SymbolicGraph 1000000 0) [] [point (.root 500000) 2 7],
  fixture "repeated-400-points" "sat" [fixed 0 0, fixed 1 1000000, fixed 2 10]
    rootGraph [query 0 7] (List.replicate 400 (point (.version 0) 2 7)),
  fixture "point-only-400-positions" "sat"
    ((List.range 400).map fun index => fixed (index + 2) (1000000 + index))
    rootGraph [] ((List.range 400).map fun index => point (.version 0) (index + 2) 7)
]

def boundaryFixtures : List Json := Id.run do
  let mut result := []
  for aliases in [false, true] do
    for rootPoint in [false, true] do
      for lower in List.range 3 do
        for upper in List.range 3 do
          for position in List.range 4 do
            for value in [0, 1] do
              let conflict := aliases && lower <= position && position < upper && value != 0
              let address := if rootPoint then .root (if aliases then 0 else 1) else .version 1
              result := result ++ [fixture
                s!"joint-{aliases}-{rootPoint}-{lower}-{upper}-{position}-{value}"
                (if conflict then "unsat" else "sat")
                [fixed 0 lower, fixed 1 upper, fixed 2 position] (rootsGraph aliases)
                [query 0 0] [point address 2 value]]
  return result

end CCFRaft.Sparse.JointEncodingFixtures

def main : IO Unit := do
  IO.println (Lean.toJson (CCFRaft.Sparse.JointEncodingFixtures.fixtures ++
    CCFRaft.Sparse.JointEncodingFixtures.boundaryFixtures)).compress
