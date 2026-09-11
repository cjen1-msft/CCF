import Sparse.IntervalQueryEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalQueryFixtures

open IntervalPredicate IntervalEncoding Smt Lean

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def query {size : Nat} (lower upper : Nat) (predicate : Predicate size) : Query size :=
  { lower, upper, predicate }

private def equalCell {size : Nat} (version : Fin size) (value : Int) : Predicate size :=
  .eq (.cell version) (.input (.literal value))

private def falsePredicate {size : Nat} : Predicate size :=
  .eq (.input (.literal 0)) (.input (.literal 1))

private def fixture {roots size : Nat} (name expected : String)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots size)
    (queries : List (Query size)) : Json :=
  let zeroID := IntervalQueryEncoding.zeroId input graph queries
  let formula := IntervalQueryEncoding.encode input graph queries
  let script := SmtScript.render formula
  Json.mkObj [
    ("name", toJson name), ("expected", toJson expected),
    ("roots", toJson roots), ("versions", toJson size), ("zero_id", toJson zeroID),
    ("demands", toJson (IntervalQueryEncoding.planned zeroID graph queries).length),
    ("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput
      (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

private def rootsGraph (aliases : Bool) : SymbolicGraph 2 2 :=
  .push (.push .empty (.root 0)) (.root (if aliases then 0 else 1))

private def rootGraph : SymbolicGraph 1 1 := .push .empty (.root 0)

private def splice : SymbolicGraph 0 3 :=
  .push (.push (.push .empty (.constant 7)) (.constant 9)) (.splice 2 3 0 1)

private def repeatedChild : (depth : Nat) -> SymbolicGraph 1 (depth + 1)
  | 0 => rootGraph
  | depth + 1 =>
    .push (repeatedChild depth) (.splice 0 1 (Fin.last depth) (Fin.last depth))

def fixtures : List Json := [
  fixture "empty" "sat" [] (.empty : SymbolicGraph 0 0) [],
  fixture "input-false" "unsat" [.boolean false] (.empty : SymbolicGraph 0 0) [],
  fixture "empty-false" "sat" [fixed 0 4, fixed 1 4] (.empty : SymbolicGraph 0 0)
    [query 0 1 falsePredicate],
  fixture "reversed-false" "sat" [fixed 0 4, fixed 1 2] (.empty : SymbolicGraph 0 0)
    [query 0 1 falsePredicate],
  fixture "nonempty-false" "unsat" [fixed 0 4, fixed 1 5] (.empty : SymbolicGraph 0 0)
    [query 0 1 falsePredicate],
  fixture "negative-unused-graph-bound" "unsat" [fixed 2 (-1)] splice [],
  fixture "negative-query-bound" "unsat" [fixed 0 (-1), fixed 1 0]
    (.empty : SymbolicGraph 0 0) [query 0 1 falsePredicate],
  fixture "negative-operand" "sat" [fixed 0 0, fixed 1 1] (.empty : SymbolicGraph 0 0)
    [query 0 1 (.lt (.input (.literal (-2))) (.input (.literal (-1))))],
  fixture "metadata-only-operand" "sat" [fixed 0 0, fixed 1 1]
    (.empty : SymbolicGraph 0 0)
    [query 0 1 (.eq (.input (.symbolic 100)) (.input (.literal 7)))],
  fixture "preserved-input-symbol-zero" "sat" [fixed 0 11]
    (.empty : SymbolicGraph 0 0) [],
  fixture "aliased-bounds" "sat" [fixed 0 11] (.empty : SymbolicGraph 0 0)
    [query 0 0 falsePredicate],
  fixture "unknown-empty-interval" "sat" [] (.empty : SymbolicGraph 0 0)
    [query 0 1 falsePredicate],
  fixture "unknown-nonempty-interval" "unsat"
    [.equal (natTerm 1) (.add (natTerm 0) (.integer 1))]
    (.empty : SymbolicGraph 0 0) [query 0 1 falsePredicate],
  fixture "shared-overlap" "unsat" [fixed 0 0, fixed 1 10, fixed 2 5, fixed 3 6]
    (rootsGraph true) [query 0 1 (equalCell 0 0), query 2 3 (equalCell 1 1)],
  fixture "shared-disjoint" "sat" [fixed 0 0, fixed 1 5, fixed 2 5, fixed 3 10]
    (rootsGraph true) [query 0 1 (equalCell 0 0), query 2 3 (equalCell 1 1)],
  fixture "independent-overlap" "sat" [fixed 0 0, fixed 1 10, fixed 2 5, fixed 3 6]
    (rootsGraph false) [query 0 1 (equalCell 0 0), query 2 3 (equalCell 1 1)],
  fixture "hidden-splice-cut" "unsat" [fixed 0 0, fixed 1 10, fixed 2 3, fixed 3 5]
    splice [query 0 1 (equalCell 2 9)],
  fixture "splice-inside" "sat" [fixed 0 3, fixed 1 5, fixed 2 3, fixed 3 5]
    splice [query 0 1 (equalCell 2 7)],
  fixture "splice-outside-boundary" "sat" [fixed 0 0, fixed 1 3, fixed 2 3, fixed 3 5]
    splice [query 0 1 (equalCell 2 9)],
  fixture "trillion-interval" "sat" [fixed 0 0, fixed 1 1000000000000]
    rootGraph [query 0 1 (equalCell 0 7)],
  fixture "million-root-domain" "sat" [fixed 0 0, fixed 1 1000000]
    (.push (.empty : SymbolicGraph 1000000 0) (.root 500000))
    [query 0 1 (equalCell 0 7)],
  fixture "preserved-input-function" "sat"
    [fixed 0 0, fixed 1 1, .equal (.app .int .int 500 (.integer 0)) (.integer 99)]
    rootGraph [query 0 1 (equalCell 0 7)],
  fixture "repeated-400-queries" "sat" [fixed 0 0, fixed 1 1000000] rootGraph
    (List.replicate 400 (query 0 1 (equalCell 0 7))),
  fixture "shared-400-versions-sat" "sat" [fixed 0 0, fixed 1 1000000]
    (repeatedChild 399) [query 0 1 (.eq (.cell 0) (.cell (Fin.last 399)))],
  fixture "shared-400-versions-unsat" "unsat" [fixed 0 0, fixed 1 1000000]
    (repeatedChild 399) [query 0 1 (.ne (.cell 0) (.cell (Fin.last 399)))]
]

def boundaryFixtures : List Json := Id.run do
  let mut result := []
  for aliases in [false, true] do
    for lowerA in List.range 3 do
      for upperA in List.range 3 do
        for lowerB in List.range 3 do
          for upperB in List.range 3 do
            let overlap := max lowerA lowerB < min upperA upperB
            let expected := if aliases && overlap then "unsat" else "sat"
            result := result ++ [fixture
              s!"bounds-{aliases}-{lowerA}-{upperA}-{lowerB}-{upperB}" expected
              [fixed 0 lowerA, fixed 1 upperA, fixed 2 lowerB, fixed 3 upperB]
              (rootsGraph aliases)
              [query 0 1 (equalCell 0 0),
                query 2 3 (.ne (.cell 1) (.input (.literal 0)))]]
  return result

end CCFRaft.Sparse.IntervalQueryFixtures

def main : IO Unit := do
  IO.println (Lean.toJson (CCFRaft.Sparse.IntervalQueryFixtures.fixtures ++
    CCFRaft.Sparse.IntervalQueryFixtures.boundaryFixtures)).compress
