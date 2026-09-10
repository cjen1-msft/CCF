import Sparse.IntervalPredicate
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.IntervalPredicateFixtures

open IntervalPredicate Smt Lean

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (.unknown .int id) (.integer value)

private def fields (formula : SmtScript.Formula) : List (Prod String Json) :=
  let script := SmtScript.render formula
  [("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput
      (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

private def operators : List (Prod String (Operand 2 -> Operand 2 -> Predicate 2)) :=
  [("eq", .eq), ("ne", .ne), ("le", .le), ("lt", .lt)]

def comparisons : List Json := Id.run do
  let mut result := []
  for (name, construct) in operators do
    for left in ([-2, 0, 3] : List Int) do
      for right in ([-2, 0, 3] : List Int) do
        for shape in List.range 4 do
          let lhs : Operand 2 :=
            if shape % 2 == 0 then .cell 0 else .input (.symbolic 0)
          let rhs : Operand 2 :=
            if shape < 2 then .cell 1 else .input (.symbolic 1)
          let predicate := construct lhs rhs
          let formula := [
            fixed 0 left, fixed 1 right, fixed 4 1000000,
            .equal (.app .int .int 9 (.unknown .int 4)) (.integer left),
            .equal (.app .int .int 10 (.unknown .int 4)) (.integer right),
            predicate.lower 2 7 4]
          result := result ++ [Json.mkObj ([
            ("name", toJson s!"{name}-{left}-{right}-{shape}"),
            ("operator", toJson name), ("left", toJson left), ("right", toJson right),
            ("shape", toJson shape)] ++ fields formula)]
  return result

private def aliasCase (same : Bool) : Json :=
  let equal : Predicate 1 := .eq (.cell 0) (.input (.symbolic 0))
  let unequal : Predicate 1 := .ne (.cell 0) (.input (.symbolic 0))
  Json.mkObj ([
    ("name", toJson (if same then "aliased-positions" else "distinct-positions")),
    ("expected", toJson (if same then "unsat" else "sat"))] ++
    fields [fixed 0 7, fixed 2 100, fixed 3 (if same then 100 else 101),
      equal.lower 1 7 2, unequal.lower 1 7 3])

private def planCase {roots size : Nat} (name : String)
    (graph : IntervalEncoding.SymbolicGraph roots size) (cuts : List Nat)
    (predicates : List (Predicate size)) : Json :=
  Json.mkObj [
    ("name", toJson name),
    ("requests", toJson (requests (roots := roots) cuts predicates).length),
    ("planned", toJson (planned graph cuts predicates).length)]

def plans : List Json := [
  planCase "repeated-400"
    (.push (.empty : IntervalEncoding.SymbolicGraph 1 0) (.root 0))
    (List.replicate 400 17) (List.replicate 400 (.eq (.cell 0) (.cell 0))),
  planCase "mixed-duplicates"
    (.push (.push (.empty : IntervalEncoding.SymbolicGraph 1 0) (.root 0)) (.root 0))
    [0, 1, 0, 1, 2]
    [.eq (.cell 0) (.cell 1), .lt (.input (.literal 0)) (.cell 1)],
  planCase "empty-references" (.empty : IntervalEncoding.SymbolicGraph 0 0)
    (List.range 400)
    (List.replicate 400 (.eq (.input (.literal 1)) (.input (.literal 1))))
]

end CCFRaft.Sparse.IntervalPredicateFixtures

open CCFRaft.Sparse.IntervalPredicateFixtures

def main : IO Unit := do
  IO.println (Lean.Json.mkObj [
    ("comparisons", Lean.toJson comparisons),
    ("aliases", Lean.toJson [aliasCase true, aliasCase false]),
    ("plans", Lean.toJson plans)]).compress
