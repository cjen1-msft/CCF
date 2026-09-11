import Sparse.TypedIntervalEncoding
import Sparse.NativeSorts
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedIntervalFixtures

open TypedIntervalEncoding Smt Lean
open IntervalEncoding (natTerm)

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def point {roots size : Nat} {ty : Ty} (address : IntervalReadback.Address roots size)
    (position : Nat) (value : Term ty) : Observation roots size ty :=
  { address, position, expected := value }

private def rootGraph (ty : Ty) : SymbolicGraph 1 ty 1 := .push .empty (.root 0)

private def spliceGraph (ty : Ty) : SymbolicGraph 2 ty 3 :=
  .push (.push (.push .empty (.root 0)) (.root 1)) (.splice 0 1 0 1)

private def repeatedChild : (depth : Nat) -> SymbolicGraph 1 .entry (depth + 1)
  | 0 => rootGraph .entry
  | depth + 1 =>
    .push (repeatedChild depth) (.splice 0 1 (Fin.last depth) (Fin.last depth))

private def fixture {roots size : Nat} {ty : Ty} (name expected : String)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots ty size)
    (observations : List (Observation roots size ty)) : Json :=
  let formula := encode input graph observations
  let script := SmtScript.render formula
  Json.mkObj [
    ("name", toJson name), ("expected", toJson expected),
    ("base", toJson (base input graph observations)),
    ("next_function", toJson (nextFunctionId input graph observations)),
    ("roots", toJson roots), ("versions", toJson size),
    ("demands", toJson (planned graph observations).length),
    ("script", toJson script),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

def fixtures : List Json :=
  (NativeSorts.allTypes.mapIdx fun index ty =>
    let left := Term.unknown ty 10
    let right := Term.unknown ty 11
    let different := Term.not (.equal left right)
    let root := rootGraph ty
    let constant : SymbolicGraph 0 ty 1 := .push .empty (.constant left)
    [fixture s!"root-version-{index}-sat" "sat" [fixed 2 0] root
       [point (.root 0) 2 left, point (.version 0) 2 left],
     fixture s!"root-version-{index}-unsat" "unsat" [fixed 2 0, different] root
       [point (.root 0) 2 left, point (.version 0) 2 right],
     fixture s!"positions-{index}-sat" "sat" [fixed 2 0, fixed 3 1, different] root
       [point (.root 0) 2 left, point (.root 0) 3 right],
     fixture s!"positions-{index}-unsat" "unsat" [fixed 2 0, fixed 3 0, different] root
       [point (.root 0) 2 left, point (.root 0) 3 right],
     fixture s!"constant-{index}-sat" "sat" [fixed 2 0] constant
       [point (.version 0) 2 left],
     fixture s!"constant-{index}-unsat" "unsat" [fixed 2 0, different] constant
       [point (.version 0) 2 right],
     fixture s!"negative-position-{index}" "unsat" [fixed 2 (-1)] root [point (.root 0) 2 left],
     fixture s!"unused-negative-bound-{index}" "unsat" [fixed 0 (-1)] (spliceGraph ty) []]).flatten ++
  [fixture "unused-constant-metadata" "sat" []
     (.push (.empty : SymbolicGraph 0 .entry 0) (.constant (.unknown .entry 1000))) [],
   fixture "expected-function-metadata" "sat" [fixed 2 0] (rootGraph .entry)
     [point (.root 0) 2 (.app .int .entry 2000 (.integer (-7)))],
   fixture "million-roots-trillion-position" "sat" [fixed 2 1000000000000]
     (.empty : SymbolicGraph 1000000 .entry 0)
     [point (.root 500000) 2 (.unknown .entry 10)],
   fixture "empty-native" "sat" [] (.empty : SymbolicGraph 0 .entry 0) []]

def boundaryFixtures : List Json := Id.run do
  let mut result := []
  for (ty, index) in NativeSorts.allTypes.zipIdx do
    let left := Term.unknown ty 10
    let right := Term.unknown ty 11
    for lower in List.range 3 do
      for upper in List.range 3 do
        for position in List.range 4 do
          for wantInside in [false, true] do
            let inside := lower <= position && position < upper
            result := result ++ [fixture s!"splice-{index}-{lower}-{upper}-{position}-{wantInside}"
              (if inside == wantInside then "sat" else "unsat")
              [fixed 0 lower, fixed 1 upper, fixed 2 position, .not (.equal left right)]
              (spliceGraph ty)
              [point (.root 0) 2 left, point (.root 1) 2 right,
               point (.version 2) 2 (if wantInside then left else right)]]
  return result

def scaleFixtures : List Json :=
  let left := Term.unknown .entry 10
  let right := Term.unknown .entry 11
  [true, false].flatMap fun valid =>
    let verdict := if valid then "sat" else "unsat"
    let input := if valid then [] else [Term.not (.equal left right)]
    let points := (List.range 400).map fun index => point (.version 0) (index + 20) left
    let points := if valid then points else points ++ [point (.version 0) 419 right]
    [fixture s!"entry-400-points-{verdict}" verdict
       (input ++ (List.range 400).map (fun index => fixed (index + 20) (1000000 + index)))
       (rootGraph .entry) points,
     fixture s!"entry-400-versions-{verdict}" verdict
       (input ++ [fixed 0 0, fixed 1 1000000000001, fixed 2 1000000000000])
       (repeatedChild 399)
       ([point (.version 399) 2 left] ++ if valid then [] else [point (.version 399) 2 right])]

def constructorFixtures : List Json :=
  let contents : List (Term .content) :=
    [.transaction (.app .int .int 3002 (.integer (-7))), .signature,
     .reconfiguration (.app .nodes .nodes 3001 (.nodes 16384)),
     .retiredCommitted (.nodes 32767)]
  (contents.mapIdx fun index content =>
    let value := Term.entry (.unknown .int 3000) content
    [false, true].flatMap fun constant =>
      [true, false].map fun valid =>
        let expected := Term.entry
          (.add (.entryTerm value) (.integer (if valid then 0 else 1)))
          (.entryContent value)
        let verdict := if valid then "sat" else "unsat"
        if constant then
          fixture s!"constructor-{index}-constant-{verdict}" verdict [fixed 2 0, fixed 3000 (-2)]
            (.push (.empty : SymbolicGraph 0 .entry 0) (.constant value))
            [point (.version 0) 2 expected]
        else
          fixture s!"constructor-{index}-root-{verdict}" verdict [fixed 2 0, fixed 3000 (-2)]
            (rootGraph .entry)
            [point (.root 0) 2 value, point (.version 0) 2 expected]).flatten

def selectorFixtures : List Json :=
  [true, false].flatMap fun valid =>
    let verdict := if valid then "sat" else "unsat"
    let value := Term.unknown .content 3000
    let input := [fixed 2 0, Term.equal value .signature]
    [fixture s!"selector-tx-{verdict}" verdict
       (input ++ [.equal (.app .content .int 0 value) (.integer 0),
         .equal (.transactionId value) (.integer 7)])
       (.push (.empty : SymbolicGraph 0 .entry 0)
         (.constant (.entry (.integer 0) (.transaction (.transactionId value)))))
       [point (.version 0) 2 (.entry (.integer 0) (.transaction (.integer (if valid then 7 else 8))))],
     fixture s!"selector-cfg-{verdict}" verdict
       (input ++ [.equal (.app .content .nodes 0 value) (.nodes 0),
         .equal (.configurationNodes value) (.nodes 16384)])
       (.push (.empty : SymbolicGraph 0 .nodes 0) (.constant (.configurationNodes value)))
       [point (.version 0) 2 (.nodes (if valid then 16384 else 1))],
     fixture s!"selector-retired-{verdict}" verdict
       (input ++ [.equal (.app .content .nodes 1 value) (.nodes 0),
         .equal (.retiredNodes value) (.nodes 32767)])
       (.push (.empty : SymbolicGraph 0 .nodes 0) (.constant (.retiredNodes value)))
       [point (.version 0) 2 (.nodes (if valid then 32767 else 0))],
     fixture s!"selector-tester-{verdict}" verdict input
       (.push (.empty : SymbolicGraph 0 .bool 0) (.constant (.isContent .signature value)))
       [point (.version 0) 2 (.boolean valid)]]

def nodeOperationFixtures : List Json :=
  let content := Term.unknown .content 3000
  let mask := Term.configurationNodes content
  let input := [fixed 2 0, Term.equal content .signature,
    .equal (.app .content .nodes 0 content) (.nodes 0), .equal mask (.nodes 21845)]
  let operations : List (Prod (Term .nodes) (BitVec NODE_COUNT)) :=
    [(.nodesAnd mask (.nodes 10922), 0), (.nodesOr mask (.nodes 10922), 32767),
     (.nodesNot mask, 10922)]
  [true, false].flatMap fun valid =>
    let verdict := if valid then "sat" else "unsat"
    (operations.mapIdx fun index (operation, answer) =>
      fixture s!"node-operation-{index}-{verdict}" verdict input
        (.push (.empty : SymbolicGraph 0 .nodes 0) (.constant operation))
        [point (.version 0) 2 (.nodes (if valid then answer else answer ^^^ 1))]) ++
    [fixture s!"node-membership-{verdict}" verdict input
      (.push (.empty : SymbolicGraph 0 .bool 0)
        (.constant (.equal (.nodesAnd mask (.nodes 16384)) (.nodes 16384))))
      [point (.version 0) 2 (.boolean valid)]]

end CCFRaft.Sparse.TypedIntervalFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.TypedIntervalFixtures.fixtures ++
    CCFRaft.Sparse.TypedIntervalFixtures.boundaryFixtures ++
    CCFRaft.Sparse.TypedIntervalFixtures.scaleFixtures ++
    CCFRaft.Sparse.TypedIntervalFixtures.constructorFixtures ++
    CCFRaft.Sparse.TypedIntervalFixtures.selectorFixtures ++
    CCFRaft.Sparse.TypedIntervalFixtures.nodeOperationFixtures)).compress
