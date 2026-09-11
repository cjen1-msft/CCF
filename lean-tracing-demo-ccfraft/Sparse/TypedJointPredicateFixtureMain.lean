import Sparse.TypedJointPredicateEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.TypedJointPredicateFixtures

open Smt EntryPredicate TypedIntervalEncoding Lean
open TypedJointPredicateEncoding
open IntervalEncoding (natTerm)

private def fixed (id : Nat) (value : Int) : Term .bool := .equal (natTerm id) (.integer value)
private def left : Term .entry := .entry (.integer (-1)) .signature
private def right : Term .entry := .entry (.integer 0) .signature
private def rootGraph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)
private def twoRoots : SymbolicGraph 2 .entry 2 := .push (.push .empty (.root 0)) (.root 1)

private def point {roots size : Nat} (address : IntervalReadback.Address roots size)
    (position : Nat) (expected : Term .entry) : Observation roots size .entry :=
  { address, position, expected }

private def fixture {roots size : Nat} (name : String) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (queries : List (Query size))
    (points : List (Observation roots size .entry)) (metadata : List (Prod String Json)) : Json :=
  let formula := TypedJointPredicateEncoding.encode input graph queries points
  let script := SmtScript.render formula
  let zeroID := zeroId input graph queries points
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("zero", toJson zeroID), ("first", toJson (first input graph queries points)),
    ("next", toJson (TypedJointPredicateEncoding.nextFunctionId input graph queries points)),
    ("roots", toJson roots), ("versions", toJson size), ("points", toJson points.length),
    ("cuts", toJson (cutIds zeroID graph queries points).length),
    ("demands", toJson (TypedIntervalReadBlock.planned graph (seeds zeroID graph queries points)).length),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def comparisons : List (Prod String (Predicate 2)) :=
  [("eq", .eq (.cell 0) (.cell 1)), ("ne", .ne (.cell 0) (.cell 1)),
   ("raw-le", .le (.entryTerm (.cell 0)) (.entryTerm (.cell 1))),
   ("decoded-le", .le (.decodedTerm (.cell 0)) (.decodedTerm (.cell 1)))]

def boundaryFixtures : List Json :=
  comparisons.flatMap fun (kind, body) =>
    (List.range 3).flatMap fun lower =>
      (List.range 3).flatMap fun upper =>
        (List.range 4).flatMap fun position =>
          [false, true].flatMap fun different =>
            [false, true].map fun enabled =>
              fixture s!"{kind}-{lower}-{upper}-{position}-{different}-{enabled}"
                [fixed 0 lower, fixed 1 upper, fixed 2 position] twoRoots
                [{ lower := 0, upper := 1, predicate := .implies (.input (.boolean enabled)) body }]
                [point (.root 0) 2 left, point (.version 1) 2 (if different then right else left)]
                [("kind", toJson kind), ("lower", toJson lower), ("upper", toJson upper),
                 ("position", toJson position), ("different", toJson different), ("enabled", toJson enabled)]

private def verdict (value : String) : List (Prod String Json) := [("expected", toJson value)]

def edgeFixtures : List Json :=
  [fixture "duplicate-points" [] rootGraph [] [point (.root 0) 2 left, point (.root 0) 2 right] (verdict "unsat"),
   fixture "aliased-points" [.equal (natTerm 2) (natTerm 3)] rootGraph []
     [point (.root 0) 2 left, point (.version 0) 3 right] (verdict "unsat"),
   fixture "different-points" [fixed 2 0, fixed 3 1] rootGraph []
     [point (.root 0) 2 left, point (.version 0) 3 right] (verdict "sat"),
   fixture "disabled-negative-bound" [fixed 0 (-1), fixed 1 0] rootGraph
     [{ lower := 0, upper := 1, predicate := .implies (.input (.boolean false)) (.eq (.cell 0) (.cell 0)) }]
     [] (verdict "unsat"),
   fixture "empty" [] (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "sat"),
   fixture "closed-false-nonempty" [fixed 0 0, fixed 1 1] (.empty : SymbolicGraph 0 .entry 0)
     [{ lower := 0, upper := 1, predicate := .input (.boolean false) }] [] (verdict "unsat"),
   fixture "closed-false-empty" [fixed 0 1, fixed 1 1] (.empty : SymbolicGraph 0 .entry 0)
     [{ lower := 0, upper := 1, predicate := .input (.boolean false) }] [] (verdict "sat"),
   fixture "unused-constant" []
     (.push (.empty : SymbolicGraph 0 .entry 0) (.constant (.unknown .entry 8000)))
     [] [] (verdict "sat"),
   fixture "disabled-function" [fixed 0 0, fixed 1 1] rootGraph
     [{ lower := 0, upper := 1,
        predicate := .implies (.input (.boolean false)) (.input (.app .entry .bool 7000 (.unknown .entry 9000))) }]
     [] (verdict "sat"),
   fixture "original-zero-symbol" [fixed 0 7] rootGraph []
     [point (.root 0) 2 left] (verdict "sat")]

private def repeatedChild : (depth : Nat) -> SymbolicGraph 1 .entry (depth + 1)
  | 0 => rootGraph
  | depth + 1 => .push (repeatedChild depth) (.splice 0 1 (Fin.last depth) (Fin.last depth))

def scaleFixtures : List Json :=
  [true, false].flatMap fun valid =>
    let expected := if valid then "sat" else "unsat"
    let points := (List.range 400).map fun index => point (.version 0) (index + 20) left
    let points := if valid then points else points ++ [point (.version 0) 419 right]
    [fixture s!"points-400-{expected}"
       ([fixed 0 0, fixed 1 1000401] ++
         (List.range 400).map (fun index => fixed (index + 20) (1000000 + index)))
       rootGraph [{ lower := 0, upper := 1, predicate := .eq (.cell 0) (.cell 0) }]
       points (verdict expected),
     fixture s!"versions-400-{expected}" [fixed 0 0, fixed 1 1000000000001, fixed 2 1000000000000]
       (repeatedChild 399) [{ lower := 0, upper := 1, predicate := .eq (.cell 399) (.cell 399) }]
       ([point (.version 399) 2 left] ++ if valid then [] else [point (.version 399) 2 right])
       (verdict expected)]

end CCFRaft.Sparse.TypedJointPredicateFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.TypedJointPredicateFixtures.boundaryFixtures ++
    CCFRaft.Sparse.TypedJointPredicateFixtures.edgeFixtures ++
    CCFRaft.Sparse.TypedJointPredicateFixtures.scaleFixtures)).compress
