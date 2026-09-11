import Sparse.LogMatchEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.LogMatchFixtures

open Smt EntryPredicate TypedIntervalEncoding Lean
open TypedJointPredicateEncoding
open IntervalEncoding (natTerm)

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def entry (term : Nat) : Term .entry :=
  .entry (.integer (BijectiveIntegerLog.encodeNat term)) .signature

private def rootGraph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)

private def spec : LogMatchEncoding.Spec 1 :=
  { version := 0, length := 0, index := 1, threshold := 2, best := 3 }

private def fixture {roots size : Nat} (name : String) (input : SmtScript.Formula)
    (graph : SymbolicGraph roots .entry size) (readers : List (LogMatchEncoding.Spec size))
    (points : List (Observation roots size .entry)) (metadata : List (String × Json))
    (queries : List (Query size) := []) (clauses : List (Witness.Clause size) := []) : Json :=
  let prepared := readers.foldl (fun (input, queries, slots) reader =>
    let first := max (reader.maximum + 1) (Witness.zero input graph queries points clauses)
    (input ++ LogMatchEncoding.constraints reader first,
      LogMatchEncoding.suffix reader first :: LogMatchEncoding.anchorQuery reader first :: queries,
      slots ++ [first])) (input, queries, ([] : List Nat))
  let assembled := Witness.encode prepared.1 graph prepared.2.1 points clauses
  let formula := match readers, prepared.2.2 with
    | [reader], [first] => LogMatchEncoding.encode input graph queries points clauses reader first
    | _, _ => assembled
  let script := SmtScript.render formula
  let outerZero := if clauses.isEmpty then zeroId prepared.1 graph prepared.2.1 points
    else Witness.zero prepared.1 graph prepared.2.1 points clauses
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("matches_assembly", toJson (script == SmtScript.render assembled)),
    ("readers", toJson readers.length), ("derived_slots", toJson prepared.2.2),
    ("outer_zero", toJson outerZero), ("witnesses", toJson clauses.length),
    ("queries", toJson prepared.2.1.length), ("points", toJson points.length),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def concreteCase (terms : List Nat) (index threshold best : Nat) : Json :=
  let positions := (List.range terms.length).map fun position => fixed (10 + position) position
  let points := terms.zipIdx |>.map fun (term, position) =>
    ({ address := .root 0, position := 10 + position, expected := entry term } :
      Observation 1 1 .entry)
  fixture s!"concrete-{terms}-{index}-{threshold}-{best}"
    ([fixed 0 terms.length, fixed 1 index, fixed 2 threshold, fixed 3 best] ++ positions)
    rootGraph [spec] points
    [("terms", toJson terms), ("index", toJson index), ("threshold", toJson threshold),
     ("best", toJson best)]

def finiteCases : List Json :=
  let logs : List (List Nat) := [[]] ++ (List.range 3).map (fun value => [value]) ++
    (List.range 3).flatMap (fun left => (List.range 3).map (fun right => [left, right]))
  logs.flatMap fun terms =>
    [0, 1, 3].flatMap fun index =>
      (List.range 3).flatMap fun threshold =>
        (List.range (terms.length + 2)).map fun best => concreteCase terms index threshold best

private def verdict (value : String) : List (String × Json) := [("expected", toJson value)]

def edgeCases : List Json :=
  let unsorted := [0, 1, 2, 3, 4, 5].flatMap fun best =>
    [concreteCase [2, 9, 1, 8] 4 2 best, concreteCase [2, 9, 1, 8] 100 2 best]
  let large := [1000000, 1000000000000].flatMap fun length =>
    [true, false].map fun valid =>
      fixture s!"sparse-{length}-{valid}"
        [fixed 0 length, fixed 1 (length + 100), fixed 2 0, fixed 3 length,
         fixed 10 (length - 1)]
        rootGraph [spec]
        [{ address := .root 0, position := 10, expected := entry (if valid then 0 else 1) }]
        (verdict (if valid then "sat" else "unsat"))
  let shared :=
    [fixture "two-readers-conflict"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixed 3 1, fixed 4 0]
      rootGraph [spec, { spec with best := 4 }] [] (verdict "unsat"),
     fixture "shared-caller-witness"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixed 3 0, fixed 4 0]
      rootGraph [spec] [] (verdict "unsat") []
      [{ lower := 4, upper := 0, predicate := .le (.decodedTerm (.cell 0)) (.input (.integer 0)),
         enable := .boolean true }],
     fixture "disabled-caller-witness"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixed 3 0, fixed 4 0]
      rootGraph [spec] [] (verdict "sat") []
      [{ lower := 4, upper := 0, predicate := .le (.decodedTerm (.cell 0)) (.input (.integer 0)),
         enable := .boolean false }],
     fixture "negative-source" [fixed 0 (-1), fixed 1 0, fixed 2 0, fixed 3 0]
      rootGraph [spec] [] (verdict "unsat"),
     fixture "aliased-source" [fixed 0 1, fixed 10 0]
      rootGraph [{ spec with length := 0, index := 0, threshold := 0, best := 0 }]
      [{ address := .root 0, position := 10, expected := entry 1 }] (verdict "sat"),
     fixture "unused-graph-symbol" [fixed 0 0, fixed 1 0, fixed 2 0, fixed 3 0]
      (.push rootGraph (.constant (.unknown .entry 1000000)))
      [{ version := 0, length := 0, index := 1, threshold := 2, best := 3 }]
      [] (verdict "sat"),
     fixture "aliased-versions-conflict"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixed 3 1, fixed 4 0]
      (.push rootGraph (.root 0))
      [{ version := 0, length := 0, index := 1, threshold := 2, best := 3 },
       { version := 1, length := 0, index := 1, threshold := 2, best := 4 }]
      [] (verdict "unsat")]
  unsorted ++ large ++ shared

end CCFRaft.Sparse.LogMatchFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.LogMatchFixtures.finiteCases ++
    CCFRaft.Sparse.LogMatchFixtures.edgeCases)).compress
