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
    (points : List (Observation roots size .entry)) (metadata : List (Prod String Json))
    (clauses : List (Witness.Clause size) := []) : Json :=
  let formula := Witness.encode input graph queries points clauses
  let script := SmtScript.render formula
  let zeroID := if clauses.isEmpty then zeroId input graph queries points
    else Witness.zero input graph queries points clauses
  let firstID := if clauses.isEmpty then first input graph queries points
    else Witness.base input graph queries points clauses
  let cutList := if clauses.isEmpty then cutIds zeroID graph queries points
    else Witness.cuts zeroID graph queries points clauses
  let requests := if clauses.isEmpty then seeds zeroID graph queries points
    else Witness.demands zeroID graph queries points clauses
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("zero", toJson zeroID), ("first", toJson firstID),
    ("next", toJson (firstID + roots + size)), ("witnesses", toJson clauses.length),
    ("empty_unchanged", toJson (if clauses.isEmpty then
      script == TypedJointPredicateEncoding.render input graph queries points else true)),
    ("roots", toJson roots), ("versions", toJson size), ("points", toJson points.length),
    ("cuts", toJson cutList.length),
    ("demands", toJson (TypedIntervalReadBlock.planned graph requests).length),
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

def witnessBoundaryFixtures : List Json :=
  comparisons.flatMap fun (kind, body) =>
    (List.range 3).flatMap fun lower =>
      (List.range 3).flatMap fun upper =>
        (List.range 4).flatMap fun position =>
          [false, true].flatMap fun different =>
            [false, true].flatMap fun enabled =>
              [false, true].map fun universal =>
                fixture s!"witness-{kind}-{lower}-{upper}-{position}-{different}-{enabled}-{universal}"
                  [fixed 0 lower, fixed 1 upper, fixed 2 position] twoRoots
                  (if universal then
                    [{ lower := 0, upper := 1, predicate := .eq (.cell 0) (.cell 1) }] else [])
                  [point (.root 0) 2 left, point (.version 1) 2 (if different then right else left)]
                  [("kind", toJson kind), ("lower", toJson lower), ("upper", toJson upper),
                   ("position", toJson position), ("different", toJson different), ("enabled", toJson enabled),
                   ("universal_equal", toJson universal)]
                  [{ lower := 0, upper := 1, predicate := body, enable := .boolean enabled }]

def witnessEdgeFixtures : List Json :=
  let mismatch : Witness.Clause 1 :=
    { lower := 0, upper := 1, predicate := .ne (.cell 0) (.input left), enable := .boolean true }
  let guard := Term.equal (.app .int .entry 5 (.integer 0)) left
  [fixture "interior-mismatch" [fixed 0 0, fixed 1 3, fixed 2 0, fixed 3 2] rootGraph []
     [point (.root 0) 2 left, point (.version 0) 3 left] (verdict "sat") [mismatch],
   fixture "overlapping-universal-mismatch" [fixed 0 0, fixed 1 3, fixed 2 0, fixed 3 2] rootGraph
     [{ lower := 0, upper := 1, predicate := .eq (.cell 0) (.input left) }]
     [point (.root 0) 2 left, point (.version 0) 3 left] (verdict "unsat") [mismatch],
   fixture "singleton-point-conflict" [fixed 0 0, fixed 1 1, fixed 2 0] rootGraph []
     [point (.root 0) 2 left] (verdict "unsat") [mismatch],
   fixture "aliased-witness-conflict" [fixed 0 0, fixed 1 1] rootGraph [] [] (verdict "unsat")
     [mismatch, { mismatch with predicate := .eq (.cell 0) (.input left) }],
   fixture "separate-witnesses" [fixed 0 0, fixed 1 2] rootGraph [] [] (verdict "sat")
     [mismatch, { mismatch with predicate := .eq (.cell 0) (.input left) }],
   fixture "root-version-witness-alias" [fixed 0 0, fixed 1 1]
     (.push (.push (.empty : SymbolicGraph 1 .entry 0) (.root 0)) (.root 0)) [] [] (verdict "unsat")
     [{ lower := 0, upper := 1, predicate := .ne (.cell 0) (.cell 1), enable := .boolean true }],
   fixture "closed-million-witness" [fixed 0 0, fixed 1 1000000]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "sat")
     [{ lower := 0, upper := 1, predicate := .input (.boolean true), enable := .boolean true }],
   fixture "closed-false-witness" [fixed 0 0, fixed 1 1]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "unsat")
     [{ lower := 0, upper := 1, predicate := .input (.boolean false), enable := .boolean true }],
   fixture "disabled-reversed-witness" [fixed 0 2, fixed 1 0]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "sat")
     [{ lower := 0, upper := 1, predicate := .input (.boolean false), enable := .boolean false }],
   fixture "disabled-negative-witness" [fixed 0 (-1), fixed 1 0]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "unsat")
     [{ lower := 0, upper := 1, predicate := .input (.boolean false), enable := .boolean false }],
   fixture "guard-only-array-uf" [fixed 0 0, fixed 1 1] rootGraph [] [] (verdict "sat")
     [{ mismatch with enable := guard },
      { mismatch with enable := .not guard, predicate := .eq (.cell 0) (.input left) }],
   fixture "disabled-high-guard" [fixed 0 0, fixed 1 0] rootGraph [] [] (verdict "sat")
     [{ mismatch with enable := .app .entry .bool 7000 (.unknown .entry 9000) }],
   fixture "wrong-selector-witness" [fixed 0 0, fixed 1 1,
       .equal (.app .content .nodes 0 .signature) (.nodes 0),
       .equal (.configurationNodes .signature) (.nodes 21845)]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "sat")
     [{ lower := 0, upper := 1, enable := .boolean true,
        predicate := .ne (.input (.configurationNodes .signature)) (.input (.app .content .nodes 0 .signature)) }]]

def nativeFixtures : List Json :=
  let content : Operand 1 .content := .entryContent (.cell 0)
  let nodes := Operand.configurationNodes content
  let quorum := Predicate.guardedConfigurationMajority (.input (.nodes 1)) content
  let matching := Predicate.and (.isContent .reconfiguration content) (.majority (.input (.nodes 1)) nodes)
  let singletonInput := [fixed 0 0, fixed 1 1, fixed 2 0]
  let entry := fun mask => Term.entry (.integer 0) (.reconfiguration (.nodes mask))
  let positions := [fixed 0 0, fixed 1 2, fixed 2 0, fixed 3 1]
  let conditions : Vector (Term .bool) NODE_COUNT := Vector.ofFn fun node => .unknown .bool (1000 + node.val)
  let conditionInput := List.ofFn fun node : Node => Term.equal conditions[node] (.boolean (node.val == 0))
  let filtered := Predicate.eq (.cardinality (nodes.filterByFixed conditions)) (.input (.integer 1))
  [fixture "native-forall-signature" singletonInput rootGraph
     [{ lower := 0, upper := 1, predicate := quorum }] [point (.root 0) 2 left] (verdict "sat"),
   fixture "native-forall-empty-configuration" singletonInput rootGraph
     [{ lower := 0, upper := 1, predicate := quorum }] [point (.root 0) 2 (entry 0)] (verdict "unsat"),
   fixture "native-forall-tie" singletonInput rootGraph
     [{ lower := 0, upper := 1, predicate := quorum }] [point (.root 0) 2 (entry 16385)] (verdict "unsat"),
   fixture "native-forall-majority" singletonInput rootGraph
     [{ lower := 0, upper := 1, predicate := quorum }] [point (.root 0) 2 (entry 1)] (verdict "sat"),
   fixture "native-exists-signature" singletonInput rootGraph [] [point (.root 0) 2 left] (verdict "unsat")
     [{ lower := 0, upper := 1, predicate := matching, enable := .boolean true }],
   fixture "native-exists-configuration" singletonInput rootGraph [] [point (.root 0) 2 (entry 1)] (verdict "sat")
     [{ lower := 0, upper := 1, predicate := matching, enable := .boolean true }]] ++
  [true, false].flatMap (fun valid =>
    let expected := verdict (if valid then "sat" else "unsat")
    let points := [point (.root 0) 2 (entry 1), point (.version 0) 3 (entry (if valid then 16384 else 16385))]
    [fixture s!"native-cardinality-{valid}" positions rootGraph
       [{ lower := 0, upper := 1, predicate := .eq (.cardinality nodes) (.input (.integer 1)) }]
       points expected,
     fixture s!"native-filter-{valid}" (positions ++ conditionInput) rootGraph
       [{ lower := 0, upper := 1, predicate := filtered }]
       [point (.root 0) 2 (entry 16385), point (.version 0) 3 (entry (if valid then 1 else 16384))] expected,
     fixture s!"native-wrong-selector-{valid}"
       (singletonInput ++ [.equal (.configurationNodes .signature) (.nodes 21845),
         .equal (.app .content .nodes 0 .signature) (.nodes 0)]) rootGraph
       [{ lower := 0, upper := 1, predicate := .eq nodes (.input (.nodes 21845)) }]
       [point (.root 0) 2 left] expected
       [{ lower := 0, upper := 1, enable := .boolean true,
          predicate := .eq nodes (.input (.nodes (if valid then 21845 else 0))) }]]) ++
  [fixture "native-inactive-filter-metadata" singletonInput rootGraph
     [{ lower := 0, upper := 1,
        predicate := .eq (.cardinality (nodes.filterByFixed EntryPredicate.Regression.inactiveConditions))
          (.input (.integer 0)) }]
     [point (.root 0) 2 (entry 32767)] (verdict "sat"),
   fixture "native-no-reference-witness" [fixed 0 0, fixed 1 1000000]
     (.empty : SymbolicGraph 0 .entry 0) [] [] (verdict "sat")
     [{ lower := 0, upper := 1, enable := .boolean true,
        predicate := .eq (.cardinality (.input (.nodes 32767))) (.input (.integer 15)) }]]

end CCFRaft.Sparse.TypedJointPredicateFixtures

def main (args : List String) : IO UInt32 := do
  let cases := match args with
    | [] => some (CCFRaft.Sparse.TypedJointPredicateFixtures.boundaryFixtures ++
        CCFRaft.Sparse.TypedJointPredicateFixtures.edgeFixtures ++
        CCFRaft.Sparse.TypedJointPredicateFixtures.scaleFixtures)
    | ["--witnesses"] => some (CCFRaft.Sparse.TypedJointPredicateFixtures.witnessBoundaryFixtures ++
        CCFRaft.Sparse.TypedJointPredicateFixtures.witnessEdgeFixtures)
    | ["--native"] => some CCFRaft.Sparse.TypedJointPredicateFixtures.nativeFixtures
    | _ => none
  let some cases := cases |
    ( <- IO.getStderr).putStrLn "usage: TypedJointPredicateFixtureMain.lean [--witnesses | --native]"
    return 1
  IO.println (Lean.toJson cases).compress
  return 0
