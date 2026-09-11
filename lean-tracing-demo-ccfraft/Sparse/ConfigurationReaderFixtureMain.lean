import Sparse.ConfigurationReaderEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigurationReaderFixtures

open Smt EntryPredicate TypedIntervalEncoding Lean
open TypedJointPredicateEncoding
open IntervalEncoding (natTerm)
open ConfigurationReaderEncoding (Request)

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (natTerm id) (.integer value)

private def mask (value : Nat) : Term .nodes := .nodes (BitVec.ofNat NODE_COUNT value)

private def fixedMask (id value : Nat) : Term .bool :=
  .equal (.unknown .nodes id) (mask value)

private def entry (content : Option Nat) (term : Int) : Term .entry :=
  .entry (.integer term) (match content with
    | none => .signature
    | some value => .reconfiguration (mask value))

private def rootGraph : SymbolicGraph 1 .entry 1 := .push .empty (.root 0)

private def request : Request 1 :=
  { version := 0, length := 0, frontier := 1, index := 2, nodes := .unknown .nodes 3 }

private def fixture [Bootstrap Node] {roots size : Nat} (name : String)
    (input : SmtScript.Formula) (graph : SymbolicGraph roots .entry size)
    (readers : List (Request size)) (points : List (Observation roots size .entry))
    (metadata : List (String × Json)) (clauses : List (Witness.Clause size) := []) : Json :=
  let prepared := readers.foldl (fun (input, queries, slots) reader =>
    let first := max (reader.maximum + 1) (Witness.zero input graph queries points clauses)
    (input ++ ConfigurationReaderEncoding.constraints reader first,
      ConfigurationReaderEncoding.queries reader first ++ queries,
      slots ++ [first])) (input, ([] : List (Query size)), ([] : List Nat))
  let formula := Witness.encode prepared.1 graph prepared.2.1 points clauses
  let script := SmtScript.render formula
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("bootstrap", toJson (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION).toNat),
    ("readers", toJson readers.length), ("queries", toJson prepared.2.1.length),
    ("derived_slots", toJson prepared.2.2), ("points", toJson points.length),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def concreteCase [Bootstrap Node] (contents : List (Option Nat))
    (frontier index nodes : Nat) : Json :=
  let positions := (List.range contents.length).map fun position => fixed (10 + position) position
  let points := contents.zipIdx |>.map fun (content, position) =>
    ({ address := .root 0, position := 10 + position,
       expected := entry content (if position % 2 = 0 then -7 else 42) } : Observation 1 1 .entry)
  fixture s!"concrete-{(NodeSetCodec.encodeNodes INITIAL_CONFIGURATION).toNat}-{reprStr contents}-{frontier}-{index}-{nodes}"
    ([fixed 0 contents.length, fixed 1 frontier, fixed 2 index, fixedMask 3 nodes] ++ positions)
    rootGraph [request] points
    [("contents", toJson contents), ("frontier", toJson frontier),
     ("index", toJson index), ("nodes", toJson nodes)]

def finiteCases : List Json :=
  let alphabet : List (Option Nat) := [none, some 0, some 31]
  let logs := [[]] ++ alphabet.map (fun content => [content]) ++
    alphabet.flatMap (fun left => alphabet.map (fun right => [left, right]))
  logs.flatMap fun contents =>
    [0, 1, 3].flatMap fun frontier =>
      (List.range (contents.length + 2)).flatMap fun index =>
        [0, 31, 2].map fun nodes => concreteCase contents frontier index nodes

private def verdict (value : String) : List (String × Json) := [("expected", toJson value)]

def edgeCases : List Json :=
  let large := [1000000, 1000000000000].flatMap fun length =>
    [true, false].map fun valid =>
      fixture s!"sparse-{length}-{valid}"
        [fixed 0 length, fixed 1 (length + 100), fixed 2 length, fixedMask 3 0,
         fixed 10 (length - 1)] rootGraph [request]
        [{ address := .root 0, position := 10,
           expected := entry (if valid then some 0 else none) (-1000000) }]
        (verdict (if valid then "sat" else "unsat"))
  let negatives := [0, 1, 2].map fun id =>
    fixture s!"negative-{id}"
      [fixed 0 (if id = 0 then -1 else 0), fixed 1 (if id = 1 then -1 else 0),
       fixed 2 (if id = 2 then -1 else 0), fixedMask 3 31]
      rootGraph [request] [] (verdict "unsat")
  let shared :=
    [fixture "two-readers-conflict"
      [fixed 0 1, fixed 1 1, fixed 2 1, fixedMask 3 0, fixedMask 4 31]
      rootGraph [request, { request with nodes := .unknown .nodes 4 }] [] (verdict "unsat"),
     fixture "aliased-versions-conflict"
      [fixed 0 1, fixed 1 1, fixed 2 1, fixedMask 3 0, fixedMask 4 31]
      (.push rootGraph (.root 0))
      [{ version := 0, length := 0, frontier := 1, index := 2, nodes := .unknown .nodes 3 },
       { version := 1, length := 0, frontier := 1, index := 2, nodes := .unknown .nodes 4 }]
      [] (verdict "unsat"),
     fixture "shared-caller-witness"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixedMask 3 31]
      rootGraph [request] [] (verdict "unsat")
      [{ lower := 2, upper := 0,
         predicate := .isContent .reconfiguration (.entryContent (.cell 0)), enable := .boolean true }],
     fixture "disabled-caller-witness"
      [fixed 0 1, fixed 1 1, fixed 2 0, fixedMask 3 31]
      rootGraph [request] [] (verdict "sat")
      [{ lower := 2, upper := 0,
         predicate := .isContent .reconfiguration (.entryContent (.cell 0)), enable := .boolean false }],
     fixture "aliased-source"
      [fixed 0 1, fixedMask 3 0, fixed 10 0]
      rootGraph [{ request with frontier := 0, index := 0 }]
      [{ address := .root 0, position := 10, expected := entry (some 0) 123 }] (verdict "sat"),
     fixture "empty-live-prefix"
      [fixed 0 0, fixed 1 100, fixed 2 0, fixedMask 3 31, fixed 10 0]
      rootGraph [request]
      [{ address := .root 0, position := 10, expected := entry (some 0) (-1) }] (verdict "sat"),
     fixture "unused-graph-symbol"
      [fixed 0 0, fixed 1 0, fixed 2 0, fixedMask 3 31]
      (.push rootGraph (.constant (.unknown .entry 1000000)))
      [{ version := 0, length := 0, frontier := 1, index := 2, nodes := .unknown .nodes 3 }]
      [] (verdict "sat"),
     fixture "inactive-mask-selector"
      [fixed 0 0, fixed 1 0, fixed 2 0, fixedMask 3 31] rootGraph
      [{ request with
         nodes := .ite (.boolean true) (.unknown .nodes 3)
           (.configurationNodes (.entryContent (.app .int .entry 1000000 (.integer (-7))))) }]
      [] (verdict "sat")]
  let gaps := [0, 1, 2, 3, 4, 5].flatMap fun index =>
    [0, 31, 2].map fun nodes => concreteCase [some 31, none, some 0, none] 100 index nodes
  large ++ negatives ++ shared ++ gaps

def alternateBootstrapCases : List Json :=
  let node : Node := Fin.mk 14 (by decide +kernel)
  letI : Bootstrap Node := { configuration := {node}, leader := node, leader_mem := by simp }
  [concreteCase [] 0 0 16384, concreteCase [] 0 0 31,
   concreteCase [some 0] 10 1 0, concreteCase [some 16384] 10 1 16384]

end CCFRaft.Sparse.ConfigurationReaderFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.ConfigurationReaderFixtures.finiteCases ++
    CCFRaft.Sparse.ConfigurationReaderFixtures.edgeCases ++
    CCFRaft.Sparse.ConfigurationReaderFixtures.alternateBootstrapCases)).compress
