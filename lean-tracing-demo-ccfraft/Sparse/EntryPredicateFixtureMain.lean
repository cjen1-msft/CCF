import Sparse.EntryPredicate
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.EntryPredicateFixtures

open Smt EntryPredicate Lean

private def cell (version : Fin 2) : Term .entry :=
  TypedIntervalEncoding.readRef 100 (IntervalReadback.Address.version (roots := 0) version) 2

private def fixture (name : String) (input : SmtScript.Formula) (predicate : Predicate 2)
    (metadata : List (Prod String Json)) : Json :=
  let formula := input ++ [predicate.lower 0 100 2]
  let script := SmtScript.render formula
  Json.mkObj ([
    ("name", toJson name), ("script", toJson script),
    ("references", toJson (predicate.references.map Fin.val)),
    ("external_max", toJson predicate.externalMax),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))] ++ metadata)

private def operators : List (Prod String (Operand 2 .int -> Operand 2 .int -> Predicate 2)) :=
  [("eq", .eq), ("ne", .ne), ("le", .le), ("lt", .lt)]

def comparisons : List Json :=
  ([-3, -2, -1, 0, 1, 2, 3] : List Int).flatMap fun left =>
    ([-3, -2, -1, 0, 1, 2, 3] : List Int).flatMap fun right =>
      ["raw", "decoded-term", "decoded-input"].flatMap fun view =>
        operators.map fun (operator, comparison) =>
          let operands : Prod (Operand 2 .int) (Operand 2 .int) :=
            if view == "raw" then (.entryTerm (.cell 0), .entryTerm (.cell 1))
            else if view == "decoded-term" then (.decodedTerm (.cell 0), .decodedTerm (.cell 1))
            else (.decodedInput (.unknown .int 10), .decodedInput (.unknown .int 11))
          fixture s!"{view}-{operator}-{left}-{right}"
            [.equal (.unknown .int 2) (.integer 1000000),
             .equal (cell 0) (.entry (.integer left) .signature),
             .equal (cell 1) (.entry (.integer right) .signature),
             .equal (.unknown .int 10) (.integer left),
             .equal (.unknown .int 11) (.integer right)]
            (comparison operands.1 operands.2)
            [("kind", toJson "comparison"), ("view", toJson view),
             ("operator", toJson operator), ("left", toJson left), ("right", toJson right)]

def identities : List Json :=
  let values : List (Term .content) :=
    [.transaction (.integer 0), .signature, .reconfiguration (.nodes 1), .retiredCommitted (.nodes 1)]
  (values.mapIdx fun leftIndex left =>
    (values.mapIdx fun rightIndex right =>
      ["eq", "ne"].map fun operator =>
        fixture s!"identity-{operator}-{leftIndex}-{rightIndex}"
          [.equal (.unknown .int 2) (.integer 0),
           .equal (cell 0) (.entry (.integer (-1)) left),
           .equal (cell 1) (.entry (.integer (-1)) right)]
          (if operator == "eq" then .eq (.cell 0) (.cell 1) else .ne (.cell 0) (.cell 1))
          [("kind", toJson "identity"), ("operator", toJson operator),
           ("left", toJson leftIndex), ("right", toJson rightIndex)]).flatten).flatten

end CCFRaft.Sparse.EntryPredicateFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.EntryPredicateFixtures.comparisons ++
    CCFRaft.Sparse.EntryPredicateFixtures.identities)).compress
