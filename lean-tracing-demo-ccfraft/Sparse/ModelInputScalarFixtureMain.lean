import Sparse.ModelInputScalarEncoding
import Lean.Data.Json

set_option autoImplicit false

namespace CCFRaft.Sparse.ModelInputScalarFixtures

open Smt Lean ModelInputScalarEncoding

private def fixed (id : Nat) (value : Int) : Term .bool :=
  .equal (.unknown .int id) (.integer value)

private def fixture (name : String) (base count : Nat) (input : SmtScript.Formula)
    (expected : String) : Json :=
  let domains := encodeDomains base count
  let formula := domains ++ input
  let script := SmtScript.render formula
  Json.mkObj [
    ("name", toJson name), ("script", toJson script), ("expected", toJson expected),
    ("base", toJson base), ("count", toJson count), ("end", toJson (highwater base count)),
    ("domain_clauses", toJson domains.length),
    ("domain_symbols", toJson (SmtScript.symbols domains).length),
    ("parsed_script", toJson ((SmtScriptText.parse script).map SmtScript.renderCommands)),
    ("command_value", toJson (SmtScript.run QueueEncoding.regressionInput (SmtScript.compile formula))),
    ("parsed_value", toJson (SmtScriptText.runText QueueEncoding.regressionInput script))]

def matrix : List Json :=
  [0, 41, 1000000, 1000000000000].flatMap fun base =>
    ([-1, 0, 1, 2, 7] : List Int).flatMap fun value =>
      [true, false].flatMap fun consistent =>
        let input := [fixed base value, fixed (base + 1) 0, fixed (base + 2) 0]
        let expected := if value >= 0 && consistent then "sat" else "unsat"
        let isZero := value == 0
        [fixture s!"nat-{base}-{value}-{consistent}" base 3
          (input ++ [.equal (sourceNat (n := 3) base (.unknown 0))
            (.integer (if consistent then value else value + 1))]) expected,
         fixture s!"bool-{base}-{value}-{consistent}" base 3
          (input ++ [.equal (sourceBool (n := 3) base (.isZero (.unknown 0)))
            (.boolean (if consistent then isZero else !isZero))]) expected,
         fixture s!"some-{base}-{value}-{consistent}" base 3
          (input ++ [.equal (sourceOption (n := 3) base (some (.unknown 0)))
            (.integer (if consistent then value + 1 else value))]) expected,
         fixture s!"none-{base}-{value}-{consistent}" base 3
          (input ++ [.equal (sourceOption (n := 3) base none)
            (.integer (if consistent then 0 else 1))]) expected]

def edges : List Json :=
  let aliases := [7, 8].flatMap fun other =>
    [true, false].map fun same =>
      fixture s!"alias-{other}-{same}" 20 2
        [fixed 20 7, fixed 21 other,
         .equal (.equal (sourceNat (n := 2) 20 (.unknown 0))
           (sourceNat (n := 2) 20 (.unknown 1))) (.boolean same)]
        (if (other == 7) == same then "sat" else "unsat")
  aliases ++
    [fixture "negative-unused" 10 3
      [fixed 10 0, fixed 11 0, fixed 12 (-1),
       .equal (sourceNat (n := 3) 10 (.literal 1)) (.integer 1)] "unsat",
     fixture "negative-outside-block" 10 3
      [fixed 9 (-1), fixed 13 (-1)] "sat",
     fixture "some-zero-is-not-none" 10 1
      [fixed 10 0, .equal (sourceOption (n := 1) 10 (some (.unknown 0)))
        (sourceOption (n := 1) 10 none)] "unsat",
     fixture "literal-is-not-entry-code" 0 0
      [.equal (sourceNat (n := 0) 0 (.literal 1)) (.integer (-1))] "unsat",
     fixture "million-literal" 0 0
      [.equal (sourceNat (n := 0) 0 (.literal 1000000)) (.integer 1000000)] "sat",
     fixture "empty-declarations" 1000000000000 0 [] "sat"]

end CCFRaft.Sparse.ModelInputScalarFixtures

def main : IO Unit :=
  IO.println (Lean.toJson (CCFRaft.Sparse.ModelInputScalarFixtures.matrix ++
    CCFRaft.Sparse.ModelInputScalarFixtures.edges)).compress
