import Sparse.QueueEncoding
import Lean.Data.Json

namespace CCFRaft.Sparse.SymbolBoundsFixtures

open Smt

private def cases : List (Prod String SmtScript.Formula) := [
  ("empty", []),
  ("large-literals", [.le (.integer 1000000000000) (.integer (-1))]),
  ("symbol-zero", [.equal (.unknown .int 0) (.integer 0)]),
  ("constant-bool", [.unknown .bool 4]),
  ("unary-bool-bool", [.app .bool .bool 5 (.unknown .bool 3)]),
  ("unary-int-bool", [.app .int .bool 6 (.unknown .int 3)]),
  ("unary-bool-int", [.equal (.app .bool .int 7 (.unknown .bool 3)) (.integer 0)]),
  ("unary-int-int", [.equal (.app .int .int 8 (.unknown .int 3)) (.integer 0)]),
  ("nested-arithmetic", [
    .le (.add (.unknown .int 11) (.integer 1)) (.sub (.integer 3) (.unknown .int 12))]),
  ("inactive-branch", [.ite (.boolean false) (.unknown .bool 100) (.boolean true)]),
  ("inactive-implication", [.implies (.boolean false) (.not (.unknown .bool 101))]),
  ("same-id-different-signatures", [
    .and (.unknown .bool 20) (.equal (.app .int .int 20 (.integer 0)) (.unknown .int 20))]),
  ("large-id", [.unknown .bool (2 ^ 129 + 3)]),
  ("many-symbols", (List.range 200).map fun id =>
    .equal (.app .int .int (id + 1000) (.unknown .int id)) (.unknown .int id))
]

def run : IO Unit := do
  for (name, formula) in cases do
    let reference := (SmtScript.symbols formula).toFinset.sup QueueEncoding.symbolId + 1
    let summary := SymbolBounds.freshBase formula
    let compiled := QueueEncoding.freshBase formula
    let allocated := fun base =>
      SmtScript.render (formula ++ [.equal (.unknown .int base) (.integer 0)])
    if reference != summary || reference != compiled ||
        allocated reference != allocated compiled then
      throw (IO.userError s!"allocation summary mismatch: {name}")
    IO.println (Lean.Json.mkObj [
      ("name", Lean.toJson name), ("bound", Lean.toJson compiled)]).compress

end CCFRaft.Sparse.SymbolBoundsFixtures

def main : IO Unit := CCFRaft.Sparse.SymbolBoundsFixtures.run
