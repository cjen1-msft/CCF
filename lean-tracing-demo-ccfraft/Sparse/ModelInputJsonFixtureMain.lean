import Sparse.ModelInputJson

set_option autoImplicit false

namespace CCFRaft.Sparse.ModelInputJsonFixtures

open Lean ModelInputJson ModelInputSyntax

private def errorJson (error : DecodeError) : Json :=
  Json.mkObj [("error", toJson (reprStr error))]

private def reference (name : String) : Json := Json.mkObj [("unknown", .str name)]

private def rho (index : Nat) : Nat := if index % 2 = 0 then 0 else index + 1

private def lookup (table : NameTable) (name : String) : Json :=
  let natJson := reference name
  let boolJson := Json.mkObj [("isZero", natJson)]
  let index := match resolveName table name with
    | .ok value => toJson value.val
    | .error error => errorJson error
  let (numeric, encodedNat) := match decodeNat table natJson with
    | .ok atom => (toJson (NatAtom.eval rho atom), encodeNat table atom)
    | .error error => (errorJson error, errorJson error)
  let (zero, encodedBool) := match decodeBool table boolJson with
    | .ok atom => (toJson (BoolAtom.eval rho atom), encodeBool table atom)
    | .error error => (errorJson error, errorJson error)
  Json.mkObj [("name", toJson name), ("index", index), ("numeric", numeric), ("zero", zero),
    ("encoded_nat", encodedNat), ("encoded_bool", encodedBool)]

private def tableCase (count : Nat) : Except String Json :=
  let names := (List.range count).map fun index => s!"slot-{index}"
  match decodeNames (.arr (names.map Json.str).toArray) [.field "unknowns"] with
  | .error error => .error s!"Unexpected name-table failure: {reprStr error}"
  | .ok table => .ok (Json.mkObj [
      ("count", toJson count), ("declared", toJson names),
      ("encoded_names", encodeNames table),
      ("lookups", toJson (names.map (lookup table))),
      ("missing", lookup table "missing")])

def run : IO Unit := do
  let mut tables : Array Json := #[]
  for count in [0, 1, 40, 400] do
    match tableCase count with
    | .ok table => tables := tables.push table
    | .error error => throw (IO.userError error)
  IO.println (Json.mkObj [
    ("controls", toJson ModelInputJson.Regression.controls),
    ("tables", .arr tables)]).compress

end CCFRaft.Sparse.ModelInputJsonFixtures

def main : IO Unit := CCFRaft.Sparse.ModelInputJsonFixtures.run
