import Sparse.EntryValue

set_option autoImplicit false

namespace CCFRaft.Sparse.SmtNodes

def bitChar (bit : Bool) : Char := if bit then '1' else '0'

def parseBit : Char -> Option Bool
  | '0' => some false
  | '1' => some true
  | _ => none

def bits (value : BitVec NODE_COUNT) : List Bool :=
  List.ofFn (fun i : Fin NODE_COUNT => value.getMsbD i.val)

def chars (value : BitVec NODE_COUNT) : List Char :=
  ['#', 'b'] ++ (bits value).map bitChar

def render (value : BitVec NODE_COUNT) : String := String.ofList (chars value)

def parseChars : List Char -> Option (BitVec NODE_COUNT)
  | '#' :: 'b' :: rest => do
    let values <- rest.mapM parseBit
    if width : values.length = NODE_COUNT then
      some ((BitVec.ofBoolListBE values).cast width)
    else none
  | _ => none

theorem parse_bits (values : List Bool) :
    (values.map bitChar).mapM parseBit = some values := by
  induction values with
  | nil => rfl
  | cons bit rest ih => cases bit <;> simp [bitChar, parseBit, ih]

theorem bits_roundtrip (value : BitVec NODE_COUNT) :
    (BitVec.ofBoolListBE (bits value)).cast (by simp only [bits, List.length_ofFn]) = value := by
  apply BitVec.eq_of_getMsbD_eq
  intro i hi
  simp only [BitVec.getMsbD_cast, BitVec.getMsbD_ofBoolListBE, bits,
    List.getD_eq_getElem?_getD, List.getElem?_ofFn, dif_pos hi, Option.getD_some]

theorem parse_render (value : BitVec NODE_COUNT) :
    parseChars (render value).toList = some value := by
  simp only [render, String.toList_ofList, chars, List.cons_append, List.nil_append,
    parseChars, parse_bits]
  dsimp only [Bind.bind, Option.bind]
  rw [dif_pos (show (bits value).length = NODE_COUNT by simp only [bits, List.length_ofFn])]
  exact congrArg some (bits_roundtrip value)

theorem fixed_width (value : BitVec NODE_COUNT) :
    (chars value).length = 17 := by
  simp [chars, bits, NODE_COUNT]

end CCFRaft.Sparse.SmtNodes

run_cmd do
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.SmtNodes).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit nodes-text axiom: {name}"
      | _ =>
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "SmtNodes: allowed-axiom gate passed."
