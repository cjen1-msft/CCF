import Sparse.Smt

-- Exact generated-symbol tokens only. No numeral, whitespace, expression, or script parser.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtText

open Smt

private abbrev parseSort := Ty.parseCode

private def parseBits : List Char -> Option Nat
  | [] => some 0
  | '0' :: rest => (parseBits rest).map (Nat.bit false)
  | '1' :: rest => (parseBits rest).map (Nat.bit true)
  | _ => none

private def parseChars : List Char -> Option Symbol
  | 'c' :: tag :: '_' :: '_' :: digits => do
    let ty <- parseSort tag
    let id <- parseBits digits
    pure (.constant ty id)
  | 'f' :: domain :: result :: '_' :: digits => do
    let domain <- parseSort domain
    let result <- parseSort result
    let id <- parseBits digits
    pure (.unary domain result id)
  | _ => none

-- Decode first, then reject noncanonical encodings such as trailing zero bits.
-- This compares concrete strings; it neither searches symbols nor assumes an inverse.
def parseSymbol (text : String) : Option Symbol := do
  let sym <- parseChars text.toList
  if sym.name = text then some sym else none

-- Proof normal forms for the frozen renderer's private helpers, not a new renderer.
private def bitChar : Bool -> Char
  | false => '0'
  | true => '1'

private abbrev sortChar := Ty.code

private def symbolChars : Symbol -> List Char
  | .constant ty id => ['c', sortChar ty, '_', '_'] ++ id.bits.map bitChar
  | .unary domain result id =>
    ['f', sortChar domain, sortChar result, '_'] ++ id.bits.map bitChar

private theorem actual_name_chars (sym : Symbol) : sym.name.toList = symbolChars sym := by
  rw [Symbol.name, String.toList_ofList]
  cases sym with
  | constant ty id => cases ty <;> rfl
  | unary domain result id => cases domain <;> cases result <;> rfl

private theorem parseBits_render (n : Nat) :
    parseBits (n.bits.map bitChar) = some n := by
  induction n using Nat.binaryRec' with
  | zero => rfl
  | bit b n hn ih =>
    rw [Nat.bits_append_bit n b hn, List.map_cons]
    cases b <;> simp [bitChar, parseBits, ih]

private theorem parse_actual_name (sym : Symbol) :
    parseChars sym.name.toList = some sym := by
  rw [actual_name_chars]
  cases sym with
  | constant ty id =>
    cases ty <;> simp [symbolChars, sortChar, Ty.code, parseChars, parseSort, Ty.parseCode, parseBits_render]
  | unary domain result id =>
    cases domain <;> cases result <;>
      simp [symbolChars, sortChar, Ty.code, parseChars, parseSort, Ty.parseCode, parseBits_render]

theorem parseSymbol_name (sym : Symbol) : parseSymbol sym.name = some sym := by
  simp [parseSymbol, parse_actual_name]

theorem parseSymbol_sound {text : String} {sym : Symbol}
    (parsed : parseSymbol text = some sym) : text = sym.name := by
  unfold parseSymbol at parsed
  cases raw : parseChars text.toList with
  | none => simp [raw] at parsed
  | some candidate =>
    simp only [raw] at parsed
    change (if candidate.name = text then some candidate else none) = some sym at parsed
    split at parsed
    next canonical =>
      have same : candidate = sym := Option.some.inj parsed
      exact canonical.symm.trans (congrArg Symbol.name same)
    next => cases parsed

theorem parseSymbol_iff (text : String) (sym : Symbol) :
    parseSymbol text = some sym <-> text = sym.name := by
  constructor
  next => exact parseSymbol_sound
  next =>
    intro same
    rw [same, parseSymbol_name]

def parseSymbolAtom (text : String) : Option SExpr :=
  (parseSymbol text).map (fun sym => .atom (.symbol sym))

theorem symbol_atom_roundtrip (sym : Symbol) :
    parseSymbolAtom (SExpr.atom (.symbol sym)).render = some (.atom (.symbol sym)) := by
  simp [parseSymbolAtom, SExpr.render, Atom.render, parseSymbol_name]

theorem symbol_atom_eval_roundtrip (assignment : Assignment) (sym : Symbol) :
    (parseSymbolAtom (SExpr.atom (.symbol sym)).render).bind (SExpr.eval assignment) =
      (SExpr.atom (.symbol sym)).eval assignment := by
  rw [symbol_atom_roundtrip]
  rfl

theorem parsed_constant_eval (assignment : Assignment) (ty : Ty) (id : Nat) :
    (parseSymbolAtom (Symbol.constant ty id).name).bind (SExpr.eval assignment) =
      some (embed ty (assignment.constant ty id)) := by
  simp [parseSymbolAtom, parseSymbol_name, SExpr.eval]

theorem parsed_unary_atom_not_value (assignment : Assignment) (domain result : Ty) (id : Nat) :
    (parseSymbolAtom (Symbol.unary domain result id).name).bind (SExpr.eval assignment) = none := by
  simp [parseSymbolAtom, parseSymbol_name, SExpr.eval]

theorem zero_id_regression :
    parseSymbol "cb__" = some (.constant .bool 0) /\
    parseSymbol "ci__" = some (.constant .int 0) := by
  decide +kernel

theorem signature_regression :
    parseSymbol "fbb_101" = some (.unary .bool .bool 5) /\
    parseSymbol "fbi_101" = some (.unary .bool .int 5) /\
    parseSymbol "fib_101" = some (.unary .int .bool 5) /\
    parseSymbol "fii_101" = some (.unary .int .int 5) := by
  decide +kernel

theorem malformed_regression :
    parseSymbol "" = none /\
    parseSymbol "ci_" = none /\
    parseSymbol "cx__" = none /\
    parseSymbol "fix_1" = none /\
    parseSymbol "ci__2" = none /\
    parseSymbol "ci__0" = none /\
    parseSymbol "fii_10" = none /\
    parseSymbol " ci__" = none /\
    parseSymbol "ci__ " = none /\
    parseSymbol "ci__) (check-sat)" = none := by
  decide +kernel

theorem non_ascii_regression :
    parseSymbol ("ci__" ++ String.singleton (Char.ofNat 955)) = none := by
  decide +kernel

end CCFRaft.Sparse.SmtText

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.SmtText |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit text-parser axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no text-parser declarations audited"
  Lean.logInfo m!"Sparse.SmtText: {checked} declarations passed the allowed-axiom gate."
