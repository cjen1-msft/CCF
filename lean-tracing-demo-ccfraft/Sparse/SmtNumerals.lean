import Sparse.Smt
import Init.Data.Repr
import Mathlib.Tactic.IntervalCases

-- Canonical nonnegative decimal tokens only. Signed values use unary-minus expressions.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtNumerals

open Smt

private def parseDigit : Char -> Option Nat
  | '0' => some 0
  | '1' => some 1
  | '2' => some 2
  | '3' => some 3
  | '4' => some 4
  | '5' => some 5
  | '6' => some 6
  | '7' => some 7
  | '8' => some 8
  | '9' => some 9
  | _ => none

private def parseDigits : List Char -> Nat -> Option Nat
  | [], value => some value
  | digit :: rest, value => do
    let d <- parseDigit digit
    parseDigits rest (value * 10 + d)

private theorem parseDigit_digitChar (d : Nat) (bound : d < 10) :
    parseDigit (Nat.digitChar d) = some d := by
  interval_cases d <;> rfl

-- The suffix can be arbitrary, even malformed. Only the generated prefix is decoded here.
private theorem parseDigits_toDigitsCore (fuel n : Nat) (suffix : List Char)
    (enough : n < fuel) :
    parseDigits (Nat.toDigitsCore 10 fuel n suffix) 0 = parseDigits suffix n := by
  induction fuel generalizing n suffix with
  | zero => omega
  | succ fuel ih =>
    simp only [Nat.toDigitsCore]
    have digit := parseDigit_digitChar (n % 10) (Nat.mod_lt _ (by decide))
    by_cases last : n / 10 = 0
    next =>
      rw [if_pos last]
      have remainder : n % 10 = n := by omega
      simp only [parseDigits, digit]
      simp [remainder]
    next =>
      have smaller : n / 10 < n := Nat.div_lt_self (by omega) (by decide)
      have remainingFuel : n / 10 < fuel := by omega
      rw [if_neg last, ih (n / 10) (Nat.digitChar (n % 10) :: suffix) remainingFuel]
      have reassemble : n / 10 * 10 + n % 10 = n := by omega
      simp [parseDigits, digit, reassemble]

private theorem parseDigits_toDigits (n : Nat) :
    parseDigits (Nat.toDigits 10 n) 0 = some n := by
  unfold Nat.toDigits
  rw [parseDigits_toDigitsCore (n + 1) n [] (by omega)]
  rfl

private theorem parse_actual_numeral (n : Nat) :
    parseDigits (Atom.render (.numeral n)).toList 0 = some n := by
  change parseDigits (Nat.repr n).toList 0 = some n
  rw [Nat.repr, String.toList_ofList]
  exact parseDigits_toDigits n

-- Canonicality rejects empty input and leading zeroes after executable decimal decoding.
def parseNumeral (text : String) : Option Nat := do
  let n <- parseDigits text.toList 0
  if (Atom.numeral n).render = text then some n else none

theorem parseNumeral_render (n : Nat) :
    parseNumeral (Atom.numeral n).render = some n := by
  simp [parseNumeral, parse_actual_numeral]

theorem parseNumeral_sound {text : String} {n : Nat}
    (parsed : parseNumeral text = some n) : text = (Atom.numeral n).render := by
  unfold parseNumeral at parsed
  cases raw : parseDigits text.toList 0 with
  | none => simp [raw] at parsed
  | some candidate =>
    simp only [raw] at parsed
    change (if (Atom.numeral candidate).render = text then some candidate else none) = some n at parsed
    split at parsed
    next canonical =>
      have same : candidate = n := Option.some.inj parsed
      exact canonical.symm.trans (congrArg (fun value => (Atom.numeral value).render) same)
    next => cases parsed

theorem parseNumeral_iff (text : String) (n : Nat) :
    parseNumeral text = some n <-> text = (Atom.numeral n).render := by
  constructor
  next => exact parseNumeral_sound
  next =>
    intro same
    rw [same, parseNumeral_render]

def parseNumeralAtom (text : String) : Option SExpr :=
  (parseNumeral text).map (fun n => .atom (.numeral n))

theorem numeral_atom_roundtrip (n : Nat) :
    parseNumeralAtom (SExpr.atom (.numeral n)).render = some (.atom (.numeral n)) := by
  simp [parseNumeralAtom, SExpr.render, parseNumeral_render]

theorem numeral_atom_eval_roundtrip (assignment : Assignment) (n : Nat) :
    (parseNumeralAtom (SExpr.atom (.numeral n)).render).bind (SExpr.eval assignment) =
      some (.integer (Int.ofNat n)) := by
  rw [numeral_atom_roundtrip]
  simp [SExpr.eval]

theorem nonnegative_literal_roundtrip (n : Nat) :
    parseNumeralAtom (Term.integer (Int.ofNat n)).render =
      some (Term.integer (Int.ofNat n)).lower := by
  simpa [Term.render, Term.lower, signedLiteral] using numeral_atom_roundtrip n

theorem zero_regression : parseNumeral "0" = some 0 := by
  decide +kernel

theorem decimal_regression :
    parseNumeral "10" = some 10 /\
    parseNumeral "123456789012345678901234567890" = some 123456789012345678901234567890 := by
  decide +kernel

theorem malformed_regression :
    parseNumeral "" = none /\
    parseNumeral "00" = none /\
    parseNumeral "01" = none /\
    parseNumeral "-1" = none /\
    parseNumeral "-0" = none /\
    parseNumeral "+1" = none /\
    parseNumeral "(- 1)" = none /\
    parseNumeral "1_000" = none /\
    parseNumeral "0x10" = none /\
    parseNumeral "1.0" = none /\
    parseNumeral " 1" = none /\
    parseNumeral "1 " = none /\
    parseNumeral "1) (check-sat)" = none := by
  decide +kernel

theorem non_ascii_regression :
    parseNumeral (String.singleton (Char.ofNat 1633)) = none := by
  decide +kernel

end CCFRaft.Sparse.SmtNumerals

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.SmtNumerals |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit numeral-parser axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no numeral-parser declarations audited"
  Lean.logInfo m!"Sparse.SmtNumerals: {checked} declarations passed the allowed-axiom gate."
