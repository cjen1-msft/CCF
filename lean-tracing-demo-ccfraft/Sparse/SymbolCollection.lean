import Sparse.Smt
import Std.Data.HashSet.Lemmas
import Mathlib.Data.List.Dedup

set_option autoImplicit false

namespace CCFRaft.Sparse.SymbolCollection

open Smt

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

-- Scan right to left and prepend survivors, retaining the last occurrence order.
def collect : List Symbol -> Std.HashSet String -> List Symbol -> List Symbol
  | [], _, output => output
  | symbol :: rest, seen, output =>
    let checked := seen.containsThenInsert symbol.name
    collect rest checked.2 (if checked.1 then output else symbol :: output)

def dedup (symbols : List Symbol) : List Symbol :=
  collect symbols.reverse {} []

def Tracks (seen : Std.HashSet String) (output : List Symbol) : Prop :=
  forall symbol, seen.contains symbol.name = true <-> symbol IN output

theorem tracks_step (seen : Std.HashSet String) (output : List Symbol)
    (tracks : Tracks seen output) (symbol : Symbol) :
    Tracks (seen.insert symbol.name)
      (if seen.contains symbol.name then output else symbol :: output) := by
  intro other
  rw [Std.HashSet.contains_insert, Bool.or_eq_true, beq_iff_eq,
    symbol_name_injective.eq_iff, tracks other]
  split
  next found =>
    constructor
    next =>
      intro member
      cases member with
      | inl same =>
        cases same
        exact (tracks symbol).mp found
      | inr member => exact member
    next => exact fun member => Or.inr member
  next => simp only [List.mem_cons, eq_comm]

theorem collect_eq_foldl (symbols : List Symbol) (seen : Std.HashSet String)
    (output : List Symbol) (tracks : Tracks seen output) :
    collect symbols seen output =
      symbols.foldl (fun output symbol => if symbol IN output then output else symbol :: output)
        output := by
  induction symbols generalizing seen output with
  | nil => rfl
  | cons symbol rest ih =>
    simp only [collect, Std.HashSet.containsThenInsert_fst, Std.HashSet.containsThenInsert_snd,
      List.foldl_cons]
    rw [ih _ _ (tracks_step seen output tracks symbol)]
    simp only [tracks symbol]

theorem foldr_eq_dedup (symbols : List Symbol) :
    symbols.foldr (fun symbol output => if symbol IN output then output else symbol :: output) [] =
      symbols.dedup := by
  induction symbols with
  | nil => rfl
  | cons symbol rest ih => rw [List.foldr_cons, ih, List.dedup_cons']

theorem dedup_eq (symbols : List Symbol) : dedup symbols = symbols.dedup := by
  unfold dedup
  rw [collect_eq_foldl _ _ _ (by intro symbol; simp), List.foldl_reverse]
  exact foldr_eq_dedup symbols

namespace Regression

def a : Symbol := .constant .int 0
def b : Symbol := .constant .bool 0
def c : Symbol := .unary .int .int 0
def d : Symbol := .unary .bool .int 0

theorem kernel_empty : dedup [] = [] := by decide +kernel

theorem kernel_last_occurrence :
    dedup [a, b, c, a, d, c, b] = [a, d, c, b] := by
  rw [dedup_eq]
  decide +kernel

theorem kernel_repeated :
    dedup [a, a, a, a, a] = [a] := by
  rw [dedup_eq]
  decide +kernel

theorem kernel_signatures :
    dedup
      [.constant .bool 0, .constant .int 0, .unary .bool .bool 0,
       .unary .bool .int 0, .unary .int .bool 0, .unary .int .int 0,
       .constant .bool 0, .unary .int .bool 0, .constant .int 0,
       .unary .bool .int 0, .unary .bool .bool 0, .unary .int .int 0] =
      [.constant .bool 0, .unary .int .bool 0, .constant .int 0,
       .unary .bool .int 0, .unary .bool .bool 0, .unary .int .int 0] := by
  rw [dedup_eq]
  decide +kernel

theorem kernel_large_ids :
    dedup
      [.constant .int (2 ^ 128 + 1), .constant .int (2 ^ 128),
       .unary .int .bool (2 ^ 128 + 1), .constant .int (2 ^ 128 + 1),
       .constant .int 1, .constant .int (2 ^ 128)] =
      [.unary .int .bool (2 ^ 128 + 1), .constant .int (2 ^ 128 + 1),
       .constant .int 1, .constant .int (2 ^ 128)] := by
  rw [dedup_eq]
  decide +kernel

theorem kernel_reference_order :
    dedup [a, b, a] = [b, a] /\ dedup [a, b, a] = [a, b, a].dedup := by
  exact And.intro (by rw [dedup_eq]; decide +kernel) (dedup_eq _)

end Regression

end CCFRaft.Sparse.SymbolCollection

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.SymbolCollection).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit symbol collection axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no symbol collection declarations audited"
  Lean.logInfo m!"SymbolCollection: {checked} declarations passed the allowed-axiom gate."
