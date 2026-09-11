import Mathlib.Data.List.Basic
import Mathlib.Data.Nat.Bits
import Lean.Util.CollectAxioms
import Sparse.SmtNodes

-- Fixed value sorts only. Int packet tokens do not serialize completeMessage.
-- The proved boundary is typed IR -> SExpr evaluation, not rendered-text parsing.

set_option autoImplicit false

namespace CCFRaft.Sparse.Smt

inductive Ty where
  | bool
  | int
  | nodes
  | content
  | entry
  deriving DecidableEq, Repr

abbrev Ty.denote : Ty -> Type
  | .bool => Bool
  | .int => Int
  | .nodes => BitVec NODE_COUNT
  | .content => EntryValue.Content
  | .entry => EntryValue.Entry

instance (ty : Ty) : DecidableEq ty.denote := by
  cases ty <;> exact inferInstance

structure Assignment where
  constant : (ty : Ty) -> Nat -> ty.denote
  unary : (domain result : Ty) -> Nat -> domain.denote -> result.denote

-- IDs identify symbols, not expressions that retain a previous AST.
inductive Term : Ty -> Type where
  | boolean (value : Bool) : Term .bool
  | integer (value : Int) : Term .int
  | nodes (value : BitVec NODE_COUNT) : Term .nodes
  | transaction (txId : Term .int) : Term .content
  | signature : Term .content
  | reconfiguration (nodes : Term .nodes) : Term .content
  | retiredCommitted (nodes : Term .nodes) : Term .content
  | entry (term : Term .int) (content : Term .content) : Term .entry
  | entryTerm (entry : Term .entry) : Term .int
  | entryContent (entry : Term .entry) : Term .content
  | unknown (ty : Ty) (id : Nat) : Term ty
  | app (domain result : Ty) (id : Nat) (argument : Term domain) : Term result
  | add (left right : Term .int) : Term .int
  | sub (left right : Term .int) : Term .int
  | le (left right : Term .int) : Term .bool
  | equal {ty : Ty} (left right : Term ty) : Term .bool
  | not (value : Term .bool) : Term .bool
  | and (left right : Term .bool) : Term .bool
  | implies (left right : Term .bool) : Term .bool
  | ite {ty : Ty} (condition : Term .bool) (yes no : Term ty) : Term ty

def Term.eval (assignment : Assignment) : {ty : Ty} -> Term ty -> ty.denote
  | _, .boolean value => value
  | _, .integer value => value
  | _, .nodes value => value
  | _, .transaction txId => .transaction (txId.eval assignment)
  | _, .signature => .signature
  | _, .reconfiguration value => .reconfiguration (value.eval assignment)
  | _, .retiredCommitted value => .retiredCommitted (value.eval assignment)
  | _, .entry term content => { term := term.eval assignment, content := content.eval assignment }
  | _, .entryTerm value => (value.eval assignment).term
  | _, .entryContent value => (value.eval assignment).content
  | _, .unknown ty id => assignment.constant ty id
  | _, .app domain result id argument =>
    assignment.unary domain result id (argument.eval assignment)
  | _, .add left right => left.eval assignment + right.eval assignment
  | _, .sub left right => left.eval assignment - right.eval assignment
  | _, .le left right => decide (left.eval assignment <= right.eval assignment)
  | _, .equal left right => decide (left.eval assignment = right.eval assignment)
  | _, .not value => !(value.eval assignment)
  | _, .and left right => left.eval assignment && right.eval assignment
  | _, .implies left right => !(left.eval assignment) || right.eval assignment
  | _, .ite condition yes no => if condition.eval assignment then yes.eval assignment else no.eval assignment

inductive Symbol where
  | constant (ty : Ty) (id : Nat)
  | unary (domain result : Ty) (id : Nat)
  deriving DecidableEq, Repr

inductive Operator where
  | add | minus | le | equal | not | and | implies | ite
  | transaction | reconfiguration | retiredCommitted | entry | entryTerm | entryContent
  deriving DecidableEq, Repr

inductive Atom where
  | boolean (value : Bool)
  | numeral (value : Nat)
  | nodes (value : BitVec NODE_COUNT)
  | signature
  | symbol (name : Symbol)
  | operator (op : Operator)
  deriving DecidableEq, Repr

inductive SExpr where
  | atom (value : Atom)
  | list (values : List SExpr)
  deriving Repr

deriving instance Repr for EntryValue.Content
deriving instance Repr for EntryValue.Entry

inductive Value where
  | boolean (value : Bool)
  | integer (value : Int)
  | nodes (value : BitVec NODE_COUNT)
  | content (value : EntryValue.Content)
  | entry (value : EntryValue.Entry)
  deriving DecidableEq, Repr

def embed : (ty : Ty) -> ty.denote -> Value
  | .bool, value => .boolean value
  | .int, value => .integer value
  | .nodes, value => .nodes value
  | .content, value => .content value
  | .entry, value => .entry value

def Value.asType : (ty : Ty) -> Value -> Option ty.denote
  | .bool, .boolean value => some value
  | .int, .integer value => some value
  | .nodes, .nodes value => some value
  | .content, .content value => some value
  | .entry, .entry value => some value
  | _, _ => none

@[simp]
theorem asType_embed (ty : Ty) (value : ty.denote) :
    (embed ty value).asType ty = some value := by
  cases ty <;> rfl

-- Wrong arities and sorts fail, including mismatched unselected ite branches.
def applyHead (assignment : Assignment) : Atom -> List Value -> Option Value
  | .operator .transaction, [.integer txId] => some (.content (.transaction txId))
  | .operator .reconfiguration, [.nodes nodes] => some (.content (.reconfiguration nodes))
  | .operator .retiredCommitted, [.nodes nodes] => some (.content (.retiredCommitted nodes))
  | .operator .entry, [.integer term, .content content] => some (.entry { term, content })
  | .operator .entryTerm, [.entry entry] => some (.integer entry.term)
  | .operator .entryContent, [.entry entry] => some (.content entry.content)
  | .symbol (.unary domain result id), [argument] => do
    let value <- argument.asType domain
    pure (embed result (assignment.unary domain result id value))
  | .operator .add, [.integer left, .integer right] => some (.integer (left + right))
  | .operator .minus, [.integer value] => some (.integer (-value))
  | .operator .minus, [.integer left, .integer right] => some (.integer (left - right))
  | .operator .le, [.integer left, .integer right] => some (.boolean (decide (left <= right)))
  | .operator .equal, [.integer left, .integer right] => some (.boolean (decide (left = right)))
  | .operator .equal, [.boolean left, .boolean right] => some (.boolean (decide (left = right)))
  | .operator .equal, [.nodes left, .nodes right] => some (.boolean (decide (left = right)))
  | .operator .equal, [.content left, .content right] => some (.boolean (decide (left = right)))
  | .operator .equal, [.entry left, .entry right] => some (.boolean (decide (left = right)))
  | .operator .not, [.boolean value] => some (.boolean (!value))
  | .operator .and, [.boolean left, .boolean right] => some (.boolean (left && right))
  | .operator .implies, [.boolean left, .boolean right] => some (.boolean (!left || right))
  | .operator .ite, [.boolean condition, .integer yes, .integer no] =>
    some (.integer (if condition then yes else no))
  | .operator .ite, [.boolean condition, .boolean yes, .boolean no] =>
    some (.boolean (if condition then yes else no))
  | .operator .ite, [.boolean condition, .nodes yes, .nodes no] =>
    some (.nodes (if condition then yes else no))
  | .operator .ite, [.boolean condition, .content yes, .content no] =>
    some (.content (if condition then yes else no))
  | .operator .ite, [.boolean condition, .entry yes, .entry no] =>
    some (.entry (if condition then yes else no))
  | _, _ => none

def SExpr.eval (assignment : Assignment) : SExpr -> Option Value
  | .atom (.boolean value) => some (.boolean value)
  | .atom (.numeral value) => some (.integer (Int.ofNat value))
  | .atom (.nodes value) => some (.nodes value)
  | .atom .signature => some (.content .signature)
  | .atom (.symbol (.constant ty id)) => some (embed ty (assignment.constant ty id))
  | .list (.atom head :: arguments) => do
    let values <- arguments.mapM (SExpr.eval assignment)
    applyHead assignment head values
  | _ => none

def call (head : Atom) (arguments : List SExpr) : SExpr :=
  .list (.atom head :: arguments)

def signedLiteral : Int -> SExpr
  | .ofNat n => .atom (.numeral n)
  | .negSucc n => call (.operator .minus) [.atom (.numeral (n + 1))]

def Term.lower : {ty : Ty} -> Term ty -> SExpr
  | _, .boolean value => .atom (.boolean value)
  | _, .integer value => signedLiteral value
  | _, .nodes value => .atom (.nodes value)
  | _, .transaction txId => call (.operator .transaction) [txId.lower]
  | _, .signature => .atom .signature
  | _, .reconfiguration value => call (.operator .reconfiguration) [value.lower]
  | _, .retiredCommitted value => call (.operator .retiredCommitted) [value.lower]
  | _, .entry term content => call (.operator .entry) [term.lower, content.lower]
  | _, .entryTerm value => call (.operator .entryTerm) [value.lower]
  | _, .entryContent value => call (.operator .entryContent) [value.lower]
  | _, .unknown ty id => .atom (.symbol (.constant ty id))
  | _, .app domain result id argument =>
    call (.symbol (.unary domain result id)) [argument.lower]
  | _, .add left right => call (.operator .add) [left.lower, right.lower]
  | _, .sub left right => call (.operator .minus) [left.lower, right.lower]
  | _, .le left right => call (.operator .le) [left.lower, right.lower]
  | _, .equal left right => call (.operator .equal) [left.lower, right.lower]
  | _, .not value => call (.operator .not) [value.lower]
  | _, .and left right => call (.operator .and) [left.lower, right.lower]
  | _, .implies left right => call (.operator .implies) [left.lower, right.lower]
  | _, .ite condition yes no => call (.operator .ite) [condition.lower, yes.lower, no.lower]

@[simp]
theorem signedLiteral_eval (assignment : Assignment) (value : Int) :
    (signedLiteral value).eval assignment = some (.integer value) := by
  cases value <;> simp [signedLiteral, call, SExpr.eval, applyHead]
  omega

theorem lower_correct (assignment : Assignment) {ty : Ty} (term : Term ty) :
    term.lower.eval assignment = some (embed ty (term.eval assignment)) := by
  induction term with
  | boolean value => simp [Term.lower, SExpr.eval, Term.eval, embed]
  | integer value => exact signedLiteral_eval assignment value
  | nodes value => simp [Term.lower, SExpr.eval, Term.eval, embed]
  | signature => simp [Term.lower, SExpr.eval, Term.eval, embed]
  | transaction value ih | reconfiguration value ih | retiredCommitted value ih
  | entryTerm value ih | entryContent value ih =>
    simp [Term.lower, call, SExpr.eval, ih, applyHead, Term.eval, embed]
  | entry term content iht ihc =>
    simp [Term.lower, call, SExpr.eval, iht, ihc, applyHead, Term.eval, embed]
  | unknown ty id => simp [Term.lower, SExpr.eval, Term.eval]
  | app domain result id argument ih =>
    simp [Term.lower, call, SExpr.eval, ih, applyHead, Term.eval]
  | add left right ihl ihr =>
    simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | sub left right ihl ihr =>
    simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | le left right ihl ihr =>
    simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | @equal ty left right ihl ihr =>
    cases ty <;> simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | not value ih =>
    simp [Term.lower, call, SExpr.eval, ih, applyHead, Term.eval, embed]
  | and left right ihl ihr =>
    simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | implies left right ihl ihr =>
    simp [Term.lower, call, SExpr.eval, ihl, ihr, applyHead, Term.eval, embed]
  | @ite ty condition yes no ihc ihy ihn =>
    cases ty <;> cases hc : condition.eval assignment <;>
      simp [Term.lower, call, SExpr.eval, ihc, ihy, ihn, applyHead, Term.eval, embed, hc]

private def bitChar : Bool -> Char
  | false => '0'
  | true => '1'

private theorem bitChar_injective : Function.Injective bitChar := by
  intro a b h
  cases a <;> cases b <;> simp_all [bitChar]

private theorem bits_value (n : Nat) : n.bits.foldr Nat.bit 0 = n := by
  induction n using Nat.binaryRec' with
  | zero => rfl
  | bit b n hn ih => simp [Nat.bits_append_bit n b hn, ih]

private def idChars (id : Nat) : List Char := id.bits.map bitChar

private theorem idChars_injective : Function.Injective idChars := by
  intro a b h
  have bitsEqual := (List.map_injective_iff.mpr bitChar_injective) h
  have valuesEqual := congrArg (fun bits => bits.foldr Nat.bit 0) bitsEqual
  simpa only [bits_value] using valuesEqual

def Ty.code : Ty -> Char
  | .bool => 'b'
  | .int => 'i'
  | .nodes => 'v'
  | .content => 'd'
  | .entry => 'e'

def Ty.parseCode : Char -> Option Ty
  | 'b' => some .bool
  | 'i' => some .int
  | 'v' => some .nodes
  | 'd' => some .content
  | 'e' => some .entry
  | _ => none

@[simp] theorem Ty.parseCode_code (ty : Ty) : Ty.parseCode ty.code = some ty := by
  cases ty <;> rfl

private abbrev sortChar := Ty.code

private theorem sortChar_injective : Function.Injective sortChar := by
  intro a b h
  cases a <;> cases b <;> simp_all [sortChar, Ty.code]

-- Binary ID suffixes are least-significant-bit first; zero has an empty suffix.
-- Fixed-width tags separate constants, functions, domains, and results.
private def Symbol.chars : Symbol -> List Char
  | .constant ty id => ['c', sortChar ty, '_', '_'] ++ idChars id
  | .unary domain result id => ['f', sortChar domain, sortChar result, '_'] ++ idChars id

def Symbol.name (symbol : Symbol) : String := String.ofList symbol.chars

theorem symbol_name_injective : Function.Injective Symbol.name := by
  intro a b h
  have charsEqual : a.chars = b.chars := by
    simpa [Symbol.name] using congrArg String.toList h
  cases a with
  | constant a ai =>
    cases b with
    | constant b bi =>
      have parts : sortChar a = sortChar b /\ idChars ai = idChars bi := by
        simpa [Symbol.chars] using charsEqual
      cases sortChar_injective parts.1
      cases idChars_injective parts.2
      rfl
    | unary domain result bi => simp [Symbol.chars] at charsEqual
  | unary ad ar ai =>
    cases b with
    | constant b bi => simp [Symbol.chars] at charsEqual
    | unary bd br bi =>
      have parts : sortChar ad = sortChar bd /\
          sortChar ar = sortChar br /\ idChars ai = idChars bi := by
        simpa [Symbol.chars] using charsEqual
      cases sortChar_injective parts.1
      cases sortChar_injective parts.2.1
      cases idChars_injective parts.2.2
      rfl

def Ty.render : Ty -> String
  | .bool => "Bool"
  | .int => "Int"
  | .nodes => "(_ BitVec 15)"
  | .content => "CCFContent"
  | .entry => "CCFEntry"

theorem node_width : NODE_COUNT = 15 := rfl

def Atom.render : Atom -> String
  | .boolean true => "true"
  | .boolean false => "false"
  | .numeral n => toString n
  | .nodes value => SmtNodes.render value
  | .signature => "ccf_sig"
  | .symbol sym => sym.name
  | .operator .add => "+"
  | .operator .minus => "-"
  | .operator .le => "<="
  | .operator .equal => "="
  | .operator .not => "not"
  | .operator .and => "and"
  | .operator .implies => "=>"
  | .operator .ite => "ite"
  | .operator .transaction => "ccf_tx"
  | .operator .reconfiguration => "ccf_cfg"
  | .operator .retiredCommitted => "ccf_retired"
  | .operator .entry => "ccf_entry"
  | .operator .entryTerm => "ccf_term"
  | .operator .entryContent => "ccf_content"

-- This renderer accepts no raw user strings. No text-parser roundtrip is claimed.
def SExpr.render : SExpr -> String
  | .atom a => a.render
  | .list values => "(" ++ String.intercalate " " (values.map SExpr.render) ++ ")"

def Term.render {ty : Ty} (term : Term ty) : String := term.lower.render

theorem uf_aliasing (assignment : Assignment) (domain result : Ty) (id : Nat)
    (a b : Term domain) (same : a.eval assignment = b.eval assignment) :
    (Term.app domain result id a).lower.eval assignment =
      (Term.app domain result id b).lower.eval assignment := by
  rw [lower_correct, lower_correct]
  simp only [Term.eval, same]

theorem negative_count_regression (assignment : Assignment) :
    (Term.sub (.integer 0) (.integer 1)).lower.eval assignment = some (.integer (-1)) /\
    (Term.le (.integer 0) (.sub (.integer 0) (.integer 1))).lower.eval assignment =
      some (.boolean false) := by
  simp [lower_correct, Term.eval, embed]

theorem alias_regression (assignment : Assignment) :
    (Term.equal
      (.app .int .int 7 (.add (.integer 1) (.integer 2)))
      (.app .int .int 7 (.integer 3))).lower.eval assignment = some (.boolean true) := by
  simp [lower_correct, Term.eval, embed]

theorem constant_function_name_separation (ty domain result : Ty) (i j : Nat) :
    Not ((Symbol.constant ty i).name = (Symbol.unary domain result j).name) := by
  intro h
  cases symbol_name_injective h

theorem function_signature_names (d r d' r' : Ty) (i j : Nat) :
    (Symbol.unary d r i).name = (Symbol.unary d' r' j).name <->
      d = d' /\ r = r' /\ i = j := by
  constructor
  next =>
    intro h
    simpa using symbol_name_injective h
  next =>
    intro h
    simp only [h.1, h.2.1, h.2.2]

theorem ill_typed_regression (assignment : Assignment) :
    (call (.operator .add) [.atom (.boolean true), .atom (.numeral 1)]).eval assignment = none /\
    (call (.operator .ite)
      [.atom (.boolean true), .atom (.numeral 1), .atom (.boolean false)]).eval assignment = none /\
    (call (.symbol (.unary .int .bool 0)) [.atom (.boolean true)]).eval assignment = none := by
  simp [call, SExpr.eval, applyHead, Value.asType]

theorem signed_text_regression :
    (Term.sub (.integer (-2)) (.integer 3)).render = "(- (- 2) 3)" := by
  change (Term.sub (.integer (Int.negSucc 1)) (.integer 3)).render = _
  simp [Term.render, Term.lower, signedLiteral, call, SExpr.render, Atom.render]
  decide

theorem typed_function_text_regression :
    (Term.app .bool .int 5 (.boolean false)).render = "(fbi_101 false)" := by
  simp [Term.render, Term.lower, call, SExpr.render, Atom.render]
  decide +kernel

end CCFRaft.Sparse.Smt

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.Smt |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit SMT IR axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no SMT IR declarations audited"
  Lean.logInfo m!"Sparse.Smt: {checked} declarations passed the allowed-axiom gate."
