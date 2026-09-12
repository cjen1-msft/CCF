-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeNames

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open NativeSExpr (Expr)
open Sparse.SmtNumerals (parseNumeral)

def parseSort : Expr -> Option Ty
  | .atom "Bool" => some .bool
  | .atom "Int" => some .int
  | .atom "NativeUnit" => some .unit
  | .list [.atom "_", .atom "BitVec", .atom text] => do
    let width <- parseNumeral text
    if positive : 0 < width then some (.bits ⟨width, positive⟩) else none
  | .list [.atom "Array", key, value] => do
    return .array (<- parseSort key) (<- parseSort value)
  | .list [.atom "NativePair", first, second] => do
    return .pair (<- parseSort first) (<- parseSort second)
  | .list [.atom "NativeSum", first, second] => do
    return .sum (<- parseSort first) (<- parseSort second)
  | _ => none

theorem parse_sort_syntax (sort : Ty) : parseSort sort.syntax = some sort := by
  induction sort with
  | bool | int | unit => simp [Ty.syntax, parseSort]
  | bits width =>
    rcases width with ⟨width, positive⟩
    have numeral : parseNumeral (toString width) = some width := Sparse.SmtNumerals.parseNumeral_render width
    simp [Ty.syntax, parseSort, numeral, positive]
  | array first second left right | pair first second left right | sum first second left right =>
    simp [Ty.syntax, parseSort, left, right]

def Value.asType : Value -> (sort : Ty) -> Option sort.denote
  | ⟨actual, value⟩, expected =>
    if same : actual = expected then some (same ▸ value) else none

@[simp] theorem Value.asType_mk (sort : Ty) (value : sort.denote) :
    Value.asType ⟨sort, value⟩ sort = some value := by
  simp [Value.asType]

attribute [local instance] Classical.propDecidable

noncomputable def applyOperator (operator : String) (values : List Value) : Option Value :=
  match operator with
  | "+" =>
    match values with
    | [⟨.int, left⟩, ⟨.int, right⟩] => some ⟨.int, left + right⟩
    | _ => none
  | "-" =>
    match values with
    | [⟨.int, value⟩] => some ⟨.int, -value⟩
    | [⟨.int, left⟩, ⟨.int, right⟩] => some ⟨.int, left - right⟩
    | _ => none
  | "<=" =>
    match values with
    | [⟨.int, left⟩, ⟨.int, right⟩] => some ⟨.bool, decide (left <= right)⟩
    | _ => none
  | "=" =>
    match values with
    | [⟨sort, left⟩, right] => do
      let right <- right.asType sort
      return ⟨.bool, decide (left = right)⟩
    | _ => none
  | "not" =>
    match values with
    | [⟨.bool, value⟩] => some ⟨.bool, !value⟩
    | _ => none
  | "and" =>
    match values with
    | [⟨.bool, left⟩, ⟨.bool, right⟩] => some ⟨.bool, left && right⟩
    | _ => none
  | "or" =>
    match values with
    | [⟨.bool, left⟩, ⟨.bool, right⟩] => some ⟨.bool, left || right⟩
    | _ => none
  | "ite" =>
    match values with
    | [⟨.bool, condition⟩, ⟨sort, yes⟩, no] => do
      let no <- no.asType sort
      return ⟨sort, if condition then yes else no⟩
    | _ => none
  | "native_pair" =>
    match values with
    | [⟨first, left⟩, ⟨second, right⟩] => some ⟨.pair first second, (left, right)⟩
    | _ => none
  | "native_fst" =>
    match values with
    | [⟨.pair first _, value⟩] => some ⟨first, value.1⟩
    | _ => none
  | "native_snd" =>
    match values with
    | [⟨.pair _ second, value⟩] => some ⟨second, value.2⟩
    | _ => none
  | "select" =>
    match values with
    | [⟨.array key value, array⟩, index] => do
      let index <- index.asType key
      return ⟨value, array index⟩
    | _ => none
  | "store" =>
    match values with
    | [⟨.array key value, array⟩, index, element] => do
      let index <- index.asType key
      let element <- element.asType value
      return ⟨.array key value, Function.update array index element⟩
    | _ => none
  | "bvand" =>
    match values with
    | [⟨.bits width, left⟩, right] => do
      let right <- right.asType (.bits width)
      return ⟨.bits width, left &&& right⟩
    | _ => none
  | "bvor" =>
    match values with
    | [⟨.bits width, left⟩, right] => do
      let right <- right.asType (.bits width)
      return ⟨.bits width, left ||| right⟩
    | _ => none
  | "bvnot" =>
    match values with
    | [⟨.bits width, value⟩] => some ⟨.bits width, ~~~value⟩
    | _ => none
  | _ => none

def applyConstructor : String -> Ty -> Value -> Option Value
  | "const", .array key element, value => do
    let value <- value.asType element
    return ⟨.array key element, fun _ => value⟩
  | "native_left", .sum first second, value => do
    let value <- value.asType first
    return ⟨.sum first second, Sum.inl value⟩
  | "native_right", .sum first second, value => do
    let value <- value.asType second
    return ⟨.sum first second, Sum.inr value⟩
  | _, _, _ => none

def extractSingle (index : Nat) : Value -> Option Value
  | ⟨.bits width, value⟩ =>
    if index < width.val then some ⟨.bits ⟨1, by decide⟩, BitVec.ofBool (value.getLsbD index)⟩ else none
  | _ => none

theorem one_bit_decision (value : Bool) [Decidable (BitVec.ofBool value = 1#1)] :
    decide (BitVec.ofBool value = 1#1) = value := by
  cases value <;> simp [BitVec.ofBool]

def evalAtom (assignment : Assignment) (environment : NamedLocals) (text : String) : Option Value :=
  match parseNumeral text with
  | some value => some ⟨.int, value⟩
  | none =>
    match parseSymbol text with
    | some (sort, id) => some ⟨sort, assignment sort id⟩
    | none =>
      match parseBinder text with
      | some level => environment level
      | none =>
        match text with
        | "true" => some ⟨.bool, true⟩
        | "false" => some ⟨.bool, false⟩
        | "native_unit" => some ⟨.unit, ()⟩
        | "#b1" => some ⟨.bits ⟨1, by decide⟩, 1⟩
        | _ => none

def parseBitWord (text : String) : Option Nat := do
  let 'b' :: 'v' :: digits := text.toList | none
  parseNumeral (String.ofList digits)

def evalBitLiteral (word widthText : String) : Option Value := do
  let value <- parseBitWord word
  let width <- parseNumeral widthText
  if positive : 0 < width then some ⟨.bits ⟨width, positive⟩, BitVec.ofNat width value⟩ else none

noncomputable def evalForall (sort : Ty) (body : sort.denote -> Option Value) : Option Value :=
  if _typed : forall value, exists result : Bool, body value = some ⟨.bool, result⟩ then
    some ⟨.bool, decide (forall value, body value = some ⟨.bool, true⟩)⟩
  else none

noncomputable def evalMatch (first second : Ty) (value : (Ty.sum first second).denote)
    (left : first.denote -> Option Value) (right : second.denote -> Option Value) : Option Value := do
  let result <- match value with
    | .inl argument => left argument
    | .inr argument => right argument
  if _typed :
      (forall argument, exists output : result.1.denote, left argument = some ⟨result.1, output⟩) /\
      (forall argument, exists output : result.1.denote, right argument = some ⟨result.1, output⟩) then
    some result
  else none

theorem eval_match_values (first second result : Ty) (value : (Ty.sum first second).denote)
    (left : first.denote -> result.denote) (right : second.denote -> result.denote) :
    evalMatch first second value (fun argument => some ⟨result, left argument⟩)
      (fun argument => some ⟨result, right argument⟩) =
        some ⟨result, match value with | .inl argument => left argument | .inr argument => right argument⟩ := by
  cases value <;> simp [evalMatch]

mutual
  noncomputable def evalSyntax (assignment : Assignment) (environment : NamedLocals) (expression : Expr) :
      Option Value :=
    match expression with
    | .atom text => evalAtom assignment environment text
    | .list (.atom operator :: arguments) =>
      match operator with
      | "_" =>
        match arguments with
        | [.atom word, .atom width] => evalBitLiteral word width
        | _ => none
      | "forall" =>
        match arguments with
        | [.list [.list [.atom name, sortExpression]], body] => do
          let sort <- parseSort sortExpression
          let level <- parseBinder name
          evalForall sort fun value =>
            evalSyntax assignment (Function.update environment level (some ⟨sort, value⟩)) body
        | _ => none
      | "match" =>
        match arguments with
        | [argument, .list [
            .list [.list [.atom "native_left", .atom leftName], leftBody],
            .list [.list [.atom "native_right", .atom rightName], rightBody]]] => do
          let ⟨.sum first second, value⟩ <- evalSyntax assignment environment argument | none
          let leftLevel <- parseBinder leftName
          let rightLevel <- parseBinder rightName
          evalMatch first second value
            (fun item => evalSyntax assignment (Function.update environment leftLevel (some ⟨first, item⟩)) leftBody)
            (fun item => evalSyntax assignment (Function.update environment rightLevel (some ⟨second, item⟩)) rightBody)
        | _ => none
      | _ => do
        applyOperator operator (<- evalArguments assignment environment arguments)
    | .list [.list [.atom "_", .atom "extract", .atom highText, .atom lowText], argument] => do
      let high <- parseNumeral highText
      let low <- parseNumeral lowText
      if high = low then extractSingle low (<- evalSyntax assignment environment argument) else none
    | .list [.list [.atom "as", .atom constructor, sortExpression], argument] => do
      let sort <- parseSort sortExpression
      applyConstructor constructor sort (<- evalSyntax assignment environment argument)
    | _ => none
  termination_by sizeOf expression
  decreasing_by
    all_goals
      simp_wf
      omega

  noncomputable def evalArguments (assignment : Assignment) (environment : NamedLocals) :
      List Expr -> Option (List Value)
    | [] => some []
    | argument :: rest => do
      let value <- evalSyntax assignment environment argument
      let values <- evalArguments assignment environment rest
      return value :: values
  termination_by arguments => sizeOf arguments
  decreasing_by all_goals simp_wf <;> omega
end

theorem eval_application (assignment : Assignment) (environment : NamedLocals)
    (operator : String) (arguments : List Expr)
    (notIndexed : operator ≠ "_") (notForall : operator ≠ "forall") (notMatch : operator ≠ "match") :
    evalSyntax assignment environment (.list (.atom operator :: arguments)) =
      (evalArguments assignment environment arguments).bind (applyOperator operator) := by
  rw [evalSyntax] <;> first | rfl | assumption

noncomputable def evalText (assignment : Assignment) (environment : NamedLocals) (text : String) :
    Option Value :=
  (NativeSExpr.parse text).bind (evalSyntax assignment environment)

example : applyOperator "+" [⟨.int, 3⟩, ⟨.bool, true⟩] = none := by simp [applyOperator]
example : applyOperator "ite" [⟨.bool, true⟩, ⟨.int, 3⟩, ⟨.bool, false⟩] = none := by
  simp [applyOperator, Value.asType]
example : applyOperator "native_fst" [⟨.int, 3⟩] = none := by simp [applyOperator]
example : extractSingle 3 ⟨.bits ⟨3, by decide⟩, 7⟩ = none := by decide +kernel

example : evalForall .int (fun _ => some ⟨.int, 3⟩) = none := by
  simp [evalForall]

example : evalMatch .int .bool (.inl 3) (fun _ => some ⟨.int, 7⟩)
    (fun _ => some ⟨.bool, true⟩) = none := by
  simp [evalMatch]

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
