-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.LedgerSuiteTerms

open Lean NativeEncode NativeSmt

abbrev Width : PNat := ⟨2, by decide⟩
abbrev Ledger : Ty := .array .int (entryTy Width)

def parameter (name : String) (ty : Ty) (id : Nat) : Json := Json.mkObj [
  ("name", toJson name), ("sort", toJson ty.render),
  ("symbol", toJson ((.free ty id : Expr ty).render))]

def definition {ty : Ty} (name : String) (params : List Json) (body : Expr ty) : Json :=
  Json.mkObj [("name", toJson name), ("params", toJson params),
    ("result", toJson ty.render), ("body", toJson body.render)]

def definitions : List Json :=
  let left : Expr Ledger := .free _ 100
  let right : Expr Ledger := .free _ 101
  let payload : Expr Ledger := .free _ 102
  let oldLength : Expr .int := .free _ 103
  let payloadLength : Expr .int := .free _ 104
  let previous : Expr .int := .free _ 105
  let value : Expr (entryTy Width) := .free _ 106
  let term : Expr .int := .free _ 107
  let tx : Expr .int := .free _ 108
  let bits : Expr (.bits Width) := .free _ 109
  [
    definition "entry_valid" [parameter "arg_value" (entryTy Width) 106] (entryDomain value),
    definition "live_valid" [parameter "arg_array" Ledger 100, parameter "arg_length" .int 103]
      (boundedForall oldLength (entryDomain (.select (left.weaken .int) (.bound .here)))),
    definition "live_equal" [
      parameter "arg_left" Ledger 100, parameter "arg_right" Ledger 101,
      parameter "arg_length" .int 103]
      (boundedForall oldLength (.equal
        (.select (left.weaken .int) (.bound .here))
        (.select (right.weaken .int) (.bound .here)))),
    definition "splice" [
      parameter "arg_old" Ledger 100, parameter "arg_old_length" .int 103,
      parameter "arg_payload" Ledger 102, parameter "arg_payload_length" .int 104,
      parameter "arg_previous" .int 105, parameter "arg_output" Ledger 101]
      (logSpliceTerm Width oldLength left payloadLength payload previous right),
    definition "make_transaction" [parameter "arg_term" .int 107, parameter "arg_tx" .int 108]
      (.pair term (.inr (.inl tx)) : Expr (entryTy Width)),
    definition "make_signature" [parameter "arg_term" .int 107]
      (.pair term (.inl .unit) : Expr (entryTy Width)),
    definition "make_configuration" [parameter "arg_term" .int 107, parameter "arg_members" (.bits Width) 109]
      (.pair term (.inr (.inr (.inl bits))) : Expr (entryTy Width)),
    definition "make_retirement" [parameter "arg_term" .int 107, parameter "arg_members" (.bits Width) 109]
      (.pair term (.inr (.inr (.inr bits))) : Expr (entryTy Width))
  ]

end CCFRaft.LedgerSuiteTerms

def main : IO Unit := do
  IO.println (Lean.Json.mkObj [
    ("header", Lean.toJson (CCFRaft.NativeSmt.renderScript [])),
    ("entrySort", Lean.toJson (CCFRaft.NativeEncode.entryTy CCFRaft.LedgerSuiteTerms.Width).render),
    ("definitions", Lean.toJson CCFRaft.LedgerSuiteTerms.definitions)]).compress
