-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeSyntaxProofs

set_option autoImplicit false

namespace CCFRaft.NativeSmt

open Sparse.SmtNumerals (parseNumeral)

def Ty.depth : Ty -> Nat
  | .bool | .int | .unit | .bits _ => 1
  | .array first second | .pair first second | .sum first second =>
    max first.depth second.depth + 1

def parseTypeCode : Nat -> List Char -> Option (Ty × List Char)
  | 0, _ => none
  | _ + 1, 'B' :: rest => some (.bool, rest)
  | _ + 1, 'I' :: rest => some (.int, rest)
  | _ + 1, 'U' :: rest => some (.unit, rest)
  | _ + 1, 'V' :: rest => do
    let digits := rest.takeWhile (fun char => char != '_')
    let '_' :: suffix := rest.dropWhile (fun char => char != '_') | none
    let width <- parseNumeral (String.ofList digits)
    if positive : 0 < width then some (.bits ⟨width, positive⟩, suffix) else none
  | fuel + 1, 'A' :: rest => do
    let (key, rest) <- parseTypeCode fuel rest
    let (value, rest) <- parseTypeCode fuel rest
    return (.array key value, rest)
  | fuel + 1, 'P' :: rest => do
    let (first, rest) <- parseTypeCode fuel rest
    let (second, rest) <- parseTypeCode fuel rest
    return (.pair first second, rest)
  | fuel + 1, 'S' :: rest => do
    let (left, rest) <- parseTypeCode fuel rest
    let (right, rest) <- parseTypeCode fuel rest
    return (.sum left right, rest)
  | _, _ => none

private theorem digit_not_separator (digit : Nat) (within : digit < 10) :
    Nat.digitChar digit ≠ '_' := by
  interval_cases digit <;> decide +kernel

private theorem digits_not_separator (fuel value : Nat) (suffix : List Char)
    (safe : forall char, char ∈ suffix -> char ≠ '_') :
    forall char, char ∈ Nat.toDigitsCore 10 fuel value suffix -> char ≠ '_' := by
  induction fuel generalizing value suffix with
  | zero => exact safe
  | succ fuel ih =>
    have extended : forall char, char ∈ Nat.digitChar (value % 10) :: suffix -> char ≠ '_' := by
      intro char member
      rcases List.mem_cons.mp member with rfl | previous
      · exact digit_not_separator _ (Nat.mod_lt _ (by decide))
      · exact safe char previous
    simp only [Nat.toDigitsCore]
    split
    · exact extended
    · exact ih _ _ extended

theorem numeral_not_separator (value : Nat) :
    forall char, char ∈ (toString value).toList -> char ≠ '_' := by
  change forall char, char ∈ (Nat.repr value).toList -> char ≠ '_'
  rw [Nat.repr, String.toList_ofList]
  exact digits_not_separator (value + 1) value [] (by simp)

private theorem numeral_scans (value : Nat) (suffix : List Char) :
    ((toString value).toList ++ '_' :: suffix).takeWhile (fun char => char != '_') =
        (toString value).toList /\
      ((toString value).toList ++ '_' :: suffix).dropWhile (fun char => char != '_') = '_' :: suffix := by
  have good : forall char, char ∈ (toString value).toList -> (char != '_') = true := by
    intro char member
    simp [numeral_not_separator value char member]
  rw [List.takeWhile_append_of_pos good, List.dropWhile_append_of_pos good]
  simp

theorem Ty.depth_positive (sort : Ty) : 0 < sort.depth := by
  cases sort <;> simp [Ty.depth]

theorem Ty.depth_le_code (sort : Ty) : sort.depth <= sort.code.toList.length := by
  induction sort with
  | bool | int | unit => decide +kernel
  | bits width =>
    simp only [Ty.depth, Ty.code, String.toList_append, List.length_append]
    change 1 <= 1 + ((toString width.val).toList.length + 1)
    omega
  | array first second left right | pair first second left right | sum first second left right =>
    simp only [Ty.depth, Ty.code, String.toList_append, List.length_append]
    simp only [show "A".toList.length = 1 from rfl, show "P".toList.length = 1 from rfl,
      show "S".toList.length = 1 from rfl]
    omega

theorem parse_type_prefix (sort : Ty) (suffix : List Char) (fuel : Nat) (enough : sort.depth <= fuel) :
    parseTypeCode fuel (sort.code.toList ++ suffix) = some (sort, suffix) := by
  induction fuel generalizing sort suffix with
  | zero => have positive := sort.depth_positive; omega
  | succ fuel ih =>
    cases sort with
    | bool | int | unit => rfl
    | bits width =>
      have scans := numeral_scans width.val suffix
      have numeral : parseNumeral (toString width.val) = some width.val :=
        Sparse.SmtNumerals.parseNumeral_render width.val
      simp only [Ty.code, String.toList_append, List.append_assoc]
      change parseTypeCode (fuel + 1) ('V' :: ((toString width.val).toList ++ '_' :: suffix)) = _
      simp [parseTypeCode, scans.1, scans.2, numeral]
      apply Subtype.ext
      rfl
    | array first second | pair first second | sum first second =>
      have firstBound : first.depth <= fuel := by simp only [Ty.depth] at enough; omega
      have secondBound : second.depth <= fuel := by simp only [Ty.depth] at enough; omega
      simp only [Ty.code, String.toList_append, List.append_assoc]
      first
      | change parseTypeCode (fuel + 1) ('A' :: (first.code.toList ++ (second.code.toList ++ suffix))) = _
      | change parseTypeCode (fuel + 1) ('P' :: (first.code.toList ++ (second.code.toList ++ suffix))) = _
      | change parseTypeCode (fuel + 1) ('S' :: (first.code.toList ++ (second.code.toList ++ suffix))) = _
      simp [parseTypeCode, ih first (second.code.toList ++ suffix) firstBound, ih second suffix secondBound]

def parseSymbol (text : String) : Option (Ty × Nat) := do
  let 'c' :: '_' :: input := text.toList | none
  let (sort, rest) <- parseTypeCode input.length input
  let '_' :: digits := rest | none
  let id <- parseNumeral (String.ofList digits)
  if symbolName sort id = text then some (sort, id) else none

theorem parse_symbol_name (sort : Ty) (id : Nat) :
    parseSymbol (symbolName sort id) = some (sort, id) := by
  have enough : sort.depth <= (sort.code.toList ++ '_' :: (toString id).toList).length := by
    have bound := sort.depth_le_code
    simp only [List.length_append, List.length_cons] at *
    omega
  have numeral : parseNumeral (toString id) = some id := Sparse.SmtNumerals.parseNumeral_render id
  simp only [parseSymbol, symbolName, String.toList_append, List.append_assoc]
  change (do
    let (ty, rest) <- parseTypeCode (sort.code.toList ++ '_' :: (toString id).toList).length
      (sort.code.toList ++ '_' :: (toString id).toList)
    let '_' :: digits := rest | none
    let number <- parseNumeral (String.ofList digits)
    if symbolName ty number = symbolName sort id then some (ty, number) else none) = _
  rw [parse_type_prefix sort _ _ enough]
  simp [numeral]

theorem symbolName_injective {left right : Ty} {first second : Nat}
    (same : symbolName left first = symbolName right second) : left = right /\ first = second := by
  have parsed := congrArg parseSymbol same
  rw [parse_symbol_name, parse_symbol_name] at parsed
  exact Prod.mk.inj (Option.some.inj parsed)

def parseBinder (text : String) : Option Nat := do
  let 'b' :: digits := text.toList | none
  parseNumeral (String.ofList digits)

theorem parse_binder_name (level : Nat) : parseBinder (binderName level) = some level := by
  have numeral : parseNumeral (toString level) = some level := Sparse.SmtNumerals.parseNumeral_render level
  simp only [parseBinder, binderName, String.toList_append]
  change parseNumeral (String.ofList (toString level).toList) = some level
  simpa using numeral

theorem binderName_injective {left right : Nat} (same : binderName left = binderName right) : left = right := by
  have parsed := congrArg parseBinder same
  rw [parse_binder_name, parse_binder_name] at parsed
  exact Option.some.inj parsed

theorem symbol_ne_binder (sort : Ty) (id level : Nat) : symbolName sort id ≠ binderName level := by
  intro same
  have head := congrArg (fun text : String => text.toList.head?) same
  simp only [symbolName, binderName, String.toList_append] at head
  change some 'c' = some 'b' at head
  contradiction

theorem Variable.level_lt {context : List Ty} {sort : Ty} (ref : Variable context sort) :
    ref.level < context.length := by
  have within := ref.index_lt
  simp only [Variable.level]
  omega

@[simp] theorem Variable.level_here {context : List Ty} {sort : Ty} :
    (Variable.here : Variable (sort :: context) sort).level = context.length := by
  simp [Variable.level, Variable.index]

@[simp] theorem Variable.level_there {context : List Ty} {sort other : Ty} (ref : Variable context sort) :
    (Variable.there (other := other) ref).level = ref.level := by
  simp [Variable.level, Variable.index]

abbrev Value := Sigma Ty.denote
abbrev NamedLocals := Nat -> Option Value

def NamedLocals.Rep {context : List Ty} (environment : NamedLocals) (locals : Locals context) : Prop :=
  forall sort (ref : Variable context sort), environment ref.level = some ⟨sort, locals sort ref⟩

theorem NamedLocals.empty (environment : NamedLocals) : environment.Rep Locals.empty :=
  fun _ ref => nomatch ref

theorem NamedLocals.Rep.cons {context : List Ty} {environment : NamedLocals} {locals : Locals context}
    (rep : environment.Rep locals) (sort : Ty) (value : sort.denote) :
    NamedLocals.Rep (Function.update environment context.length (some ⟨sort, value⟩)) (locals.cons value) := by
  intro ty ref
  cases ref with
  | here => simp [Variable.level, Variable.index, Locals.cons]
  | there previous =>
    have different : previous.level ≠ context.length := Nat.ne_of_lt previous.level_lt
    simpa [Locals.cons, different] using rep ty previous

example : parseSymbol "c_AIPIV130__17" = some (.array .int (.pair .int (.bits ⟨130, by decide⟩)), 17) := by
  decide +kernel

example : ((parseSymbol "c_V0__1").isNone && (parseSymbol "c_I_01").isNone &&
    (parseSymbol "c_AI_1").isNone && (parseBinder "bv1").isNone) = true := by
  decide +kernel

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
