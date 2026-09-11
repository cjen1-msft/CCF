-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Mathlib

set_option autoImplicit false

namespace CCFRaft.NativeSExpr

-- Generated unquoted S-expressions only, not the full SMT-LIB lexical grammar.
inductive Expr where
  | atom (text : String)
  | list (items : List Expr)
  deriving Repr

def Expr.render : Expr -> String
  | .atom text => text
  | .list items => "(" ++ String.intercalate " " (items.map Expr.render) ++ ")"

def whitespace (char : Char) : Bool :=
  char == ' ' || char == '\t' || char == '\n' || char == '\r'

def delimiter (char : Char) : Bool := whitespace char || char == '(' || char == ')'

def SafeAtom (text : String) : Prop :=
  text.toList ≠ [] /\ forall char, char ∈ text.toList -> delimiter char = false

instance (text : String) : Decidable (SafeAtom text) :=
  decidable_of_iff (text.toList ≠ [] /\ text.toList.all (fun char => !delimiter char) = true)
    (by simp [SafeAtom, List.all_eq_true])

def Expr.Safe : Expr -> Prop
  | .atom text => SafeAtom text
  | .list items => forall item, item ∈ items -> item.Safe

inductive Token where
  | openParen
  | closeParen
  | atom (text : String)
  deriving Repr, DecidableEq

def nextToken (input : List Char) : Option (Token × List Char) :=
  match input.dropWhile whitespace with
  | [] => none
  | '(' :: rest => some (.openParen, rest)
  | ')' :: rest => some (.closeParen, rest)
  | char :: rest =>
    some (.atom (String.ofList (char :: rest.takeWhile (fun next => !delimiter next))),
      rest.dropWhile (fun next => !delimiter next))

theorem nextToken_consumes {input rest : List Char} {token : Token}
    (parsed : nextToken input = some (token, rest)) : rest.length < input.length := by
  have bound := (List.dropWhile_sublist (l := input) whitespace).length_le
  cases trimmed : input.dropWhile whitespace with
  | nil => simp [nextToken, trimmed] at parsed
  | cons char tail =>
    rw [trimmed] at bound
    by_cases opening : char = '('
    · subst char
      have pair : (Token.openParen, tail) = (token, rest) := by
        simpa [nextToken, trimmed] using parsed
      have same := congrArg Prod.snd pair
      change tail = rest at same
      rw [same] at bound
      simp only [List.length_cons] at bound
      omega
    · by_cases closing : char = ')'
      · subst char
        have pair : (Token.closeParen, tail) = (token, rest) := by
          simpa [nextToken, trimmed] using parsed
        have same := congrArg Prod.snd pair
        change tail = rest at same
        rw [same] at bound
        simp only [List.length_cons] at bound
        omega
      · have pair :
            (.atom (String.ofList (char :: tail.takeWhile (fun next => !delimiter next))),
              tail.dropWhile (fun next => !delimiter next)) = (token, rest) := by
          simpa [nextToken, trimmed, opening, closing] using parsed
        have same := congrArg Prod.snd pair
        change tail.dropWhile (fun next => !delimiter next) = rest at same
        have tailBound := (List.dropWhile_sublist (l := tail) (fun next => !delimiter next)).length_le
        rw [same] at tailBound
        simp only [List.length_cons] at bound
        omega

def parseStack (input : List Char) (frames : List (List Expr)) : Option (Expr × List Char) :=
  match _found : nextToken input with
  | none => none
  | some (.openParen, rest) => parseStack rest ([] :: frames)
  | some (.atom text, rest) =>
    match frames with
    | [] => none
    | frame :: parents => parseStack rest ((.atom text :: frame) :: parents)
  | some (.closeParen, rest) =>
    match frames with
    | [] => none
    | [frame] => some (.list frame.reverse, rest)
    | frame :: parent :: parents => parseStack rest ((.list frame.reverse :: parent) :: parents)
termination_by input.length
decreasing_by all_goals exact nextToken_consumes _found

def parseOne (input : List Char) : Option (Expr × List Char) :=
  match nextToken input with
  | some (.atom text, rest) => some (.atom text, rest)
  | some (.openParen, rest) => parseStack rest [[]]
  | _ => none

def parse (text : String) : Option Expr := do
  let (expression, rest) <- parseOne text.toList
  if rest.dropWhile whitespace = [] then some expression else none

def Boundary : List Char -> Prop
  | [] => True
  | char :: _ => delimiter char = true

private theorem boundary_scans (rest : List Char) (boundary : Boundary rest) :
    rest.takeWhile (fun char => !delimiter char) = [] /\
      rest.dropWhile (fun char => !delimiter char) = rest := by
  cases rest with
  | nil => exact ⟨rfl, rfl⟩
  | cons char tail =>
    change delimiter char = true at boundary
    simp [List.takeWhile, List.dropWhile, boundary]

private theorem scan_atom_append (word rest : List Char)
    (safe : forall char, char ∈ word -> delimiter char = false) (boundary : Boundary rest) :
    (word ++ rest).takeWhile (fun char => !delimiter char) = word /\
      (word ++ rest).dropWhile (fun char => !delimiter char) = rest := by
  have good : forall char, char ∈ word -> Bool.not (delimiter char) = true := by
    intro char member
    simp [safe char member]
  rw [List.takeWhile_append_of_pos good, List.dropWhile_append_of_pos good]
  rw [(boundary_scans rest boundary).1, (boundary_scans rest boundary).2, List.append_nil]
  exact ⟨rfl, rfl⟩

theorem nextToken_atom (text : String) (safe : SafeAtom text)
    (rest : List Char) (boundary : Boundary rest) :
    nextToken (text.toList ++ rest) = some (.atom text, rest) := by
  cases chars : text.toList with
  | nil => exact False.elim (safe.1 chars)
  | cons char word =>
    have safeChars := safe.2
    rw [chars] at safeChars
    have head : whitespace char = false /\ char ≠ '(' /\ char ≠ ')' := by
      simpa [delimiter, Bool.or_eq_false_iff, and_assoc] using safeChars char (by simp)
    have scans := scan_atom_append word rest (fun next member => safeChars next (by simp [member])) boundary
    have original : String.ofList (char :: word) = text := by
      rw [<- chars, String.ofList_toList]
    simp [nextToken, head.1, head.2.1, head.2.2, scans.1, scans.2, original]

private def renderedItems : List Expr -> List Char
  | [] => []
  | expression :: rest =>
    expression.render.toList ++ rest.flatMap (fun item => ' ' :: item.render.toList)

private theorem intercalate_cons_chars (texts : List String) (acc : String) :
    (String.intercalate " " (acc :: texts)).toList =
      acc.toList ++ texts.flatMap (fun text => ' ' :: text.toList) := by
  induction texts generalizing acc with
  | nil =>
    simp only [List.flatMap_nil, List.append_nil]
    rfl
  | cons text rest ih =>
    change (String.intercalate " " ((acc ++ " " ++ text) :: rest)).toList = _
    rw [ih]
    simp [String.toList_append, List.append_assoc, show " ".toList = [' '] from rfl]

private theorem list_render_chars (items : List Expr) :
    (Expr.list items).render.toList = '(' :: (renderedItems items ++ [')']) := by
  cases items with
  | nil =>
    simp [Expr.render, String.intercalate, renderedItems]
    decide +kernel
  | cons expression rest =>
    simp [Expr.render, String.toList_append, intercalate_cons_chars, renderedItems, List.flatMap_map,
      show "(".toList = ['('] from rfl, show ")".toList = [')'] from rfl]

private theorem renderedItems_cons_cons (first second : Expr) (rest : List Expr) :
    renderedItems (first :: second :: rest) =
      first.render.toList ++ ' ' :: renderedItems (second :: rest) := by
  simp [renderedItems]

private theorem nextToken_space (input : List Char) : nextToken (' ' :: input) = nextToken input := by
  simp [nextToken, whitespace]

private theorem parseStack_space (input : List Char) (frames : List (List Expr)) :
    parseStack (' ' :: input) frames = parseStack input frames := by
  conv_lhs => rw [parseStack]
  conv_rhs => rw [parseStack]
  rw [nextToken_space]

private theorem nextToken_open (rest : List Char) : nextToken ('(' :: rest) = some (.openParen, rest) := by
  simp [nextToken, whitespace]

private theorem nextToken_close (rest : List Char) : nextToken (')' :: rest) = some (.closeParen, rest) := by
  simp [nextToken, whitespace]

mutual
  private theorem stack_render_expression (expression : Expr) (safe : expression.Safe) (frame : List Expr)
      (parents : List (List Expr)) (rest : List Char) (boundary : Boundary rest) :
      parseStack (expression.render.toList ++ rest) (frame :: parents) =
        parseStack rest ((expression :: frame) :: parents) := by
    cases expression with
    | atom text =>
      simp only [Expr.Safe] at safe
      simp only [Expr.render]
      conv_lhs => rw [parseStack]
      rw [nextToken_atom text safe rest boundary]
    | list items =>
      simp only [Expr.Safe] at safe
      rw [list_render_chars]
      simp only [List.cons_append, List.append_assoc]
      conv_lhs => rw [parseStack]
      rw [nextToken_open]
      change parseStack (renderedItems items ++ ')' :: rest) ([] :: frame :: parents) = _
      rw [stack_render_items items safe [] (frame :: parents) (')' :: rest) (by rfl)]
      simp only [List.append_nil]
      conv_lhs => rw [parseStack]
      rw [nextToken_close]
      simp only [List.reverse_reverse]
  termination_by sizeOf expression
  decreasing_by
    all_goals
      subst_vars
      simp_wf

  private theorem stack_render_items (items : List Expr) (safe : forall item, item ∈ items -> item.Safe)
      (frame : List Expr) (parents : List (List Expr)) (rest : List Char) (boundary : Boundary rest) :
      parseStack (renderedItems items ++ rest) (frame :: parents) =
        parseStack rest ((items.reverse ++ frame) :: parents) := by
    cases items with
    | nil => simp [renderedItems]
    | cons expression tail =>
      have firstSafe := safe expression (by simp)
      cases tail with
      | nil =>
        simpa [renderedItems] using stack_render_expression expression firstSafe frame parents rest boundary
      | cons head tail =>
        rw [renderedItems_cons_cons]
        simp only [List.append_assoc, List.cons_append]
        rw [stack_render_expression expression firstSafe frame parents
          (' ' :: (renderedItems (head :: tail) ++ rest)) (by rfl)]
        rw [parseStack_space, stack_render_items (head :: tail)
          (fun item member => safe item (by simp [member])) (expression :: frame) parents rest boundary]
        simp [List.reverse_cons, List.append_assoc]
  termination_by sizeOf items
  decreasing_by
    all_goals
      subst_vars
      simp_wf <;> omega
end

theorem parseOne_render (expression : Expr) (safe : expression.Safe)
    (rest : List Char) (boundary : Boundary rest) :
    parseOne (expression.render.toList ++ rest) = some (expression, rest) := by
  cases expression with
  | atom text =>
    simp only [Expr.Safe] at safe
    simp only [Expr.render, parseOne, nextToken_atom text safe rest boundary]
  | list items =>
    simp only [Expr.Safe] at safe
    rw [list_render_chars]
    simp only [List.cons_append, List.nil_append, List.append_assoc, parseOne, nextToken_open]
    rw [stack_render_items items safe [] [] (')' :: rest) (by rfl)]
    simp only [List.append_nil]
    rw [parseStack, nextToken_close]
    simp only [List.reverse_reverse]

theorem parse_render (expression : Expr) (safe : expression.Safe) :
    parse expression.render = some expression := by
  have complete := parseOne_render expression safe [] (by trivial)
  simp only [List.append_nil] at complete
  unfold parse
  rw [complete]
  rfl

example : (match parse " \t(native_pair 12\n(native_left true)) " with
    | some (.list [.atom "native_pair", .atom "12", .list [.atom "native_left", .atom "true"]]) => true
    | _ => false) = true := by decide +kernel

example : (match parse "(())" with | some (.list [.list []]) => true | _ => false) = true := by decide +kernel
example : ((parse "").isNone && (parse "(").isNone && (parse ")").isNone &&
    (parse "(true) false").isNone && (parse "((true)").isNone) = true := by decide +kernel

end CCFRaft.NativeSExpr

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSExpr).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
