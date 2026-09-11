-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeScriptSyntax

set_option autoImplicit false

namespace CCFRaft.NativeSExpr

private theorem intercalate_chars (separator : String) (texts : List String) (acc : String) :
    (String.intercalate separator (acc :: texts)).toList =
      acc.toList ++ texts.flatMap (fun text => separator.toList ++ text.toList) := by
  induction texts generalizing acc with
  | nil =>
    simp only [List.flatMap_nil, List.append_nil]
    rfl
  | cons text rest ih =>
    change (String.intercalate separator ((acc ++ separator ++ text) :: rest)).toList = _
    rw [ih]
    simp [String.toList_append, List.append_assoc]

private theorem intercalate_lists (separator head : List Char) (tail : List (List Char)) :
    separator.intercalate (head :: tail) =
      head ++ tail.flatMap (fun item => separator ++ item) := by
  induction tail generalizing head with
  | nil => simp [List.intercalate, List.intersperse]
  | cons item rest ih =>
    change head ++ (separator ++ separator.intercalate (item :: rest)) = _
    rw [ih]
    simp [List.append_assoc]

private theorem intercalate_noLF (texts : List String)
    (safe : forall text, text ∈ texts -> '\n' ∉ text.toList) :
    '\n' ∉ (String.intercalate " " texts).toList := by
  cases texts with
  | nil => simp [String.intercalate]
  | cons text rest =>
    rw [intercalate_chars]
    simp only [List.mem_append, not_or]
    refine ⟨safe text (by simp), ?_⟩
    intro member
    obtain ⟨item, present, bad⟩ := List.mem_flatMap.mp member
    have excluded := safe item (by simp [present])
    simpa [show " ".toList = [' '] from rfl, excluded] using bad

theorem Expr.render_noLF (expression : Expr) (safe : expression.Safe) :
    '\n' ∉ expression.render.toList := by
  match expression with
  | .atom text =>
    simp only [Expr.Safe] at safe
    simp only [Expr.render]
    intro member
    have bad := safe.2 '\n' member
    simp [delimiter, whitespace] at bad
  | .list items =>
    simp only [Expr.Safe] at safe
    simp only [Expr.render, String.toList_append, List.mem_append, not_or]
    refine ⟨⟨by decide +kernel, intercalate_noLF _ ?_⟩, by decide +kernel⟩
    intro text member
    obtain ⟨item, present, same⟩ := List.mem_map.mp member
    subst text
    exact item.render_noLF (safe item present)
termination_by sizeOf expression
decreasing_by
  have smaller := List.sizeOf_lt_of_mem present
  simp_wf
  omega

def renderLines (commands : List Expr) : String :=
  String.intercalate "\n" (commands.map Expr.render ++ [""])

-- The generated script format has one command per line and a final LF.
def parseLines (text : String) : Option (List Expr) := do
  let [] :: reversed := (text.toList.splitOn '\n').reverse | none
  reversed.reverse.mapM (fun line => parse (String.ofList line))

private theorem rendered_lines_chars (commands : List Expr) :
    (renderLines commands).toList =
      ['\n'].intercalate (commands.map (fun command => command.render.toList) ++ [[]]) := by
  cases commands with
  | nil => rfl
  | cons command rest =>
    simp only [renderLines, List.map_cons, List.cons_append]
    rw [intercalate_chars, intercalate_lists]
    simp [List.flatMap_map, List.flatMap_append, show "\n".toList = ['\n'] from rfl]

private theorem parse_rendered_lines (commands : List Expr)
    (safe : forall command, command ∈ commands -> command.Safe) :
    (commands.map (fun command => command.render.toList)).mapM
      (fun line => parse (String.ofList line)) = some commands := by
  induction commands with
  | nil => rfl
  | cons command rest ih =>
    simp [parse_render command (safe command (by simp)),
      ih (fun item member => safe item (by simp [member]))]

theorem parse_renderLines (commands : List Expr)
    (safe : forall command, command ∈ commands -> command.Safe) :
    parseLines (renderLines commands) = some commands := by
  have noLF : forall line, line ∈ commands.map (fun command => command.render.toList) ++ [[]] ->
      '\n' ∉ line := by
    intro line member
    simp only [List.mem_append, List.mem_map, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with ⟨command, member, same⟩ | empty
    · subst line
      exact command.render_noLF (safe command member)
    · subst line
      simp
  rw [parseLines, rendered_lines_chars, List.splitOn_intercalate _ '\n' noLF (by simp)]
  simp only [List.reverse_append, List.reverse_cons, List.reverse_nil, List.nil_append,
    List.cons_append, List.reverse_reverse]
  exact parse_rendered_lines commands safe

example : parseLines "(check-sat)" = none := by decide +kernel
example : parseLines "(check-sat)\n\n" = none := by decide +kernel
example : parseLines "(assert true false)\nextra)\n" = none := by decide +kernel

end CCFRaft.NativeSExpr

namespace CCFRaft.NativeSmt

theorem script_text_parses (assertions : List (Term [] .bool)) (named : Bool) :
    NativeSExpr.parseLines (renderScript assertions named) = some (scriptSyntax assertions named) :=
  NativeSExpr.parse_renderLines _ (script_syntax_safe assertions named)

end CCFRaft.NativeSmt

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeSmt).isPrefixOf name || (`CCFRaft.NativeSExpr).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
