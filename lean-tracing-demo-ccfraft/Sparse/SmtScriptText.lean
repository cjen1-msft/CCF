import Sparse.SmtScript
import Sparse.SmtExpressionText

-- Exact emitted command format: one command per LF-terminated line.
-- This is not a general SMT-LIB command parser or a solver correctness theorem.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtScriptText

open Smt SmtScript
open SmtExpressionText (nextToken parseOne nextToken_render_atom parseOne_render Boundary)

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

private def NoLF (chars : List Char) : Prop :=
  forall c, c IN chars -> Not (c = '\n')

private instance (chars : List Char) : Decidable (NoLF chars) := by
  exact decidable_of_iff (chars.all (fun c => c != '\n') = true)
    (by simp [NoLF, List.all_eq_true])

private theorem noLF_append (left right : List Char) (hl : NoLF left) (hr : NoLF right) :
    NoLF (left ++ right) := by
  intro c hc
  rcases List.mem_append.mp hc with h | h
  next => exact hl c h
  next => exact hr c h

private theorem noLF_string_append (left right : String)
    (hl : NoLF left.toList) (hr : NoLF right.toList) : NoLF (left ++ right).toList := by
  rw [String.toList_append]
  exact noLF_append _ _ hl hr

private theorem noLF_intercalate_cons (texts : List String) (acc : String)
    (ha : NoLF acc.toList) (hs : forall text, text IN texts -> NoLF text.toList) :
    NoLF (String.intercalate " " (acc :: texts)).toList := by
  induction texts generalizing acc with
  | nil => exact ha
  | cons text rest ih =>
    change NoLF (String.intercalate " " ((acc ++ " " ++ text) :: rest)).toList
    apply ih
    next =>
      apply noLF_string_append
      next => exact noLF_string_append _ _ ha (by decide +kernel)
      next => exact hs text (by simp)
    next => intro t ht; exact hs t (by simp [ht])

private theorem noLF_intercalate (texts : List String)
    (hs : forall text, text IN texts -> NoLF text.toList) :
    NoLF (String.intercalate " " texts).toList := by
  cases texts with
  | nil => simp [String.intercalate, NoLF]
  | cons text rest =>
    exact noLF_intercalate_cons rest text (hs text (by simp))
      (fun t ht => hs t (by simp [ht]))

mutual
  private theorem expression_noLF (expression : SExpr) : NoLF expression.render.toList := by
    cases expression with
    | atom value =>
      rw [SExpr.render]
      intro c hc same
      have safe := SmtExpressionText.atom_render_safe value c hc
      subst c
      cases safe
    | list items =>
      rw [SExpr.render]
      apply noLF_string_append
      next =>
        apply noLF_string_append
        next => decide +kernel
        next =>
          apply noLF_intercalate
          intro text ht
          cases List.mem_map.mp ht with
          | intro item hi =>
            rw [<- hi.2]
            exact expressions_noLF items item hi.1
      next => decide +kernel
  termination_by sizeOf expression
  decreasing_by all_goals simp_wf

  private theorem expressions_noLF (items : List SExpr) :
      forall item, item IN items -> NoLF item.render.toList := by
    cases items with
    | nil => simp
    | cons item rest =>
      intro e he
      rcases List.mem_cons.mp he with same | later
      next => subst e; exact expression_noLF item
      next => exact expressions_noLF rest e later
  termination_by sizeOf items
  decreasing_by all_goals simp_wf <;> omega
end

private theorem type_noLF (ty : Ty) : NoLF ty.render.toList := by
  cases ty <;> decide +kernel

private theorem name_noLF (sym : Symbol) : NoLF sym.name.toList := by
  intro c hc same
  have safe := SmtExpressionText.atom_render_safe (.symbol sym) c hc
  subst c
  cases safe

private theorem command_noLF (command : Command) : NoLF command.render.toList := by
  cases command with
  | setLogic => decide +kernel
  | setNativeLogic => decide +kernel
  | declareSchema schema => cases schema <;> decide +kernel
  | checkSat => decide +kernel
  | assertion expression =>
    simp only [Command.render]
    apply noLF_string_append
    next => exact noLF_string_append _ _ (by decide +kernel) (expression_noLF expression)
    next => decide +kernel
  | declare declaration =>
    simp only [Command.render, Declaration.render]
    have arguments : NoLF (String.intercalate " " (declaration.arguments.map Ty.render)).toList := by
      apply noLF_intercalate
      intro text ht
      cases List.mem_map.mp ht with
      | intro ty hty => rw [<- hty.2]; exact type_noLF ty
    have h1 := noLF_string_append "(declare-fun " declaration.symbol.name
      (by decide +kernel) (name_noLF _)
    have h2 := noLF_string_append _ " (" h1 (by decide +kernel)
    have h3 := noLF_string_append _ _ h2 arguments
    have h4 := noLF_string_append _ ") " h3 (by decide +kernel)
    have h5 := noLF_string_append _ _ h4 (type_noLF declaration.result)
    exact noLF_string_append _ ")" h5 (by decide +kernel)

private def signatureChars (arguments : List Ty) (result : Ty) : List Char :=
  [' ', '('] ++ (String.intercalate " " (arguments.map Ty.render)).toList ++
    [')', ' '] ++ result.render.toList ++ [')']

private def parseType : List Char -> Option (Prod Ty (List Char))
  | 'B' :: 'o' :: 'o' :: 'l' :: rest => some (.bool, rest)
  | 'I' :: 'n' :: 't' :: rest => some (.int, rest)
  | '(' :: '_' :: ' ' :: 'B' :: 'i' :: 't' :: 'V' :: 'e' :: 'c' :: ' ' :: '1' :: '5' :: ')' :: rest =>
    some (.nodes, rest)
  | 'C' :: 'C' :: 'F' :: 'C' :: 'o' :: 'n' :: 't' :: 'e' :: 'n' :: 't' :: rest =>
    some (.content, rest)
  | 'C' :: 'C' :: 'F' :: 'E' :: 'n' :: 't' :: 'r' :: 'y' :: rest => some (.entry, rest)
  | _ => none

private def parseArguments : List Char -> Option (Prod (List Ty) (List Char))
  | ')' :: rest => some ([], rest)
  | input => do
    let (ty, rest) <- parseType input
    match rest with
    | ')' :: tail => some ([ty], tail)
    | _ => none

private def parseSignature : List Char -> Option (Prod (List Ty) Ty)
  | ' ' :: '(' :: input => do
    let (arguments, tail) <- parseArguments input
    match tail with
    | ' ' :: resultText => do
      let (result, rest) <- parseType resultText
      if rest = [')'] then some (arguments, result) else none
    | _ => none
  | _ => none

-- Parse the signature as written, not inferred from the name. run checks agreement.
def parseLine : List Char -> Option Command
  | ['(', 's', 'e', 't', '-', 'l', 'o', 'g', 'i', 'c', ' ', 'Q', 'F', '_', 'U', 'F', 'L', 'I', 'A', ')'] =>
    some .setLogic
  | ['(', 's', 'e', 't', '-', 'l', 'o', 'g', 'i', 'c', ' ', 'A', 'L', 'L', ')'] =>
    some .setNativeLogic
  | ['(', 'c', 'h', 'e', 'c', 'k', '-', 's', 'a', 't', ')'] => some .checkSat
  | '(' :: 'a' :: 's' :: 's' :: 'e' :: 'r' :: 't' :: ' ' :: body => do
    let (expression, rest) <- parseOne body
    if rest = [')'] then some (.assertion expression) else none
  | '(' :: 'd' :: 'e' :: 'c' :: 'l' :: 'a' :: 'r' :: 'e' :: '-' :: 'f' :: 'u' :: 'n' :: ' ' :: body => do
    let (token, rest) <- nextToken body
    match token with
    | .atom (.symbol sym) => do
      let (arguments, result) <- parseSignature rest
      pure (.declare { symbol := sym, arguments, result })
    | _ => none
  | '(' :: 'd' :: 'e' :: 'c' :: 'l' :: 'a' :: 'r' :: 'e' :: '-' :: 'd' :: 'a' :: 't' :: 'a' ::
      't' :: 'y' :: 'p' :: 'e' :: ' ' :: body =>
    if body = Schema.content.body.toList then some (.declareSchema .content)
    else if body = Schema.entry.body.toList then some (.declareSchema .entry)
    else none
  | _ => none

private theorem declaration_chars (declaration : Declaration) :
    declaration.render.toList =
      "(declare-fun ".toList ++ declaration.symbol.name.toList ++
        signatureChars declaration.arguments declaration.result := by
  simp [Declaration.render, signatureChars, String.toList_append, List.append_assoc,
    show " (".toList = [' ', '('] from rfl, show ") ".toList = [')', ' '] from rfl,
    show ")".toList = [')'] from rfl]

private theorem signature_roundtrip (sym : Symbol) :
    parseSignature (signatureChars (symbolDomain sym) (symbolResult sym)) =
      some (symbolDomain sym, symbolResult sym) := by
  cases sym with
  | constant ty id =>
    cases ty <;> simp only [symbolDomain, symbolResult] <;> decide +kernel
  | unary domain result id =>
    cases domain <;> cases result <;> simp only [symbolDomain, symbolResult] <;> decide +kernel

private theorem valid_eq_ofSymbol (declaration : Declaration) (valid : declaration.Valid) :
    declaration = Declaration.ofSymbol declaration.symbol := by
  cases declaration with
  | mk sym arguments result =>
    have args := valid.1
    have res := valid.2
    simp only at args res
    subst arguments
    subst result
    rfl

def Generated : Command -> Prop
  | .declare declaration => declaration.Valid
  | _ => True

theorem parseLine_render (command : Command) (generated : Generated command) :
    parseLine command.render.toList = some command := by
  cases command with
  | setLogic => rfl
  | setNativeLogic => rfl
  | declareSchema schema =>
    have different : Not (Schema.entry.body.toList = Schema.content.body.toList) := by decide +kernel
    cases schema <;>
      simp only [Command.render, Schema.render, String.toList_append,
        show "(declare-datatype ".toList =
          ['(', 'd', 'e', 'c', 'l', 'a', 'r', 'e', '-', 'd', 'a', 't', 'a', 't', 'y', 'p', 'e', ' '] from rfl,
        List.cons_append, List.nil_append, parseLine, ite_true, if_neg different]
  | checkSat => rfl
  | assertion expression =>
    have chars : (Command.assertion expression).render.toList =
        "(assert ".toList ++ expression.render.toList ++ [')'] := by
      simp [Command.render, String.toList_append, show ")".toList = [')'] from rfl]
    rw [chars]
    change (do
      let (e, rest) <- parseOne (expression.render.toList ++ [')'])
      if rest = [')'] then some (Command.assertion e) else none) = _
    rw [parseOne_render expression [')'] (by rfl)]
    rfl
  | declare declaration =>
    have equal := valid_eq_ofSymbol declaration generated
    rw [equal]
    simp only [Command.render, declaration_chars, Declaration.ofSymbol]
    have token := nextToken_render_atom (.symbol declaration.symbol)
      (signatureChars (symbolDomain declaration.symbol) (symbolResult declaration.symbol)) (by rfl)
    change nextToken (declaration.symbol.name.toList ++
      signatureChars (symbolDomain declaration.symbol) (symbolResult declaration.symbol)) =
        some (.atom (.symbol declaration.symbol),
          signatureChars (symbolDomain declaration.symbol) (symbolResult declaration.symbol)) at token
    change (do
      let (tok, rest) <- nextToken (declaration.symbol.name.toList ++
        signatureChars (symbolDomain declaration.symbol) (symbolResult declaration.symbol))
      match tok with
      | .atom (.symbol sym) => do
        let (arguments, result) <- parseSignature rest
        pure (Command.declare { symbol := sym, arguments, result })
      | _ => none) = _
    rw [token]
    simp [signature_roundtrip]

-- A missing final LF and blank lines are outside the emitted format.
def splitLines : List Char -> List Char -> Option (List (List Char))
  | [], reversed => if reversed = [] then some [] else none
  | c :: rest, reversed =>
    if c = '\n' then (splitLines rest []).map (fun lines => reversed.reverse :: lines)
    else splitLines rest (c :: reversed)

private theorem splitLines_prefix (word rest reversed : List Char) (safe : NoLF word) :
    splitLines (word ++ rest) reversed = splitLines rest (word.reverse ++ reversed) := by
  induction word generalizing reversed with
  | nil => simp
  | cons c word ih =>
    have hc := safe c (by simp)
    have tail : NoLF word := fun x hx => safe x (by simp [hx])
    simp [splitLines, hc, ih _ tail, List.reverse_cons, List.append_assoc]

private theorem splitLines_line (word rest : List Char) (safe : NoLF word) :
    splitLines (word ++ '\n' :: rest) [] =
      (splitLines rest []).map (fun lines => word :: lines) := by
  rw [splitLines_prefix word _ [] safe]
  simp [splitLines]

private theorem splitLines_join (lines : List (List Char))
    (safe : forall line, line IN lines -> NoLF line) :
    splitLines (lines.flatMap (fun line => line ++ ['\n'])) [] = some lines := by
  induction lines with
  | nil => simp [splitLines]
  | cons line rest ih =>
    have tail : forall l, l IN rest -> NoLF l := fun l hl => safe l (by simp [hl])
    simp only [List.flatMap_cons, List.append_assoc, List.cons_append, List.nil_append]
    rw [splitLines_line line _ (safe line (by simp)), ih tail]
    rfl

private theorem intercalate_lines (texts : List String) (acc : String) :
    (String.intercalate "\n" (acc :: texts) ++ "\n").toList =
      acc.toList ++ '\n' :: texts.flatMap (fun text => text.toList ++ ['\n']) := by
  induction texts generalizing acc with
  | nil =>
    change (acc ++ "\n").toList = _
    simp [String.toList_append, show "\n".toList = ['\n'] from rfl]
  | cons text rest ih =>
    change (String.intercalate "\n" ((acc ++ "\n" ++ text) :: rest) ++ "\n").toList = _
    rw [ih]
    simp [String.toList_append, List.append_assoc, show "\n".toList = ['\n'] from rfl]

private theorem renderCommands_chars (head : Command) (tail : List Command) :
    (renderCommands (head :: tail)).toList =
      (head :: tail).flatMap (fun command => command.render.toList ++ ['\n']) := by
  simp only [renderCommands, List.map_cons]
  rw [intercalate_lines]
  simp [List.flatMap_map, List.append_assoc]

private def bodyShape : List Command -> Bool
  | [.checkSat] => true
  | .declare _ :: rest | .assertion _ :: rest | .declareSchema _ :: rest => bodyShape rest
  | _ => false

def scriptShape : List Command -> Bool
  | .setLogic :: rest | .setNativeLogic :: rest => bodyShape rest
  | _ => false

-- All lines are parsed. Shape validation rejects second scripts and trailing commands.
def parse (text : String) : Option (List Command) := do
  let lines <- splitLines text.toList []
  let commands <- lines.mapM parseLine
  if scriptShape commands then some commands else none

private theorem parse_rendered_lines (commands : List Command)
    (generated : forall command, command IN commands -> Generated command) :
    (commands.map (fun command => command.render.toList)).mapM parseLine = some commands := by
  induction commands with
  | nil => rfl
  | cons command rest ih =>
    have tail : forall c, c IN rest -> Generated c := fun c hc => generated c (by simp [hc])
    simp [parseLine_render command (generated command (by simp)), ih tail]

theorem parse_renderCommands (commands : List Command)
    (generated : forall command, command IN commands -> Generated command)
    (shape : scriptShape commands = true) :
    parse (renderCommands commands) = some commands := by
  cases commands with
  | nil => simp [scriptShape] at shape
  | cons command rest =>
    have split : splitLines (renderCommands (command :: rest)).toList [] =
        some ((command :: rest).map (fun c => c.render.toList)) := by
      rw [renderCommands_chars]
      have safe : forall line, line IN (command :: rest).map (fun c => c.render.toList) -> NoLF line := by
        intro line hl
        cases List.mem_map.mp hl with
        | intro c hc => rw [<- hc.2]; exact command_noLF c
      simpa [List.flatMap_map, Function.comp_def] using splitLines_join _ safe
    unfold parse
    rw [split]
    change (do
      let commands : List Command <-
        ((command :: rest).map (fun c : Command => c.render.toList)).mapM parseLine
      if scriptShape commands then some commands else none) = _
    rw [parse_rendered_lines _ generated]
    simp [shape]

private theorem bodyShape_declarations (decls : List Declaration) (rest : List Command) :
    bodyShape (decls.map Command.declare ++ rest) = bodyShape rest := by
  induction decls with
  | nil => simp
  | cons declaration tail ih => simpa [bodyShape] using ih

private theorem bodyShape_assertions (formula : Formula) (rest : List Command) :
    bodyShape (formula.map (fun term => Command.assertion term.lower) ++ rest) = bodyShape rest := by
  induction formula with
  | nil => simp
  | cons term tail ih => simpa [bodyShape] using ih

theorem compiled_shape (formula : Formula) : scriptShape (compile formula) = true := by
  unfold compile prelude
  split
  next =>
    simp [compiledBody, scriptShape, List.append_assoc, bodyShape_declarations,
      bodyShape_assertions, bodyShape]
  next =>
    split
    next =>
      simp [compiledBody, scriptShape, List.append_assoc, bodyShape_declarations,
        bodyShape_assertions, bodyShape]
    next =>
      split <;>
        simp [compiledBody, scriptShape, List.append_assoc, bodyShape_declarations,
          bodyShape_assertions, bodyShape]

private theorem prelude_generated (formula : Formula) :
    forall command, command IN prelude formula -> Generated command := by
  unfold prelude
  split
  next => simp [Generated]
  next =>
    split
    next => simp [Generated]
    next => split <;> simp [Generated]

theorem compiled_generated (formula : Formula) :
    forall command, command IN compile formula -> Generated command := by
  intro command hc
  simp only [compile, compiledBody, List.mem_append, List.mem_cons,
    List.not_mem_nil, or_false, or_assoc] at hc
  rcases hc with first | declaration | assertion | last
  next => exact prelude_generated formula command first
  next =>
    cases List.mem_map.mp declaration with
    | intro d hd =>
      rw [<- hd.2]
      exact (declarations_wellFormed formula).1 d hd.1
  next =>
    cases List.mem_map.mp assertion with
    | intro term ht => rw [<- ht.2]; trivial
  next => subst command; trivial

theorem parse_render (formula : Formula) : parse (render formula) = some (compile formula) :=
  parse_renderCommands (compile formula) (compiled_generated formula) (compiled_shape formula)

def runText (assignment : Assignment) (text : String) : Option Bool :=
  (parse text).bind (SmtScript.run assignment)

theorem runText_renderCommands (assignment : Assignment) (commands : List Command)
    (generated : forall command, command IN commands -> Generated command)
    (shape : scriptShape commands = true) :
    runText assignment (renderCommands commands) = SmtScript.run assignment commands := by
  simp [runText, parse_renderCommands commands generated shape]

theorem runText_render (assignment : Assignment) (formula : Formula) :
    runText assignment (render formula) = SmtScript.run assignment (compile formula) := by
  simp [runText, parse_render]

theorem formula_text_iff (assignment : Assignment) (formula : Formula) :
    SmtScript.Holds assignment formula <-> runText assignment (render formula) = some true := by
  rw [runText_render]
  exact SmtScript.formula_holds_iff assignment formula

theorem fixture_regression :
    (parse (render repeatedFormula)).map List.length = some 6 /\
    (parse (render mixedSignatureFormula)).map List.length = some 14 := by
  simp only [parse_render]
  decide +kernel

theorem empty_regression (assignment : Assignment) :
    runText assignment "(set-logic QF_UFLIA)\n(check-sat)\n" = some true := by
  have text := (SmtScript.empty_formula_regression assignment).2.2
  rw [<- text, runText_render]
  exact (SmtScript.empty_formula_regression assignment).2.1

theorem signed_regression (assignment : Assignment) :
    runText assignment
      "(set-logic QF_UFLIA)\n(assert (= (- (- 2) 3) (- 5)))\n(check-sat)\n" = some true := by
  rw [<- SmtScript.signed_script_text_regression, runText_render]
  exact (SmtScript.signed_formula_regression assignment).2

theorem signature_fields_regression :
    (match parse "(set-logic QF_UFLIA)\n(declare-fun fbi_ (Int) Int)\n(check-sat)\n" with
     | some [.setLogic, .declare declaration, .checkSat] =>
       decide (declaration.symbol = .unary .bool .int 0 /\
         declaration.arguments = [.int] /\ declaration.result = .int)
     | _ => false) = true := by
  decide +kernel

theorem mismatched_signature_regression (assignment : Assignment) :
    runText assignment
      "(set-logic QF_UFLIA)\n(declare-fun fbi_ (Int) Int)\n(check-sat)\n" = none := by
  rfl

theorem missing_declaration_regression (assignment : Assignment) :
    runText assignment "(set-logic QF_UFLIA)\n(assert cb__)\n(check-sat)\n" = none := by
  have text : renderCommands
      [.setLogic, .assertion (.atom (.symbol (.constant .bool 0))), .checkSat] =
      "(set-logic QF_UFLIA)\n(assert cb__)\n(check-sat)\n" := by
    simp only [renderCommands, List.map_cons, List.map_nil, Command.render,
      SExpr.render, Atom.render]
    decide +kernel
  rw [<- text, runText_renderCommands _ _ (by simp [Generated]) (by rfl)]
  exact SmtScript.missing_declaration_regression assignment

theorem duplicate_declaration_regression (assignment : Assignment) :
    runText assignment
      "(set-logic QF_UFLIA)\n(declare-fun ci__ () Int)\n(declare-fun ci__ () Int)\n(check-sat)\n" =
      none := by
  rfl

theorem assertion_error_regression (assignment : Assignment) :
    runText assignment (renderCommands
      [.setLogic, .assertion (.list [.atom (.operator .add), .atom (.numeral 1)]),
       .checkSat]) = none /\
    runText assignment (renderCommands
      [.setLogic, .assertion (.list
        [.atom (.operator .add), .atom (.boolean true), .atom (.numeral 1)]),
       .checkSat]) = none := by
  constructor
  all_goals
    rw [runText_renderCommands _ _ (by simp [Generated]) (by rfl)]
    simp [run, schemaCheck, runBody, Covered, exprSymbols, SExpr.eval, applyHead]

theorem rejected_scripts_regression :
    (parse "").isNone = true /\
    (parse "(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_LIA)\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(check-sat)").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(check-sat)\n\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(check-sat)\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(check-sat)\n(assert true)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(check-sat)\n(set-logic QF_UFLIA)\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(get-model)\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(assert true false)\n(check-sat)\n").isNone = true /\
    (parse "(set-logic QF_UFLIA)\n(declare-fun fii_ (Int Int) Int)\n(check-sat)\n").isNone = true := by
  decide +kernel

theorem false_assertion_regression (assignment : Assignment) :
    runText assignment (render [.boolean false]) = some false := by
  rw [runText_render, compile_eval]
  rfl

end CCFRaft.Sparse.SmtScriptText

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.SmtScriptText |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit script-text axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no script-text declarations audited"
  Lean.logInfo m!"Sparse.SmtScriptText: {checked} declarations passed the allowed-axiom gate."
  for theoremName in [
      ``CCFRaft.Sparse.SmtScriptText.parseLine_render,
      ``CCFRaft.Sparse.SmtScriptText.parse_render,
      ``CCFRaft.Sparse.SmtScriptText.formula_text_iff] do
    let axioms <- Lean.collectAxioms theoremName
    Lean.logInfo m!"{theoremName}: {axioms}"
