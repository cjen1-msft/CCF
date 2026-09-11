import Sparse.SmtText
import Sparse.SmtNumerals

-- Full existing SExpr grammar, not command/script syntax. Typing stays in SExpr.eval.
set_option autoImplicit false

namespace CCFRaft.Sparse.SmtExpressionText

open Smt SmtText SmtNumerals

local notation:50 x:51 " IN " xs:51 => Membership.mem xs x

private def parseFixed : List Char -> Option Atom
  | ['t', 'r', 'u', 'e'] => some (.boolean true)
  | ['f', 'a', 'l', 's', 'e'] => some (.boolean false)
  | ['+'] => some (.operator .add)
  | ['-'] => some (.operator .minus)
  | ['<', '='] => some (.operator .le)
  | ['='] => some (.operator .equal)
  | ['n', 'o', 't'] => some (.operator .not)
  | ['a', 'n', 'd'] => some (.operator .and)
  | ['=', '>'] => some (.operator .implies)
  | ['i', 't', 'e'] => some (.operator .ite)
  | _ => none

def parseAtom (text : String) : Option Atom :=
  match parseFixed text.toList with
  | some value => some value
  | none =>
    match parseSymbol text with
    | some sym => some (.symbol sym)
    | none => (parseNumeral text).map Atom.numeral

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

private theorem numeral_head_core (fuel n : Nat) (suffix : List Char) (enough : n < fuel) :
    exists d rest, d < 10 /\ Nat.toDigitsCore 10 fuel n suffix = Nat.digitChar d :: rest := by
  induction fuel generalizing n suffix with
  | zero => omega
  | succ fuel ih =>
    simp only [Nat.toDigitsCore]
    by_cases last : n / 10 = 0
    next =>
      rw [if_pos last]
      exact Exists.intro (n % 10) (Exists.intro suffix (And.intro (Nat.mod_lt _ (by decide)) rfl))
    next =>
      rw [if_neg last]
      have smaller : n / 10 < n := Nat.div_lt_self (by omega) (by decide)
      exact ih _ _ (by omega)

private theorem numeral_head (n : Nat) :
    exists d rest, d < 10 /\ (Atom.numeral n).render.toList = Nat.digitChar d :: rest := by
  change exists d rest, d < 10 /\ (Nat.repr n).toList = Nat.digitChar d :: rest
  rw [Nat.repr, String.toList_ofList]
  exact numeral_head_core (n + 1) n [] (by omega)

private theorem decimal_not_fixed (d : Nat) (hd : d < 10) (rest : List Char) :
    parseFixed (Nat.digitChar d :: rest) = none := by
  interval_cases d <;> rfl

private theorem decimal_not_symbol (d : Nat) (hd : d < 10) (rest : List Char) :
    parseSymbol (String.ofList (Nat.digitChar d :: rest)) = none := by
  unfold parseSymbol
  rw [String.toList_ofList]
  interval_cases d <;> rfl

theorem parseAtom_render (atom : Atom) : parseAtom atom.render = some atom := by
  cases atom with
  | boolean b => cases b <;> decide +kernel
  | operator op => cases op <;> decide +kernel
  | symbol sym =>
    have fixed : parseFixed sym.name.toList = none := by
      rw [actual_name_chars]
      cases sym with
      | constant ty id => cases ty <;> rfl
      | unary domain result id => cases domain <;> cases result <;> rfl
    simp [parseAtom, Atom.render, fixed, parseSymbol_name]
  | numeral n =>
    cases numeral_head n with
    | intro d hd =>
      cases hd with
      | intro rest hr =>
        have text : (Atom.numeral n).render = String.ofList (Nat.digitChar d :: rest) := by
          rw [<- hr.2, String.ofList_toList]
        have noSymbol : parseSymbol (Atom.numeral n).render = none := by
          rw [text]
          exact decimal_not_symbol d hr.1 rest
        simp [parseAtom, hr.2, decimal_not_fixed d hr.1 rest, noSymbol, parseNumeral_render]

def whitespace (c : Char) : Bool :=
  c == ' ' || c == '\t' || c == '\n' || c == '\r'

def delimiter (c : Char) : Bool := whitespace c || c == '(' || c == ')'

def Safe (chars : List Char) : Prop :=
  forall c, c IN chars -> delimiter c = false

instance (chars : List Char) : Decidable (Safe chars) := by
  exact decidable_of_iff (chars.all (fun c => !delimiter c) = true)
    (by simp [Safe, List.all_eq_true])

private theorem safe_append (left right : List Char) (hl : Safe left) (hr : Safe right) :
    Safe (left ++ right) := by
  intro c hc
  rcases List.mem_append.mp hc with h | h
  next => exact hl c h
  next => exact hr c h

private theorem digit_safe (d : Nat) (hd : d < 10) : delimiter (Nat.digitChar d) = false := by
  interval_cases d <;> rfl

private theorem digits_safe (fuel n : Nat) (suffix : List Char) (safe : Safe suffix) :
    Safe (Nat.toDigitsCore 10 fuel n suffix) := by
  induction fuel generalizing n suffix with
  | zero => exact safe
  | succ fuel ih =>
    have extended : Safe (Nat.digitChar (n % 10) :: suffix) := by
      intro c hc
      rcases List.mem_cons.mp hc with same | old
      next => subst c; exact digit_safe _ (Nat.mod_lt _ (by decide))
      next => exact safe c old
    simp only [Nat.toDigitsCore]
    split
    next => exact extended
    next => exact ih _ _ extended

theorem atom_render_safe (atom : Atom) : Safe atom.render.toList := by
  cases atom with
  | boolean b => cases b <;> decide +kernel
  | operator op => cases op <;> decide +kernel
  | numeral n =>
    change Safe (Nat.repr n).toList
    rw [Nat.repr, String.toList_ofList]
    exact digits_safe (n + 1) n [] (by simp [Safe])
  | symbol sym =>
    change Safe sym.name.toList
    rw [actual_name_chars]
    have bits : forall b, delimiter (bitChar b) = false := by
      intro b
      cases b <;> rfl
    have suffixSafe : forall id : Nat, Safe (id.bits.map bitChar) := by
      intro id c hc
      cases List.mem_map.mp hc with
      | intro b hb =>
        rw [<- hb.2]
        exact bits b
    cases sym with
    | constant ty id =>
      apply safe_append
      next => cases ty <;> decide +kernel
      next => exact suffixSafe id
    | unary domain result id =>
      apply safe_append
      next => cases domain <;> cases result <;> decide +kernel
      next => exact suffixSafe id

theorem atom_render_nonempty (atom : Atom) : Not (atom.render.toList = []) := by
  intro empty
  have text : atom.render = "" := String.toList_injective (by simpa using empty)
  have parsed := parseAtom_render atom
  rw [text] at parsed
  have invalid : parseAtom "" = none := by decide +kernel
  rw [invalid] at parsed
  cases parsed

inductive Token where
  | openParen
  | closeParen
  | atom (value : Atom)
  deriving DecidableEq, Repr

-- One token and its unconsumed character suffix. Library scans recurse on input tails.
def nextToken (input : List Char) : Option (Prod Token (List Char)) :=
  match input.dropWhile whitespace with
  | [] => none
  | '(' :: rest => some (.openParen, rest)
  | ')' :: rest => some (.closeParen, rest)
  | c :: rest => do
    let value <- parseAtom (String.ofList (c :: rest.takeWhile (fun x => !(delimiter x))))
    pure (.atom value, rest.dropWhile (fun x => !(delimiter x)))

def Boundary : List Char -> Prop
  | [] => True
  | c :: _ => delimiter c = true

private theorem boundary_scans (rest : List Char) (hb : Boundary rest) :
    rest.takeWhile (fun c => !(delimiter c)) = [] /\
    rest.dropWhile (fun c => !(delimiter c)) = rest := by
  cases rest with
  | nil => exact And.intro rfl rfl
  | cons c cs =>
    change delimiter c = true at hb
    simp [List.takeWhile, List.dropWhile, hb]

private theorem scan_safe_append (word rest : List Char) (safe : Safe word) (hb : Boundary rest) :
    (word ++ rest).takeWhile (fun c => !(delimiter c)) = word /\
    (word ++ rest).dropWhile (fun c => !(delimiter c)) = rest := by
  have good : forall c, c IN word -> Bool.not (delimiter c) = true := by
    intro c hc
    simp [safe c hc]
  rw [List.takeWhile_append_of_pos good, List.dropWhile_append_of_pos good]
  rw [(boundary_scans rest hb).1, (boundary_scans rest hb).2, List.append_nil]
  exact And.intro rfl rfl

private theorem delimiter_false (c : Char) :
    delimiter c = false <->
      whitespace c = false /\ Not (c = '(') /\ Not (c = ')') := by
  simp [delimiter, Bool.or_eq_false_iff, and_assoc]

theorem nextToken_render_atom (atom : Atom) (rest : List Char) (hb : Boundary rest) :
    nextToken (atom.render.toList ++ rest) = some (.atom atom, rest) := by
  have safe := atom_render_safe atom
  cases chars : atom.render.toList with
  | nil => exact False.elim (atom_render_nonempty atom chars)
  | cons c word =>
    rw [chars] at safe
    have head := (delimiter_false c).mp (safe c (by simp))
    have tailSafe : Safe word := fun x hx => safe x (by simp [hx])
    have scans := scan_safe_append word rest tailSafe hb
    have original : String.ofList (c :: word) = atom.render := by
      rw [<- chars, String.ofList_toList]
    simp [nextToken, head.1, head.2.1, head.2.2,
      scans.1, scans.2, original, parseAtom_render]

theorem nextToken_consumes {input rest : List Char} {token : Token}
    (parsed : nextToken input = some (token, rest)) : rest.length < input.length := by
  have bound := (List.dropWhile_sublist (l := input) whitespace).length_le
  cases trimmed : input.dropWhile whitespace with
  | nil => simp [nextToken, trimmed] at parsed
  | cons c tail =>
    rw [trimmed] at bound
    by_cases opening : c = '('
    next =>
      subst c
      have pair : (Token.openParen, tail) = (token, rest) :=
        Option.some.inj (by simpa [nextToken, trimmed] using parsed)
      have same := congrArg Prod.snd pair
      simp only at same
      rw [same] at bound
      simpa using Nat.lt_of_lt_of_le (Nat.lt_succ_self rest.length) bound
    next =>
      by_cases closing : c = ')'
      next =>
        subst c
        have pair : (Token.closeParen, tail) = (token, rest) :=
          Option.some.inj (by simpa [nextToken, trimmed] using parsed)
        have same := congrArg Prod.snd pair
        simp only at same
        rw [same] at bound
        simpa using Nat.lt_of_lt_of_le (Nat.lt_succ_self rest.length) bound
      next =>
        cases atom : parseAtom (String.ofList (c :: tail.takeWhile (fun x => !(delimiter x)))) with
        | none => simp [nextToken, trimmed, atom] at parsed
        | some value =>
          have pair : (Token.atom value, tail.dropWhile (fun x => !(delimiter x))) = (token, rest) :=
            Option.some.inj (by simpa [nextToken, trimmed, opening, closing, atom] using parsed)
          have same := congrArg Prod.snd pair
          have tailBound := (List.dropWhile_sublist (l := tail) (fun x => !(delimiter x))).length_le
          simp only at same
          rw [same] at tailBound
          simp only [List.length_cons] at bound
          omega

-- Iterative nesting stack. The only recursive measure is remaining input length.
private def parseStack (input : List Char) (frames : List (List SExpr)) :
    Option (Prod SExpr (List Char)) :=
  match _found : nextToken input with
  | none => none
  | some (.openParen, rest) => parseStack rest ([] :: frames)
  | some (.atom value, rest) =>
    match frames with
    | [] => none
    | frame :: parents => parseStack rest ((.atom value :: frame) :: parents)
  | some (.closeParen, rest) =>
    match frames with
    | [] => none
    | [frame] => some (.list frame.reverse, rest)
    | frame :: parent :: parents => parseStack rest ((.list frame.reverse :: parent) :: parents)
termination_by input.length
decreasing_by all_goals exact nextToken_consumes _found

def parseOne (input : List Char) : Option (Prod SExpr (List Char)) :=
  match nextToken input with
  | some (.atom value, rest) => some (.atom value, rest)
  | some (.openParen, rest) => parseStack rest [[]]
  | _ => none

def parse (text : String) : Option SExpr := do
  let (expression, rest) <- parseOne text.toList
  if rest.dropWhile whitespace = [] then some expression else none

private def renderedItems : List SExpr -> List Char
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

private theorem list_render_chars (items : List SExpr) :
    (SExpr.list items).render.toList = '(' :: (renderedItems items ++ [')']) := by
  cases items with
  | nil =>
    simp [SExpr.render, String.intercalate, renderedItems]
    decide +kernel
  | cons expression rest =>
    simp [SExpr.render, String.toList_append, intercalate_cons_chars,
      renderedItems, List.flatMap_map,
      show "(".toList = ['('] from rfl, show ")".toList = [')'] from rfl]

private theorem renderedItems_cons_cons (a b : SExpr) (rest : List SExpr) :
    renderedItems (a :: b :: rest) = a.render.toList ++ ' ' :: renderedItems (b :: rest) := by
  simp [renderedItems]

private theorem nextToken_space (input : List Char) :
    nextToken (' ' :: input) = nextToken input := by
  simp [nextToken, whitespace]

private theorem parseStack_space (input : List Char) (frames : List (List SExpr)) :
    parseStack (' ' :: input) frames = parseStack input frames := by
  conv_lhs => rw [parseStack]
  conv_rhs => rw [parseStack]
  rw [nextToken_space]

private theorem nextToken_open (rest : List Char) :
    nextToken ('(' :: rest) = some (.openParen, rest) := by
  simp [nextToken, whitespace]

private theorem nextToken_close (rest : List Char) :
    nextToken (')' :: rest) = some (.closeParen, rest) := by
  simp [nextToken, whitespace]

mutual
  private theorem stack_render_expression (expression : SExpr) (frame : List SExpr)
      (parents : List (List SExpr)) (rest : List Char) (hb : Boundary rest) :
      parseStack (expression.render.toList ++ rest) (frame :: parents) =
        parseStack rest ((expression :: frame) :: parents) := by
    cases expression with
    | atom value =>
      simp only [SExpr.render]
      conv_lhs => rw [parseStack]
      rw [nextToken_render_atom value rest hb]
    | list items =>
      rw [list_render_chars]
      simp only [List.cons_append, List.append_assoc]
      conv_lhs => rw [parseStack]
      rw [nextToken_open]
      change parseStack (renderedItems items ++ ')' :: rest) ([] :: frame :: parents) = _
      rw [stack_render_items items [] (frame :: parents) (')' :: rest) (by rfl)]
      simp only [List.append_nil]
      conv_lhs => rw [parseStack]
      rw [nextToken_close]
      simp only [List.reverse_reverse]
  termination_by sizeOf expression
  decreasing_by all_goals simp_wf

  private theorem stack_render_items (items : List SExpr) (frame : List SExpr)
      (parents : List (List SExpr)) (rest : List Char) (hb : Boundary rest) :
      parseStack (renderedItems items ++ rest) (frame :: parents) =
        parseStack rest ((items.reverse ++ frame) :: parents) := by
    cases items with
    | nil => simp [renderedItems]
    | cons expression tail =>
      cases tail with
      | nil =>
        simpa [renderedItems] using stack_render_expression expression frame parents rest hb
      | cons head tail =>
        rw [renderedItems_cons_cons]
        simp only [List.append_assoc, List.cons_append]
        rw [stack_render_expression expression frame parents
          (' ' :: (renderedItems (head :: tail) ++ rest)) (by rfl)]
        rw [parseStack_space, stack_render_items (head :: tail) (expression :: frame) parents rest hb]
        simp [List.reverse_cons, List.append_assoc]
  termination_by sizeOf items
  decreasing_by all_goals simp_wf <;> omega
end

theorem parseOne_render (expression : SExpr) (rest : List Char) (hb : Boundary rest) :
    parseOne (expression.render.toList ++ rest) = some (expression, rest) := by
  cases expression with
  | atom value =>
    simp only [SExpr.render, parseOne, nextToken_render_atom value rest hb]
  | list items =>
    rw [list_render_chars]
    simp only [List.cons_append, List.nil_append, List.append_assoc, parseOne, nextToken_open]
    rw [stack_render_items items [] [] (')' :: rest) (by rfl)]
    simp only [List.append_nil]
    rw [parseStack, nextToken_close]
    simp only [List.reverse_reverse]

theorem parse_render (expression : SExpr) : parse expression.render = some expression := by
  have complete := parseOne_render expression [] (by trivial)
  simp only [List.append_nil] at complete
  unfold parse
  rw [complete]
  rfl

def eval (assignment : Assignment) (text : String) : Option Value :=
  (parse text).bind (SExpr.eval assignment)

theorem eval_render (assignment : Assignment) (expression : SExpr) :
    eval assignment expression.render = expression.eval assignment := by
  simp [eval, parse_render]

theorem typed_render_eval (assignment : Assignment) {ty : Ty} (term : Term ty) :
    eval assignment term.render = some (embed ty (term.eval assignment)) := by
  change eval assignment term.lower.render = _
  rw [eval_render, lower_correct]

theorem whitespace_regression :
    (match parse " \t(+ 1\r\n2) \n" with
     | some (.list [.atom (.operator .add), .atom (.numeral 1), .atom (.numeral 2)]) => true
     | _ => false) = true := by
  decide +kernel

theorem nested_empty_regression :
    (match parse "(())" with
     | some (.list [.list []]) => true
     | _ => false) = true := by
  decide +kernel

theorem remainder_regression :
    (match parseOne " (fbi_101 false) )tail".toList with
     | some (.list [.atom (.symbol (.unary .bool .int 5)), .atom (.boolean false)], rest) =>
       decide (rest = " )tail".toList)
     | _ => false) = true := by
  decide +kernel

theorem malformed_regression :
    (parse "").isNone = true /\
    (parse " \n\t").isNone = true /\
    (parse "(").isNone = true /\
    (parse ")").isNone = true /\
    (parse "(1").isNone = true /\
    (parse "1)").isNone = true /\
    (parse "1 2").isNone = true /\
    (parse "()()").isNone = true /\
    (parse "(+ 01 2)").isNone = true /\
    (parse "(-1)").isNone = true /\
    (parse "(fii_10 1)").isNone = true /\
    (parse "unknown").isNone = true := by
  decide +kernel

theorem signed_regression (assignment : Assignment) :
    eval assignment "(- (- 2) 3)" = some (.integer (-5)) := by
  rw [<- signed_text_regression, typed_render_eval]
  simp [Term.eval, embed]

theorem typing_regression (assignment : Assignment) :
    eval assignment (call (.operator .add) [.atom (.boolean true), .atom (.numeral 1)]).render = none /\
    eval assignment (call (.operator .ite)
      [.atom (.boolean true), .atom (.numeral 1), .atom (.boolean false)]).render = none /\
    eval assignment (call (.symbol (.unary .int .bool 0)) [.atom (.boolean true)]).render = none := by
  simp only [eval_render]
  exact ill_typed_regression assignment

end CCFRaft.Sparse.SmtExpressionText

run_cmd do
  let env <- Lean.getEnv
  let mut checked := 0
  for (name, info) in env.constants.toList do
    if `CCFRaft.Sparse.SmtExpressionText |>.isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit expression-parser axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected transitive axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no expression-parser declarations audited"
  Lean.logInfo m!"Sparse.SmtExpressionText: {checked} declarations passed the allowed-axiom gate."
  for theoremName in [
      ``CCFRaft.Sparse.SmtExpressionText.parseAtom_render,
      ``CCFRaft.Sparse.SmtExpressionText.atom_render_safe,
      ``CCFRaft.Sparse.SmtExpressionText.nextToken_render_atom,
      ``CCFRaft.Sparse.SmtExpressionText.parse_render,
      ``CCFRaft.Sparse.SmtExpressionText.typed_render_eval] do
    let axioms <- Lean.collectAxioms theoremName
    Lean.logInfo m!"{theoremName}: {axioms}"
