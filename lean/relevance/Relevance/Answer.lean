module

public meta import Lean

/-! `answer% rule` compiles the decidable side of a proved `question ↔ test`.
Leading binders may describe a valid model step or reachability. They are *not*
runtime inputs: elaboration fails if the test (including its decision procedure)
uses any of them. The rule only justifies the answer where its hypotheses hold. -/

public meta section

open Lean Meta Elab Term

elab "answer% " rule:term : term => do
  let e ← elabTerm rule none
  synthesizeSyntheticMVarsNoPostponing
  forallTelescope (← instantiateMVars (← inferType e)) fun xs body => do
    let_expr Iff _ rhs := body | throwErrorAt rule "expected a rule ending in an iff"
    let answer ← instantiateMVars (← mkDecide rhs)
    if answer.hasMVar || xs.any (fun x => answer.containsFVar x.fvarId!) then
      throwErrorAt rule "the executable answer depends on an unsupplied binder"
    return answer

/-- For each constructor of the first binder's enum, prove `question ↔ ?test`.
The tactic chooses a reduction; unification supplies `?test`. Only its decidable
answer is compiled. No default answer when a question has no reduction. -/
elab "question_table% " spec:term " by " tac:tacticSeq : term => do
  let e ← elabTerm spec none
  synthesizeSyntheticMVarsNoPostponing
  let e ← instantiateMVars e
  let .lam _ enum _ _ := e | throwErrorAt spec "expected a function of a question"
  let .const name [] := enum | throwErrorAt spec "expected a simple question enum"
  let ind ← getConstInfoInduct name
  unless ind.numParams == 0 && ind.numIndices == 0 do
    throwErrorAt spec "expected a simple question enum"
  let answers ← ind.ctors.mapM fun c => do
    unless (← getConstInfoCtor c).numFields == 0 do
      throwErrorAt spec "question constructor {c} has fields"
    lambdaTelescope (e.beta #[mkConst c]) fun hs q => do
      let rhs ← mkFreshExprMVar (mkSort .zero)
      let goal ← mkFreshExprSyntheticOpaqueMVar (mkIff q rhs)
      let rest ← withoutErrToSorry <| withExporting (isExporting := false) <|
        Tactic.run goal.mvarId! (Tactic.evalTactic tac)
      unless rest.isEmpty do throwErrorAt tac "no complete reduction for {c}"
      let proof ← instantiateMVars goal
      if proof.hasSorry || proof.hasMVar then throwErrorAt tac "unfinished reduction for {c}"
      withExporting (isExporting := false) <| checkWithKernel proof
      let test ← instantiateMVars (← mkDecide (← instantiateMVars rhs))
      if test.hasMVar || hs.any (fun h => test.containsFVar h.fvarId!) then
        throwErrorAt spec "the answer to {c} needs an unsupplied binder"
      return test
  withLocalDeclD `question enum fun x => do
    let motive ← mkLambdaFVars #[x] (mkConst ``Bool)
    let body := mkAppN (mkConst (ind.name ++ `casesOn) [.succ .zero])
      (#[motive, x] ++ answers.toArray)
    mkLambdaFVars #[x] body
