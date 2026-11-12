module

public meta import Lean

/-!
# Recorded case splits

Nothing here mentions a particular model. A proof author writes

    split_rel earlier := (by_cases earlier : c < d) with
      | pos => exact ...
      | neg => ...

`split_rel name := (splitter) with | tag => tac ...` runs `splitter` on the main goal, which must
produce one goal per alternative, and runs each alternative's tactic on its goal.

The record is kept in the proof term itself, so it travels with the theorem to every module that
imports it. The goal is closed by `Relevance.splitMark name coveredBy p`, and each branch goal by
`Relevance.branchMark tag dead (Relevance.condMark h₁ (... p))`, where

- the conditions `hᵢ` are the propositions the splitter added to the branch's context (the local
  hypotheses whose ids were not in the context before the split);
- `dead` is `true` when the branch script also proves `False` (it closes the branch by
  contradiction);
- `coveredBy` is the tag of the first live (not dead) branch whose script also closes the goal of
  every other live branch (the replay test), or `""` when there is none or fewer than two branches
  are live.

The tests rerun the branch script in a discarded state. Nested `split_rel`s inside a test run
do not run tests of their own.
-/

public section

namespace Relevance

/-- Marks the proof of a recorded case split. -/
@[inline] def splitMark {α : Sort u} (_name _coveredBy : String) (p : α) : α := p

/-- Marks the proof of one branch of a recorded case split. -/
@[inline] def branchMark {α : Sort u} (_tag : String) (_dead : Bool) (p : α) : α := p

/-- Records one condition of the enclosing branch. -/
@[inline] def condMark {α : Sort u} {C : Prop} (_h : C) (p : α) : α := p

end Relevance

end

public meta section

open Lean Elab Tactic Meta

namespace Relevance

/-- Set while a test reruns a branch script: nested splits then run without tests. -/
def quietKey : Name := `relevance.quiet

def isQuiet : CoreM Bool := return (← getOptions).getBool quietKey

def errorCount : CoreM Nat :=
  return (← Core.getMessageLog).toList.filter (·.severity == .error) |>.length

/-- Run `tac` quietly on the goal made by `prepare`; `true` iff it closes that goal without
errors or `sorry`. Everything, including `prepare`, is undone afterwards. -/
def closes (tac : Syntax) (prepare : MetaM MVarId) : TacticM Bool := do
  let saved ← saveState
  let errors ← errorCount
  let ok ← try
      let g ← prepare
      withTheReader Core.Context (fun c => { c with options := c.options.setBool quietKey true }) do
        let rest ← withoutRecover <| Term.withoutErrToSorry <| evalTacticAt tac g
        let term ← instantiateMVars (mkMVar g)
        pure (rest.isEmpty && !term.hasSorry && (← errorCount) == errors)
    catch _ => pure false
  saved.restore
  return ok

syntax splitAlt := ppDedent(ppLine) "| " ident " => " tacticSeq
syntax (name := splitRel)
  "split_rel " ident " := " "(" tacticSeq ")" " with" withPosition((colGe splitAlt)+) : tactic

@[tactic splitRel] def evalSplitRel : Tactic := fun stx => do
  let name := stx[1].getId.toString
  let splitter := stx[4]
  let alts := stx[7].getArgs
  let g ← getMainGoal
  g.withContext do
  let before := (← getLCtx).getFVarIds
  let inner ← mkFreshExprSyntheticOpaqueMVar (← g.getType) (← g.getTag)
  let gs ← evalTacticAt splitter inner.mvarId!
  unless gs.length == alts.size do
    throwError "split_rel {name}: the splitter made {gs.length} goals for {alts.size} alternatives"
  let quiet ← isQuiet
  -- conditions and the tests of every branch, before any branch script runs
  let mut infos : Array (Array FVarId × Bool) := #[]
  for (gi, alt) in gs.zip alts.toList do
    let tac := alt[3]
    let info ← gi.withContext do
      let mut conds := #[]
      for d in (← getLCtx) do
        if d.isImplementationDetail || before.contains d.fvarId then continue
        if ← isProp d.type then conds := conds.push d.fvarId
      let dead ← if quiet then pure false else closes tac gi.exfalso
      pure (conds, dead)
    infos := infos.push info
  -- replay test: a live branch whose script closes every other live branch
  let live := (List.range gs.length).filter fun i => !(infos[i]!.2)
  let mut coveredBy := ""
  if !quiet && live.length ≥ 2 then
    for i in live do
      let tac := alts[i]![3]
      let mut all := true
      for j in live do
        if i == j then continue
        let gj := gs[j]!
        unless ← gj.withContext (closes tac (pure gj)) do
          all := false
          break
      if all then
        coveredBy := alts[i]![1].getId.toString
        break
  g.assign (← mkAppM ``splitMark #[mkStrLit name, mkStrLit coveredBy, inner])
  for ((gi, alt), (conds, dead)) in (gs.zip alts.toList).zip infos.toList do
    let tag := alt[1].getId.toString
    let tac := alt[3]
    gi.withContext do
    let body ← mkFreshExprSyntheticOpaqueMVar (← gi.getType) (← gi.getTag)
    let mut term := body
    for c in conds.reverse do
      term ← mkAppM ``condMark #[mkFVar c, term]
    term ← mkAppM ``branchMark #[mkStrLit tag, toExpr dead, term]
    gi.assign term
    let rest ← evalTacticAt tac body.mvarId!
    unless rest.isEmpty do throwError "split_rel {name}: branch {tag} left goals"
  replaceMainGoal []

end Relevance

end
