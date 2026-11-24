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
- `dead` is `true` only when `p` eliminates a proof of `False` in the branch context;
- `coveredBy` is the tag of the first live (not dead) branch whose script also closes the goal of
  every other live branch (the replay test), or `""` when there is none or fewer than two branches
  are live. This is diagnostic only: the replay can use different hypotheses in different branches.

An attempt to prove `False` retains the successful proof; if it fails, the script is run on the
original goal. Replay tests run in a discarded state without testing nested splits.
-/

public section

namespace Relevance

/-- Marks the proof of a recorded case split. -/
@[inline] def splitMark {α : Sort u} (_name _coveredBy : String) (p : α) : α := p

/-- Marks one branch. A `true` flag must be backed by a `False.elim` in the proof. -/
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

private def tryClose (tac : Syntax) (prepare : MetaM MVarId)
    (replay : Bool) : TacticM (Option Expr) := do
  let saved ← saveState
  let errors ← errorCount
  let proof ← try
      let g ← prepare
      withTheReader Core.Context (fun c => { c with options := c.options.setBool quietKey replay }) do
        let rest ← withoutRecover <| Term.withoutErrToSorry <| evalTacticAt tac g
        let term ← instantiateMVars (mkMVar g)
        return if rest.isEmpty && !term.hasSorry && (← errorCount) == errors then some term else none
    catch _ => pure none
  if replay || proof.isNone then saved.restore
  return proof

/-- Test replay without keeping any metavariable assignments. -/
def closes (tac : Syntax) (prepare : MetaM MVarId) : TacticM Bool :=
  return (← tryClose tac prepare true).isSome

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
  let mut infos : Array (Array FVarId × Option Expr) := #[]
  for (gi, alt) in gs.zip alts.toList do
    let tac := alt[3]
    let info ← gi.withContext do
      let mut conds := #[]
      for d in (← getLCtx) do
        if d.isImplementationDetail || before.contains d.fvarId then continue
        if ← isProp d.type then conds := conds.push d.fvarId
      let absurd ← if quiet then pure none else
        tryClose tac (return (← mkFreshExprSyntheticOpaqueMVar (mkConst ``False) (← gi.getTag)).mvarId!) false
      pure (conds, absurd)
    infos := infos.push info
  -- replay test: a live branch whose script closes every other live branch
  let live := (List.range gs.length).filter fun i => infos[i]!.2.isNone
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
  for ((gi, alt), (conds, absurd)) in (gs.zip alts.toList).zip infos.toList do
    let tag := alt[1].getId.toString
    let tac := alt[3]
    gi.withContext do
    let ty ← gi.getType
    let body ← match absurd with
      | some proof => mkFalseElim ty proof
      | none => mkFreshExprSyntheticOpaqueMVar ty (← gi.getTag)
    let mut term := body
    for c in conds.reverse do
      term ← mkAppM ``condMark #[mkFVar c, term]
    term ← mkAppM ``branchMark #[mkStrLit tag, toExpr absurd.isSome, term]
    gi.assign term
    if absurd.isNone then
      let rest ← evalTacticAt tac body.mvarId!
      unless rest.isEmpty do throwError "split_rel {name}: branch {tag} left goals"
  replaceMainGoal []

end Relevance

end
