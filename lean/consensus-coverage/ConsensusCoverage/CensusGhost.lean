module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ExplorerGhost
public import ConsensusCoverage.Readers
import all ConsensusCoverage.ExplorerGhost
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
meta import Lean

namespace ConsensusCoverage.CensusGhost

open Consensus Consensus.Model Consensus.Model.Node ReadersAtoms
open ExplorerGhost (Ghost)

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

private structure Slice where
  ghost : Ghost
  ids : List NodeID
  currentTerms : List Nat
  logs : List (List Entry)
  indices : List Nat

/-- The index bound in this reader snapshot is introduced only by
`electedExact_idx`: only an index present in an election tuple can satisfy
its guard. The other three marginals range over actual seen observations. -/
private def slice (g : Ghost) : Slice :=
  ⟨g, (g.seen.map (·.1)).eraseDups, (g.seen.map (·.2.1)).eraseDups,
    (g.seen.map (·.2.2)).eraseDups, (g.elected.map (·.2.2.2)).eraseDups⟩

/-- Replacing the index domain in an election-guarded existential does not
assume that the ghost remembers every past commit index. Its election
tuples must contain the actual elections, not merely elected terms. -/
private theorem index_domain (g : Ghost) (h : List Model.State) (n k : Nat) (l : List Entry)
    (query : Nat → Bool)
    (contains : ∀ i, electedExact n k l i h = true → (n, k, l, i) ∈ g.elected) :
    ((histNodes h).map (·.2.commitIndex)).any (fun i => electedExact n k l i h && query i) =
      (slice g).indices.any (fun i => electedExact n k l i h && query i) := by
  apply Bool.eq_iff_iff.mpr
  simp only [List.any_eq_true, Bool.and_eq_true]
  constructor
  · rintro ⟨i, _, yes, p⟩
    exact ⟨i, List.mem_eraseDups.mpr (List.mem_map.mpr ⟨(n, k, l, i), contains i yes, rfl⟩), yes, p⟩
  · rintro ⟨i, _, yes, p⟩
    exact ⟨i, electedExact_idx yes, yes, p⟩

private structure Input where
  old : Slice
  next : Slice
  elections : List (NodeID × Nat × List Entry × Nat)

private def canon (s : Slice) (k : Nat) (l : List Entry) := s.ghost.canonical.contains (k, l)
private def elect (s : Slice) (n k : Nat) (l : List Entry) (i : Nat) :=
  s.ghost.elected.contains (n, k, l, i)
private def election (s : Input) (n k : Nat) (l : List Entry) (i : Nat) :=
  s.elections.contains (n, k, l, i)
private def grants (s : Slice) := ExplorerGhost.Ghost.granted s.ghost
private def obs (s : Slice) := ExplorerGhost.observations s.ghost
private def terms (s : Slice) := ExplorerGhost.Ghost.terms s.ghost
private def votes (s : Slice) := s.ghost.votes
private def prefixes (s : Slice) :=
  ([] :: s.ghost.seen.flatMap (fun (_, _, l) => ReadersAtoms.prefixes l)).eraseDups

meta section

open Lean Meta Elab Command

private def scope := `ConsensusCoverage.CensusGhost.Exec

private def clone (n : Name) := scope ++ Name.mkSimple n.getString!

private def relevant (n : Name) :=
  (`ConsensusCoverage.ReadersCompiler.R).isPrefixOf n ||
    n == ``ReadersCompiler.readView || n == ``Readers.read?

private def slice? (g hist : Expr) : Option Expr := do
  guard (hist.isAppOfArity ``List.cons 3)
  let pre := hist.getArg! 1
  let tail := hist.getArg! 2
  if pre.isAppOf ``GuardedDomain.View.before && tail.isAppOf ``GuardedDomain.View.past then
    return mkApp (mkConst ``Input.old) g
  guard (pre.isAppOf ``GuardedDomain.View.after && tail.isAppOfArity ``List.cons 3 &&
    (tail.getArg! 1).isAppOf ``GuardedDomain.View.before &&
    (tail.getArg! 2).isAppOf ``GuardedDomain.View.past)
  return mkApp (mkConst ``Input.next) g

private def domain? (fn : Expr) : Option Name := do
  if fn.isAppOfArity ``Prod.fst 2 then return ``Slice.ids
  let .lam _ _ body _ := fn | none
  if body.isAppOfArity ``Prod.fst 3 && body.appArg! == .bvar 0 then return ``Slice.ids
  let .app (.const n _) pair := body | none
  guard (pair.isAppOfArity ``Prod.snd 3 && pair.appArg! == .bvar 0)
  if n == ``NodeState.currentTerm then return ``Slice.currentTerms
  if n == ``NodeState.log then return ``Slice.logs
  if n == ``NodeState.commitIndex then return ``Slice.indices
  none

private def replaceAtom (g e : Expr) : Option Expr := do
  let n ← e.getAppFn.constName?
  let a := e.getAppArgs
  let atHist (pos : Nat) := slice? g a[pos]!
  if n == ``List.map && a.size == 4 && a[3]!.isAppOfArity ``histNodes 1 then
    return mkApp (mkConst (← domain? a[2]!)) (← slice? g a[3]!.appArg!)
  if n == ``electionExact && a.size == 7 then
    guard (a[0]!.isAppOf ``GuardedDomain.View.after && a[1]!.isAppOf ``GuardedDomain.View.before &&
      a[2]!.isAppOf ``GuardedDomain.View.past)
    return mkAppN (mkApp (mkConst ``election) g) (a.extract 3 7)
  if n == ``electedExact && a.size == 5 then
    return mkAppN (mkApp (mkConst ``elect) (← atHist 4)) (a.extract 0 4)
  if n == ``GuardedDomain.canonAt && a.size == 4 then
    return mkAppN (mkApp (mkConst ``canon) (← atHist 3)) (a.extract 1 3)
  if n == ``grantedIn && a.size == 5 then
    return mkAppN (mkApp (mkConst ``grants) (← atHist 0)) (a.extract 1 5)
  if n == ``GuardedDomain.observations && a.size == 2 then
    return mkApp2 (mkConst ``obs) (← atHist 0) a[1]!
  if n == ``GuardedDomain.ledTerms && a.size == 3 then
    return mkApp3 (mkConst ``terms) (← atHist 1) a[0]! a[2]!
  guard (a.size == 1)
  let target ← if n == ``voteStamps then some ``votes
    else if n == ``historicalPrefixes then some ``prefixes else none
  return mkApp (mkConst target) (← atHist 0)

private partial def compile (n : Name) : MetaM Unit := do
  if (← getEnv).contains (clone n) then return
  let decl ← getConstInfoDefn n
  let calls := decl.value.getUsedConstants.filter relevant
  for c in calls do compile c
  withLocalDeclD `input (mkConst ``Input) fun g => do
    let mut body := decl.value
    repeat
      let next := body.replace fun e => replaceAtom g e
      if next == body then break
      body := next
    body := body.replace fun e => do
      let .const c _ := e | none
      guard (relevant c)
      return mkApp (mkConst (clone c)) g
    if body.find? (fun e => e.isConstOf ``GuardedDomain.View.past) |>.isSome then
      throwError "unfactored history in {n}: {body}"
    let value ← mkLambdaFVars #[g] body
    addAndCompile <| .defnDecl {
      name := clone n
      levelParams := []
      value
      type := ← mkForallFVars #[g] decl.type
      hints := .regular 0
      safety := .safe }

end

local elab "compile_census" : command => Lean.Elab.Command.liftTermElabM (compile ``Readers.read?)
compile_census

public def answers (cfg : FullProfile.Configuration) (g h : Ghost) (before after : Model.State)
    (act : Model.Action) : Option (Classes.StepBranch → Option Bool) := do
  let v ← GuardedDomain.ofAction cfg before after [] act
  let event := eventOf act
  let x : XView := ⟨v, event, outputsOf v.actor v.pre event, g.committed, h.committed⟩
  let s : Input := ⟨slice g, slice h, ExplorerGhost.elections h before after⟩
  return Exec.read? s ⟨cfg, some x⟩

end ConsensusCoverage.CensusGhost
