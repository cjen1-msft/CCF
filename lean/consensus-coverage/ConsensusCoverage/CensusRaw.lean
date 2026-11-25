module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusReplay
import all ConsensusCoverage.CensusReplay
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReplayAnswers
meta import Lean

namespace ConsensusCoverage.CensusRaw

open ReadersAtoms

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

meta section

open Lean Meta Elab Command

/-- Only clone the ancestors of the profiled closed subexpression.
Every clone still uses the original ordered history and real query. -/
private partial def specialize (n target : Name) (memo : NameMap (Option Name)) :
    MetaM (NameMap (Option Name)) := do
  if memo.contains n then return memo
  let d ← getConstInfoDefn n
  let mut memo := memo
  for fn in d.value.getUsedConstants do
    if fn.getPrefix == target.getPrefix && fn != target then memo ← specialize fn target memo
  forallBoundedTelescope d.type (some 2) fun inputs _ => do
    let body := d.value.beta inputs
    withLocalDeclD `cached (← mkAppM ``Thunk #[mkConst ``Bool]) fun cached => do
      let get ← mkAppM ``Thunk.get #[cached]
      let rewrite (e : Expr) : Option Expr := do
        let fn ← e.getAppFn.constName?
        let args := e.getAppArgs
        guard (args.size ≥ inputs.size && args.extract 0 inputs.size == inputs)
        if fn == target && args.size == inputs.size then return get
        let some shared ← memo.find? fn | none
        return mkAppN (mkApp (mkAppN (mkConst shared) inputs) cached) (args.extract inputs.size args.size)
      let mut transformed := body
      repeat
        let next := transformed.replace rewrite
        if next == transformed then break
        transformed := next
      if transformed == body then return memo.insert n none
      let shared := `ConsensusCoverage.CensusRaw.Shared ++ Name.mkSimple n.getString!
      let value ← mkLambdaFVars (inputs.push cached) transformed
      addAndCompile <| .defnDecl {
        name := shared, levelParams := [], type := ← inferType value, value,
        hints := .regular 0, safety := .safe }
      return memo.insert n (some shared)

end

local elab "share_raw" : command => Lean.Elab.Command.liftTermElabM do
  let _ ← specialize ``ReadersCompiler.readView `ConsensusCoverage.ReadersCompiler.R.reach_8 {}

share_raw

private def selected (cfg : FullProfile.Configuration) (x : XView) :
    { f : Classes.StepBranch → Option Bool // f = Readers.read? ⟨cfg, some x⟩ } := by
  let v := Thunk.mk fun _ => @ReadersCompiler.R.reach_8 ⟨cfg⟩ x
  first
  | exact ⟨@Shared.readView ⟨cfg⟩ x v, rfl⟩
  | exact ⟨Readers.read? ⟨cfg, some x⟩, rfl⟩

@[noinline] private def fill (old : ReplayAnswers.Evidence) (f : Classes.StepBranch → Option Bool) : ByteArray :=
  FullProfile.stepBranches.foldl (fun row branch =>
    let v := (ReplayAnswers.answer old (.step branch)).orElse fun _ => f branch
    row.push (v.elim 0 (fun yes => if yes then 2 else 1))) .empty

/-- Reuses the result of a pure closed reach at one actual ordered-history
boundary. Other queries still go through the full three-valued dispatcher. -/
public def row (old : ReplayAnswers.Evidence) (e : Readers.Evidence) : ByteArray :=
  match e with
  | ⟨cfg, some x⟩ => fill old (selected cfg x).val
  | ⟨_, none⟩ => fill old (Readers.read? e)

public theorem row_eq (old : ReplayAnswers.Evidence) (e : Readers.Evidence) :
    row old e = fill old (Readers.read? e) := by
  cases e with
  | mk cfg x =>
    cases x with
    | none => rfl
    | some x => simp only [row, (selected cfg x).property]

end ConsensusCoverage.CensusRaw
