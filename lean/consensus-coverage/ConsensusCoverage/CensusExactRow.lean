module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusFresh
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
meta import Lean

namespace ConsensusCoverage.CensusExactRow

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
      let shared := `ConsensusCoverage.CensusExactRow.Shared ++ Name.mkSimple n.getString!
      let value ← mkLambdaFVars (inputs.push cached) transformed
      addAndCompile <| .defnDecl {
        name := shared, levelParams := [], type := ← inferType value, value,
        hints := .regular 0, safety := .safe }
      return memo.insert n (some shared)

end

local elab "share_raw" : command => Lean.Elab.Command.liftTermElabM do
  let _ ← specialize ``ReadersCompiler.readView `ConsensusCoverage.ReadersCompiler.R.reach_8 {}

share_raw

private theorem sameThunk (cfg : FullProfile.Configuration) (x : XView) :
    (Thunk.mk fun _ => @CensusFresh.guarded ⟨cfg⟩ x) =
      (Thunk.mk fun _ => @ReadersCompiler.R.reach_8 ⟨cfg⟩ x) := by
  apply congrArg Thunk.mk
  funext
  exact @CensusFresh.guarded_eq ⟨cfg⟩ x

/-- Share one expensive closed reach across all branches of the same real
step. The ordered input stays intact and the result is the total dispatcher. -/
public def exactView (cfg : FullProfile.Configuration) (x : XView) :
    { f : Classes.StepBranch → Option Bool // f = @ReadersCompiler.readView ⟨cfg⟩ x } := by
  refine ⟨@Shared.readView ⟨cfg⟩ x (Thunk.mk fun _ => @CensusFresh.guarded ⟨cfg⟩ x), ?_⟩
  rw [sameThunk]
  rfl

end ConsensusCoverage.CensusExactRow
