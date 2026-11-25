module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.CensusReplay
import ConsensusCoverage.CensusExactRow
import all ConsensusCoverage.CensusReplay
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersPolarGenerated
import all ConsensusCoverage.ReplayAnswers

namespace ConsensusCoverage.CensusRaw

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 16384
set_option maxHeartbeats 0

private def selected (cfg : FullProfile.Configuration) (x : ReadersAtoms.XView) (pools : Thunk (Option ReadersPolar.Pools)) :
    { f : Classes.StepBranch → Option Bool // f = Readers.read? ⟨cfg, some x, pools⟩ } := by
  let checked := CensusExactRow.exactView cfg x
  refine ⟨fun b => (checked.val b).orElse fun _ =>
    pools.get.bind fun p => @ReadersPolarCompiler.readView ⟨cfg⟩ x p b, ?_⟩
  funext b
  unfold Readers.read?
  simp only [Option.bind_some]
  exact congrArg (fun (v : Option Bool) => v.orElse fun _ =>
    pools.get.bind fun p => @ReadersPolarCompiler.readView ⟨cfg⟩ x p b) (congrFun checked.property b)

@[noinline] private def fill (old : ReplayAnswers.Evidence) (f : Classes.StepBranch → Option Bool) : ByteArray :=
  FullProfile.stepBranches.foldl (fun row branch =>
    let v := (ReplayAnswers.answer old (.step branch)).orElse fun _ => f branch
    row.push (v.elim 0 (fun yes => if yes then 2 else 1))) .empty

/-- Reuse the exact reach at the actual ordered-history boundary, with the
unmodified full one-sided dispatcher and its actual ordered pools. -/
public def row (old : ReplayAnswers.Evidence) (e : Readers.Evidence) : ByteArray :=
  match e with
  | ⟨cfg, some x, pools⟩ => fill old (selected cfg x pools).val
  | ⟨_, none, _⟩ => fill old (Readers.read? e)

public theorem row_eq (old : ReplayAnswers.Evidence) (e : Readers.Evidence) :
    row old e = FullProfile.stepBranches.foldl (fun row b =>
      let v := CensusReplay.answer old e b
      row.push (v.elim 0 (fun yes => if yes then 2 else 1))) .empty := by
  change row old e = fill old (Readers.read? e)
  cases e with
  | mk cfg x pools =>
    cases x with
    | none => rfl
    | some x => simp only [row, (selected cfg x pools).property]

end ConsensusCoverage.CensusRaw
