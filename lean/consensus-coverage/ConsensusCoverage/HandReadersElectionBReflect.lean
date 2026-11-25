module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.ReadersPolarCompiler
import all ConsensusCoverage.ReadersCompiler
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionProfile
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReadersCompiler
public meta import ConsensusCoverage.ReadersPolarCompiler
public meta import Lean

namespace ConsensusCoverage.HandReadersElectionB.Reflect

open Consensus Consensus.Proofs Safety ActionProfile ReadersAtoms HandReadersA
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public meta section
open Lean Meta Elab Command ReadersCompiler

/-- Stop at existing certified readers, rebuilding only blocked ancestors of
the requested roots with the supplied invariant simplifications. -/
def compile (scope : Name) (work rules : Array Name) (requireAll : Bool := true) : MetaM Unit :=
  driverWith (some fun env _ _ => do
    let mut first := env.first
    for r in rules do first ← first.addConst r (post := false)
    let env := {env with target := scope,extraRules := true,first := first}
    let mut st : St := {}
    let mut pending := work
    let mut seen : NameSet := {}
    while let some n := pending.back? do
      pending := pending.pop
      if seen.contains n then continue
      seen := seen.insert n
      let inf ← ReadersPolarCompiler.retained env n
      if inf.reader.isSome then st := {st with memo := st.memo.insert n inf}
      else pending := pending ++ (←getConstInfo n).value!.getUsedConstants.filter isGenerated
    for n in work do
      let (i,next) ← (compileConst env n).run st
      st := next
      unless i.reader.isSome && i.conds.isEmpty do
        if requireAll then throwError "unresolved {n}: {st.blockers.toList.getLast?}"
    unless requireAll do
      for (n,k,d) in st.blockers do logInfo m!"{n} {k}: {d.take 180}"
      for n in work do logInfo m!"{n.getString!}: {(st.memo[n]?.bind (·.reader)).isSome}")

end

def exact (b : Classes.StepBranch) (eval : [Config.InitialConfiguration] → XView → Bool)
    (cert : ∀ [Config.InitialConfiguration] {f t} (c : Ctx f t) (x : XView)
      (_ : x.Matches c), eval x = true ↔ SolvedWitnesses.sig c b) : Exact b where
  eval cfg s a t hist := (ofXAction cfg s t hist a).any (@eval ⟨cfg⟩)
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    rw [made,Option.any_some]
    exact Bool.eq_iff_iff.mpr ((label_true s (.step b)).trans
      ((SolvedWitnesses.sig_iff s.context b).trans (cert s.context x ok).symm))

end ConsensusCoverage.HandReadersElectionB.Reflect
