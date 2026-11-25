module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersBGate
import all ConsensusCoverage.HandReadersBPaths
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.StutterProfile
import all ConsensusCoverage.InertProfile
import all ConsensusCoverage.ProofWalk
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBPaths

namespace ConsensusCoverage.HandReadersTrunkD.Table

open Consensus Model Proofs Safety ActionProfile SolvedWitnesses EvidenceSupport Lean Meta Elab Command

set_option maxRecDepth 16384
set_option maxHeartbeats 3500000

structure Still [Config.InitialConfiguration] (f : Frame) (t : Model.State) : Prop where
  now : Stable f t .now
  seen : Stable f t .seen
  elected : Stable f t .elected
  canon : Stable f t .canon
  committed : Stable f t .committed

theorem still (s : Step) : letI : Config.InitialConfiguration := ⟨s.cfg⟩
    Now s.frame s.context.actor s.context.post → Stable s.frame s.after .committed → Still s.frame s.after := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  intro old keys
  have same := s.context.now_pre old
  have nodes : s.after.nodes = s.frame.current.nodes := by
    change s.context.tr.post = s.context.tr.pre at same
    rw [s.context.tr.nodesEq,same]
    exact InertProfile.replace_eq s.context.inv.distinct s.context.tr.found
  have eq := StutterProfile.advance_logs_nodes nodes
  have se := (congrArg LogFacts.Ghost.seen eq).trans (StutterProfile.frozenSeen s.folded.invariant)
  have el := (congrArg LogFacts.Ghost.elected eq).trans (StutterProfile.frozenElection s.folded.invariant)
  have ca := (congrArg LogFacts.Ghost.canon eq).trans (StutterProfile.frozenCanon s.folded)
  refine ⟨?_,?_,?_,?_,keys⟩
  · intro n st now; change (n,st) ∈ s.after.nodes at now; change (n,st) ∈ s.frame.current.nodes
    rwa [← nodes]
  · intro n o h; simpa only [Seen,se] using h
  · intro n k l i h; simpa only [Elected,el] using h
  · intro k l h; simpa only [Canon,ca] using h

meta section
private def excluded (r : Name) := (`ConsensusCoverage.HandReadersTrunkD.Table.Excluded).str r.getString!
private abbrev Gen := StateRefT (Std.HashMap Name Bool) MetaM

private partial def exclude (r stop : Name) : Gen Bool := do
  if let some ok := (←get)[r]? then return ok
  let ci ← getConstInfo r
  let ok ←lambdaTelescope ci.value! fun xs body => do
    let fp := xs.extract 0 3
    withLocalDeclD `still (mkAppN (mkConst ``Still) fp) fun st => do
      let hs := #[``Still.now,``Still.now,``Still.seen,``Still.seen,``Still.elected,``Still.canon,``Still.committed].map
        (fun n => mkAppN (mkConst n) (fp.push st))
      let ck : EvidenceSupport.Check := ⟨xs,mkAppN (mkConst ``Frame.advance) fp,hs,118⟩
      withLocalDeclD `h (mkAppN (mkConst r) xs) fun h => do
        let some pf ← ProofWalk.refute (fun (p,hp) => do
          if HandReadersBPaths.reaches p then
            let child := p.getAppFn.constName!
            if child == stop then return some (mkAppN (mkConst ``HandReadersBGate.grantClosed) (p.getAppArgs.push hp))
            if ←exclude child stop then return some (mkAppN (mkConst (excluded child)) (p.getAppArgs ++ #[st,hp]))
          if p.isAppOf ``ElectStep && p.getArg! 1 == xs[1]! && p.getArg! 2 == xs[2]! then
            let no ←mkAppM ``Iff.mp #[mkAppN (mkConst ``stable_elect_iff) (xs.extract 0 4),hs[4]!]
            return some (mkAppN no ((p.getAppArgs.extract 3 p.getAppNumArgs).push hp))
          return none) (fun facts => do
            for (p,n) in facts do
              if p.isAppOfArity ``Not 1 then
                if let some v ←rebuild ck facts p.appArg! then return some (mkApp n v)
            return none) [(body,h)] | return false
        let v ←mkLambdaFVars (xs ++ #[st,h]) pf
        addDecl (.thmDecl {name := excluded r,levelParams := [],type := ←inferType v,value := v})
        return true
  modify (·.insert r ok)
  return ok
end

run_cmd liftTermElabM do
  let q := ``step_mem_replaceNode_here_pos
  let stop ← ReachPath.resolve (←`(reachPath|step_summary_event_receive[10,0,0,0]))
  let rs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  let task : Gen (List Nat) := do
    let mut out := []
    for (r,i) in rs.toList.zipIdx do unless ←exclude r stop do out := i::out
    return out.reverse
  let live ← task.run' {}
  logInfo m!"table membership sites surviving fixed node and commitment evidence: {live}"

end ConsensusCoverage.HandReadersTrunkD.Table
