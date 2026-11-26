module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersOtherTransferSites
import all ConsensusCoverage.HandReadersOtherFactsSites
import all ConsensusCoverage.HandReadersTrunkAFactor
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersOtherTransferSites
public meta import ConsensusCoverage.HandReadersOtherFactsSites
public meta import ConsensusCoverage.HandReadersTrunkAFactor

namespace ConsensusCoverage.HandReadersTrunkD.Term

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
open HandReadersOther

set_option maxRecDepth 16384
set_option maxHeartbeats 2000000

private theorem notCandidate {n} {m z : NodeState} (a : Advance n m z) (primary : m.role = .primary) :
    z.role ≠ .candidate := by rcases a.role with h | h <;> first | rw [h,primary]; decide | rw [h]; decide

private theorem keepVote {n pre ev cand} (camp : Campaign n pre ev cand) (same : cand.currentTerm = pre.currentTerm)
    (v : NodeID) (h : pre.votedFor = some v) : cand.votedFor = some v := by
  rcases camp.2.2.2 with fresh | old
  · have inc := fresh.2.1; omega
  · rcases old.2.2.1 with eq | no <;> simp_all

private theorem leaderImpossible {n pre ev cand} (camp : Campaign n pre ev cand) (role : pre.role = .primary)
    (term : cand.currentTerm = pre.currentTerm) : False := by
  rcases camp.2.2.2 with fresh | old
  · have inc := fresh.2.1; omega
  · exact Role.noConfusion (old.1.symm.trans role)

meta section

private def shortName (r : Name) := (`ConsensusCoverage.HandReadersTrunkD.Term.Site).str r.getString!
private def shortIff (r : Name) := (shortName r).appendAfter "_iff"

private partial def fields (p : Expr) (xs : Array (Expr × Expr)) : MetaM (Option Expr) := do
  for (x,t) in xs do
    if ← Facts.matching t p then return some x
  if p.isAppOfArity ``Eq 3 then
    if ←withReducible <| isDefEq (p.getArg! 1) p.appArg! then return some (←mkEqRefl p.appArg!)
  if p.isAppOfArity ``And 2 then
    let some a ← fields (p.getArg! 0) xs | return none
    let some b ← fields p.appArg! xs | return none
    return some (←mkAppM ``And.intro #[a,b])
  if p.isAppOfArity ``Exists 2 then
    for (x,t) in xs do
      if ← Facts.matching t (p.getArg! 0) then
        if let some h ← fields (p.appArg!.beta #[x]) xs then
          return some (←mkAppOptM ``Exists.intro #[none,p.appArg!,x,h])
  return none

-- The term projection is called repeatedly in different postconditions of
-- the same batch, ACK, or campaign. Keep one weak continuation per origin.
private def thin (r : Name) : MetaM Unit := do
  let ci ← getConstInfo r
  lambdaTelescope ci.value! fun xs body => do
    let arms := HandReadersBFactor.disjuncts body
    let mut heads := #[]
    let mut ids := #[]
    for arm in arms do
      let #[dep] := ReachPath.children r.getPrefix arm | throwError "expected one immediate caller"
      unless ids.contains dep do heads := heads.push arm; ids := ids.push dep
    let slim := HandReadersTrunkA.Factor.disj heads.toList
    let dest := shortName r
    addDecl (.defnDecl {name := dest,levelParams := [],type := ci.type,value := ←mkLambdaFVars xs slim,hints := .abbrev,safety := .safe})
    let forward ← arms.mapM fun arm => do
      let i := ids.idxOf (ReachPath.children r.getPrefix arm)[0]!
      let target := heads[i]!
      withLocalDeclD `site arm fun site => do
        let pf ← if arm == target then pure site else
          Transfer.unpack [] arm site #[] fun data => do
            let mut args := data
            let mut ty := target
            let mut pin := none
            for e in data do
              let p ←inferType e
              if p.isAppOfArity ``Eq 3 && p.getArg! 1 == xs[4]! then
                ty := target.replaceFVar xs[4]! p.appArg!
                pin := some e
              if p.isAppOf ``Advance then
                args := args ++ #[←mkAppM ``Advance.term #[e],←mkAppM ``Advance.log #[e]]
                if let some nc ← observing? (mkAppM ``notCandidate #[e,←mkEqRefl (mkConst ``Role.primary)]) then
                  args := args.push nc
              if p.isAppOf ``Campaign then args := args ++ #[←mkAppM ``keepVote #[e],←mkAppM ``leaderImpossible #[e]]
            let typed ←args.mapM fun x => do return (x,←inferType x)
            let some out ← fields ty typed | throwError "cannot project {r.getString!} arm {arms.idxOf arm} to {i}"
            let out ← if let some eq := pin then do
              let cong ←mkAppM ``congrArg #[←mkLambdaFVars #[xs[4]!] target,eq]
              mkAppM ``Eq.mpr #[cong,out]
              else pure out
            mkExpectedTypeHint out target
        mkLambdaFVars #[site] (←HandReadersBFactor.into slim pf i heads.size)
    let reverse ← heads.toList.mapM fun arm => withLocalDeclD `s arm fun s => do
      mkLambdaFVars #[s] (←HandReadersBFactor.into body s (arms.idxOf arm) arms.length)
    let lhs := mkAppN (mkConst r) xs
    let rhs := mkAppN (mkConst dest) xs
    let mp ←withLocalDeclD `h lhs fun h => do mkLambdaFVars #[h] (←HandReadersBFactor.outOf body h rhs forward)
    let mpr ←withLocalDeclD `h rhs fun h => do mkLambdaFVars #[h] (←HandReadersBFactor.outOf slim h lhs reverse)
    addDecl (.thmDecl {
      name := shortIff r,levelParams := [],type := ←mkForallFVars xs (←mkAppM ``Iff #[lhs,rhs])
      value := ←mkLambdaFVars xs (←mkAppM ``Iff.intro #[mp,mpr])})

end

run_cmd liftTermElabM do
  let q := ``step_term_advance_inr
  for r in ReachPath.children q.getPrefix (←getConstInfo q).value! do thin r

end ConsensusCoverage.HandReadersTrunkD.Term
