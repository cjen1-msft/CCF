module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkDAtZero
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.PromotionImpossibleB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.PromotionImpossibleB

namespace ConsensusCoverage.HandReadersTrunkD.Condition

open Consensus Model Model.Node Proofs Safety SolvedWitnesses Lean Meta Elab Command
set_option maxRecDepth 16384
set_option maxHeartbeats 2400000

private abbrev Ready (P : NodeState → List Model.Envelope → Prop) (p : Prop) (m n : NodeEffect NodeState) :=
  (p → Sends P m) ∧ (¬p → Sends P n)

private theorem pinned {P Q p q m a n b} (pP : P = Q) (pp : p = q) (pm : m = a) (pn : n = b)
    (h : Ready Q q a b) : Ready P p m n := pP ▸ pp ▸ pm ▸ pn ▸ h

private abbrev Site := (NodeState → List Model.Envelope → Prop) → Prop → NodeEffect NodeState → NodeEffect NodeState → Prop
private abbrev Picks (b : Bool) (p : Prop) := if b then p else ¬p
private abbrev Picked (R : Site) (b : Bool) := ∃ P p m n, R P p m n ∧ Picks b p

private theorem erase (R : Site) (b : Bool) (sends : ∀ P p m n, R P p m n → Ready P p m n) :
    (∃ P p m n, R P p m n ∧ Picks b p ∧ Ready P p m n) ↔ Picked R b :=
  ⟨fun ⟨P,p,m,n,h,cut,_⟩ => ⟨P,p,m,n,h,cut⟩,fun ⟨P,p,m,n,h,cut⟩ => ⟨P,p,m,n,h,cut,sends _ _ _ _ h⟩⟩

meta section
private def ns := `ConsensusCoverage.HandReadersTrunkD.Condition.Source

private def hasCall (e : Expr) := (e.find? (·.isConstOf ``Sends.ite')).isSome

-- Replay the two continuation proofs from the original application. In
-- particular, no executable search over higher-order postconditions is needed.
private partial def visit (owner : Name) (e : Expr) (locals : Array Expr) (next : IO.Ref Nat) : MetaM Unit := do
  unless hasCall e do return
  if e.isAppOfArity ``Sends.ite' 11 then
    let args := e.getAppArgs
    let proof ←mkAppM ``And.intro #[args[9]!,args[10]!]
    let value ←mkLambdaFVars locals proof (usedOnly := true)
    let i ←next.get
    let name := (ns.str owner.getString!).str s!"continuation{i}"
    addDecl (.thmDecl {name,levelParams:=[],type:=←inferType value,value})
    next.set (i+1)
  match e with
  | .lam n d b bi => withLocalDecl n bi d fun x => visit owner (b.instantiate1 x) (locals.push x) next
  | .letE n d v b _ =>
    visit owner v locals next
    withLetDecl n d v fun x => visit owner (b.instantiate1 x) (locals.push x) next
  | .app _ _ =>
    for arg in e.getAppArgs do visit owner arg locals next
    visit owner e.getAppFn locals next
  | .mdata _ b | .proj _ _ b => visit owner b locals next
  | _ => pure ()

private def handlers := [``startElection_summary,``appendEntriesResponse_summary,``voteResponse_summary,
  ``preVoteResponse_summary,``proposeVote_summary,``aeReply,``appendEntry_batch,``advanceCommit_sends,``electIfQuorum_sends]

run_cmd liftTermElabM do
  for owner in handlers do
    let next ←IO.mkRef 0
    let some value := (←getConstInfo owner).value? (allowOpaque := true) | throwError "missing source proof {owner}"
    visit owner value #[] next
    if (←next.get) == 0 then throwError "no conditional continuations in {owner}"

private def extracted : MetaM (Array Name) := do
  let env ←getEnv
  let mut out := #[]
  for h in handlers do
    let mut i : Nat := 0
    repeat
      let n := (ns.str h.getString!).str s!"continuation{i}"
      unless env.contains n do break
      out := out.push n
      i := i+1
  return out

private def realize (decl : Name) (args : Array Expr) (fs : PromotionImpossibleB.Fields) : MetaM Expr := do
  let (vs,_,p) ←forallMetaTelescope (←getConstInfo decl).type
  let target ←mkAppM ``Ready args
  let target := (←unfoldDefinition? target).get!
  unless ←withReducible (isDefEq p target) do failure
  for v in vs do
    if ←v.mvarId!.isAssigned then continue
    let ty ←instantiateMVars (←inferType v)
    let some (_,h) ←fs.findM? (fun (q,_)=>withReducible (isDefEq q ty)) | failure
    v.mvarId!.assign h
  let val ←instantiateMVars (mkAppN (mkConst decl) vs)
  if val.hasMVar then failure
  return val

private def readyName (r : Name) := (`ConsensusCoverage.HandReadersTrunkD.Condition.ReadyAt).str r.getString!

run_cmd liftTermElabM do
  let q := ``step_ite__condition_pos_2
  let sources ←extracted
  let rs := ReachPath.children q.getPrefix (←getConstInfo q).value!
  for r in rs do
    lambdaTelescope (←getConstInfo r).value! fun xs p=>do
      let args := xs.extract 4 8
      let target ←mkAppM ``Ready args
      withLocalDeclD `site (mkAppN (mkConst r) xs) fun h=>do
        let proof ←PromotionImpossibleB.withFields p h #[] fun fs=>do
          let pins ←args.mapM fun x=>do
            let some (p,h) := fs.find? (fun (p,_)=>p.isAppOfArity ``Eq 3 && p.getArg! 1 == x) |
              throwError "no conditional argument pin for {x}"
            return (p.appArg!,h)
          for src in sources do
            if let some pf ←observing? (realize src (pins.map Prod.fst) fs) then
              return ←mkAppM ``pinned ((pins.map Prod.snd).push pf)
          throwError "no source continuation for {(pins[1]!).1}"
        let v ←mkLambdaFVars (xs.push h) (←mkExpectedTypeHint proof target)
        addDecl (.thmDecl {name:=readyName r,levelParams:=[],type:=←inferType v,value:=v})

run_cmd liftTermElabM do
  let group := `ConsensusCoverage.HandReadersTrunkD.Condition.Guards
  for (q,b) in [(``step_ite__condition_pos_2,true),(``step_ite__condition_neg_2,false)] do
    lambdaTelescope (←getConstInfo q).value! fun xs body=>do
      let rs := ReachPath.children q.getPrefix body
      let ts ←rs.mapM fun r=>mkAppM ``Picked #[mkAppN (mkConst r) xs,toExpr b]
      let name := group.str (if b then "Positive" else "Negative")
      let disj := ts.toList.dropLast.foldr (mkApp2 (mkConst ``Or)) ts.back!
      let value ←mkLambdaFVars xs disj
      addDecl (.defnDecl {name,levelParams:=[],type:=←inferType value,value,hints:=.abbrev,safety:=.safe})
      let ps ←rs.mapM fun r=>mkAppM ``erase #[mkAppN (mkConst r) xs,toExpr b,mkAppN (mkConst (readyName r)) xs]
      let mut eq := ps.back!
      for p in ps.toList.dropLast.reverse do eq ←mkAppM ``or_congr #[p,eq]
      let type ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst q) xs,mkAppN (mkConst name) xs])
      addDecl (.thmDecl {name:=name.appendAfter "_iff",levelParams:=[],type,value:=←mkLambdaFVars xs eq})
end

end ConsensusCoverage.HandReadersTrunkD.Condition
