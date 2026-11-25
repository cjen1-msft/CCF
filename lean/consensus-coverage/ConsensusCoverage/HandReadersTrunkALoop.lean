module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersTrunkALoopGate
import all ConsensusCoverage.HandReadersTrunkARequest
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.FollowerFoldCasesB
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersBFactor
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.HandReadersTrunkA.Loop

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open HandReadersA ActionProfile FollowerFoldCasesB

set_option maxRecDepth 8192
set_option maxHeartbeats 600000
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

open Lean Meta Elab Command Term in
/-- Prove the local induction case once for an arbitrary caller predicate,
    then specialize it to each of the concrete direct and summary paths. -/
local elab "loop_equiv " q:ident " using " pr:term : command => liftTermElabM do
  let n ← realizeGlobalConstNoOverloadWithInfo q
  let cs := ReachPath.children n.getPrefix (← getConstInfo n).value!
  lambdaTelescope (←getConstInfo n).value! fun xs p => do
    let es := HandReadersBFactor.disjuncts p
    let live := mkAppN (mkConst ``Live) xs
    let ls := HandReadersBFactor.disjuncts (←unfoldDefinition? live).get!
    let stem := mkAppN (mkConst cs[0]!) xs
    let first ← withLocalDeclD `R (←inferType stem) fun r => do
      let sub (e : Expr) := e.replace fun w => if w == stem then some r else none
      let ty ← mkAppM ``Iff #[sub es.head!,sub ls.head!]
      let pf ← elabTermEnsuringType pr ty
      synthesizeSyntheticMVarsNoPostponing
      mkLambdaFVars #[r] (←instantiateMVars pf)
    let mut eq := mkApp first (mkAppN (mkConst cs.back!) xs)
    for ch in cs.toList.dropLast.reverse do
      eq ← mkAppM ``or_congr #[mkApp first (mkAppN (mkConst ch) xs),eq]
    addDecl (.thmDecl {
      name := (`ConsensusCoverage.HandReadersTrunkA.Loop.Equiv).str n.getString!,levelParams := []
      type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,live])
      value := ←mkLambdaFVars xs eq })

loop_equiv step_fromLeader_loop_entries_cons using
  ⟨fun ⟨s,l,h,_⟩ => ⟨s,l,h⟩,fun ⟨s,l,h⟩ => ⟨s,l,h,[],Ledger.fromLeader_loop s l []⟩⟩
loop_equiv step_fromLeader_loop_signature_pos using
  ⟨fun ⟨s,l,h,_⟩ => ⟨s,l,h⟩,fun ⟨s,l,h⟩ => ⟨s,l,h,sg,[],Ledger.fromLeader_loop s l [],state [],rfl,Nat.le_refl _⟩⟩
loop_equiv step_fromLeader_loop_signature_neg using
  ⟨fun ⟨s,l,h,_⟩ => ⟨s,l,h⟩,fun ⟨s,l,h⟩ => ⟨s,l,h,tx,[],Ledger.fromLeader_loop s l [],state [],by decide,Nat.le_refl _⟩⟩

-- A generalized starting record with role none can retain its role and have
-- role none simultaneously, regardless of the request's commit bound.
local macro "both_roles" : term => `(by
  refine ⟨fun ⟨s,l,h,_⟩ => ⟨s,l,h⟩,?_⟩
  rintro ⟨self,lim,seed⟩
  refine ⟨self,lim,seed,sg,[],Ledger.fromLeader_loop self lim [],state [],rfl,?_⟩
  let j := max (state []).commitIndex (maxCommittableIndexUpTo ((state []).log ++ [sg]) lim)
  obtain ⟨r,b,k,re,roles⟩ := Ledger.NodeState.recordCommit_eq self
    {state [] with log := (state []).log ++ [sg]} j
  have gone : b = .none := roles.elim id id
  subst b
  repeat' first
    | assumption
    | rfl
    | exact Or.inl rfl
    | exact Or.inr rfl
    | exact Nat.le_refl _
    | exact Nat.le_max_left _ _
    | exact Nat.zero_le _
    | apply And.intro
    | refine Exists.intro r ?_
    | refine Exists.intro Role.none ?_
    | refine Exists.intro k ?_
    | refine Exists.intro j ?_)

loop_equiv step_fromLeader_loop_roleCase_inl using both_roles
loop_equiv step_fromLeader_loop_roleCase_inr using both_roles

private theorem nilDirect [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) :
    (reach% step_fromLeader_loop_entries_nil[0]) f t c ↔ ∃ self lim,
      (reach% step_fromLeader_loop_entries_cons[0]) f t c self lim := by
  constructor
  · rintro (⟨z,q,obs,rest⟩ | ⟨z,q,obs,rest⟩)
    all_goals
      obtain ⟨self,pre,src,m,recv,suffix⟩ := obs
      have obs : (reach% step_fromLeader_loop_entries_cons[0,0,0,0]) f t c self z q :=
        ⟨pre,src,m,recv,suffix⟩
      refine ⟨self,_,q,?_,rfl⟩
      first | exact .inl ⟨z,obs,rest⟩ | exact .inr ⟨z,obs,rest⟩
  · rintro ⟨self,_,q,entry,_⟩
    change (reach% step_fromLeader_loop_entries_cons[0,0,0]) f t c self q at entry
    rcases entry with ⟨z,obs,rest⟩ | ⟨z,obs,rest⟩
    all_goals
      obtain ⟨pre,src,m,recv,suffix⟩ := obs
      have obs : (reach% step_fromLeader_loop_entries_nil[0,0,0,0]) f t c z q :=
        ⟨self,pre,src,m,recv,suffix⟩
      first | exact .inl ⟨z,q,obs,rest⟩ | exact .inr ⟨z,q,obs,rest⟩

-- Only the order of existential witnesses changes for the summary callers.
local macro "nil_origin" : term => `(by
  constructor
  · rintro (⟨self,src,z,q,call,rest⟩ | ⟨self,src,z,q,call,rest⟩)
    · exact ⟨self,_,q,Or.inl ⟨src,z,call,rest⟩,rfl⟩
    · exact ⟨self,_,q,Or.inr ⟨src,z,call,rest⟩,rfl⟩
  · rintro ⟨self,_,q,h,_⟩
    rcases h with ⟨src,z,call,rest⟩ | ⟨src,z,call,rest⟩
    · exact .inl ⟨self,src,z,q,call,rest⟩
    · exact .inr ⟨self,src,z,q,call,rest⟩)

local macro "nil_pair" : term => `(by
  constructor
  · rintro (⟨self,src,z,q,call,rest⟩ | ⟨self,src,z,q,call,rest⟩ |
          ⟨self,src,z,q,call,rest⟩ | ⟨self,src,z,q,call,rest⟩)
    · exact ⟨self,_,q,Or.inl ⟨src,z,call,rest⟩,rfl⟩
    · exact ⟨self,_,q,Or.inr (Or.inl ⟨src,z,call,rest⟩),rfl⟩
    · exact ⟨self,_,q,Or.inr (Or.inr (Or.inl ⟨src,z,call,rest⟩)),rfl⟩
    · exact ⟨self,_,q,Or.inr (Or.inr (Or.inr ⟨src,z,call,rest⟩)),rfl⟩
  · rintro ⟨self,_,q,h,_⟩
    rcases h with ⟨src,z,call,rest⟩ | ⟨src,z,call,rest⟩ | ⟨src,z,call,rest⟩ | ⟨src,z,call,rest⟩
    · exact .inl ⟨self,src,z,q,call,rest⟩
    · exact .inr (.inl ⟨self,src,z,q,call,rest⟩)
    · exact .inr (.inr (.inl ⟨self,src,z,q,call,rest⟩))
    · exact .inr (.inr (.inr ⟨self,src,z,q,call,rest⟩)))

open Lean Meta in
private meta partial def replaceCallers (xs : Array Expr) (names : Array Name) (vars : Array Expr) (e : Expr) :
    MetaM Expr := do
  Core.transform e fun p => do
    let some n := p.getAppFn.constName? | return .continue
    unless n.getPrefix == `ConsensusCoverage.SolvedWitnesses && p.getAppNumArgs ≥ 4 do return .continue
    if let some i := names.idxOf? n then
      return .done (mkAppN vars[i]! (p.getAppArgs.extract xs.size p.getAppNumArgs))
    let body := (←getConstInfo n).value!.beta p.getAppArgs
    return .done (←replaceCallers xs names vars body)

open Lean Meta Elab Command Term in
run_cmd liftTermElabM do
  let n := ``step_fromLeader_loop_entries_nil
  lambdaTelescope (←getConstInfo n).value! fun xs p => do
    let live := mkAppN (mkConst ``Live) xs
    let as := HandReadersBFactor.disjuncts p
    let bs := HandReadersBFactor.disjuncts (←unfoldDefinition? live).get!
    let mut proofs := #[mkAppN (mkConst ``nilDirect) xs]
    let stops := ReachPath.children n.getPrefix (←getConstInfo ``step_aeReply_conflict_none).value!
    let mut generic : Std.HashMap Nat Expr := {}
    for (a,b) in as.tail!.zip bs.tail! do
      let names := (← (Factor.sources stops a).run' {}).toArray
      let stems := names.map fun r => mkAppN (mkConst r) xs
      let pf ← if let some old := generic[names.size]? then pure old else
        withLocalDeclsD (←stems.mapM fun st => do
          let ty ← inferType st
          pure (`R,fun _ => pure ty)) fun vs => do
          let lhs ← replaceCallers xs names vs a
          let rhs ← replaceCallers xs names vs b
          let pr ← if names.size == 1 then `(nil_origin) else `(nil_pair)
          let pf ← elabTermEnsuringType pr (←mkAppM ``Iff #[lhs,rhs])
          synthesizeSyntheticMVarsNoPostponing
          mkLambdaFVars vs (←instantiateMVars pf)
      generic := generic.insert names.size pf
      proofs := proofs.push (mkAppN pf stems)
    let mut eq := proofs.back!
    for pf in proofs.toList.dropLast.reverse do eq ← mkAppM ``or_congr #[pf,eq]
    addDecl (.thmDecl {
      name := `ConsensusCoverage.HandReadersTrunkA.Loop.Equiv.step_fromLeader_loop_entries_nil,levelParams := []
      type := ←mkForallFVars xs (←mkAppM ``Iff #[mkAppN (mkConst n) xs,live])
      value := ←mkLambdaFVars xs eq })

def exactOfLoop (b : Classes.StepBranch) (h : ∀ [Config.InitialConfiguration] {f : Frame} {t : State}
    (c : Ctx f t), sig c b ↔ Live f t c) : Exact b :=
  Request.exactOfTail b accepted fun s => by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    exact (h s.context).trans (live_iff s)

def cons := exactOfLoop .fromLeader_loop_entries_cons (fun c => Equiv.step_fromLeader_loop_entries_cons _ _ c)
def nilCase := exactOfLoop .fromLeader_loop_entries_nil (fun c => Equiv.step_fromLeader_loop_entries_nil _ _ c)
def signature := exactOfLoop .fromLeader_loop_signature_pos (fun c => Equiv.step_fromLeader_loop_signature_pos _ _ c)
def transaction := exactOfLoop .fromLeader_loop_signature_neg (fun c => Equiv.step_fromLeader_loop_signature_neg _ _ c)
def sameRole := exactOfLoop .fromLeader_loop_roleCase_inl (fun c => Equiv.step_fromLeader_loop_roleCase_inl _ _ c)
def noneRole := exactOfLoop .fromLeader_loop_roleCase_inr (fun c => Equiv.step_fromLeader_loop_roleCase_inr _ _ c)

end ConsensusCoverage.HandReadersTrunkA.Loop
