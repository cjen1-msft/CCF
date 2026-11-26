module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBReflect
public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.ReadersAtoms
public import ConsensusCoverage.ReadersShapes
public import ConsensusCoverage.HandReadersABase
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersElectionBReflect
public meta import ConsensusCoverage.ReachPath
public meta import Lean

namespace ConsensusCoverage.HandReadersElectionB.LedRows

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety
open ActionProfile SolvedWitnesses HandReadersA ReadersAtoms HandReadersElection
set_option maxRecDepth 16384
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option Elab.async false

private theorem peer [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) (n k : Nat) :
    ¬(reach% step_led_after_led_inl[0,1]) f t c c n k := by
  rintro ⟨_,⟨_,_,delta,_⟩,⟨other,old⟩,_,_,_,led,_⟩
  exact delta ⟨old,c.led_other other led⟩

open Lean Meta Elab Command in
set_option maxHeartbeats 0 in
run_cmd liftTermElabM do
  let q := ``step_led_after_led_inl
  let sites := ReachPath.children q.getPrefix (←getConstInfo q).value!
  Reflect.compile `ConsensusCoverage.HandReadersElectionB.LedRows.Reflected sites #[``peer]

open Lean Meta Elab Term in
local elab "sites% " args:term:arg* : term => do
  let q := ``step_led_after_led_inl
  let mut arms := #[]
  for n in ReachPath.children q.getPrefix (←getConstInfo q).value! do
    let id := mkIdent n
    arms := arms.push (←elabTerm (←`($id $args*)) none)
  return arms.pop.foldr (mkApp2 (mkConst ``Or)) arms.back!

open Lean Meta Elab Term in
local elab "tests% " args:term:arg* : term => do
  let q := ``step_led_after_led_inl
  let mut arms := #[]
  for n in ReachPath.children q.getPrefix (←getConstInfo q).value! do
    let id := mkIdent ((`ConsensusCoverage.HandReadersElectionB.LedRows.Reflected.R).str n.getString!)
    arms := arms.push (←`($id $args*))
  let mut r := arms.back!
  for a in arms.pop.reverse do r ←`($a || $r)
  elabTerm r none

open Lean Meta Elab Tactic in
local elab "testIffs " ctx:term:arg x:term:arg ok:term:arg : tactic => do
  let q := ``step_led_after_led_inl
  let mut rs := #[]
  for n in ReachPath.children q.getPrefix (← getConstInfo q).value! do
    let id := mkIdent ((`ConsensusCoverage.HandReadersElectionB.LedRows.Reflected.R).str (n.getString! ++ "_iff"))
    rs := rs.push (←`($id _ _ $ctx $x $ok))
  evalTactic (←`(tactic| simp only [Bool.or_eq_true,$[$rs:term],*]))

private abbrev Sites [Config.InitialConfiguration] {f t} (c : Ctx f t) (n : NodeID) (k : Nat) :=
  sites% f t c n k

private def test [Config.InitialConfiguration] (x : XView) (n : NodeID) (k : Nat) := tests% x n k

private theorem test_iff [Config.InitialConfiguration] {f t} (c : Ctx f t) (x : XView) (ok : x.Matches c)
    (n : NodeID) (k : Nat) : test x n k = true ↔ Sites c n k := by
  unfold test Sites
  testIffs c x ok

inductive Kind where | bootstrap | elected | previous
def column : Kind → Classes.StepBranch
  | .bootstrap => .led_after_led_inl
  | .elected => .led_after_led_inr
  | .previous => .led_after_elected_after_inl

private def eval [Config.InitialConfiguration] (kind : Kind) (x : XView) : Bool :=
  match kind with
  | .bootstrap => test x x.base.bootstrap BOOTSTRAP_TERM
  | .elected => (Pairs.elections (x.base.after :: x.base.before :: x.base.past)).any fun v => test x v.1 v.2.1
  | .previous => (Pairs.elections (x.base.before :: x.base.past)).any fun v => test x v.1 v.2.1

private abbrev Voted [Config.InitialConfiguration] (f : Frame) (t : State) (old : Bool)
    (n k : Nat) (l : List Entry) (i : Nat) := if old then Elected f n k l i else Elected (f.advance t) n k l i

private theorem vote_iff [Config.InitialConfiguration] {f t} (c : Ctx f t) (old : Bool) :
    sig c (if old then .led_after_elected_after_inl else .led_after_led_inr) ↔
    ∃ n k l i, Sites c n k ∧ Voted f t old n k l i := by
  constructor
  · intro h
    cases old
    all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨n,k,site,_,l,_,i,h,tail⟩ := h
      refine ⟨n,k,l,i,?_,?_⟩
      · repeat' first | exact site | exact Or.inl site | apply Or.inr
      · first | exact h | exact tail.1
  · rintro ⟨n,k,l,i,site,v⟩
    have after_ : Elected (f.advance t) n k l i := by cases old <;> first | exact v | exact .inl v
    have led : Led (f.advance t) n k := .inr ⟨l,i,after_⟩
    cases old <;> rcases site with site | site | site | site | site | site | site | site | site | site | site
    all_goals
      repeat' first
        | exact ⟨n,k,site,⟨l,i,after_⟩,l,⟨i,after_⟩,i,after_,led⟩
        | exact Or.inl ⟨n,k,site,⟨l,i,after_⟩,l,⟨i,after_⟩,i,after_,led⟩
        | exact ⟨n,k,site,⟨l,i,after_⟩,l,⟨i,after_⟩,i,after_,v,led⟩
        | exact Or.inl ⟨n,k,site,⟨l,i,after_⟩,l,⟨i,after_⟩,i,after_,v,led⟩ | apply Or.inr

private theorem eq_test (kind : Kind) [Config.InitialConfiguration] {f t} (c : Ctx f t)
    (x : XView) (ok : x.Matches c) : eval kind x = true ↔ sig c (column kind) := by
  cases kind
  case bootstrap =>
    have led : Led (f.advance t) Config.INITIAL_PRIMARY BOOTSTRAP_TERM := .inl ⟨rfl,rfl⟩
    rw [eval,X.bootstrap ok,test_iff c x ok]
    change Sites c _ _ ↔ step_led_after_led_inl _ _ _
    simp only [Sites,step_led_after_led_inl,led,and_true]
  case elected =>
    change _ ↔ sig c (if false then .led_after_elected_after_inl else .led_after_led_inr)
    rw [vote_iff c false]
    simp only [eval,List.any_eq_true,Prod.exists,Pairs.mem_elections,
      ← X.elected_after ok,test_iff c x ok,Voted,Bool.false_eq_true,ite_false]
    constructor <;> rintro ⟨n,k,l,i,a,b⟩ <;> exact ⟨n,k,l,i,b,a⟩
  case previous =>
    change _ ↔ sig c (if true then .led_after_elected_after_inl else .led_after_led_inr)
    rw [vote_iff c true]
    simp only [eval,List.any_eq_true,Prod.exists,Pairs.mem_elections,
      ← X.elected_before ok,test_iff c x ok,Voted,ite_true]
    constructor <;> rintro ⟨n,k,l,i,a,b⟩ <;> exact ⟨n,k,l,i,b,a⟩

def bootstrap : Exact .led_after_led_inl := Reflect.exact _ (fun {_} => eval .bootstrap) (eq_test .bootstrap)
def elected : Exact .led_after_led_inr := Reflect.exact _ (fun {_} => eval .elected) (eq_test .elected)
def previous : Exact .led_after_elected_after_inl := Reflect.exact _ (fun {_} => eval .previous) (eq_test .previous)

end ConsensusCoverage.HandReadersElectionB.LedRows
