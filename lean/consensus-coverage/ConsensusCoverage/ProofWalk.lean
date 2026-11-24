module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import Lean

namespace ConsensusCoverage.ProofWalk

public meta section

open Lean Meta

abbrev Fact := Expr × Expr

def conjuncts (p h : Expr) : Fact × Fact :=
  let args := p.getAppArgs.push h
  ((p.getArg! 0, mkAppN (mkConst ``And.left) args),
   (p.getArg! 1, mkAppN (mkConst ``And.right) args))

def casesOr (p h result left right : Expr) : Expr :=
  mkAppN (mkConst ``Or.elim) (p.getAppArgs ++ #[result, h, left, right])

def casesExists (p h result branch : Expr) : Expr :=
  mkAppN (mkConst ``Exists.elim p.getAppFn.constLevels!) (p.getAppArgs ++ #[result, h, branch])

-- Abstract local hypotheses in the individual proof fragments, not in every
-- enclosing partial certificate as a long chain of branches is closed.
private abbrev Proof := Array Expr → Expr

private partial def search [Monad m] [MonadLiftT MetaM m] [MonadControlT MetaM m]
    (atom : Fact → m (Option Expr)) (path : List Fact → m (Option Expr))
    (pending facts choices : List Fact) : m (Option Proof) := do
  match pending with
  | (p, h) :: rest =>
    if p.isAppOfArity ``And 2 then
      let (left, right) := conjuncts p h
      search atom path (left :: right :: rest) facts choices
    else if p.isAppOfArity ``Or 2 then
      search atom path rest facts ((p, h) :: choices)
    else if p.isAppOfArity ``Exists 2 then
      let domain := p.getArg! 0
      withLocalDeclD `w domain fun w => do
        let body := p.appArg!.beta #[w]
        withLocalDeclD `hw body fun hw => do
          let some proof ← search atom path ((body, hw) :: rest) facts choices | return none
          return some fun xs =>
            let ys := xs.push w
            let branch := Lean.mkLambda `w .default (domain.abstract xs)
              (Lean.mkLambda `hw .default (body.abstract ys) (proof (ys.push hw)))
            casesExists (p.abstract xs) (h.abstract xs) (mkConst ``False) branch
    else if let some proof ← atom (p, h) then
      return some proof.abstract
    else
      search atom path rest ((p, h) :: facts) choices
  | [] =>
    if let some proof ← path facts then return some proof.abstract
    let (p, h) :: rest := choices | return none
    let split (p h : Expr) (more : List Fact) : m (Option Proof) := do
      let arm (q : Expr) := withLocalDeclD `hq q fun hq => do
        let some proof ← search atom path [(q, hq)] facts more | return none
        return some fun xs => Lean.mkLambda `hq .default (q.abstract xs) (proof (xs.push hq))
      let some left ← arm (p.getArg! 0) | return none
      let some right ← arm (p.getArg! 1) | return none
      return some fun xs => casesOr (p.abstract xs) (h.abstract xs) (mkConst ``False)
        (left xs) (right xs)
    unless rest.isEmpty do
      for (q, hq) in choices do
        if let some proof ← split q hq [] then return some proof
    split p h rest

/-- Process the conjunctive spine and try its disjunctions independently
before exploring combinations of disjuncts. -/
def refute [Monad m] [MonadLiftT MetaM m] [MonadControlT MetaM m]
    (atom : Fact → m (Option Expr)) (path : List Fact → m (Option Expr))
    (pending : List Fact) : m (Option Expr) := do
  return (← search atom path pending [] []).map (· #[])

end

end ConsensusCoverage.ProofWalk
