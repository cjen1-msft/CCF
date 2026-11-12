module

public meta import Lean
public import Relevance.Split

/-!
# The eliminator chains of a recorded split

Nothing here mentions a particular model. The proof of a recorded split is the splitter's term:
eliminators (`casesOn`, `dite`, `Or.casesOn`, `And.casesOn`, transports such as `Eq.ndrec`, ...)
whose minor premises are functions that end, after zero or more further eliminators, in a branch
marker. The chain of a branch is the list of binders of those functions, in order, from the split
marker to the branch marker.

The type of each binder is read from the type of the eliminator, not from the binder's annotation
in the term: for an application `f a₁ … aₖ` whose argument `aᵢ` leads to a branch marker, the
expected type of `aᵢ` is the domain of the type of `f a₁ … aᵢ₋₁`, and the type of each binder of
`aᵢ` is the domain of that type (instantiated with the earlier binders, after weak-head
normalisation, which unfolds the motive application). This is the type that the kernel checks the
binder against.

A binder is consumed when a later eliminator on the chain mentions it outside the arguments that
lead to the branch marker (for example the major premise `h : A ∧ B` of `And.casesOn h`, or the
equation that a transport rewrites with); the others are the hypotheses that the split leaves in
the branch.
-/

public meta section

open Lean Meta

namespace Relevance

structure ChainBinder where
  name : Name
  /-- The type that the eliminator gives the binder, over the earlier binders of the chain as loose
  bound variables (`instantiateRev` with them, in order). -/
  type : Expr
  isProp : Bool
  isLet : Bool
  consumed : Bool := false
  deriving Inhabited

structure Chain where
  tag : String
  binders : Array ChainBinder := #[]
  /-- Why the chain could not be read, if it could not. -/
  error : String := ""
  deriving Inhabited

/-- The tags of the branch markers in `e` that belong to the split whose term `e` is part of:
not inside a branch marker or a nested split marker. -/
partial def ownMarks (e : Expr) : Array String :=
  match e with
  | .app .. =>
    let f := e.getAppFn
    let args := e.getAppArgs
    if f.isConstOf ``branchMark then #[(args[1]?.bind strLit?).getD "?"]
    else if f.isConstOf ``splitMark then #[]
    else args.foldl (fun acc a => acc ++ ownMarks a) (ownMarks f)
  | .lam _ t b _ | .forallE _ t b _ => ownMarks t ++ ownMarks b
  | .letE _ t v b _ => ownMarks t ++ ownMarks v ++ ownMarks b
  | .mdata _ b | .proj _ _ b => ownMarks b
  | _ => #[]
where
  strLit? : Expr → Option String
    | .lit (.strVal s) => some s
    | .mdata _ e => strLit? e
    | _ => none

def hasBranchMark (e : Expr) : Bool := !(ownMarks e).isEmpty

/-- The chains of the branch markers reached from `p` (the splitter's term), in the order of
the arguments that lead to them. -/
partial def elimChains (p : Expr) : MetaM (Array Chain) :=
  go p none #[] #[]
where
  /-- `fvs`: the chain's binders so far (local variables); `bs`: their records. -/
  go (e : Expr) (expected : Option Expr) (fvs : Array Expr) (bs : Array ChainBinder) :
      MetaM (Array Chain) := do
    match e with
    | .mdata _ b => go b expected fvs bs
    | .lam n _ b bi =>
      let some ex := expected | return fail e s!"binder {n} has no eliminator type"
      let ex ← whnf ex
      let .forallE _ d _ _ := ex | return fail e s!"binder {n}: expected type is not a function"
      withLocalDecl n bi d fun x => do
        let rec_ : ChainBinder :=
          { name := n, type := (← instantiateMVars d).abstract fvs, isProp := ← isProp d,
            isLet := false }
        go (b.instantiate1 x) (some (ex.bindingBody!.instantiate1 x)) (fvs.push x) (bs.push rec_)
    | .letE n t v b _ =>
      withLetDecl n t v fun x => do
        let rec_ : ChainBinder :=
          { name := n, type := (← instantiateMVars t).abstract fvs, isProp := ← isProp t,
            isLet := true }
        go (b.instantiate1 x) expected (fvs.push x) (bs.push rec_)
    | .app .. =>
      let f := e.getAppFn
      let args := e.getAppArgs
      if f.isConstOf ``branchMark then
        return (ownMarks e).map ({ tag := ·, binders := bs })
      if f.isLambda then return ← go e.headBeta expected fvs bs
      unless f.isConst do
        return fail e "the head of an application on the chain is not a constant"
      -- binders mentioned by the proofs passed to the eliminator (major premises, equations)
      -- that do not lead to a branch marker are consumed
      let mut bs := bs
      for a in args do
        if hasBranchMark a then continue
        unless ← (try isProof a catch _ => pure false) do continue
        for i in [0:fvs.size] do
          if a.containsFVar fvs[i]!.fvarId! then bs := bs.modify i ({ · with consumed := true })
      let fty ← inferType f
      let mut out := #[]
      for i in [0:args.size] do
        let a := args[i]!
        unless hasBranchMark a do continue
        let ty ← instantiateForall fty (args.extract 0 i)
        let ty ← whnf ty
        let .forallE _ d _ _ := ty | return out ++ fail a s!"argument {i} has no expected type"
        out := out ++ (← go a (some d) fvs bs)
      return out
    | _ => return fail e "no branch marker"
  /-- One failed chain per branch marker of `e`. -/
  fail (e : Expr) (msg : String) : Array Chain := (ownMarks e).map ({ tag := ·, error := msg })

end Relevance

end
