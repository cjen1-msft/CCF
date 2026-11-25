module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBPrefixDirect
public import ConsensusCoverage.HandReadersElectionBPrefixAccept
public import ConsensusCoverage.HandReadersElectionBPrefixLogs
public import ConsensusCoverage.HandReadersElectionBPrefixCopies
import all ConsensusCoverage.HandReadersElectionBPrefixParts
import all ConsensusCoverage.HandReadersElectionBComparable
import all ConsensusCoverage.HandReadersElectionBAnchor
import all ConsensusCoverage.DeepComparableCases
import all ConsensusCoverage.HandReadersElectionAgreement
import all ConsensusCoverage.HandReadersElectionCoreSites
import all ConsensusCoverage.HandReadersElectionPairs
import all ConsensusCoverage.HandReadersBFactor
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersElectionBPrefixParts
public meta import ConsensusCoverage.HandReadersBFactor
public meta import Lean

namespace ConsensusCoverage.HandReadersElectionB.Prefix

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety SolvedWitnesses
open ActionProfile HandReadersA HandReadersElection ReadersAtoms
set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option Elab.async false
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private theorem agreement {f t} [Config.InitialConfiguration] (c : Ctx f t) {l log b i d}
    (h : Agreement.Site c l b i log d) (lt : b < d) (le : d ≤ i) :
    Pairs.Evidence c Comparable.test := by
  obtain ⟨k,pair⟩ := Agreement.pair_of_site c h
  exact ⟨l,k,b,i,log,d,pair,decide_eq_true ⟨lt,le⟩⟩

local macro "pathFact " h:ident : tactic => `(tactic| {
  have spine := $h
  repeat' first | exact spine | exact spine.1
                | change _ ∧ _ at spine; obtain ⟨_,spine⟩ := spine
                | change Exists _ at spine; obtain ⟨_,spine⟩ := spine })

open Lean Meta Elab Command Term in
run_cmd liftTermElabM do
  for d in [true,false] do
    let as_ ← PrefixParts.atoms d
    let q := if d then ``step_take_eq_take_of_comparable_comparable_inl else ``step_take_eq_take_of_comparable_comparable_inr
    lambdaTelescope (←getConstInfo q).value! fun xs _ => do
      let c := xs[3]!
      let proof := mkAppN (Lean.mkConst (PrefixParts.splitName d)) xs
      let tree := (←inferType proof).appArg!
      let direct := as_.filter (·.family == .direct)
      let groups := (List.range 4).map fun j => direct.toList.filter fun a => PrefixParts.batch a.site == j
      let propositions := groups.map fun g => g.map fun a => mkAppN (Lean.mkConst a.name) xs
      let grouped := propositions.map PrefixParts.disj
      let directTy := PrefixParts.disj grouped
      let ns := PrefixParts.scope ++ (if d then `Forward else `Reverse)
      let dn := ns ++ `Direct
      addDecl (.defnDecl {
        name := dn,levelParams := [],type := ←mkForallFVars xs (mkSort .zero),
        value := ←mkLambdaFVars xs directTy,hints := .abbrev,safety := .safe })
      let dir ←mkAppM ``Pairs.Evidence #[c,Lean.mkConst ``Comparable.test]
      let anchor ←mkAppM ``Anchor.Evidence #[c,toExpr d]
      let other := mkApp2 (Lean.mkConst ``Or) dir anchor
      let tgt := mkApp2 (Lean.mkConst ``Or) (mkAppN (Lean.mkConst dn) xs) other
      let leaf (p h : Expr) : TermElabM Expr := do
        let n := p.getAppFn.constName!
        let some a := as_.find? (·.name == n) | throwError "lost comparison leaf {n}"
        match a.family with
        | .direct =>
          let j := PrefixParts.batch a.site
          let i := groups[j]!.findIdx (·.name == n)
          let sub ←HandReadersBFactor.into grouped[j]! h i groups[j]!.length
          mkAppOptM ``Or.inl #[none,some other,some (←HandReadersBFactor.into directTy sub j groups.length)]
        | _ =>
          let (lemma,tac) ← if a.family == .agreement then do
            pure (dir,←`(tactic| {
              rintro ⟨_,_,_,⟨l,log,b,i,site,lt,_,_,_,le,_⟩,_⟩
              apply agreement _ (l := l) (log := log) (b := b) (i := i) _ lt le
              repeat' first | exact site | exact Or.inl site | apply Or.inr }))
          else do
            pure (anchor,←`(tactic| {
              rintro ⟨a,l,i,⟨g,n,k,b,later,commit,bound,j,log,site,rest⟩,direction,_⟩
              apply Anchor.necessary _ (g := g) (n := n) (k := k) (b := b) (i := i) (later := later)
                (d := commit) (bound := bound) (j := j) (l := l) (r := log) (a := a)
              · repeat' first | exact site | exact Or.inl site | apply Or.inr
              all_goals first | exact direction | pathFact rest }))
          let g ←mkFreshExprSyntheticOpaqueMVar (←mkArrow p lemma)
          let gs ← Tactic.run g.mvarId! <| Tactic.withoutRecover (Tactic.evalTactic tac)
          unless gs.isEmpty do throwError "unresolved {a.name} ({gs.length} goals): {←gs[0]!.getType}"
          let v := mkApp (←instantiateMVars g) h
          let v ← if a.family == .agreement then mkAppOptM ``Or.inl #[none,some anchor,some v]
            else mkAppOptM ``Or.inr #[some dir,none,some v]
          mkAppOptM ``Or.inr #[some (mkAppN (Lean.mkConst dn) xs),none,some v]
      let rec walk (p h : Expr) : TermElabM Expr := do
        if !p.isAppOf ``Or then return ←leaf p h
        let branch (s : Expr) := withLocalDeclD `arm s fun a => do mkLambdaFVars #[a] (←walk s a)
        return ProofWalk.casesOr p h tgt (←branch (p.getArg! 0)) (←branch p.appArg!)
      let fw ←withLocalDeclD `raw (mkAppN (Lean.mkConst q) xs) fun h => do
        mkLambdaFVars #[h] (←walk tree (←mkAppM ``Iff.mp #[proof,h]))
      addDecl (.thmDecl {
        name := ns ++ `necessary,levelParams := [],
        type := ←mkForallFVars xs (←mkArrow (mkAppN (Lean.mkConst q) xs) tgt),
        value := ←mkLambdaFVars xs fw })
      let rec enter (p val : Expr) : MetaM (Option Expr) := do
        if !p.isAppOf ``Or then return if (←inferType val).getAppFn == p.getAppFn then some val else none
        if let some w ←enter (p.getArg! 0) val then return some (←mkAppOptM ``Or.inl #[none,some p.appArg!,some w])
        if let some w ←enter p.appArg! val then return some (←mkAppOptM ``Or.inr #[some (p.getArg! 0),none,some w])
        return none
      let back ←withLocalDeclD `h (mkAppN (Lean.mkConst dn) xs) fun h => do
        let fs ←propositions.mapM fun group => withLocalDeclD `group (PrefixParts.disj group) fun h => do
          let gs ←group.mapM fun p => withLocalDeclD `leaf p fun a => do
            let some w ← enter tree a | throwError "lost direct comparison"
            mkLambdaFVars #[a] (←mkAppM ``Iff.mpr #[proof,w])
          mkLambdaFVars #[h] (←HandReadersBFactor.outOf (PrefixParts.disj group) h (mkAppN (Lean.mkConst q) xs) gs)
        mkLambdaFVars #[h] (←HandReadersBFactor.outOf directTy h (mkAppN (Lean.mkConst q) xs) fs)
      addDecl (.thmDecl {
        name := ns ++ `ofDirect,levelParams := [],type := ←mkForallFVars xs (←inferType back),value := ←mkLambdaFVars xs back })
      let xt := Lean.mkConst ``XView
      withLocalDeclD `x xt fun x => do
        let okTy ←mkAppM ``XView.Matches #[x,c]
        withLocalDeclD `matches okTy fun ok => do
          let mut bs := #[]
          let mut ps := #[]
          for j in [:4] do
            let gn := PrefixParts.groupName j d
            let run := Lean.mkConst gn
            let cert := Lean.mkConst (gn.appendAfter "_iff")
            bs := bs.push (mkApp2 run xs[0]! x)
            ps := ps.push (mkAppN cert ((xs.push x).push ok))
          let body := bs.pop.foldr (mkApp2 (Lean.mkConst ``Bool.or)) bs.back!
          let mut pr := ps.back!
          for p in ps.pop.reverse do pr ←mkAppM ``ReadersAtoms.or_cert #[p,pr]
          let fn := ns ++ `readDirect
          let runtime := #[xs[0]!,x]
          ReadersCompiler.addReader (.defnDecl {
            name := fn,levelParams := [],type := ←mkForallFVars runtime (Lean.mkConst ``Bool),
            value := ←mkLambdaFVars runtime body,hints := .regular 0,safety := .safe })
          let vars := (xs.push x).push ok
          addDecl (.thmDecl {
            name := ns ++ `readDirect_iff,levelParams := [],
            type := ←mkForallFVars vars (←mkAppM ``Iff #[←mkEq (mkAppN (Lean.mkConst fn) runtime) (toExpr true),
              mkAppN (Lean.mkConst dn) xs]),value := ←mkLambdaFVars vars pr })

def column (forward : Bool) : Classes.StepBranch :=
  if forward then .take_eq_take_of_comparable_comparable_inl else .take_eq_take_of_comparable_comparable_inr

private def direct [Config.InitialConfiguration] (forward : Bool) (x : XView) :=
  if forward then PrefixParts.Forward.readDirect x else PrefixParts.Reverse.readDirect x

def reader (forward : Bool) : Reader := fun cfg s a t hist =>
  (Comparable.agreementReader cfg s a t hist || Anchor.reader forward cfg s a t hist) ||
    (ofXAction cfg s t hist a).any (@direct ⟨cfg⟩ forward)

private def rawExact (forward : Bool) : Exact (column forward) where
  eval := reader forward
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    let c := s.context
    obtain ⟨x,made,ok⟩ := ofXAction_matches s
    apply Bool.eq_iff_iff.mpr
    rw [label_true,holds,sig_iff,reader,Bool.or_eq_true,Bool.or_eq_true,
      Comparable.agreementReader,Pairs.reader_iff,Anchor.reader_iff,made,Option.any_some]
    cases forward
    case false =>
      rw [direct,ite_eq_right Bool.false_ne_true,PrefixParts.Reverse.readDirect_iff _ _ c x ok]
      constructor
      · intro h
        rcases PrefixParts.Reverse.necessary _ _ c h with direct | agreement | anchor
        · exact .inr direct
        · exact .inl (.inl agreement)
        · exact .inl (.inr anchor)
      · rintro ((a | b) | d)
        · exact (Comparable.both c a).2
        · exact Anchor.sufficient s false b
        · exact PrefixParts.Reverse.ofDirect _ _ c d
    case true =>
      rw [direct,ite_eq_left rfl,PrefixParts.Forward.readDirect_iff _ _ c x ok]
      constructor
      · intro h
        rcases PrefixParts.Forward.necessary _ _ c h with direct | agreement | anchor
        · exact .inr direct
        · exact .inl (.inl agreement)
        · exact .inl (.inr anchor)
      · rintro ((a | b) | d)
        · exact (Comparable.both c a).1
        · exact Anchor.sufficient s true b
        · exact PrefixParts.Forward.ofDirect _ _ c d

private def unchangedLog : Reader := fun cfg pre a post hist =>
  (ofXAction cfg pre post hist a).any fun x =>
    decide (x.base.changed = true ∧ x.base.pre.log = x.base.post.log ∧ 1 ≤ x.base.pre.log.length)

def exactReader (forward : Bool) : Exact (column forward) where
  eval cfg pre a post hist := unchangedLog cfg pre a post hist || reader forward cfg pre a post hist
  eq_label s := by
    cases h : unchangedLog s.cfg s.before s.act s.after s.past with
    | false => exact (rawExact forward).eq_label s
    | true => exact DeepComparableCases.sound s forward h

end ConsensusCoverage.HandReadersElectionB.Prefix
