module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public meta import ConsensusCoverage.DelayedNominationPrune
public meta import ConsensusCoverage.EvidenceSupport
public meta import ConsensusCoverage.EventSupport
public meta import ConsensusCoverage.ProofWalk
public meta import ConsensusCoverage.StutterProfile
public import ConsensusCoverage.EvidenceSupport
public import ConsensusCoverage.EventSupport
public import ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.ActionContext
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.DelayedNominationPrune
import all ConsensusCoverage.EvidenceSupport
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.FamilyPrune

open ActionProfile FullProfile Consensus Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

/-- Baseline: intersect the independently certified event and freshness exclusions. -/
public def separate (tag : EventSupport.Tag) (stale : List EvidenceSupport.Family)
    (b : Classes.StepBranch) : Bool :=
  decide (tag ∈ EventSupport.allowed b) && !(EvidenceSupport.supports b).any (·.all (· ∈ stale))

public theorem lift_exclusion (s : Step) (tag : EventSupport.Tag) (stale : List EvidenceSupport.Family)
    (b : Classes.StepBranch)
    (act : EventSupport.actionTag s.act = tag)
    (bits : ∀ k ∈ stale, EvidenceSupport.fresh s.cfg s.before s.act s.after s.past k = false)
    (deny : letI : Config.InitialConfiguration := ⟨s.cfg⟩
      EventSupport.actionTag (ActionContext.action s.context) = tag →
      (∀ k ∈ stale, EvidenceSupport.Stable s.frame s.after k) →
      ¬ SolvedWitnesses.sig s.context b) : label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have kind : EventSupport.actionTag (ActionContext.action s.context) = tag :=
    ((s.context_eq s.context).mpr rfl).symm ▸ act
  exact Bool.eq_false_iff.mpr fun yes =>
    deny kind (fun k mem => (EvidenceSupport.fresh_iff s k).mp (bits k mem))
      ((SolvedWitnesses.sig_iff s.context b).mp ((label_true s _).mp yes))

private theorem lift_possible (tag : EventSupport.Tag) (stale : List EvidenceSupport.Family)
    (possible : Classes.StepBranch → Bool)
    (extra : ∀ [Config.InitialConfiguration] (f : Frame) (t : Model.State), Ctx f t → Prop)
    (cert : ∀ [Config.InitialConfiguration] (f : Frame) (t : Model.State) (c : Ctx f t) b,
      EventSupport.eventTag c.event ∈ [tag] → EvidenceSupport.AllStable f t stale →
      extra f t c → SolvedWitnesses.sig c b → possible b = true)
    (s : Step) (act : EventSupport.actionTag s.act = tag)
    (bits : ∀ k ∈ stale, EvidenceSupport.fresh s.cfg s.before s.act s.after s.past k = false)
    (h : letI : Config.InitialConfiguration := ⟨s.cfg⟩; extra s.frame s.after s.context)
    (b : Classes.StepBranch) (out : possible b = false) : label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply lift_exclusion s tag stale b act bits
  intro kind stable sig
  rw [EventSupport.actionTag_eq] at kind
  exact Bool.noConfusion (out.symm.trans (cert _ _ _ _ (List.mem_singleton.mpr kind) stable h sig))

private theorem noTag [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (tag : EventSupport.Tag) (b : Classes.StepBranch)
    (kind : EventSupport.eventTag c.event ∈ [tag]) (no : tag ∉ EventSupport.allowed b) :
    ¬ SolvedWitnesses.sig c b := by
  intro yes
  have support := EventSupport.sig_support c b ((SolvedWitnesses.sig_iff c b).mpr yes)
  rw [EventSupport.actionTag_eq, show EventSupport.eventTag c.tr.event = tag from
    List.mem_singleton.mp kind] at support
  exact no support

meta section
open Lean Meta Elab Command

public abbrev Atom := Expr × Expr

/-- Specializations can provide an extra proposition of the pinned context
and reuse local equations, reach implications, or contradictions from it. -/
public structure Extra where
  type : Array Expr → MetaM Expr := fun _ => pure (mkConst ``True)
  rules : Array Expr → Expr → MetaM SimpTheorems := fun _ _ => pure {}
  deny : Expr → List Atom → MetaM (Option Expr) := fun _ _ => pure none

private structure Spec where
  ns : Name
  tag : Name
  mask : EvidenceSupport.Mask
  extra : Extra
  simplify : Bool
  inlineDepth : Nat
  certificates : List EvidenceSupport.Mask

private structure Path where
  evidence : EvidenceSupport.Check
  key : Expr
  initial : EventSupport.Fact
  extra : Expr
  simpCtx : Simp.Context

private abbrev Gen := StateRefT (Std.HashMap Name (Option Name)) MetaM

private def isReach (n : Name) : Bool :=
  n.getPrefix == `ConsensusCoverage.SolvedWitnesses && n.getString!.startsWith "reach_"

private theorem mem_nil_false {tag : EventSupport.Tag} (h : tag ∈ ([] : List EventSupport.Tag)) :
    False := List.not_mem_nil h

private def oldEvidence (sp : Spec) (path : Path) (p h : Expr) : MetaM (Option Expr) := do
  let .const n us := p.getAppFn | return none
  unless n.getPrefix == `ConsensusCoverage.SolvedWitnesses &&
      (n.getString!.startsWith "reach_" || n.getString!.startsWith "step_") do return none
  let env ← getEnv
  for mask in sp.certificates do
    let cert := `ConsensusCoverage.EvidenceSupport ++ Name.mkSimple
      (n.getString! ++ "_stable_" ++ toString mask)
    if env.contains cert then
      let args := p.getAppArgs
      let old := mkAppN (mkConst (`ConsensusCoverage.PinnedClasses ++ Name.mkSimple n.getString!) us) args
      let iff := mkAppN (mkConst (n.appendAfter "_iff") us) args
      let pin := mkAppN (mkConst ``Iff.mpr) #[old, p, iff, h]
      return some (mkAppN (mkConst cert us) (args ++ mask.indices.toArray.map (path.evidence.stable[·]!) ++ #[pin]))
  return none

private def tagConflict (path : Path) (tags : Array EventSupport.Fact) : MetaM (Option Expr) := do
  if tags.isEmpty then return none
  let tags ← EventSupport.close (tags.push path.initial)
  for f in tags do
    if let .mem _ [] := f.cond then return some (← mkAppM ``mem_nil_false #[f.proof])
  return none

private def atLeaf (sp : Spec) (path : Path) (atoms : List Atom)
    (tags : Array EventSupport.Fact) : MetaM (Option Expr) := do
  for (p, h) in atoms do
    if p.isAppOfArity ``Not 1 then
      if let some hp ← EvidenceSupport.rebuild path.evidence atoms p.appArg! then
        return some (mkApp h hp)
  if let some pf ← tagConflict path tags then return some pf
  if let some pf ← sp.extra.deny path.extra atoms then return some pf
  if sp.simplify then
    DelayedNomination.contradict path.simpCtx atoms
  else return none

private def tagFacts (p h : Expr) : MetaM (Array EventSupport.Fact) := do
  if p.isAppOfArity ``Eq 3 then
    EventSupport.fromEq (p.getArg! 0) (p.getArg! 1) (p.getArg! 2) h
  else if p.isAppOfArity ``And 2 && (p.getArg! 0).isAppOfArity ``Eq 3 &&
      (p.getArg! 1).isAppOfArity ``HEq 4 && ((p.getArg! 1).getArg! 0).isAppOf ``LocalTransition then
    let a := (p.getArg! 1).getAppArgs
    let some l ← EventSupport.observation a[0]! a[1]! | return #[]
    let some r ← EventSupport.observation a[2]! a[3]! | return #[]
    return #[⟨.eq l r, ← mkAppM ``EventSupport.tag_of_pin #[h]⟩]
  else return #[]

/-- Reuse the precomputed tag summaries via the checked normalization iff. -/
private def reachTags (n : Name) (us : List Level) (p h : Expr) : MetaM (Array EventSupport.Fact) := do
  let base := `ConsensusCoverage.EventSupport ++ Name.mkSimple n.getString!
  let env ← getEnv
  unless env.contains (base.appendIndexAfter 0) do return #[]
  let args := p.getAppArgs
  let pin ← mkAppM ``Iff.mpr #[mkAppN (mkConst (n.appendAfter "_iff") us) args, h]
  let mut out := #[]
  let mut i := 0
  repeat
    let name := base.appendIndexAfter i
    unless env.contains name do break
    i := i + 1
    let proof := mkAppN (mkConst name us) (args.push pin)
    let prop ← inferType proof
    if prop.isAppOfArity ``Eq 3 then
      out := out.push ⟨.eq (prop.getArg! 1) (prop.getArg! 2), proof⟩
    else if prop.isAppOfArity ``List.Mem 3 then
      let mut names := []
      let mut list := prop.getArg! 2
      while list.isAppOfArity ``List.cons 3 do
        let some tag := (list.getArg! 1).constName? | throwError "expected tag constructor"
        names := tag :: names
        list := list.getArg! 2
      unless list.isAppOf ``List.nil do throwError "expected a tag list"
      out := out.push ⟨.mem (prop.getArg! 1) names.reverse, proof⟩
  return out

mutual

/-- Walk the normalized path once; event pins, stabilities and handler facts
remain in scope together. A failed search leaves the arm possible. -/
private partial def deny (sp : Spec) (path : Path) (todo : List Atom) (atoms : List Atom)
    (tags : Array EventSupport.Fact) (inlineDepth : Nat) (choices : List Atom := []) :
    Gen (Option Expr) := do
  let (p, h) :: rest := todo |
    if let some pf ← atLeaf sp path atoms tags then return some pf
    let (p, h) :: rest := choices | return none
    let split (p h : Expr) (more : List Atom) : Gen (Option Expr) := do
      let arm (q : Expr) := withLocalDeclD `hq q fun hq => do
        let some pf ← deny sp path [(q, hq)] atoms tags inlineDepth more | return none
        return some (← mkLambdaFVars #[hq] pf)
      let some l ← arm (p.getArg! 0) | return none
      let some r ← arm (p.getArg! 1) | return none
      return some (ProofWalk.casesOr p h (mkConst ``False) l r)
    unless rest.isEmpty do
      for (q, hq) in choices do
        if let some pf ← split q hq [] then return some pf
    split p h rest
  if let some pf ← sp.extra.deny path.extra [(p, h)] then return some pf
  if let .const n us := p.getAppFn then
    if isReach n then
      if let some pf ← oldEvidence sp path p h then return some pf
      let summaries ← reachTags n us p h
      if summaries.any (fun f => match f.cond with
          | .mem x tags => x == path.key && !tags.contains sp.tag
          | _ => false) then
        if let some pf ← tagConflict path summaries then return some pf
      let tags := tags ++ summaries
      if let some cert ← certify sp n then
        return some (mkAppN (mkConst cert us) (p.getAppArgs ++
          #[path.initial.proof] ++ sp.mask.indices.toArray.map (path.evidence.stable[·]!) ++ #[path.extra, h]))
      if inlineDepth > 0 then
        let body := (← getConstInfo n).instantiateValueLevelParams! us |>.beta p.getAppArgs
        return ← deny sp path ((body, h) :: rest) ((p, h) :: atoms) tags (inlineDepth - 1) choices
      return ← deny sp path rest ((p, h) :: atoms) tags inlineDepth choices
  if sp.mask.testBit 4 && p.isAppOf ``ElectStep &&
      p.getArg! 1 == path.evidence.params[1]! && p.getArg! 2 == path.evidence.params[2]! then
    let no := mkAppN (mkConst ``EvidenceSupport.stable_elect_iff) (path.evidence.params.extract 0 4)
    let no ← mkAppM ``Iff.mp #[no, path.evidence.stable[4]!]
    return some (mkAppN no ((p.getAppArgs.extract 3 p.getAppNumArgs).push h))
  let tags := tags ++ (← tagFacts p h)
  if p.isAppOfArity ``And 2 then
    let (left, right) := ProofWalk.conjuncts p h
    return ← deny sp path (left :: right :: rest) atoms tags inlineDepth choices
  if p.isAppOfArity ``Or 2 then
    return ← deny sp path rest atoms tags inlineDepth ((p, h) :: choices)
  if p.isAppOfArity ``Exists 2 then
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := p.appArg!.beta #[w]
      withLocalDeclD `hq q fun hq => do
        let rest ← if ← isProp (p.getArg! 0) then pure ((p.getArg! 0, w) :: rest) else pure rest
        let some pf ← deny sp path ((q, hq) :: rest) atoms tags inlineDepth choices | return none
        return some (ProofWalk.casesExists p h (mkConst ``False) (← mkLambdaFVars #[w, hq] pf))
  deny sp path rest ((p, h) :: atoms) tags inlineDepth choices

private partial def certify (sp : Spec) (n : Name) : Gen (Option Name) := do
  if let some done := (← get)[n]? then return done
  let ci ← getConstInfo n
  let result ← lambdaTelescope ci.value! fun xs p => do
    let ps := xs.extract 0 4
    let fp := ps.extract 0 3
    let ctx := ps[3]!
    let some key ← EventSupport.observation (← inferType ctx) ctx | throwError "expected pinned context"
    let cond : EventSupport.Condition := .mem key [sp.tag]
    withLocalDeclD `event (← cond.prop) fun kind => do
      let decls : Array (Name × (Array Expr → Gen Expr)) := EvidenceSupport.families.map fun k =>
        (`stable, fun _ => pure (mkAppN (mkConst ``EvidenceSupport.Stable) (fp.push (mkConst k))))
      withLocalDeclsD decls fun hs => do
        withLocalDeclD `extra (← sp.extra.type ps) fun extra => do
          let mut rules ← sp.extra.rules ps extra
          rules ← rules.addConst ``Nat.lt_irrefl
          let simpCtx ← Simp.mkContext (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
          let path : Path :=
            ⟨⟨ps, mkAppN (mkConst ``Frame.advance) fp, hs, sp.mask⟩, key, ⟨cond, kind⟩, extra, simpCtx⟩
          withLocalDeclD `h p fun h => do
            let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
            let pf ← oldEvidence sp path pred h
            let pf ← if pf.isSome then pure pf else deny sp path [(p, h)] [] #[] sp.inlineDepth
            let some pf := pf | return none
            let name := sp.ns ++ Name.mkSimple (n.getString! ++ "_denied")
            let args := xs ++ #[kind] ++ sp.mask.indices.toArray.map (hs[·]!) ++ #[extra]
            addDecl (.thmDecl {
              name
              levelParams := ci.levelParams
              type := ← mkForallFVars args (← mkArrow pred (mkConst ``False)),
              value := ← mkLambdaFVars (args.push h) (← instantiateMVars pf) })
            return some name
  modify (·.insert n result)
  return result

end

/-- Generate `ns.stale`, `ns.possible`, `ns.possible_of_sig`, and `ns.excluded`
on recorded steps. Each certificate takes `extra` as an explicit hypothesis. -/
public def generate (ns tag : Name) (stale : List Name) (extra : Extra := {})
    (simplify : Bool := false) (inlineDepth : Nat := 0) : MetaM Unit := do
  unless (EventSupport.inputNames ++ EventSupport.messageNames).contains tag do
    throwError "{tag} is not an action tag"
  let mut mask : EvidenceSupport.Mask := 0
  for k in stale do
    let some i := EvidenceSupport.families.findIdx? (· == k) | throwError "{k} is not an evidence family"
    mask := mask ||| (1 <<< i)
  let candidates := mask :: 0 :: (mask.indices.map (fun k => 1 <<< k)) ++
    ((List.range mask).filter fun m => m &&& mask == m)
  let sp : Spec := ⟨ns, tag, mask, extra, simplify, inlineDepth, candidates.eraseDups⟩
  let ci ← getConstInfo ``SolvedWitnesses.dispatch
  let branch ← getConstInfoInduct ``Classes.StepBranch
  let ls := ci.levelParams.map mkLevelParam
  lambdaTelescope ci.value! fun xs body => do
    let ps := xs.extract 0 4
    let b := xs[4]!
    let arms := body.getAppArgs.extract 2 body.getAppNumArgs
    unless arms.size == branch.ctors.length && body.isAppOf ``Classes.StepBranch.casesOn &&
        arms.all (·.getAppArgs == ps) do throwError "unexpected normalized dispatcher"
    let tags ← branch.ctors.toArray.mapM (fun b =>
      DelayedNomination.notAllowed (mkConst tag) (mkConst b))
    let (results, cache) ← (arms.zipWithM (fun arm no =>
      if no.isSome then pure none else certify sp arm.getAppFn.constName!) tags : Gen _).run {}
    let possible := tags.zipWith (fun a b => a.isNone && b.isNone) results
    let name := ns ++ `possible
    let caseFn u := mkConst ``Classes.StepBranch.casesOn [u]
    let tableTy := mkConst ``Bool
    let yes := mkConst ``Bool.true
    let decl := Declaration.defnDecl {
      name
      levelParams := []
      type := ← mkForallFVars #[b] tableTy
      value := ← mkLambdaFVars #[b] (mkAppN (caseFn (.succ .zero))
        (#[← mkLambdaFVars #[b] tableTy, b] ++
          possible.map toExpr))
      hints := .abbrev
      safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let stale ← EvidenceSupport.Mask.list mask
    let staleName := ns ++ `stale
    let decl := Declaration.defnDecl {
      name := staleName, levelParams := [], type := ← inferType stale, value := stale
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let extraFn ← mkLambdaFVars ps (← extra.type ps)
    let cert := ns ++ `possible_of_sig
    let ctx := ps[3]!
    let some key ← EventSupport.observation (← inferType ctx) ctx | throwError "expected pinned context"
    let cond : EventSupport.Condition := .mem key [tag]
    withLocalDeclD `kind (← cond.prop) fun kind => do
      let all := mkAppN (mkConst ``EvidenceSupport.AllStable) (ps.extract 0 3 |>.push (mkConst staleName))
      withLocalDeclD `stable all fun stable => do
        withLocalDeclD `extra (← extra.type ps) fun extra => do
          let hs ← mask.indices.toArray.mapM fun i => do
            let k := mkConst EvidenceSupport.families[i]!
            return mkApp2 stable k (← EvidenceSupport.memberProof k stale)
          let motive ← withLocalDeclD `b (mkConst ``Classes.StepBranch) fun q => do
            let out ← mkEq (mkApp (mkConst name) q) yes
            mkLambdaFVars #[q] (← mkArrow (mkAppN (mkConst ci.name ls) (ps.push q)) out)
          let proofs ← arms.zipIdx.mapM fun (arm, i) => withLocalDeclD `h arm fun h => do
            let out ← mkEq (mkApp (mkConst name) (mkConst branch.ctors[i]!)) yes
            let proof ← match tags[i]!, results[i]! with
              | some no, _ => mkFalseElim out (mkAppN (mkConst ``noTag)
                  (ps ++ #[mkConst tag, mkConst branch.ctors[i]!, kind, no, h]))
              | none, some cert => mkFalseElim out (mkAppN (mkConst cert ls) (ps ++ #[kind] ++ hs ++ #[extra, h]))
              | none, none => mkEqRefl yes
            mkLambdaFVars #[h] proof
          let args := xs ++ #[kind, stable, extra]
          addDecl (.thmDecl {
            name := cert
            levelParams := ci.levelParams
            type := ← mkForallFVars args (motive.beta #[b]),
            value := ← mkLambdaFVars args (mkAppN (caseFn .zero) (#[motive, b] ++ proofs)) })
    let proof := mkAppN (mkConst ``lift_possible)
      #[mkConst tag, mkConst staleName, mkConst name, extraFn, mkConst cert ls]
    addDecl (.thmDecl {
      name := ns ++ `excluded
      levelParams := ci.levelParams
      type := ← inferType proof
      value := proof })
    logInfo m!"{ns}: {possible.countP id}/{arms.size} possible, {cache.size} shared checks"

end

end ConsensusCoverage.FamilyPrune
