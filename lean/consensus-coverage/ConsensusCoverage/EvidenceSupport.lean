module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public meta import ConsensusCoverage.DeltaSupport
public import ConsensusCoverage.ActionProfile
public import ConsensusCoverage.CanonicalLogs
public import ConsensusCoverage.CommitKeys
public import ConsensusCoverage.GrantFrontier
public import ConsensusCoverage.GuardedDomain
public import ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CanonicalLogs
import all ConsensusCoverage.CommitKeys
import all ConsensusCoverage.CommitMonitor
import all ConsensusCoverage.DeltaSupport
import all ConsensusCoverage.GrantFrontier
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.Historical
import all ConsensusCoverage.PinnedClasses
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant

/-! Each listed set is independently sufficient to refute a column when
all of its families are stale. A fresh family does not by itself prove a label. -/

namespace ConsensusCoverage.EvidenceSupport

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

public inductive Family
  | pending | now | seen | grant | elected | canon | committed
  deriving Repr, DecidableEq

/-- Inclusion of the post-step relation in the pre-step relation. Envelopes
are compared by value, not by position or multiplicity. -/
public def Stable [Config.InitialConfiguration] (f : FullProfile.ProofFrame)
    (t : Model.State) : Family → Prop
  | .pending => ∀ e, Pending (f.advance t) e → Pending f e
  | .now => ∀ n st, Now (f.advance t) n st → Now f n st
  | .seen => ∀ n o, Seen (f.advance t) n o → Seen f n o
  | .grant => ∀ v c k r, Granted (f.advance t) v c k r → Granted f v c k r
  | .elected => ∀ n k l i, Elected (f.advance t) n k l i → Elected f n k l i
  | .canon => ∀ k l, Canon (f.advance t) k l → Canon f k l
  | .committed => ∀ k l, Committed (f.advance t) k l → Committed f k l

private theorem oldLed [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : Stable f t .elected) {n k} : Led (f.advance t) n k → Led f n k :=
  fun led => led.imp_right fun ⟨l, i, elect⟩ => ⟨l, i, h _ _ _ _ elect⟩

private theorem oldSeen [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (h : Stable f t .seen) {n k l} : (f.advance t).logs.seen n k l → f.logs.seen n k l :=
  h n ⟨k, l⟩

private theorem elect_not_old [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {n k l i} (elect : ElectStep f t n k l i) : ¬ Elected f n k l i := by
  intro old
  obtain ⟨rfl, _, _, term, _⟩ := c.electStep elect
  have prior := c.inv.led_cur c.actor c.pre k c.pre_now (Or.inr ⟨l, i, old⟩)
  rcases term with lt | ⟨eq, role⟩ <;> rcases prior with gt | ⟨same, notCandidate⟩
  · omega
  · omega
  · omega
  · exact notCandidate role

private theorem stable_elect_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    Stable f t .elected ↔ ∀ n k l i, ¬ ElectStep f t n k l i := by
  exact ⟨fun stable n k l i step => elect_not_old c step (stable n k l i (Or.inr ⟨_, rfl, step⟩)),
    fun no _ _ _ _ post => (c.elected_after post).elim id (fun step => (no _ _ _ _ step).elim)⟩

private abbrev AllStable [Config.InitialConfiguration] (f : Frame) (t : Model.State)
    (ks : List Family) : Prop := ∀ k ∈ ks, Stable f t k

private theorem blockNil [Config.InitialConfiguration] {f t} {P : Prop} :
    ∀ ks ∈ ([] : List (List Family)), AllStable f t ks → ¬ P := by simp

private theorem blockCons [Config.InitialConfiguration] {f t} {P : Prop} {ks : List Family}
    {ss : List (List Family)} (head : AllStable f t ks → ¬ P)
    (tail : ∀ js ∈ ss, AllStable f t js → ¬ P) :
    ∀ js ∈ ks :: ss, AllStable f t js → ¬ P := by
  intro js mem
  rcases List.mem_cons.mp mem with rfl | rest
  · exact head
  · exact tail js rest

meta section

open Lean Meta Elab Command

private def families : Array Name :=
  #[``Family.pending, ``Family.now, ``Family.seen, ``Family.grant, ``Family.elected,
    ``Family.canon, ``Family.committed]

private abbrev Mask := Nat
private abbrev Fact := Expr × Expr
private abbrev Gen := StateRefT (Std.HashMap (Name × Mask) (Option Name)) MetaM

private def Mask.indices (m : Mask) : List Nat :=
  (List.range families.size).filter m.testBit

private def Mask.list (m : Mask) : MetaM Expr :=
  mkListLit (mkConst ``Family) (m.indices.map fun i => mkConst families[i]!)

private partial def memberProof (k ks : Expr) : MetaM Expr := do
  unless ks.isAppOfArity ``List.cons 3 do throwError "expected {k} in generated evidence set"
  let head := ks.getArg! 1
  let tail := ks.getArg! 2
  if head == k then
    return mkAppN (mkConst ``List.Mem.head [.zero]) #[mkConst ``Family, k, tail]
  return mkAppN (mkConst ``List.Mem.tail [.zero])
    #[mkConst ``Family, k, head, tail, ← memberProof k tail]

private structure Check where
  params : Array Expr
  next : Expr
  stable : Array Expr
  mask : Mask

private def atomFamily (n : Name) : Option Nat :=
  if n == ``Pending then some 0
  else if n == ``Now then some 1
  else if n == ``Seen then some 2
  else if n == ``Granted then some 3
  else if n == ``Elected || n == ``Led then some 4
  else if n == ``Canon then some 5
  else if n == ``Committed then some 6
  else none

private def ghostFamily (n : Name) : Option Nat :=
  if n == ``LogFacts.Ghost.seen then some 2
  else if n == ``LogFacts.Ghost.grant then some 3
  else if n == ``LogFacts.Ghost.elected then some 4
  else if n == ``LogFacts.Ghost.canon then some 5
  else if n == ``LogFacts.Ghost.committed then some 6
  else none

/-- Rebuild the positive part of a newness guard. Transport only positive
facts, in the post-to-pre direction. -/
private partial def rebuild (c : Check) (atoms : List Fact) (p : Expr) : MetaM (Option Expr) := do
  if let some (_, h) := atoms.find? (fun (q, _) => q == p) then return some h
  if p.isAppOfArity ``And 2 then
    let some l ← rebuild c atoms (p.getArg! 0) | return none
    let some r ← rebuild c atoms (p.getArg! 1) | return none
    return some (mkAppN (mkConst ``And.intro) (p.getAppArgs ++ #[l, r]))
  let .const n _ := p.getAppFn | return none
  let args := p.getAppArgs
  let some (i, j, next) := (do
    if let some i := ghostFamily n then
      let logs := mkConst ``Frame.logs
      guard (args[0]? == some (mkApp logs c.params[1]!))
      return (i, 0, mkApp logs c.next)
    let i ← atomFamily n
    let j ← args.findIdx? (· == c.params[1]!)
    return (i, j, c.next) : Option (Nat × Nat × Expr)) | return none
  unless c.mask.testBit i do return none
  let q := mkAppN p.getAppFn (args.set! j next)
  let some (_, h) := atoms.find? (fun (r, _) => r == q) | return none
  let stable := c.stable[i]!
  if n == ``Led then return some (← mkAppM ``oldLed #[stable, h])
  if n == ``LogFacts.Ghost.seen then return some (← mkAppM ``oldSeen #[stable, h])
  return some (mkAppN stable ((args.extract (j + 1) args.size).push h))

private def reachName? (p : Expr) : Option Name := do
  let n ← p.getAppFn.constName?
  guard (n.getPrefix == `ConsensusCoverage.PinnedClasses && n.getString!.startsWith "reach_")
  return n

mutual

/-- Reuse certificates for shared reach conditions, and stop at the first
conflict on each path. The path succeeds only if both disjuncts close. -/
private partial def refute (c : Check) (todo : List Fact) (atoms : List Fact := [])
    : Gen (Option Expr) := do
  let (p, h) :: rest := todo |
    for (p, h) in atoms do
      if p.isAppOfArity ``Not 1 then
        if let some hp ← rebuild c atoms p.appArg! then return some (mkApp h hp)
    return none
  if let some n := reachName? p then
    if let some lemma ← certify n c.mask then
      let .const _ us := p.getAppFn | throwError "expected a reach constant"
      let hs := c.mask.indices.toArray.map (fun i => c.stable[i]!)
      return some (mkAppN (mkConst lemma us) (p.getAppArgs ++ hs ++ #[h]))
  if c.mask.testBit 4 && p.isAppOf ``ElectStep &&
      p.getArg! 1 == c.params[1]! && p.getArg! 2 == c.params[2]! then
    let no := mkAppN (mkConst ``stable_elect_iff) (c.params.extract 0 4)
    let no ← mkAppM ``Iff.mp #[no, c.stable[4]!]
    return some (mkAppN no ((p.getAppArgs.extract 3 p.getAppNumArgs).push h))
  if p.isAppOfArity ``And 2 then
    let left := mkAppN (mkConst ``And.left) (p.getAppArgs.push h)
    let right := mkAppN (mkConst ``And.right) (p.getAppArgs.push h)
    return ← refute c
      ((p.getArg! 0, left) :: (p.getArg! 1, right) :: rest)
      atoms
  if p.isAppOfArity ``Or 2 then
    let arm (q : Expr) := withLocalDeclD `hq q fun hq => do
      let some pf ← refute c ((q, hq) :: rest) atoms | return none
      return some (← mkLambdaFVars #[hq] pf)
    let some l ← arm (p.getArg! 0) | return none
    let some r ← arm (p.getArg! 1) | return none
    return some (mkAppN (mkConst ``Or.elim) (p.getAppArgs ++ #[mkConst ``False, h, l, r]))
  if p.isAppOfArity ``Exists 2 then
    let .const _ us := p.getAppFn | throwError "expected existential"
    return ← withLocalDeclD `w (p.getArg! 0) fun w => do
      let q := p.appArg!.beta #[w]
      withLocalDeclD `hq q fun hq => do
        let some pf ← refute c ((q, hq) :: rest) atoms | return none
        return some (mkAppN (mkConst ``Exists.elim us)
          (p.getAppArgs ++ #[mkConst ``False, h, ← mkLambdaFVars #[w, hq] pf]))
  refute c rest ((p, h) :: atoms)

private partial def certify (n : Name) (m : Mask) : Gen (Option Name) := do
  if let some done := (← get)[(n, m)]? then return done
  let .defnInfo ci ← getConstInfo n | throwError "expected generated definition {n}"
  let result ← lambdaTelescope ci.value fun xs p => do
    let fp := xs.extract 0 3
    let decls : Array (Name × (Array Expr → Gen Expr)) := families.map fun k =>
      (`stable, fun _ => pure (mkAppN (mkConst ``Stable) (fp.push (mkConst k))))
    withLocalDeclsD decls fun hs => do
      withLocalDeclD `h p fun h => do
        let checks := ⟨xs, mkAppN (mkConst ``Frame.advance) fp, hs, m⟩
        let some proof ← refute checks [(p, h)] | return none
        let pred := mkAppN (mkConst n (ci.levelParams.map mkLevelParam)) xs
        let stable := m.indices.toArray.map (fun i => hs[i]!)
        let name := `ConsensusCoverage.EvidenceSupport ++ Name.mkSimple
          (n.getString! ++ "_stable_" ++ toString m)
        let type ← mkForallFVars (xs ++ stable) (← mkArrow pred (mkConst ``False))
        let value ← mkLambdaFVars (xs ++ stable ++ #[h]) proof
        addDecl (.thmDecl { name, levelParams := ci.levelParams, type, value })
        return some name
  modify (·.insert (n, m) result)
  return result

end

private def supportsFor (n : Name) : Gen (List (Mask × Name)) := do
  if let some lemma ← certify n 0 then return [(0, lemma)]
  let mut singles := []
  for i in [:families.size] do
    let m : Mask := 1 <<< i
    if let some lemma ← certify n m then singles := (m, lemma) :: singles
  if !singles.isEmpty then return singles.reverse
  let mut m : Mask := (1 <<< families.size) - 1
  let some proof ← certify n m | return []
  let mut proof := proof
  for i in [:families.size] do
    let smaller := m - (1 <<< i)
    if let some lemma ← certify n smaller then
      m := smaller
      proof := lemma
  return [(m, proof)]

private def compile : MetaM Unit := do
  let .defnInfo ci ← getConstInfo ``PinnedClasses.dispatch | throwError "expected pinned dispatcher"
  let branch ← getConstInfoInduct ``Classes.StepBranch
  unless (← getConstInfoInduct ``Family).ctors.toArray == families do
    throwError "family enumeration does not match the generator"
  lambdaTelescope ci.value fun xs body => do
    let params := xs.extract 0 4
    let args := body.getAppArgs
    let b := xs[4]!
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == branch.ctors.length + 2 && args[1]! == b do
      throwError "unexpected pinned dispatcher"
    let arms := args.extract 2 args.size
    let inner := mkApp (mkConst ``List [.zero]) (mkConst ``Family)
    let (results, cache) ← (arms.mapM fun arm => do
      let .const n us := arm.getAppFn | throwError "unexpected dispatcher arm {arm}"
      unless n.getPrefix == `ConsensusCoverage.PinnedClasses &&
          n.getString!.startsWith "step_" && arm.getAppArgs == params do
        throwError "unexpected dispatcher arm {arm}"
      let found ← supportsFor n
      let mut sets := []
      let paramsP := (xs.extract 0 3).push arm
      let mut proof := mkAppN (mkConst ``blockNil) paramsP
      for (m, lemma) in found.reverse do
        let ks ← m.list
        let tail ← mkListLit inner sets
        sets := ks :: sets
        let ty := mkAppN (mkConst ``AllStable) (xs.extract 0 3 |>.push ks)
        let head ← withLocalDeclD `stable ty fun stable => do
          let hs ← m.indices.toArray.mapM fun i => do
            let k := mkConst families[i]!
            let mem ← memberProof k ks
            return mkApp2 stable k mem
          mkLambdaFVars #[stable] (mkAppN (mkConst lemma us) (params ++ hs))
        proof := mkAppN (mkConst ``blockCons) (paramsP ++ #[ks, tail, head, proof])
      return (sets, proof, found.map Prod.fst) : Gen _).run {}
    let missing := (arms.zip results).filterMap fun (arm, sets, _, _) =>
      if sets.isEmpty then some arm.getAppFn.constName! else none
    unless missing.isEmpty do throwError "no evidence certificate for {missing}"
    let tableTy := mkApp (mkConst ``List [.zero]) inner
    let table := `ConsensusCoverage.EvidenceSupport.supports
    let caseFn u := mkConst ``Classes.StepBranch.casesOn [u]
    let lists ← results.mapM fun (sets, _, _) => mkListLit inner sets
    let decl := Declaration.defnDecl {
      name := table, levelParams := [], type := ← mkForallFVars #[b] tableTy
      value := ← mkLambdaFVars #[b]
        (mkAppN (caseFn (.succ .zero)) (#[← mkLambdaFVars #[b] tableTy, b] ++ lists))
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let ty ← withLocalDeclD `ks inner fun ks => do
      let mem ← mkAppM ``List.Mem #[ks, mkApp (mkConst table) b]
      let stable := mkAppN (mkConst ``AllStable) (xs.extract 0 3 |>.push ks)
      let pred := mkAppN (mkConst ci.name (ci.levelParams.map mkLevelParam)) xs
      mkForallFVars #[ks] (← mkArrow mem (← mkArrow stable (← mkArrow pred (mkConst ``False))))
    addDecl (.thmDecl {
      name := `ConsensusCoverage.EvidenceSupport.dispatch_excluded
      levelParams := ci.levelParams, type := ← mkForallFVars xs ty
      value := ← mkLambdaFVars xs (mkAppN (caseFn .zero)
        (#[← mkLambdaFVars #[b] ty, b] ++ results.map fun (_, proof, _) => proof)) })
    let smallest : Array Mask := results.map fun (_, _, ms) => ms.head!
    let sizes := (List.range families.size).map fun i =>
      smallest.countP (fun m => (Mask.indices m).length == i + 1)
    let counts := (List.range families.size).map fun i => smallest.countP (·.testBit i)
    let tiedCounts := (List.range families.size).map fun i => results.countP fun (_, _, ms) =>
      ms.any fun (m : Mask) => m.indices.length == (Mask.indices ms.head!).length && m.testBit i
    logInfo m!"evidence support: {arms.size} columns, {cache.size} memoized definition/mask pairs; \
      smallest set sizes {sizes}, family counts in first smallest set {counts}; \
      in any smallest set {tiedCounts}, empty {smallest.countP (· == 0)}"

end

public section

local elab "generate_evidence_support" : command => Lean.Elab.Command.liftTermElabM compile
generate_evidence_support

/-- Generated sufficient sets of fresh evidence for each column, ordered by
size and then by family mask. Every listed set is an independent guard. -/
add_decl_doc supports

theorem sig_false [Config.InitialConfiguration] {f : FullProfile.ProofFrame} {t : Model.State}
    (c : Ctx f t) (b : Classes.StepBranch) {ks : List Family}
    (mem : ks ∈ supports b) (stable : AllStable f t ks) : ¬ PinnedClasses.sig c b :=
  dispatch_excluded f t c b ks mem stable

end

private def freshSeen (t : Model.State) (history : List Model.State) : Bool :=
  t.nodes.any fun (n, st) => decide (observe st ∉ GuardedDomain.observations history n)

private theorem seen_iff (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    freshSeen s.after (s.before :: s.past) = false ↔ Stable s.frame s.after .seen := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have seen (n o) : Seen s.frame n o ↔ o ∈ GuardedDomain.observations (s.before :: s.past) n := by
    change (StateCoverage.frame s.before s.past).logs.seen n _ _ ↔ _
    rw [StateCoverage.frame_logs, GuardedDomain.seen_mem]
  classical
  simp only [freshSeen, List.any_eq_false, Prod.forall, decide_eq_true_eq, Classical.not_not, ← seen]
  constructor
  · intro test n o post
    rcases post with old | ⟨st, here, term, log⟩
    · exact old
    · cases o
      cases term
      cases log
      exact test n st here
  · intro stable n st here
    exact stable n (observe st) (Or.inr ⟨st, here, rfl, rfl⟩)

private def freshElection (s t : Model.State) (past : List Model.State) : Bool :=
  t.nodes.any fun (n, st) => CommitMonitor.election t s past n st.currentTerm

private theorem election_iff (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    freshElection s.before s.after s.past = false ↔ Stable s.frame s.after .elected := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have atStep (n k l i) : Historical.ElectStep s.after s.before s.past n k l i ↔
      ElectStep s.frame s.after n k l i := by
    change _ ↔ LogFacts.ElectionAt (FullProfile.current s.frame) s.after
      (StateCoverage.frame s.after (s.before :: s.past)).logs.grant n k l i
    rw [s.current_eq, StateCoverage.frame_logs]
    simp only [Historical.ElectStep, LogFacts.ElectionAt,
      (Historical.logFacts_correct (s.after :: s.before :: s.past)).grant]
    rfl
  rw [stable_elect_iff s.context]
  simp only [freshElection, List.any_eq_false, Prod.forall,
    CommitMonitor.election_iff, atStep]
  constructor
  · intro test n k l i elect
    obtain ⟨rfl, _, _, _, term, _⟩ := s.context.electStep elect
    exact test _ _ s.context.post_now ⟨l, i, term.symm ▸ elect⟩
  · intro no n st _ ⟨l, i, elect⟩
    exact no n st.currentTerm l i elect

private theorem canon_iff (s : ActionProfile.Step) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    CanonicalLogs.fresh (s.cfg.min?.getD 0) s.after (s.before :: s.past) = false ↔
      Stable s.frame s.after .canon := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  simp only [Bool.eq_false_iff, ne_eq, CanonicalLogs.step_fresh s]
  change (¬ ∃ k l, Canon (s.frame.advance s.after) k l ∧ ¬ Canon s.frame k l) ↔ _
  classical
  simp only [Stable, not_exists, not_and, Classical.not_not]

/-- Exact batch of freshness flags (true means the relation gained a fact). -/
public structure Evidence where
  pending : Bool
  now : Bool
  seen : Bool
  grant : Bool
  elected : Bool
  canon : Bool
  committed : Bool
  deriving DecidableEq, Repr

@[expose] public def Evidence.fresh (e : Evidence) : Family → Bool
  | .pending => e.pending
  | .now => e.now
  | .seen => e.seen
  | .grant => e.grant
  | .elected => e.elected
  | .canon => e.canon
  | .committed => e.committed

/-- Reuse snapshots and the already-read envelope, node, grant and commit
answers when the caller is also reading other columns. -/
@[expose] public def readFrom (s t : Model.State) (past : List Model.State) (bootstrap : NodeID)
    (payloads : List Message) (view : Option GuardedDomain.View) (noNewGrant newCommit : Bool) : Evidence :=
  ⟨payloads.any (fun _ => true), (view.map (·.changed)).getD false,
    freshSeen t (s :: past), !noNewGrant, freshElection s t past,
    CanonicalLogs.fresh bootstrap t (s :: past), newCommit⟩

@[expose] public def read (cfg : FullProfile.Configuration) (s : Model.State) (a : Model.Action)
    (t : Model.State) (past : List Model.State) : Evidence :=
  readFrom s t past (cfg.min?.getD 0) (ReducedQuestions.freshPayloads s t.network)
    (GuardedDomain.ofAction cfg s t past a) (GrantFrontier.noNewGrant t (s :: past))
    (!CommitKeys.noNew (cfg.min?.getD 0) t (s :: past))

@[expose] public def fresh (cfg : FullProfile.Configuration) (s : Model.State) (a : Model.Action)
    (t : Model.State) (past : List Model.State) (k : Family) : Bool :=
  (read cfg s a t past).fresh k

/-- All seven freshness tests are exact on initialized recorded steps. -/
public theorem fresh_iff (s : ActionProfile.Step) (k : Family) :
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    fresh s.cfg s.before s.act s.after s.past k = false ↔ Stable s.frame s.after k := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  cases k with
  | pending =>
    change (ReducedQuestions.freshPayloads s.before s.after.network).any (fun _ => true) = false ↔ _
    rw [← s.current_eq]
    simp [ReducedQuestions.freshPayloads, Stable, Pending, List.any_eq_false] <;> rfl
  | now =>
    obtain ⟨v, made, ok⟩ := GuardedDomain.ofAction_matches s
    simp only [fresh, read, readFrom, Evidence.fresh, made, Option.map_some, Option.getD_some]
    rw [← GuardedDomain.View.old_post ok]
    change _ ↔ ∀ n st, Now (s.frame.advance s.after) n st → Now s.frame n st
    exact ⟨fun old n st post => (s.context.now_after post).elim
      (fun ⟨eq, same⟩ => eq.symm ▸ same.symm ▸ old) And.right,
      fun stable => stable _ _ s.context.post_now⟩
  | seen => exact seen_iff s
  | grant =>
    change (!GrantFrontier.noNewGrant s.after (s.before :: s.past)) = false ↔ _
    rw [Bool.not_eq_false']
    exact GrantFrontier.step_noNew s
  | elected => exact election_iff s
  | canon => exact canon_iff s
  | committed =>
    change (!CommitKeys.noNew (s.cfg.min?.getD 0) s.after (s.before :: s.past)) = false ↔ _
    rw [Bool.not_eq_false']
    exact CommitKeys.step_noNew s

@[expose] public def excluded (e : Evidence) (b : Classes.StepBranch) : Bool :=
  (supports b).any fun ks => ks.all fun k => !e.fresh k

public theorem label_false (s : ActionProfile.Step) (b : Classes.StepBranch)
    (h : excluded (read s.cfg s.before s.act s.after s.past) b = true) :
    ActionProfile.label s (.step b) = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  obtain ⟨ks, mem, test⟩ := List.any_eq_true.mp h
  have stable k (hk : k ∈ ks) := (fresh_iff s k).mp
    (by simpa only [fresh, Bool.not_eq_true'] using List.all_eq_true.mp test k hk)
  exact Bool.eq_false_iff.mpr fun yes =>
    sig_false s.context b mem stable ((ActionProfile.label_true s (.step b)).mp yes)

private def deltaFamily : DeltaSupport.Family → Family
  | .pending => .pending
  | .now => .now
  | .election => .elected
  | .commit => .committed

private def missingDelta : List (Classes.StepBranch × DeltaSupport.Family) :=
  FullProfile.stepBranches.toList.flatMap fun b =>
    ((DeltaSupport.blockers b).filter fun k =>
      !(supports b).any fun ks => ks.all (· == deltaFamily k)).map fun k => (b, k)

/-- The legacy commit guard excludes *all* post-step `CommitStep` witnesses,
including certificates proving a key that was already present. The exact
committed-family bit excludes only new keys. Check the precise difference. -/
public theorem delta_exceptions : missingDelta =
    ([.rankedElections_elected_inl, .old_complete_elected_after_inl,
      .new_in_elected_led_inl, .new_in_elected_led_inr,
      .new_in_elected_backing_inl, .new_in_elected_backing_inr,
      .new_in_elected_lt_trichotomy_inl, .new_in_elected_lt_trichotomy_inr_inl,
      .new_in_elected_canon_chain_inl, .new_in_elected_canon_chain_inr,
      .new_in_elected_lt_trichotomy_inr_inr, .new_in_elected_agree_or_contained_inl,
      .new_in_elected_agree_or_contained_inr] : List Classes.StepBranch).map (·, .commit) := by
  decide +kernel

private def familiesInOrder : List Family := [.pending, .now, .seen, .grant, .elected, .canon, .committed]

/-- Count columns by smallest listed set size (1 through 7), then by
membership in a smallest set (ties count for all their families). -/
public theorem census :
    let columns := FullProfile.stepBranches.toList
    let size := fun b => ((supports b).headD []).length
    columns.length = 461 ∧
      columns.all (fun b => !(supports b).isEmpty) = true ∧
      ([1, 2, 3, 4, 5, 6, 7].map fun n => columns.countP (fun b => size b == n)) =
        [119, 121, 22, 28, 6, 30, 135] ∧
      (familiesInOrder.map fun k => columns.countP fun b =>
        (supports b).any fun ks => ks.length == size b && ks.contains k) =
        [232, 368, 187, 146, 296, 216, 249] := by
  decide +kernel

end ConsensusCoverage.EvidenceSupport
