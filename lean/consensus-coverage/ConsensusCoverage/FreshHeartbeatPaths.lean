module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

meta import Lean
public import ConsensusCoverage.FreshHeartbeat
import all ConsensusCoverage.FreshHeartbeat
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StutterProfile
import all Consensus.Proofs.SafetyInvariant

/-! Specialize the reach DAG for the first fresh heartbeat. A closed branch
is used only with its proof; an open path is not a negative answer. -/

namespace ConsensusCoverage.FreshHeartbeatPaths

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open FullProfile ActionProfile FreshHeartbeat

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxRecDepth 8192

attribute [local instance] FreshHeartbeat.instInitialConfiguration_consensusCoverage

private theorem queue25 (c : Ctx witness.frame witness.after) (e : Model.Envelope) :
    SolvedWitnesses.reach_25 witness.frame witness.after concrete c e ↔ e = heartbeat ∧ c = concrete := by
  change (Pending (witness.frame.advance witness.after) e ∧ ¬Pending witness.frame e ∧ c = concrete) ↔ _
  simp [new_pending, old_pending]

private theorem queue26 (c : Ctx witness.frame witness.after) (e : Model.Envelope) :
    SolvedWitnesses.reach_26 witness.frame witness.after concrete c e ↔ e = heartbeat ∧ c = concrete := by
  change (SolvedWitnesses.reach_25 witness.frame witness.after concrete concrete e ∧
    e ∈ concrete.tr.outputs.outgoing ∧ Pending (witness.frame.advance witness.after) e ∧ c = concrete) ↔ _
  simp [queue25, new_pending, outgoing]

private theorem queue43 (c : Ctx witness.frame witness.after) (e : Model.Envelope) :
    SolvedWitnesses.reach_43 witness.frame witness.after concrete c e ↔ e = heartbeat ∧ c = concrete := by
  change (Pending (witness.frame.advance witness.after) e ∧ Bumping e.payload ∧
    ¬(Pending witness.frame e ∧ Bumping e.payload) ∧ c = concrete) ↔ _
  simp only [new_pending, old_pending, false_and, not_false_eq_true, true_and]
  constructor
  · exact fun h => ⟨h.1, h.2.2⟩
  · rintro ⟨h, rfl⟩
    subst e
    exact ⟨rfl, trivial, rfl⟩

private theorem actor_eq : concrete.tr.actor = 0 := rfl
private theorem event_eq : concrete.tr.event = .internal (.sendEntries 1 0) := rfl
private theorem pre_eq : concrete.tr.pre = primary := rfl
private theorem post_eq : concrete.tr.post = primary := rfl
private theorem sent_eq : concrete.tr.outputs.outgoing = [heartbeat] := rfl
private theorem pending_eq : concrete.tr.pending = [] := rfl
private theorem role_eq : primary.role = .primary := rfl
private theorem term_eq : primary.currentTerm = BOOTSTRAP_TERM := rfl
private theorem log_eq : primary.log = [Config.GENESIS] := rfl
private theorem vote_eq : primary.votedFor = none := rfl
private theorem index_eq : primary.commitIndex = 0 := rfl
private theorem primary_id : Config.INITIAL_PRIMARY = 0 := rfl

private theorem no_wins : ¬ Wins concrete.actor concrete.pre concrete.event concrete.post := by
  rintro ⟨cam, campaign, _, advance⟩
  have term : concrete.post.currentTerm = cam.currentTerm :=
    advance.elim (congrArg NodeState.currentTerm) (fun h => h.2.1)
  rcases campaign.2.2.2 with h | h
  · have higher := h.2.1
    change cam.currentTerm = primary.currentTerm + 1 at higher
    change primary.currentTerm = cam.currentTerm at term
    omega
  · have eq : Role.primary = Role.candidate := h.1
    cases eq

private abbrev backup := initialNodeState witness.cfg 1

private theorem old_now (n : NodeID) (st : NodeState) :
    Now witness.frame n st ↔ (n = 0 ∧ st = primary) ∨ (n = 1 ∧ st = backup) := by
  change (n, st) ∈ [(0, primary), (1, backup)] ↔ _
  simp

private theorem no_new_now :
    Now (witness.frame.advance witness.after) = Now witness.frame :=
  now_eq sameNodes

private theorem log_ghost_eq : (witness.frame.advance witness.after).logs = witness.frame.logs :=
  stableLogs

private theorem seen_stable : Seen (witness.frame.advance witness.after) = Seen witness.frame :=
  StutterProfile.seen_eq log_ghost_eq

private theorem led_stable : Led (witness.frame.advance witness.after) = Led witness.frame :=
  StutterProfile.led_eq log_ghost_eq

private theorem no_old_grant (v c : NodeID) (k : Nat) (r : RequestVoteRequest) :
    ¬ witness.frame.logs.grant v c k r := by
  change ¬ (False ∨ ∃ p, none = some p ∧ _)
  simp

private theorem no_old_elected (n : NodeID) (k : Nat) (l : List Entry) (i : Nat) :
    ¬ witness.frame.logs.elected n k l i := by
  change ¬ (False ∨ ∃ p, none = some p ∧ _)
  simp

private theorem old_led (n : NodeID) (k : Nat) :
    Led witness.frame n k ↔ k = BOOTSTRAP_TERM ∧ n = 0 := by
  change (k = BOOTSTRAP_TERM ∧ n = 0 ∨ ∃ l i, witness.frame.logs.elected n k l i) ↔ _
  simp [no_old_elected]

private theorem quiet : StutterProfile.UnsignedUnvoted witness.before :=
  StutterProfile.unsigned_check (by decide +kernel)

private theorem no_old_commit (k : Nat) (l : List Entry) :
    ¬ witness.frame.logs.committed k l := by
  rintro (h | ⟨n, st, _, i, step, _, _⟩)
  · exact h
  · exact Bool.noConfusion (((quiet n st step.1.1).2 i).symm.trans step.2.2.2.1)

private theorem no_commit (n : NodeID) (st : NodeState) (k base i : Nat) :
    ¬ CommitStep (witness.frame.advance witness.after) n st k base i := by
  intro h
  have mem := h.1.1
  change (n, st) ∈ witness.after.nodes at mem
  rw [sameNodes] at mem
  exact Bool.noConfusion (((quiet n st mem).2 i).symm.trans h.2.2.2.1)

private theorem no_election (n : NodeID) (k : Nat) (l : List Entry) (i : Nat) :
    ¬ ElectStep witness.frame witness.after n k l i := by
  rintro ⟨x, y, old, new, rest⟩
  rw [sameNodes] at new
  exact StutterProfile.noElection witness.folded.invariant ⟨x, y, old, new, rest⟩

private theorem primary_unsigned (i : Nat) : isSignatureAt primary.log i = false :=
  (quiet 0 primary (List.mem_cons_self ..)).2 i

private theorem observed (n : NodeID) (o : Safety.Observation) :
    Seen witness.frame n o ↔ (n = 0 ∧ o = observe primary) ∨ (n = 1 ∧ o = observe backup) := by
  change (False ∨ ∃ st, (n, st) ∈ [(0, primary), (1, backup)] ∧ st.currentTerm = o.currentTerm ∧ st.log = o.log) ↔ _
  constructor
  · rintro (_ | ⟨st, mem, term, log⟩)
    · contradiction
    · exact (old_now n st).mp mem |>.imp
        (fun ⟨hn, hs⟩ => ⟨hn, by cases o; cases hs; cases term; cases log; rfl⟩)
        (fun ⟨hn, hs⟩ => ⟨hn, by cases o; cases hs; cases term; cases log; rfl⟩)
  · rintro (⟨rfl, rfl⟩ | ⟨rfl, rfl⟩)
    · exact .inr ⟨primary, by simp, rfl, rfl⟩
    · exact .inr ⟨backup, by simp, rfl, rfl⟩

private theorem coherent : AEOk 0 1 primary request :=
  ⟨by decide +kernel, rfl, by decide +kernel, rfl, List.nil_prefix, by decide +kernel⟩

private theorem primary_engaged : Engaged primary := by
  constructor
  · intro h
    change Role.primary = Role.none at h
    cases h
  · intro h
    have eq : Role.primary = Role.follower := h.1
    cases eq

private theorem at_zero (f : Frame) (l : List Entry) (k : Nat) : Backed f l 0 k :=
  .inl rfl

private theorem advance_primary (n : NodeID) (middle : NodeState) :
    Advance n middle primary ↔ middle = primary :=
  ⟨fun h => h.elim Eq.symm (fun h => (Nat.not_lt_zero _ h.2.2.2.2.2.2.1).elim),
    fun h => .inl h.symm⟩

private theorem owner : Led (witness.frame.advance witness.after) 0 BOOTSTRAP_TERM :=
  .inl ⟨rfl, rfl⟩

private theorem boot_floor : 2 ≤ BOOTSTRAP_TERM := by decide +kernel

private theorem queue28 (c : Ctx witness.frame witness.after) (n : NodeID) (st : NodeState) :
    SolvedWitnesses.reach_28 witness.frame witness.after concrete c n st ↔
      c = concrete ∧ n = 0 ∧ st = primary := by
  constructor
  · rintro ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hc, hn, hs⟩
    exact ⟨hc, hn, hs⟩
  · rintro ⟨rfl, rfl, rfl⟩
    have stay : concrete.pre.role = .primary ∧ concrete.post.currentTerm = concrete.pre.currentTerm :=
      ⟨rfl, rfl⟩
    have nc : concrete.post.role ≠ .candidate := by decide +kernel
    have root := (queue26 concrete heartbeat).2 ⟨rfl, rfl⟩
    have sent := (outgoing heartbeat).2 rfl
    have ok := coherent
    exact ⟨heartbeat, root, rfl, ⟨ok, nc, .inl stay⟩,
      request, rfl, rfl, ok, ⟨nc, .inl stay⟩, nc, .inl stay, ok.1,
      ok.2, ok.2.1, ok.2.2, ok.2.2.1, ok.2.2.2, ok.2.2.2.1, ok.2.2.2.2,
      ok.2.2.2.2.1, ok.2.2.2.2.2, sent, owner, rfl, rfl, rfl⟩

private theorem same_table : witness.after.nodes = witness.frame.current.nodes := sameNodes

private def Certified (p : Prop) : Option Bool → Prop
  | some true => p
  | some false => ¬ p
  | none => True

private theorem certified_yes {p : Prop} (h : p = True) : Certified p (some true) :=
  h.symm ▸ True.intro

private theorem certified_no {p : Prop} (h : p = False) : Certified p (some false) :=
  h ▸ id

meta section

open Lean Meta Elab Command

private def fixedParams : MetaM (Array Expr) := do
  let c := mkConst ``concrete
  return (← inferType c).getAppArgs.push c

private def baseRules : MetaM SimpTheorems := do
  let mut rules ← getSimpTheorems
  for n in #[``queue25, ``queue26, ``queue28, ``queue43, ``old_pending, ``new_pending, ``outgoing,
      ``no_new_now, ``old_now, ``log_ghost_eq, ``seen_stable, ``observed, ``led_stable, ``old_led,
      ``no_old_grant, ``no_old_elected, ``no_old_commit, ``no_commit, ``no_election, ``no_wins,
      ``primary_engaged, ``at_zero, ``advance_primary, ``coherent, ``boot_floor] do
    rules ← rules.addConst n (post := false)
  for n in #[``actor_eq, ``event_eq, ``pre_eq, ``post_eq, ``sent_eq, ``pending_eq,
      ``role_eq, ``term_eq, ``log_eq, ``vote_eq, ``index_eq, ``primary_id, ``primary_unsigned, ``and_assoc] do
    rules ← rules.addConst n
  for n in #[``Ctx.actor, ``Ctx.pre, ``Ctx.post, ``Ctx.event, ``Ctx.sent,
      ``Committed, ``Canon, ``Elected, ``Granted, ``Bumping, ``Safety.observe] do
    rules ← rules.addDeclToUnfold n
  return rules

private def inReach (n : Name) : Bool :=
  n.getPrefix == `ConsensusCoverage.SolvedWitnesses &&
    n.getString!.startsWith "reach_" && !n.getString!.endsWith "_iff"

private def dependencies (p : Expr) : Array Name := p.getUsedConstants.filter inReach

/-- Do not inline the large open nodes of the proof DAG. Closed nodes and
small tests (e.g. packet equality) are enough to cut whole subtrees. -/
private partial def small (fuel : Nat) (p : Expr) : Bool :=
  if fuel == 0 then false
  else
    match p with
    | .app _ _ => p.getAppNumArgs ≤ 10 && p.getAppArgs.all (small (fuel - 1))
    | .lam .. | .forallE .. | .letE .. => false
    | .proj _ _ p => small (fuel - 1) p
    | .mdata _ p => small fuel p
    | _ => true

private def simplify (rules : SimpTheorems) (body : Expr) : MetaM Simp.Result := do
  let ctx ← Simp.mkContext (config := { maxSteps := 1800, failIfUnchanged := false })
    (simpTheorems := #[rules]) (congrTheorems := ← getSimpCongrTheorems)
  let simprocs := #[← Simp.getSimprocs]
  return (← simp body ctx simprocs).1

private def coreRefute (n : Name) (us : List Level) (xs : Array Expr) : MetaM (Option Expr) := do
  let cert := `ConsensusCoverage.FreshHeartbeat ++ Name.mkSimple (n.getString! ++ "_stable_core")
  if !(← getEnv).contains cert then return none
  let refute := mkAppN (mkConst cert us) (xs ++ #[mkConst ``same_table, mkConst ``log_ghost_eq])
  let transfer := mkAppN (mkConst (n.appendAfter "_iff") us) xs
  let mp ← mkAppM ``Iff.mpr #[transfer]
  return some (← mkEqFalse (← mkAppM ``mt #[mp, refute]))

private structure Compiler where
  seen : Std.HashSet Name := {}
  rules : SimpTheorems

private abbrev Reduce := StateRefT Compiler MetaM

private partial def specialize (params : Array Expr) (n : Name) : Reduce Unit := do
  if (← get).seen.contains n then return
  let ci ← getConstInfo n
  let us := ci.levelParams.map mkLevelParam
  let value := ci.value!.beta params
  let name := `ConsensusCoverage.FreshHeartbeatPaths ++ Name.mkSimple (n.getString! ++ "_at_send")
  -- Reuse existing generic no-new-node/no-new-log proofs before walking children.
  let mut found ← lambdaTelescope value fun xs _ => do
    let some proof ← coreRefute n us (params ++ xs) | return false
    let pred := mkAppN (mkConst n us) (params ++ xs)
    let ty ← mkForallFVars xs (← mkEq pred (mkConst ``False))
    let value ← mkLambdaFVars xs proof
    addDecl (.thmDecl { name, levelParams := ci.levelParams, type := ty, value })
    return true
  unless found do
    (dependencies value).forM (specialize params)
    let rules := (← get).rules
    found ← lambdaTelescope value fun xs p => do
      let simplified : MetaM (Option Simp.Result) := observing? (simplify rules p)
      let some result ← simplified | return false
      if result.expr == p || !small 6 result.expr then return false
      let pred := mkAppN (mkConst n us) (params ++ xs)
      let ty ← mkForallFVars xs (← mkEq pred result.expr)
      let value ← mkLambdaFVars xs (← result.getProof)
      addDecl (.thmDecl { name, levelParams := ci.levelParams, type := ty, value })
      return true
  let rules := (← get).rules
  let rules ← if found then rules.addConst name (post := false) else pure rules
  modify fun s => { seen := s.seen.insert n, rules }

private def casesFn (u : Level) := mkConst ``Classes.StepBranch.casesOn [u]

private def boolOption (v : Option Bool) : Expr :=
  match v with
  | none => mkApp (mkConst ``Option.none [.zero]) (mkConst ``Bool)
  | some v => mkApp2 (mkConst ``Option.some [.zero]) (mkConst ``Bool) (toExpr v)

private def tableName := `ConsensusCoverage.FreshHeartbeatPaths.pathRead
private def certName := `ConsensusCoverage.FreshHeartbeatPaths.pathCertified

private partial def slots (xs : Expr) : MetaM (List Nat) := do
  let xs ← whnf xs
  if xs.isAppOf ``List.nil then return []
  unless xs.isAppOfArity ``List.cons 3 do throwError "expected literal residual slots"
  let some n ← getNatValue? (xs.getArg! 1) | throwError "expected literal slot"
  return n :: (← slots (xs.getArg! 2))

private def compile : MetaM Unit := do
  let params ← fixedParams
  let wanted ← slots ((← getConstInfo ``FreshHeartbeat.residual_slots).type.getArg! 2)
  let .defnInfo ci ← getConstInfo ``SolvedWitnesses.dispatch | throwError "expected solved dispatcher"
  let branches := (← getConstInfoInduct ``Classes.StepBranch).ctors.toArray
  let arms := (ci.value.beta params).bindingBody!.getAppArgs.extract 2 (branches.size + 2)
  unless arms.size == branches.size do throwError "unexpected dispatcher layout"
  let mut state : Compiler := { rules := ← baseRules }
  let mut answers : Array (Option Bool × Expr) := #[]
  let mut unresolved : Array Nat := #[]
  let mut covered := 0
  for i in [:arms.size] do
    let .const n _ := arms[i]!.getAppFn | throwError "unexpected dispatcher arm"
    if !wanted.contains i then
      answers := answers.push (none, mkConst ``True.intro)
      continue
    let val := (← getConstInfo n).value!.beta params
    let (_, st) ← ((dependencies val).forM (specialize params)).run state
    state := st
    let result ← observing? (simplify st.rules val)
    if let some r := result then
      if r.expr.isConstOf ``True || r.expr.isConstOf ``False then
        let yes := r.expr.isConstOf ``True
        let proof := mkApp2 (mkConst (if yes then ``certified_yes else ``certified_no))
          arms[i]! (← r.getProof)
        answers := answers.push (some yes, proof)
        covered := covered + 1
        continue
    unresolved := unresolved.push i
    answers := answers.push (none, mkConst ``True.intro)
  logInfo m!"fresh heartbeat paths: {covered} new decisions; {unresolved.size} still open"
  withLocalDeclD `branch (mkConst ``Classes.StepBranch) fun b => do
    let answer := mkApp (mkConst ``Option [.zero]) (mkConst ``Bool)
    let motive ← mkLambdaFVars #[b] answer
    let ty ← mkForallFVars #[b] answer
    let value ← mkLambdaFVars #[b] (mkAppN (casesFn (.succ .zero))
      (#[motive, b] ++ answers.map (boolOption ∘ Prod.fst)))
    let decl := Declaration.defnDecl {
      name := tableName, levelParams := [], type := ty, value := value
      hints := .abbrev, safety := .safe }
    addDecl decl (forceExpose := true)
    compileDecl decl
    let solved := mkAppN (mkConst ``SolvedWitnesses.dispatch) (params.push b)
    let ty := mkApp2 (mkConst ``Certified) solved (mkApp (mkConst tableName) b)
    let motive ← mkLambdaFVars #[b] ty
    let type ← mkForallFVars #[b] ty
    let value ← mkLambdaFVars #[b] (mkAppN (casesFn .zero) (#[motive, b] ++ answers.map Prod.snd))
    addDecl (.thmDecl { name := certName, levelParams := [], type, value })

end

local elab "compile_heartbeat_paths" : command => Lean.Elab.Command.liftTermElabM compile
set_option maxHeartbeats 0 in
compile_heartbeat_paths

/-- The earlier answers, supplemented by the specialized reach certificates. -/
public def read? (q : Question) : Option Bool :=
  match q with
  | .step b => (pathRead b).orElse fun _ => FreshHeartbeat.read? q
  | _ => FreshHeartbeat.read? q

private theorem path_sound (b : Classes.StepBranch) {v : Bool}
    (h : pathRead b = some v) : label witness (.step b) = v := by
  have proof := pathCertified b
  rw [h] at proof
  have equiv : holds witness (.step b) ↔ SolvedWitnesses.sig concrete b := by
    change PinnedClasses.sig witness.context b ↔ SolvedWitnesses.sig concrete b
    rw [← concrete_context]
    exact SolvedWitnesses.sig_iff _ _
  cases v
  · exact Bool.eq_false_iff.mpr fun yes => proof (equiv.mp ((label_true _ _).mp yes))
  · exact (label_true _ _).mpr (equiv.mpr proof)

public theorem read_sound (q : Question) {v : Bool} (h : read? q = some v) :
    label witness q = v := by
  cases q with
  | pre b => exact FreshHeartbeat.read_sound _ h
  | post b => exact FreshHeartbeat.read_sound _ h
  | step b =>
    change (pathRead b).orElse (fun _ => FreshHeartbeat.read? (.step b)) = some v at h
    cases hs : pathRead b with
    | none => exact FreshHeartbeat.read_sound _ (by simpa only [hs, Option.orElse_none] using h)
    | some ans => exact path_sound b (hs.trans (by simpa only [hs, Option.orElse_some] using h))

@[expose] public def residual : List Classes.StepBranch :=
  FreshHeartbeat.residual.filter fun b => (pathRead b).isNone

@[expose] public def positives : List Classes.StepBranch :=
  stepBranches.toList.filter fun b => read? (.step b) == some true

public theorem residual_iff (b : Classes.StepBranch) : b ∈ residual ↔ read? (.step b) = none := by
  cases h : pathRead b <;> simp [residual, read?, h, FreshHeartbeat.residual_iff b]

public theorem positive (b : Classes.StepBranch) (h : b ∈ positives) :
    label witness (.step b) = true :=
  read_sound _ (beq_iff_eq.mp (List.mem_filter.mp h).2)

public theorem negative (b : Classes.StepBranch) (resolved : b ∉ residual)
    (notPositive : b ∉ positives) : label witness (.step b) = false := by
  cases h : read? (.step b) with
  | none => exact (resolved ((residual_iff b).2 h)).elim
  | some v =>
    cases v
    · exact read_sound _ h
    · exact (notPositive (List.mem_filter.mpr ⟨FreshHeartbeat.mem_universe b, beq_iff_eq.mpr h⟩)).elim

/-- Verified census of the combined reader on this action, not an upper
bound on the number of true bits. -/
public theorem counts :
    stepBranches.size = 433 ∧ residual.length = 167 ∧ positives.length = 15 ∧
      (stepBranches.toList.filter fun b => read? (.step b) == some false).length = 251 :=
  by decide +kernel

public theorem positive_slots : positives.map (·.ctorIdx) =
    [48, 49, 71, 72, 73, 104, 105, 114, 146, 174, 186, 187, 248, 272, 274] :=
  by decide +kernel

public theorem residual_slots : residual.map (·.ctorIdx) =
    [50, 108, 109, 113, 131, 132, 133, 134, 148, 149, 150, 152, 154, 155, 166, 168, 169, 170,
     171, 172, 173, 181, 182, 183, 184, 212, 213, 214, 215, 221, 222, 223, 224, 225, 228, 229,
     230, 231, 232, 233, 250, 251, 273, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285,
     286, 287, 295, 296, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317,
     318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 346, 347,
     348, 349, 354, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369,
     370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384, 385, 386, 387,
     388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 403, 404, 405,
     406, 407, 408, 409, 410, 411, 412, 413, 414, 417, 418, 419, 420, 421, 422, 423, 424, 425,
     426, 429, 430, 431, 432] :=
  by decide +kernel

end ConsensusCoverage.FreshHeartbeatPaths
