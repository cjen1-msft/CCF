module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.Classes
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.ProofContexts
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
meta import Lean

/-!
# The step questions of each invariant clause

For each field `c` of `Inv`, `questions c` is the list `Q_c` of generated step questions
recorded in the transitive proof-term closure of that field of `Ctx.inv_step`. `calls c d`
is the cross-clause dependency relation and `trunk` the questions shared by every clause
that is not local. A per-clause table has one row per `(pre, answers on Q_c, post)`.

The sizes are deliberately not theorems here: `scripts/clause-sizes.lean` prints them, so
that a schema change only touches the per-clause modules whose lists changed.
-/

namespace ConsensusCoverage.ClauseQuestions

set_option maxRecDepth 8192
set_option maxHeartbeats 0

public inductive Clause where
  | node_logs | active | ballots | grantFacts | led_cur | leader_led | candidate | elections
  | election_safety | canon_mono | chains | canonLogs | commit_backed | persist | match_ack
  | messages | message_terms | leader_logs | comparable | unique | frontier | observed
  | term_mono
  deriving DecidableEq, Repr, Inhabited

open FullProfile in
public def Clause.all : List Clause := (constructors% Clause).toList

public theorem Clause.enumeration : Clause.all.length = 23 ∧ Clause.all.Nodup := by decide +kernel
public theorem Clause.mem_all (c : Clause) : c ∈ Clause.all := by cases c <;> decide +kernel

open Lean Meta Elab Term in
private meta def proofClosure (env : Environment) (e : Expr) : NameSet := Id.run do
  let mut seen : NameSet := {}
  let mut todo := e.getUsedConstants
  while let some n := todo.back? do
    todo := todo.pop
    if seen.contains n || !(`Consensus.Proofs).isPrefixOf (privateToUserName n) then continue
    seen := seen.insert n
    if let some body := env.find? n >>= (·.value? true) then
      todo := todo ++ body.getUsedConstants
  return seen

open Lean Meta in
/-- Match the generated class ledger to the proof in *each constructor slot*.
An inline split belongs only to the slot containing its `splitMark`. For other
owners we follow constants in proof bodies, not just calls visible in source. -/
local elab "clauseData%" : term => do
  let env ← getEnv
  let root := ``Consensus.Proofs.Safety.Ctx.inv_step
  let inv := ``Consensus.Proofs.Safety.Inv
  let fields := getStructureFields env inv
  let clauses := (← getConstInfoInduct ``Clause).ctors.toArray
  unless fields.map Name.toString == clauses.map Name.getString! do
    throwError "Clause differs from the fields of Inv"
  let some proof := (← getConstInfo root).value? true | throwError "missing inv_step proof"
  let mut body := proof
  while body.isLambda do body := body.bindingBody!
  let ctor ← getConstInfoCtor (inv ++ `mk)
  unless body.isAppOfArity ctor.name (ctor.numParams + fields.size) do
    throwError "inv_step no longer constructs Inv directly"
  let args := body.getAppArgs.extract ctor.numParams
  let some (.lit (.strVal ledger)) := (← getConstInfo ``Classes.table).value?
    | throwError "missing branch ledger"
  let mut sites : Std.HashMap Name (String × String) := {}
  for row in ledger.splitOn "\n" do
    let "class" :: label :: "step" :: owner :: site :: _ := row.splitOn "\t" | continue
    unless label.startsWith "step_" do throwError "unexpected class label {label}"
    let branch := ``Classes.StepBranch ++ (label.drop 5).toString.toName
    if sites.contains branch then throwError "duplicate ledger row {label}"
    sites := sites.insert branch (owner, site)
  let branches := (← getConstInfoInduct ``Classes.StepBranch).ctors
  unless sites.size == branches.length do throwError "incomplete branch ledger"
  let mut qs := #[]
  let mut deps := #[]
  for (arg, field) in args.zip fields do
    let names := proofClosure env arg
    let owners := names.toList.map Name.toString
    let mut found := #[]
    for b in branches do
      let some (owner, site) := sites[b]? | throwError "missing site for {b}"
      let inlineSite := owner == root.toString && (arg.find? fun e =>
        e.isAppOfArity ``Relevance.splitMark 4 && e.getArg! 1 == mkStrLit site).isSome
      if owners.contains owner || inlineSite then found := found.push (mkConst b)
    qs := qs.push (← mkListLit (mkConst ``Classes.StepBranch) found.toList)
    -- Other post-invariant fields whose proof helper occurs in this closure.
    -- Compound and inline fields have no single helper to call.
    let mut used := #[]
    for ((arg', other), c) in (args.zip fields).zip clauses do
      if field != other then
        if let some head := arg'.getAppFn.constName? then
          if names.contains head then used := used.push (mkConst c)
    deps := deps.push (← mkListLit (mkConst ``Clause) used.toList)
  mkAppM ``Prod.mk #[← mkArrayLit (← mkAppM ``List #[mkConst ``Classes.StepBranch]) qs.toList,
                     ← mkArrayLit (← mkAppM ``List #[mkConst ``Clause]) deps.toList]

private def data : Array (List Classes.StepBranch) × Array (List Clause) := clauseData%

public def questions (c : Clause) : List Classes.StepBranch := data.1[c.ctorIdx]?.getD []
public def calls (c d : Clause) : Bool := (data.2[c.ctorIdx]?.getD []).contains d
/-- In how many clause lists a question occurs. -/
public def frequency (b : Classes.StepBranch) : Nat := (Clause.all.filter fun c => (questions c).contains b).length

/-- A clause is local when it asks no more than the `unique` clause, whose proof only
compares the states stored for one node. -/
public def localOnly (c : Clause) : Bool := (questions c).length ≤ (questions .unique).length

/-- The shared trunk: the questions asked by every clause that is not local. -/
public def trunk (b : Classes.StepBranch) : Bool :=
  Clause.all.all fun c => localOnly c || (questions c).contains b

public def nonTrunk (c : Clause) : List Classes.StepBranch := (questions c).filter (!trunk ·)

public theorem questions_nodup (c : Clause) : (questions c).Nodup := by
  cases c <;> decide +kernel

/-- The union in the same canonical order as the full step profile. -/
public theorem union_eq :
    FullProfile.stepBranches.toList.filter (fun b => Clause.all.any fun c => (questions c).contains b) =
      FullProfile.stepBranches.toList := by decide +kernel

public structure RestrictedProfile where
  pre : StateCoverage.Row
  bits : List Bool
  post : StateCoverage.Row
  deriving DecidableEq, Repr

public abbrev ClauseProfile (_ : Clause) := RestrictedProfile

public noncomputable def restrictedLabel (qs : List Classes.StepBranch) (s : ActionProfile.Step) :
    RestrictedProfile :=
  ⟨StateCoverage.read s.cfg s.before s.past, qs.map fun b => ActionProfile.label s (.step b),
    StateCoverage.read s.cfg s.after (s.before :: s.past)⟩

public noncomputable def clauseLabel (c : Clause) := restrictedLabel (questions c)

private theorem answers_eq {r t : StateCoverage.Row} :
    ProofContexts.answers r = ProofContexts.answers t ↔ r = t :=
  ⟨fun h => congrFun h .committed_logs_comparable_committed_comparable_inl, congrArg _⟩

public theorem restrictedLabel_eq_iff (qs : List Classes.StepBranch) (s t : ActionProfile.Step) :
    restrictedLabel qs s = restrictedLabel qs t ↔
      (ActionProfile.label s).pre = (ActionProfile.label t).pre ∧
      (∀ b ∈ qs, ActionProfile.label s (.step b) = ActionProfile.label t (.step b)) ∧
      (ActionProfile.label s).post = (ActionProfile.label t).post := by
  simp only [restrictedLabel, RestrictedProfile.mk.injEq, List.map_inj_left,
    ActionProfile.pre_answers, ActionProfile.post_answers, answers_eq]

public theorem clauseLabel_eq_iff (c : Clause) (s t : ActionProfile.Step) :
    clauseLabel c s = clauseLabel c t ↔
      (ActionProfile.label s).pre = (ActionProfile.label t).pre ∧
      (∀ b ∈ questions c, ActionProfile.label s (.step b) = ActionProfile.label t (.step b)) ∧
      (ActionProfile.label s).post = (ActionProfile.label t).post :=
  restrictedLabel_eq_iff _ _ _

public def ClauseRealized (c : Clause) (p : ClauseProfile c) : Prop :=
  ∃ s : ActionProfile.Step, clauseLabel c s = p

public def ClauseExactTable (c : Clause) (rows : List (ClauseProfile c)) : Prop :=
  rows.Nodup ∧ ∀ p, p ∈ rows ↔ ClauseRealized c p

/-- Both endpoints of every recorded step answer the state questions positively. -/
public theorem endpoints (qs : List Classes.StepBranch) (s : ActionProfile.Step) :
    (restrictedLabel qs s).pre = true ∧ (restrictedLabel qs s).post = true :=
  StateCoverage.step_read s.ran s.past (s.before :: s.past)

/-- The table of any question list: the rows of bit vectors, with both endpoints true. -/
public def ExactBits (qs : List Classes.StepBranch) (rows : List (List Bool)) : Prop :=
  rows.Nodup ∧ ∀ p, p ∈ rows ↔ ∃ s : ActionProfile.Step, (restrictedLabel qs s).bits = p

public theorem ExactBits.table {c : Clause} {rows : List (List Bool)} (h : ExactBits (questions c) rows) :
    ClauseExactTable c (rows.map fun bits => ⟨true, bits, true⟩) := by
  refine ⟨h.1.map _ (fun _ _ ne eq => ne (RestrictedProfile.mk.inj eq).2.1), fun p => ?_⟩
  simp only [List.mem_map, h.2, ClauseRealized, clauseLabel]
  constructor
  · rintro ⟨_, ⟨s, rfl⟩, rfl⟩
    refine ⟨s, ?_⟩
    obtain ⟨a, b⟩ := endpoints (questions c) s
    generalize restrictedLabel (questions c) s = r at a b
    cases r; simp_all
  · rintro ⟨s, rfl⟩
    refine ⟨_, ⟨s, rfl⟩, ?_⟩
    obtain ⟨a, b⟩ := endpoints (questions c) s
    generalize restrictedLabel (questions c) s = r at a b
    cases r; simp_all

end ConsensusCoverage.ClauseQuestions
