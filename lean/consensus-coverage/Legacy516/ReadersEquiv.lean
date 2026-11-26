module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.Readers
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.Readers
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersGenerated
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.ReadersEquiv

open ActionProfile ReadersAtoms SolvedWitnesses
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option maxHeartbeats 0
set_option maxRecDepth 8192

private def guard (commit : Nat) (positive : Bool) : Bool :=
  if positive then decide (0 < commit) else !decide (0 < commit)

private theorem guard_pos (i : Nat) : guard i true = true ↔ 0 < i := by
  simp only [guard, ↓reduceIte, decide_eq_true_eq]

private theorem guard_neg (i : Nat) : guard i false = true ↔ ¬0 < i := by
  simp only [guard, Bool.false_eq_true, ↓reduceIte, Bool.not_eq_true', decide_eq_false_iff_not]

private structure Rule where
  branch : Classes.StepBranch
  source : Classes.StepBranch
  positive : Bool
  available : source ∈ Readers.covered
  related : ∀ [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t),
    sig c branch ↔ sig c source ∧ guard c.pre.commitIndex positive = true

open Lean Meta Elab Term in
private meta def generate : TermElabM Unit := do
  let info ← getConstInfo ``SolvedWitnesses.dispatch
  let ctors := (← getConstInfoInduct ``Classes.StepBranch).ctors.toArray
  let rules ← lambdaTelescope info.value! fun xs body => do
    let args := body.getAppArgs
    unless xs.size == 5 && body.isAppOf ``Classes.StepBranch.casesOn &&
        args.size == ctors.size + 2 do
      throwError "unexpected normalized step dispatcher"
    let arms ← args.extract 2 args.size |>.mapM fun arm => do
      let expanded ← unfoldDefinition? arm
      let rec split (p : Expr) (common : Array Expr) : Option (Array Expr × Expr) :=
        match p with
        | .mdata _ p' => split p' common
        | .app (.app (.const n _) left) right =>
          if n != ``And then none else
          let common := common.push left
          if left.isAppOf ``Wins then some (common, right) else split right common
        | _ => none
      pure <| expanded.bind (split · #[])
    let mut rules := #[]
    for i in [:arms.size] do
      let some (common, tail) := arms[i]! | continue
      unless tail.isAppOf ``Exists do continue
      for j in [:arms.size] do
        let some (base, end') := arms[j]! | continue
        unless base == common && end'.isAppOf ``And do continue
        for positive in #[true, false] do
          let b := mkIdent ctors[i]!
          let source := mkIdent ctors[j]!
          let sign := mkIdent (if positive then ``Bool.true else ``Bool.false)
          let premise := mkIdent (if positive then ``guard_pos else ``guard_neg)
          let proof ←
            `(term| Rule.mk $b $source $sign (by decide +kernel) (by
              intro inst f t c
              constructor
              · rintro ⟨root, now, role, _, wins, _, facts, more⟩
                rcases more with ⟨_, _, _, _, _, _, _, _, _, _, condition, _, _, _⟩
                refine ⟨⟨root, now, role, now, wins, now, role⟩, ?_⟩
                rw [($premise)]
                exact facts.1.2.2.1 ▸ condition
              · rintro ⟨⟨root, now, primary, _, wins, _, _⟩, condition⟩
                obtain ⟨candidate, facts⟩ := Wins.facts wins
                have ⟨campaign, quorum, postLog, term, vote, matchEq, role, le⟩ := facts
                have ⟨candRole, candLog, candCommit, active⟩ := campaign
                have nonempty := hasQuorum_nonempty quorum
                rw [($premise)] at condition
                rw [← candCommit] at condition
                refine ⟨root, now, primary, now, wins, candidate, ?_⟩
                repeat' first | assumption | apply And.intro))
          let saved ← Term.saveState
          try
            let rule ← withoutErrToSorry do
              let rule ← Term.elabTermEnsuringType proof (mkConst ``Rule)
              Term.synthesizeSyntheticMVarsNoPostponing
              pure rule
            let rule ← instantiateMVars rule
            if !(← Core.getMessageLog).hasErrors && !rule.hasExprMVar && !rule.hasFVar then
              rules := rules.push rule
              logInfo m!"equivalence reader {ctors[i]!} from {ctors[j]!}"
              break
          catch _ => pure ()
          saved.restore
    pure rules
  let type ← mkAppM ``List #[mkConst ``Rule]
  let value ← mkListLit (mkConst ``Rule) rules.toList
  addAndCompile <| .defnDecl {
    name := `ConsensusCoverage.ReadersEquiv.rules, levelParams := [], type, value,
    hints := .regular 0, safety := .safe }

local elab "derive_equivalences" : command => Lean.Elab.Command.liftTermElabM generate
derive_equivalences

public def covered : List Classes.StepBranch := rules.map Rule.branch

private theorem answer_eq (s : Step) (x : XView) (r : Rule)
    (ok : letI : Config.InitialConfiguration := ⟨s.cfg⟩; x.Matches s.context) :
    label s (.step r.branch) =
      (label s (.step r.source) && guard x.base.pre.commitIndex r.positive) := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  apply Bool.eq_iff_iff.mpr
  simp only [Bool.and_eq_true, label_true, holds, SolvedWitnesses.sig_iff,
    ← GuardedDomain.View.pre_eq ok.1]
  exact r.related s.context

private def find (b : Classes.StepBranch) : Option Rule :=
  rules.find? fun r => decide (r.branch = b)

private theorem find_branch {b : Classes.StepBranch} {r : Rule} (h : find b = some r) :
    r.branch = b :=
  of_decide_eq_true (List.find?_some (p := fun (r : Rule) => decide (r.branch = b)) h)

public def read? (x : XView) (parent : Classes.StepBranch → Option Bool)
    (b : Classes.StepBranch) : Option Bool := do
  let r ← find b
  let yes ← parent r.source
  pure (yes && guard x.base.pre.commitIndex r.positive)

public theorem read?_correct (s : Step) (x : XView)
    (ok : letI : Config.InitialConfiguration := ⟨s.cfg⟩; x.Matches s.context)
    {parent : Classes.StepBranch → Option Bool}
    (known : ∀ {b yes}, parent b = some yes → label s (.step b) = yes)
    {b : Classes.StepBranch} {v : Bool} (h : read? x parent b = some v) :
    label s (.step b) = v := by
  unfold read? at h
  cases eq : find b with
  | none => simp only [eq, Option.bind_eq_bind, Option.bind_none] at h; cases h
  | some r =>
    simp only [eq, Option.bind_eq_bind, Option.bind_some] at h
    cases p : parent r.source with
    | none => simp only [p, Option.bind_none] at h; cases h
    | some yes =>
      rw [p, Option.bind_some] at h
      exact (find_branch eq ▸ (answer_eq s x r ok)).trans
        ((congrArg (· && guard x.base.pre.commitIndex r.positive) (known p)).trans (Option.some.inj h))

public theorem read?_at (s : Step) (x : XView)
    (ok : letI : Config.InitialConfiguration := ⟨s.cfg⟩; x.Matches s.context)
    {parent : Classes.StepBranch → Option Bool}
    (known : ∀ {b}, b ∈ Readers.covered → parent b = some (label s (.step b)))
    {b : Classes.StepBranch} (mem : b ∈ covered) :
    read? x parent b = some (label s (.step b)) := by
  obtain ⟨r, present, same⟩ := List.mem_map.mp mem
  obtain ⟨found, eq⟩ := Option.isSome_iff_exists.mp <|
    (List.find?_isSome (p := fun (r : Rule) => decide (r.branch = b))).mpr
      ⟨r, present, decide_eq_true same⟩
  change find b = some found at eq
  simp only [read?, eq, Option.bind_eq_bind, Option.bind_some, known found.available, pure]
  exact congrArg some (find_branch eq ▸ (answer_eq s x found ok).symm)

end ConsensusCoverage.ReadersEquiv
