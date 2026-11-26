module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.CaseUnreachable
import all ConsensusCoverage.VoteRequestRoute
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
meta import Lean

namespace ConsensusCoverage.StableGrantImpossibleB

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Lean Meta Elab Tactic ActionProfile SolvedWitnesses

set_option maxRecDepth 16384
set_option maxHeartbeats 0

private theorem reject (s : Step) {dst : Model.State} {tr : LocalTransition s.frame.current dst}
    (same : dst = s.after) (trEq : HEq tr (@Ctx.tr ⟨s.cfg⟩ _ _ s.context)) {before : NodeState} {src : NodeID}
    {req : RequestVoteRequest} (pre : before = tr.pre) (ev : tr.event = .receive src (.requestVoteRequest req))
    (cand : before.role = .candidate) (vote : before.votedFor = none ∨ before.votedFor = some src) : False := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  subst dst
  obtain rfl := eq_of_heq trEq
  subst before
  have own := (s.context.inv.candidate _ _ s.context.pre_now cand).2.1
  rcases vote with zero | srcVote
  · simp [own] at zero
  · have toSelf := Option.some.inj (own.symm.trans srcVote)
    obtain ⟨packet, queued, source, target, payload⟩ := s.context.received ev
    exact VoteRequestRoute.folded s.folded queued payload (source.trans (toSelf.symm.trans target.symm))

-- The origin of the summary differs in each caller. After any of its
-- disjuncts, the final two conjuncts identify the recorded transition.
private meta partial def ends (body : Expr) (h : Expr) (goal : Expr) : MetaM Expr := do
  if body.isAppOf ``Or then
    let branch (q : Expr) := withLocalDeclD `branch q fun b => do
      mkLambdaFVars #[b] (← ends q b goal)
    return ← mkAppM ``Or.elim #[h, ← branch (body.getArg! 0), ← branch (body.getArg! 1)]
  let mut proof := h
  let mut type := body
  while type.isAppOf ``And do
    if ← isDefEq type goal then return proof
    proof := mkProj ``And 1 proof
    type := type.getArg! 1
  throwError "transition identity missing from caller"

local elab "project_origin " h:ident : tactic => withMainContext do
  let proof ← getFVarFromUserName h.getId
  let some body ← unfoldDefinition? (← inferType proof) | throwError "expected transition caller"
  let g ← getMainGoal
  g.assign (← ends body proof (← g.getType))
  replaceMainGoal []

local macro "one_grant " s:ident h:ident : tactic => `(tactic|
  (obtain ⟨_, before, src, req, path, _, _, _, _, cand, vote, _⟩ := $h
   obtain ⟨event, summary, message, actual, _, payload⟩ := path
   obtain ⟨dst, tr, origin, _, pre, recv⟩ := summary
   have eqs : dst = ($s).after ∧ HEq tr ($s).context.tr := by project_origin origin
   apply reject $s eqs.1 eqs.2 pre (recv.symm.trans (actual.trans (congrArg (Event.receive src) payload))) cand
   first | exact Or.inl vote | exact Or.inr vote))

local macro "no_grant " s:ident b:ident : tactic => do
  let f := mkIdent ((`ConsensusCoverage.SolvedWitnesses).str ("step_" ++ b.getId.getString!))
  `(tactic|
    (letI : Config.InitialConfiguration := ⟨($s).cfg⟩
     apply CaseUnreachable.solved_false
     change ¬ $f ($s).frame ($s).after ($s).context
     intro path
     iterate 28 (rcases path with path | path; case inl => one_grant $s path)
     one_grant $s path))

public theorem none (s : Step) : label s (.step .voteRequest_summary_granted_inl) = false := by
  no_grant s voteRequest_summary_granted_inl

public theorem previous (s : Step) : label s (.step .voteRequest_summary_granted_inr) = false := by
  no_grant s voteRequest_summary_granted_inr

end ConsensusCoverage.StableGrantImpossibleB
