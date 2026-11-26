module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReachPath
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.DeepGrantCases

open Consensus Consensus.Proofs Consensus.Model Consensus.Model.Node Safety
open ActionProfile ReadersAtoms SolvedWitnesses

set_option maxRecDepth 8192

inductive GrantCase where
  | recorded | selfVote | peerVote

def GrantCase.column : GrantCase → Classes.StepBranch
  | .recorded => .grantFactsBefore_grant_inr
  | .selfVote => .grantFactsBefore_supported_inl
  | .peerVote => .grantFactsBefore_supported_inr

private def side (v n : NodeID) : GrantCase → Bool
  | .recorded => true
  | .selfVote => v == n
  | .peerVote => v != n

def check (s : Step) (k : GrantCase) (v n t : Nat) (r : RequestVoteRequest) : Bool :=
  (ofXAction s.cfg s.before s.after s.past s.act).any fun x =>
    let before := x.base.before :: x.base.past
    decide (grantedIn (x.base.after :: before) v n t r = true ∧
      ¬grantedIn before v n t r = true ∧ side v n k = true)

theorem correct (s : Step) (k : GrantCase) (v n t : Nat) (r : RequestVoteRequest)
    (yes : check s k v n t r = true) : label s (.step k.column) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  let f := s.frame
  let c := s.context
  obtain ⟨x, made, ok⟩ := ofXAction_matches s
  simp only [check, made, Option.any_some, decide_eq_true_eq] at yes
  obtain ⟨post, notOld, onSide⟩ := yes
  have grant := (X.grant_after ok v n t r).mpr post
  have fresh := fun h => notOld ((X.grant_before ok v n t r).mp h)
  have root : (reach% SolvedWitnesses.step_grantFactsBefore_grant_inr[0]) f s.after c v n t r :=
    ⟨⟨grant, fresh⟩, grant⟩
  obtain ⟨p, eq, atStep, support⟩ := Or.resolve_left grant fresh
  obtain rfl : f.current = p := Option.some.inj eq
  obtain ⟨⟨stamp, rank⟩, _⟩ := c.grantFactsBefore v n t r grant
  have oldRank : VoterRank f.logs f.logs.canon v t t r :=
    fun k l i seen => rank k l i (.inl seen)
  have extend : (⟨v, t, some n⟩ ∈ (f.advance s.after).votes) → VoterRank f.logs f.logs.canon v t t r →
      VoterRank (f.advance s.after).logs f.logs.canon v t t r := fun _ _ => rank
  refine (label_true s _).mpr ((SolvedWitnesses.sig_iff c _).mpr ?_)
  cases k with
  | recorded =>
    exact Or.inl ⟨v, n, t, r, root, ⟨_, rfl, atStep, support⟩, f.current,
      ⟨rfl, atStep, support⟩, rfl, ⟨atStep, support⟩, atStep, support, grant, extend⟩
  | selfVote =>
    have vn : v = n := beq_iff_eq.mp onSide
    subst n
    have sup : True ∨ ∃ l, f.logs.seen v t l := .inl trivial
    refine Or.inl ⟨v, t, r, root, ⟨_, rfl, atStep, sup⟩, f.current,
      ⟨rfl, atStep, sup⟩, rfl, ⟨atStep, sup⟩, atStep, sup, rfl, .rfl, atStep, ?_⟩
    obtain ⟨st, post, preMem, postMem, le, term, vote, up⟩ := atStep
    refine ⟨st, ⟨post, preMem, postMem, le, term, vote, up⟩, post, ?_⟩
    repeat' first | assumption | apply And.intro
  | peerVote =>
    have different : v ≠ n := by simpa [side] using onSide
    obtain ⟨l, seen⟩ := support.resolve_left different
    refine Or.inl ⟨v, n, t, r, root, ⟨_, rfl, atStep, support⟩, f.current,
      ⟨rfl, atStep, support⟩, rfl, ⟨atStep, support⟩, atStep, support, rfl, .rfl, atStep, ?_⟩
    obtain ⟨st, post, preMem, postMem, le, term, vote, up⟩ := atStep
    exact ⟨st, ⟨post, preMem, postMem, le, term, vote, up⟩, post,
      ⟨preMem, postMem, le, term, vote, up⟩, preMem, ⟨postMem, le, term, vote, up⟩,
      postMem, ⟨le, term, vote, up⟩, le, ⟨term, vote, up⟩, term, ⟨vote, up⟩, vote, up,
      ⟨l, seen⟩, l, seen, grant, extend, oldRank, stamp⟩

end ConsensusCoverage.DeepGrantCases
