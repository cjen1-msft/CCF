module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

/-! The request underlying a positive vote reply is either the current
candidate's exact request or can be replaced by one above every past rank. -/

namespace ConsensusCoverage.ReadersVoteReply

open CCF
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage.ReadersAtoms
open ConsensusCoverage.GuardedDomain

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

def rankCeiling (hist : List Model.State) : Nat :=
  ((histNodes hist).map fun p => maxCommittableTerm p.2.log).foldl max 0

theorem rankCeiling_le {hist : List Model.State} {n : NodeID} {s : NodeState}
    (h : (n, s) ∈ histNodes hist) : maxCommittableTerm s.log ≤ rankCeiling hist := by
  have le (xs : List Nat) (bound k : Nat) (h : k ≤ bound ∨ k ∈ xs) :
      k ≤ xs.foldl max bound := by
    induction xs generalizing bound with
    | nil => simpa using h
    | cons x xs ih =>
      refine ih (max bound x) ?_
      rcases h with old | mem
      · exact Or.inl (Nat.le_trans old (Nat.le_max_left _ _))
      · rcases List.mem_cons.mp mem with rfl | rest
        · exact Or.inl (Nat.le_max_right _ _)
        · exact Or.inr rest
  exact le _ _ _ (Or.inr (List.mem_map_of_mem h))

def dominant (hist : List Model.State) (k : Nat) : RequestVoteRequest :=
  ⟨k, rankCeiling hist + 1, 0⟩

theorem granted_dominant {hist : List Model.State} {v c k : Nat} {r : RequestVoteRequest}
    (h : grantedIn hist v c k r = true) :
    grantedIn hist v c k (dominant hist k) = true := by
  rw [grantedIn_iff] at h ⊢
  obtain ⟨a, b, rest, suffix, ⟨x, y, pre, post, le, eq, vote, _⟩, seen⟩ := h
  have mem : (v, x) ∈ histNodes hist := mem_histNodes (suffix.subset (by simp)) pre
  have up : voteLogUpToDate x (dominant hist k) :=
    Or.inl (Nat.lt_succ_of_le (rankCeiling_le mem))
  exact ⟨a, b, rest, suffix, ⟨x, y, pre, post, le, eq, vote, up⟩, seen⟩

def candidates (hist : List Model.State) (s : Model.State) (k : Nat) :
    List RequestVoteRequest :=
  dominant hist k :: s.nodes.map (makeRequestVoteRequest ·.2)

theorem bound_reply (hist : List Model.State) (s : Model.State) (v c k : Nat) (P : Prop) :
    (∃ r, grantedIn hist v c k r = true ∧ P ∧
      ∀ x, (c, x) ∈ s.nodes → x.role = .candidate → x.currentTerm = k →
        makeRequestVoteRequest x = r) ↔
    ∃ r ∈ candidates hist s k, grantedIn hist v c k r = true ∧ P ∧
      ∀ x, (c, x) ∈ s.nodes → x.role = .candidate → x.currentTerm = k →
        makeRequestVoteRequest x = r := by
  classical
  constructor
  · rintro ⟨r, grant, p, req⟩
    by_cases has : ∃ x, (c, x) ∈ s.nodes ∧ x.role = .candidate ∧ x.currentTerm = k
    · obtain ⟨x, mem, role, term⟩ := has
      have eq := req x mem role term
      exact ⟨r, List.mem_cons_of_mem _ (List.mem_map.mpr ⟨(c, x), mem, eq⟩), grant, p, req⟩
    · refine ⟨dominant hist k, List.mem_cons_self, granted_dominant grant, p, ?_⟩
      exact fun x mem role term => (has ⟨x, mem, role, term⟩).elim
  · rintro ⟨r, _, grant, p, req⟩
    exact ⟨r, grant, p, req⟩

public def replyAt (hist : List Model.State) (s : Model.State) (v c : NodeID)
    (response : RequestVoteResponse) : Bool :=
  !response.voteGranted ||
    (observations hist c).any (fun o => o.currentTerm == response.term) &&
      (candidates hist s response.term).any fun r =>
        grantedIn hist v c response.term r &&
          s.nodes.all fun (n, x) =>
            decide ((n = c ∧ x.role = .candidate ∧ x.currentTerm = response.term) →
              makeRequestVoteRequest x = r)

theorem replyAt_iff (hist : List Model.State) (s : Model.State) (v c : NodeID)
    (response : RequestVoteResponse) :
    replyAt hist s v c response = true ↔ response.voteGranted = true →
      ∃ r, grantedIn hist v c response.term r = true ∧
        (∃ o ∈ observations hist c, o.currentTerm = response.term) ∧
        ∀ x, (c, x) ∈ s.nodes → x.role = .candidate → x.currentTerm = response.term →
          makeRequestVoteRequest x = r := by
  cases flag : response.voteGranted
  · simp [replyAt, flag]
  · simp only [replyAt, flag, Bool.not_true, Bool.false_or, true_implies,
      List.any_eq_true, List.all_eq_true, Prod.forall, Bool.and_eq_true, beq_iff_eq,
      decide_eq_true_eq, bound_reply]
    constructor
    · rintro ⟨seen, r, mem, grant, agrees⟩
      exact ⟨r, mem, grant, seen, fun x now role term => agrees c x now ⟨rfl, role, term⟩⟩
    · rintro ⟨r, mem, grant, seen, agrees⟩
      exact ⟨seen, r, mem, grant, fun n x now ⟨rfl, role, term⟩ => agrees x now role term⟩

theorem before_response [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) (source target : NodeID)
    (response : RequestVoteResponse) :
    MessageOK f ⟨source, target, .requestVoteResponse response⟩ ↔
      replyAt (x.base.before :: x.base.past) x.base.before source target response = true := by
  rw [replyAt_iff]
  simp only [MessageOK, Granted, Seen, X.grant_before ok, X.seen_before ok, X.now_before ok, obs_eta]

theorem after_response [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    {x : XView} {c : Ctx f t} (ok : x.Matches c) (source target : NodeID)
    (response : RequestVoteResponse) :
    MessageOK (f.advance t) ⟨source, target, .requestVoteResponse response⟩ ↔
      replyAt (x.base.after :: x.base.before :: x.base.past) x.base.after source target response = true := by
  rw [replyAt_iff]
  simp only [MessageOK, Granted, Seen, X.grant_after ok, X.seen_after ok, X.now_after ok, obs_eta]

end ConsensusCoverage.ReadersVoteReply
