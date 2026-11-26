module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model
public import Consensus.Model.Messages
public import ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.ReadersShapes
import all ConsensusCoverage.GuardedDomain
import all ConsensusCoverage.Historical
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ReadersShapes

open Consensus Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open ConsensusCoverage.ReadersAtoms
open ConsensusCoverage.GuardedDomain

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

/-- Keep an endpoint and the first value above it for every comparison threshold. -/
def cuts (thresholds : List Nat) : List Nat :=
  0 :: thresholds ++ thresholds.map (· + 1)

def cutRep (n : Nat) (thresholds : List Nat) : Nat :=
  (cuts thresholds).foldl (fun b k => if k ≤ n then max b k else b) 0

theorem cutRep_properties (n : Nat) (thresholds : List Nat) :
    cutRep n thresholds ∈ cuts thresholds ∧
      cutRep n thresholds ≤ n ∧
      ∀ k ∈ cuts thresholds, k ≤ n → k ≤ cutRep n thresholds := by
  have fold (xs : List Nat) (b : Nat) (le : b ≤ n) :
      let r := xs.foldl (fun b k => if k ≤ n then max b k else b) b
      (r = b ∨ r ∈ xs) ∧ r ≤ n ∧ b ≤ r ∧ ∀ k ∈ xs, k ≤ n → k ≤ r := by
    induction xs generalizing b with
    | nil => simp [le]
    | cons a xs ih =>
      simp only [List.foldl_cons]
      by_cases ha : a ≤ n
      · rw [ite_eq_left ha]
        obtain ⟨source, le', ge, all⟩ := ih (max b a) (Nat.max_le.mpr ⟨le, ha⟩)
        refine ⟨?_, le', Nat.le_trans (Nat.le_max_left _ _) ge, ?_⟩
        · rcases source with same | old
          · by_cases order : a ≤ b
            · exact Or.inl (same.trans (Nat.max_eq_left order))
            · refine Or.inr ?_
              rw [same, Nat.max_eq_right (Nat.le_of_lt (Nat.lt_of_not_ge order))]
              exact List.mem_cons_self
          · exact Or.inr (List.mem_cons_of_mem _ old)
        · intro k mem le
          rcases List.mem_cons.mp mem with rfl | old
          · exact Nat.le_trans (Nat.le_max_right _ _) ge
          · exact all k old le
      · rw [ite_eq_right ha]
        obtain ⟨source, le', ge, all⟩ := ih b le
        refine ⟨source.imp_right (List.mem_cons_of_mem _), le', ge, ?_⟩
        intro k mem le
        rcases List.mem_cons.mp mem with rfl | old
        · exact (ha le).elim
        · exact all k old le
  obtain ⟨source, le, _, all⟩ := fold (cuts thresholds) 0 (Nat.zero_le _)
  refine ⟨source.elim ?_ id, le, all⟩
  intro eq
  change cutRep n thresholds = 0 at eq
  simp [eq, cuts]

theorem cutRep_same (n : Nat) {thresholds : List Nat} {k : Nat} (mem : k ∈ thresholds) :
    (k ≤ cutRep n thresholds ↔ k ≤ n) ∧
    (k < cutRep n thresholds ↔ k < n) ∧
    (k = cutRep n thresholds ↔ k = n) := by
  obtain ⟨_, le, all⟩ := cutRep_properties n thresholds
  have le' : k ≤ cutRep n thresholds ↔ k ≤ n :=
    ⟨fun h => Nat.le_trans h le, all k (by simp [cuts, mem])⟩
  have lt' : k < cutRep n thresholds ↔ k < n :=
    ⟨fun h => Nat.lt_of_lt_of_le h le, fun h => all (k + 1)
      (by simp [cuts, List.mem_map_of_mem (f := (· + 1)) mem]) h⟩
  rcases Nat.lt_trichotomy k n with h | h | h
  · exact ⟨le', lt', by simp [Nat.ne_of_lt h, Nat.ne_of_lt (lt'.mpr h)]⟩
  · subst k
    exact ⟨le', lt', by simp [Nat.le_antisymm le (le'.mpr (Nat.le_refl n))]⟩
  · exact ⟨le', lt', by simp [Nat.ne_of_gt h, Nat.ne_of_gt (Nat.lt_of_le_of_lt le h)]⟩

def requestRep (terms indices : List Nat) (r : RequestVoteRequest) : RequestVoteRequest :=
  { r with lastCommittableTerm := cutRep r.lastCommittableTerm terms
           lastCommittableIndex := cutRep r.lastCommittableIndex indices }

theorem requestRep_rank {terms indices : List Nat} {k i : Nat}
    (term : k ∈ terms) (idx : i ∈ indices) (r : RequestVoteRequest) :
    VoteRank (requestRep terms indices r) k i ↔ VoteRank r k i := by
  obtain ⟨_, lt, eq⟩ := cutRep_same r.lastCommittableTerm term
  obtain ⟨le, _, _⟩ := cutRep_same r.lastCommittableIndex idx
  simp only [requestRep, VoteRank, lt, eq, le]

theorem requestRep_fresh {terms indices : List Nat} {x : NodeState}
    (term : maxCommittableTerm x.log ∈ terms)
    (idx : maxCommittableIndex x.log ∈ indices) (r : RequestVoteRequest) :
    voteLogUpToDate x (requestRep terms indices r) ↔ voteLogUpToDate x r := by
  simpa only [voteLogUpToDate, VoteRank, gt_iff_lt, ge_iff_le, eq_comm] using
    requestRep_rank term idx r

theorem requestRep_grantAt {terms indices : List Nat} {s t : Consensus.Model.State}
    (supported : ∀ p ∈ s.nodes,
      maxCommittableTerm p.2.log ∈ terms ∧ maxCommittableIndex p.2.log ∈ indices)
    (v c k : Nat) (r : RequestVoteRequest) :
    LogFacts.GrantAt s t v c k (requestRep terms indices r) ↔ LogFacts.GrantAt s t v c k r := by
  have agree : ∀ x, (v, x) ∈ s.nodes →
      (voteLogUpToDate x (requestRep terms indices r) ↔ voteLogUpToDate x r) := by
    intro x h
    obtain ⟨term, idx⟩ := supported (v, x) h
    exact requestRep_fresh term idx r
  constructor
  · rintro ⟨x, y, pre, post, le, eq, vote, up⟩
    exact ⟨x, y, pre, post, le, eq, vote, (agree x pre).mp up⟩
  · rintro ⟨x, y, pre, post, le, eq, vote, up⟩
    exact ⟨x, y, pre, post, le, eq, vote, (agree x pre).mpr up⟩

def historicalTerms (h : List Consensus.Model.State) : List Nat :=
  (histNodes h).map fun (_, x) => maxCommittableTerm x.log

def historicalIndices (h : List Consensus.Model.State) : List Nat :=
  (histNodes h).map fun (_, x) => maxCommittableIndex x.log

theorem requestRep_grantedIn {terms indices : List Nat}
    (h : List Consensus.Model.State) (v c k : Nat) (r : RequestVoteRequest)
    (supportsTerm : ∀ t ∈ historicalTerms h, t ∈ terms)
    (supportsIndex : ∀ i ∈ historicalIndices h, i ∈ indices) :
    grantedIn h v c k (requestRep terms indices r) = true ↔ grantedIn h v c k r = true := by
  simp only [grantedIn_iff]
  have agree {a b rest x} (suf : a :: b :: rest <:+ h) (old : (v, x) ∈ b.nodes) :
      voteLogUpToDate x (requestRep terms indices r) ↔ voteLogUpToDate x r := by
    have mem : (v, x) ∈ histNodes h := mem_histNodes (suf.subset (by simp)) old
    exact requestRep_fresh
      (supportsTerm _ (List.mem_map_of_mem mem))
      (supportsIndex _ (List.mem_map_of_mem mem)) r
  constructor
  · rintro ⟨a, b, rest, suf, ⟨x, y, pre, post, le, eq, vote, up⟩, seen⟩
    exact ⟨a, b, rest, suf, ⟨x, y, pre, post, le, eq, vote, (agree suf pre).mp up⟩, seen⟩
  · rintro ⟨a, b, rest, suf, ⟨x, y, pre, post, le, eq, vote, up⟩, seen⟩
    exact ⟨a, b, rest, suf, ⟨x, y, pre, post, le, eq, vote, (agree suf pre).mpr up⟩, seen⟩

def seenTerms (h : List Consensus.Model.State) : List Nat :=
  (histNodes h).map fun (_, x) => x.currentTerm

def seenIndices (h : List Consensus.Model.State) : List Nat :=
  (histNodes h).flatMap fun (_, x) => signatureIndices x.log

theorem requestRep_voterRank [Config.InitialConfiguration] {terms indices : List Nat}
    (h : List Consensus.Model.State) (canon : Nat → List Entry → Prop)
    (v t bound : Nat) (r : RequestVoteRequest)
    (supportsTerm : ∀ k ∈ seenTerms h, k ∈ terms)
    (supportsIndex : ∀ i ∈ seenIndices h, i ∈ indices) :
    VoterRank (Historical.logFacts h) canon v t bound (requestRep terms indices r) ↔
      VoterRank (Historical.logFacts h) canon v t bound r := by
  have equivalent (k : Nat) (l : List Entry) (i : Nat)
      (seen : (Historical.logFacts h).seen v k l) (sig : isSignatureAt l i = true) :
      RankOrLoss canon bound (requestRep terms indices r) k i (l.take i) ↔
        RankOrLoss canon bound r k i (l.take i) := by
    rw [(Historical.logFacts_correct h).seen] at seen
    obtain ⟨x, ⟨s, hs, mem⟩, rfl, rfl⟩ := seen
    have old := mem_histNodes hs mem
    have term := supportsTerm _ (List.mem_map_of_mem old)
    have index := supportsIndex _ (List.mem_flatMap.mpr ⟨_, old, sig_index.mp sig⟩)
    simp only [RankOrLoss, requestRep_rank term index r]
  exact ⟨fun h k l i seen lt sig eq => (equivalent k l i seen sig).mp (h k l i seen lt sig eq),
    fun h k l i seen lt sig eq => (equivalent k l i seen sig).mpr (h k l i seen lt sig eq)⟩

def requestCuts (term : Nat) (terms indices : List Nat) : List RequestVoteRequest :=
  (cuts terms).flatMap fun t => (cuts indices).map fun i => ⟨term, t, i⟩

theorem requestRep_mem (term : Nat) (terms indices : List Nat) (r : RequestVoteRequest) :
    { requestRep terms indices r with term } ∈ requestCuts term terms indices := by
  apply List.mem_flatMap.mpr
  refine ⟨_, (cutRep_properties r.lastCommittableTerm terms).1, ?_⟩
  exact List.mem_map.mpr ⟨_, (cutRep_properties r.lastCommittableIndex indices).1, rfl⟩

theorem requestCuts_exists (term : Nat) (terms indices : List Nat) (P : RequestVoteRequest → Prop)
    (same : ∀ r, P r ↔ P { requestRep terms indices r with term }) :
    (∃ r, P r) ↔ ∃ r ∈ requestCuts term terms indices, P r :=
  ⟨fun ⟨r, hr⟩ => ⟨_, requestRep_mem term terms indices r, (same r).mp hr⟩,
    fun ⟨r, _, hr⟩ => ⟨r, hr⟩⟩

theorem grantedIn_set_term (h : List Consensus.Model.State) (v c k term : Nat)
    (r : RequestVoteRequest) :
    grantedIn h v c k { r with term } = true ↔ grantedIn h v c k r = true := by
  simp only [grantedIn_iff, Historical.Granted, Historical.GrantStep, voteLogUpToDate]

def requestTerms (history : List Model.State) : List Nat :=
  historicalTerms history ++ seenTerms history

def requestIndices (history : List Model.State) : List Nat :=
  historicalIndices history ++ seenIndices history

def replayRequestRep (history : List Consensus.Model.State) (r : RequestVoteRequest) :
    RequestVoteRequest :=
  { requestRep (requestTerms history) (requestIndices history) r with term := 0 }

theorem replayRequestRep_grantAt {s t : Consensus.Model.State}
    {history : List Consensus.Model.State} (mem : s ∈ history)
    (v c k : Nat) (r : RequestVoteRequest) :
    LogFacts.GrantAt s t v c k (replayRequestRep history r) ↔ LogFacts.GrantAt s t v c k r := by
  have supported (p : NodeID × NodeState) (pMem : p ∈ s.nodes) :
      maxCommittableTerm p.2.log ∈ requestTerms history ∧
        maxCommittableIndex p.2.log ∈ requestIndices history := by
    have hist := mem_histNodes mem pMem
    exact ⟨List.mem_append_left _ (List.mem_map_of_mem hist),
      List.mem_append_left _ (List.mem_map_of_mem hist)⟩
  have sameTerm (q : RequestVoteRequest) :
      LogFacts.GrantAt s t v c k { q with term := 0 } ↔ LogFacts.GrantAt s t v c k q := by
    simp only [LogFacts.GrantAt, voteLogUpToDate]
  exact (sameTerm _).trans (requestRep_grantAt supported v c k r)

theorem replayRequestRep_grantedIn {prior history : List Consensus.Model.State}
    (same : ∀ s ∈ prior, s ∈ history) (v c k : Nat) (r : RequestVoteRequest) :
    grantedIn prior v c k (replayRequestRep history r) = grantedIn prior v c k r := by
  have subset {α : Type} (f : NodeID × NodeState → α) :
      ∀ a ∈ (histNodes prior).map f, a ∈ (histNodes history).map f := by
    intro a ha
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp ha
    obtain ⟨s, hs, pMem⟩ := List.mem_flatMap.mp hp
    exact List.mem_map_of_mem (mem_histNodes (same s hs) pMem)
  apply Bool.eq_iff_iff.mpr
  exact (grantedIn_set_term ..).trans (requestRep_grantedIn prior v c k r
    (fun _ hm => List.mem_append_left _ (subset _ _ hm))
    (fun _ hm => List.mem_append_left _ (subset _ _ hm)))

public def replayRequests (history : List Consensus.Model.State) : List RequestVoteRequest :=
  let terms := (cuts (requestTerms history)).eraseDups
  let indices := (cuts (requestIndices history)).eraseDups
  terms.flatMap fun t => indices.map fun i => ⟨0, t, i⟩

theorem replayRequests_bound {history : List Consensus.Model.State} {P : RequestVoteRequest → Prop}
    (same : ∀ r, P r ↔ P (replayRequestRep history r)) :
    (∃ r, P r) ↔ ∃ r ∈ replayRequests history, P r := by
  have equivalent (r : RequestVoteRequest) :
      r ∈ replayRequests history ↔ r ∈ requestCuts 0 (requestTerms history) (requestIndices history) := by
    simp only [replayRequests, requestCuts, List.mem_flatMap, List.mem_map, List.mem_eraseDups]
  exact (requestCuts_exists _ _ _ P same).trans
    (exists_congr fun r => and_congr (equivalent r).symm Iff.rfl)

theorem replayRequestRep_voteLogUpToDate {history : List Model.State}
    {state : NodeState} (mem : ∃ n, (n, state) ∈ histNodes history)
    (r : RequestVoteRequest) :
    voteLogUpToDate state (replayRequestRep history r) ↔ voteLogUpToDate state r := by
  obtain ⟨n, mem⟩ := mem
  have h := requestRep_fresh (terms := requestTerms history) (indices := requestIndices history)
    (List.mem_append_left _ (List.mem_map_of_mem (f := fun (_, st) => maxCommittableTerm st.log) mem))
    (List.mem_append_left _ (List.mem_map_of_mem (f := fun (_, st) => maxCommittableIndex st.log) mem)) r
  simpa only [replayRequestRep, voteLogUpToDate, requestRep] using h

theorem replayRequestRep_voterRank [Config.InitialConfiguration] {prior history : List Model.State}
    (incl : ∀ s ∈ prior, s ∈ history)
    (canon : Nat → List Entry → Prop) (v t bound : Nat) (r : RequestVoteRequest) :
    VoterRank (Historical.logFacts prior) canon v t bound (replayRequestRep history r) ↔
      VoterRank (Historical.logFacts prior) canon v t bound r := by
  have inclNodes : ∀ p ∈ histNodes prior, p ∈ histNodes history := by
    intro p hp
    obtain ⟨s, hs, hp⟩ := List.mem_flatMap.mp hp
    exact mem_histNodes (incl s hs) hp
  have h := requestRep_voterRank (terms := requestTerms history) (indices := requestIndices history)
    prior canon v t bound r
    (fun k hk =>
      let ⟨p, hp, eq⟩ := List.mem_map.mp hk
      List.mem_append_right _ (List.mem_map.mpr ⟨p, inclNodes p hp, eq⟩))
    (fun i hi =>
      let ⟨p, hp, mem⟩ := List.mem_flatMap.mp hi
      List.mem_append_right _ (List.mem_flatMap.mpr ⟨p, inclNodes p hp, mem⟩))
  simpa only [replayRequestRep, requestRep, VoterRank, RankOrLoss, VoteRank] using h

abbrev requestHistory (x : XView) : List Model.State :=
  x.base.after :: x.base.before :: x.base.past

section Frame

variable [inst : Config.InitialConfiguration] {f : Frame} {t : Model.State}
  {x : XView} {c : Ctx f t} (ok : x.Matches c)

include ok in
theorem request_grant_before (v n k : Nat) (r : RequestVoteRequest) :
    f.logs.grant v n k (replayRequestRep (requestHistory x) r) ↔ f.logs.grant v n k r := by
  simp only [X.grant_before ok]
  rw [replayRequestRep_grantedIn (fun _ => List.mem_cons_of_mem _)]

include ok in
theorem request_grant_after (v n k : Nat) (r : RequestVoteRequest) :
    (f.advance t).logs.grant v n k (replayRequestRep (requestHistory x) r) ↔
      (f.advance t).logs.grant v n k r := by
  simp only [X.grant_after ok]
  rw [replayRequestRep_grantedIn (fun _ => id)]

include ok in
theorem request_rank_before (v k b : Nat) (r : RequestVoteRequest) :
    VoterRank f.logs f.logs.canon v k b (replayRequestRep (requestHistory x) r) ↔
      VoterRank f.logs f.logs.canon v k b r := by
  rw [X.logs_before ok]
  exact @replayRequestRep_voterRank inst _ _ (fun _ => List.mem_cons_of_mem _) _ _ _ _ _

include ok in
theorem request_grantAt_prior {prior : Model.State} (eq : prior = f.current)
    (next : Model.State) (v n k : Nat) (r : RequestVoteRequest) :
    LogFacts.GrantAt prior next v n k (replayRequestRep (requestHistory x) r) ↔
      LogFacts.GrantAt prior next v n k r := by
  rw [eq, X.before_eq ok]
  exact replayRequestRep_grantAt (by simp [requestHistory]) _ _ _ _

include ok in
theorem request_vote_before {st : NodeState} (mem : ∃ n, (n, st) ∈ f.current.nodes)
    (r : RequestVoteRequest) :
    voteLogUpToDate st (replayRequestRep (requestHistory x) r) ↔ voteLogUpToDate st r := by
  obtain ⟨n, mem⟩ := mem
  rw [X.before_eq ok] at mem
  exact replayRequestRep_voteLogUpToDate ⟨n, mem_histNodes (by simp [requestHistory]) mem⟩ r

end Frame

example : (∃ r, RequestVoteRequest.term r = 9 ∧ VoteRank r 100 400 ∧ ¬ VoteRank r 101 0) ↔
    ∃ r ∈ requestCuts 9 [100, 101] [400, 0],
      RequestVoteRequest.term r = 9 ∧ VoteRank r 100 400 ∧ ¬ VoteRank r 101 0 := by
  -- The equality is required only in this example. Do not select a fixed request
  -- term for a general formula without proving that it does not change it.
  constructor
  · rintro ⟨r, term, outranks, notOutranks⟩
    have a := requestRep_rank (terms := [100, 101]) (indices := [400, 0])
      (k := 100) (i := 400) (by decide) (by decide) r
    have b := requestRep_rank (terms := [100, 101]) (indices := [400, 0])
      (k := 101) (i := 0) (by decide) (by decide) r
    exact ⟨_, requestRep_mem 9 [100, 101] [400, 0] r, rfl, a.mpr outranks, notOutranks ∘ b.mp⟩
  · rintro ⟨r, _, eq, outranks, notOutranks⟩
    exact ⟨r, eq, outranks, notOutranks⟩

end ConsensusCoverage.ReadersShapes
