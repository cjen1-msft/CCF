module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReadersAtoms
public import Consensus.Proofs.LogFacts
import all ConsensusCoverage.ReadersAtoms
import all ConsensusCoverage.GuardedDomain
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.ReadersPolar

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs ReadersAtoms

/-! Pools only affect which cases are found. None of the soundness lemmas
requires a pool to contain every possible witness. -/

public structure Pools where
  states : List Model.State
  ids : Thunk (List NodeID)
  records : Thunk (List NodeState)
  entries : Thunk (List Entry)
  logs : Thunk (List (List Entry))
  envelopes : Thunk (List Model.Envelope)
  messages : Thunk (List Message)
  requests : Thunk (List RequestVoteRequest)
  acknowledgements : Thunk (List AppendEntriesResponse)
  appendRequests : Thunk (List AppendEntriesRequest)
  voteResponses : Thunk (List RequestVoteResponse)
  naturals : Thunk (List Nat)
  configurations : Thunk (List Configuration)
  sets : Thunk (List (CCF.Finset NodeID))

open Safety in
def observations (pools : Pools) : List Observation :=
  (pools.records.get.map observe).eraseDups

theorem finset_mem {v : NodeID} {s : CCF.Finset NodeID} (h : v ∈ s) : v ∈ s.val :=
  h

private def subsets : List NodeID → List (List NodeID)
  | [] => [[]]
  | n :: rest =>
    let tail := subsets rest
    tail ++ tail.map (n :: ·)

private def indices : Message → List Nat
  | .appendEntriesRequest r => [r.prevLogIndex, r.prevLogTerm, r.entries.length, r.primaryCommit]
  | .appendEntriesResponse r => [r.lastLogIndex]
  | .requestVoteRequest r | .requestPreVoteRequest r => [r.lastCommittableTerm, r.lastCommittableIndex]
  | _ => []

private def voteRequest : Message → Option RequestVoteRequest
  | .requestVoteRequest r | .requestPreVoteRequest r => some r
  | _ => none

private def voteResponse : Message → Option RequestVoteResponse
  | .requestVoteResponse r | .requestPreVoteResponse r => some r
  | _ => none

private def grantRequests (nodes : List (NodeID × NodeState)) : List RequestVoteRequest :=
  let candidates := nodes.map fun (n, s) => (n, LogFacts.requestAt s.currentTerm s.log s.commitIndex)
  let candidates := candidates.eraseDups
  candidates.map Prod.snd ++
    (nodes.map fun (n, s) => VoteFacts.stamp n s).eraseDups.flatMap fun stamp =>
      match stamp.vote with
      | none => []
      | some n => candidates.filterMap fun (c, r) =>
        if c == n then some { r with term := stamp.term } else none

public def prepare (cfg : CCF.Finset NodeID) (x : XView) : Pools :=
  let states := x.base.after :: x.base.before :: x.base.past
  let nodes := Thunk.mk fun _ => states.flatMap (·.nodes)
  let deployed := x.base.after.nodes.map Prod.fst
  let logs := Thunk.mk fun _ =>
    ((nodes.get.map (·.2.log)) ++ x.committedAfter.map Prod.snd).eraseDups
  let configurations := Thunk.mk fun _ => (logs.get.flatMap configurationHistory).eraseDups
  let ids := Thunk.mk fun _ =>
    (cfg.val ++ nodes.get.map Prod.fst ++ configurations.get.flatMap (·.nodes.val)).eraseDups
  let envelopes := Thunk.mk fun _ => (x.sent ++ states.flatMap (·.network)).eraseDups
  let messages := Thunk.mk fun _ =>
    let delivered := match x.event with
      | .receive _ p => [p]
      | .internal _ => []
    (delivered ++ envelopes.get.map (·.payload)).eraseDups
  let requests := Thunk.mk fun _ =>
    ((messages.get.filterMap voteRequest) ++ grantRequests nodes.get).eraseDups
  let configurationsSets := Thunk.mk fun _ =>
    let observed := cfg :: configurations.get.map (·.nodes)
    -- Above six nodes, retain the recorded sets without enumerating subsets.
    let finite := if deployed.length ≤ 6 then (subsets deployed).map CCF.Finset.ofList else []
    (observed ++ finite).eraseDups
  let naturals := Thunk.mk fun _ =>
    let nodeValues := nodes.get.flatMap fun (_, s) =>
      [s.currentTerm, s.commitIndex, s.log.length] ++ s.retiredCommittedIndex.toList ++
      (deployed.flatMap fun n => [s.matchIndex n, s.sentIndex n])
    let logValues := logs.get.flatMap fun l => l.map (·.term) ++ List.range (l.length + 1)
    let messageValues := messages.get.flatMap fun m => m.term :: indices m
    let values := (0 :: ids.get ++ nodeValues ++ logValues ++ messageValues).eraseDups
    (values ++ values.map Nat.succ).eraseDups
  { states, ids, envelopes, messages, requests, configurations, naturals
    records := Thunk.mk fun _ => nodes.get.map Prod.snd
    entries := Thunk.mk fun _ => (logs.get.flatten).eraseDups
    logs := Thunk.mk fun _ => ([] :: logs.get.flatMap ReadersAtoms.prefixes).eraseDups
    acknowledgements := Thunk.mk fun _ => messages.get.filterMap fun
      | .appendEntriesResponse r => some r
      | _ => none
    appendRequests := Thunk.mk fun _ => messages.get.filterMap fun
      | .appendEntriesRequest r => some r
      | _ => none
    voteResponses := Thunk.mk fun _ => messages.get.filterMap voteResponse
    sets := configurationsSets }

theorem exact_yes {p : Prop} {b : Bool} (h : b = true ↔ p) : b = true → p := h.mp

theorem exact_no {p : Prop} {b : Bool} (h : b = true ↔ p) : (!b) = true → ¬ p := by
  cases b <;> simp_all

theorem and_yes {p q : Prop} {a b : Bool} (ha : a = true → p)
    (hb : p → b = true → q) : (a && b) = true → p ∧ q := by
  intro h
  rw [Bool.and_eq_true] at h
  obtain ⟨hl, hr⟩ := h
  exact ⟨ha hl, hb (ha hl) hr⟩

theorem and_no_left {p q : Prop} {a : Bool} (ha : a = true → ¬ p) : a = true → ¬ (p ∧ q) :=
  fun h hpq => ha h hpq.1

theorem and_no_right {p q : Prop} {b : Bool} (hb : p → b = true → ¬ q) :
    b = true → ¬ (p ∧ q) :=
  fun h hpq => hb hpq.1 h hpq.2

theorem or_yes_left {p q : Prop} {a : Bool} (ha : a = true → p) : a = true → p ∨ q :=
  fun h => Or.inl (ha h)

theorem or_yes_right {p q : Prop} {b : Bool} (hb : b = true → q) : b = true → p ∨ q :=
  fun h => Or.inr (hb h)

theorem or_no {p q : Prop} {a b : Bool} (ha : a = true → ¬ p) (hb : b = true → ¬ q) :
    (a && b) = true → ¬ (p ∨ q) := by
  intro h hpq
  rw [Bool.and_eq_true] at h
  obtain ⟨hl, hr⟩ := h
  exact hpq.elim (ha hl) (hb hr)

theorem either {p : Prop} {a b : Bool} (ha : a = true → p) (hb : b = true → p) :
    (a || b) = true → p := by
  intro h
  rw [Bool.or_eq_true] at h
  exact h.elim ha hb

theorem recert_yes {p q : Prop} {b : Bool} (eq : p = q) (h : b = true → q) :
    b = true → p :=
  fun yes => eq.mpr (h yes)

theorem recert_no {p q : Prop} {b : Bool} (eq : p = q) (h : b = true → ¬ q) :
    b = true → ¬ p :=
  fun yes hp => h yes (eq.mp hp)

theorem not_no {p : Prop} {b : Bool} (h : b = true → p) : b = true → ¬ ¬ p :=
  fun yes no => no (h yes)

def sndPool {α β : Type} [DecidableEq α] (pairs : List (α × β)) (key : α) : List β :=
  (pairs.filter fun p => decide (p.1 = key)).map Prod.snd

def fstPool {α β : Type} [DecidableEq β] (pairs : List (α × β)) (key : β) : List α :=
  (pairs.filter fun p => decide (p.2 = key)).map Prod.fst

theorem mem_sndPool {α β : Type} [DecidableEq α] (pairs : List (α × β)) (key : α) (a : β) :
    a ∈ sndPool pairs key ↔ (key, a) ∈ pairs := by
  simp only [sndPool, List.mem_map, List.mem_filter, decide_eq_true_eq, Prod.exists]
  constructor
  · rintro ⟨k, b, ⟨mem, rfl⟩, rfl⟩
    exact mem
  · exact fun mem => ⟨key, a, ⟨mem, rfl⟩, rfl⟩

theorem mem_fstPool {α β : Type} [DecidableEq β] (pairs : List (α × β)) (key : β) (a : α) :
    a ∈ fstPool pairs key ↔ (a, key) ∈ pairs := by
  simp only [fstPool, List.mem_map, List.mem_filter, decide_eq_true_eq, Prod.exists]
  constructor
  · rintro ⟨b, k, ⟨mem, rfl⟩, rfl⟩
    exact mem
  · exact fun mem => ⟨a, key, ⟨mem, rfl⟩, rfl⟩

theorem exists_yes {α : Type u} {p : α → Prop} (pool : List α) (test : α → Bool)
    (sound : ∀ a, test a = true → p a) :
    pool.any test = true → ∃ a, p a := by
  intro h
  obtain ⟨a, _, yes⟩ := List.any_eq_true.mp h
  exact ⟨a, sound a yes⟩

theorem forall_no {α : Type u} {p : α → Prop} (pool : List α) (test : α → Bool)
    (sound : ∀ a, test a = true → ¬ p a) :
    pool.any test = true → ¬ (∀ a, p a) := by
  intro h all
  obtain ⟨a, _, no⟩ := List.any_eq_true.mp h
  exact sound a no (all a)

theorem exists_no {α : Type u} {p : α → Prop} (pool : List α)
    (test : (a : α) → a ∈ pool → Bool) (bound : ∀ a, p a → a ∈ pool)
    (sound : ∀ a (mem : a ∈ pool), test a mem = true → ¬ p a) :
    pool.attach.all (fun a => test a.1 a.2) = true → ¬ (∃ a, p a) := by
  intro h ⟨a, yes⟩
  have mem := bound a yes
  exact sound a mem (List.all_eq_true.mp h ⟨a, mem⟩ (by simp)) yes

theorem guarded_exists_yes {α : Type u} {p : α → Prop} (pool : List α)
    (test : (a : α) → a ∈ pool → Bool)
    (sound : ∀ a (mem : a ∈ pool), test a mem = true → p a) :
    pool.attach.any (fun a => test a.1 a.2) = true → ∃ a, p a := by
  intro h
  obtain ⟨a, _, yes⟩ := List.any_eq_true.mp h
  exact ⟨a.1, sound a.1 a.2 yes⟩

theorem forall_yes {α : Type u} {p : α → Prop} (pool : List α)
    (test : (a : α) → a ∈ pool → Bool) (bound : ∀ a, ¬ a ∈ pool → p a)
    (sound : ∀ a (mem : a ∈ pool), test a mem = true → p a) :
    pool.attach.all (fun a => test a.1 a.2) = true → ∀ a, p a := by
  intro h a
  by_cases mem : a ∈ pool
  · exact sound a mem (List.all_eq_true.mp h ⟨a, mem⟩ (by simp))
  · exact bound a mem

theorem guarded_forall_no {α : Type u} {p : α → Prop} (pool : List α)
    (test : (a : α) → a ∈ pool → Bool)
    (sound : ∀ a (mem : a ∈ pool), test a mem = true → ¬ p a) :
    pool.attach.any (fun a => test a.1 a.2) = true → ¬ (∀ a, p a) := by
  intro h all
  obtain ⟨a, _, no⟩ := List.any_eq_true.mp h
  exact sound a.1 a.2 no (all a.1)

theorem exists_prop_yes {p : Prop} {q : p → Prop} {a b : Bool}
    (ha : a = true → p) (hb : ∀ h, b = true → q h) :
    (a && b) = true → ∃ h, q h := by
  intro yes
  rw [Bool.and_eq_true] at yes
  obtain ⟨hl, hr⟩ := yes
  exact ⟨ha hl, hb (ha hl) hr⟩

theorem exists_prop_no_left {p : Prop} {q : p → Prop} {a : Bool} (ha : a = true → ¬ p) :
    a = true → ¬ (∃ h, q h) :=
  fun yes ⟨hp, _⟩ => ha yes hp

theorem exists_prop_no_right {p : Prop} {q : p → Prop} {b : Bool}
    (hb : ∀ h, b = true → ¬ q h) : b = true → ¬ (∃ h, q h) :=
  fun yes ⟨hp, hq⟩ => hb hp yes hq

theorem forall_prop_yes_left {p : Prop} {q : p → Prop} {a : Bool} (ha : a = true → ¬ p) :
    a = true → ∀ h, q h :=
  fun yes h => False.elim (ha yes h)

theorem forall_prop_yes_right {p : Prop} {q : p → Prop} {b : Bool}
    (hb : ∀ h, b = true → q h) : b = true → ∀ h, q h :=
  fun yes h => hb h yes

theorem forall_prop_no {p : Prop} {q : p → Prop} {a b : Bool}
    (ha : a = true → p) (hb : ∀ h, b = true → ¬ q h) :
    (a && b) = true → ¬ (∀ h, q h) := by
  intro yes all
  rw [Bool.and_eq_true] at yes
  obtain ⟨hl, hr⟩ := yes
  exact hb (ha hl) hr (all (ha hl))

public def answer (yes : Bool) (no : Unit → Bool) : Option Bool :=
  if yes then some true else if no () then some false else none

end ConsensusCoverage.ReadersPolar
