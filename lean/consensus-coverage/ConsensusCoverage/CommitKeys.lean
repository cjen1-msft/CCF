module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.GrantMonitor
import all ConsensusCoverage.Historical
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
import ConsensusCoverage.Schedule

/-! Exact commit readers over newest-first histories. All rules use the entire
current ghost, not the ghost at the snapshot where a leader log was observed. -/

namespace ConsensusCoverage.CommitKeys

open CCF Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

public abbrev Key := Nat × List Entry

private def canonicalAt (cfg : Finset NodeID) (s : Model.State) (past : List Model.State) :
    List Key :=
  (s.nodes.filter fun (n, st) =>
    decide (st.role ≠ .candidate) && GrantMonitor.led cfg (s :: past) n st.currentTerm).map
      fun (_, st) => (st.currentTerm, st.log)

private def canonical (cfg : Finset NodeID) : List Model.State → List Key
  | [] => []
  | s :: h => canonicalAt cfg s h ++ canonical cfg h

private theorem mem_canonicalAt [Config.InitialConfiguration]
    (s : Model.State) (h : List Model.State) (t : Nat) (l : List Entry) :
    (t, l) ∈ canonicalAt Config.INITIAL_CONFIGURATION s h ↔
      ∃ n st, Historical.CanonNow (s :: h) n st t ∧ st.log = l := by
  simp only [canonicalAt, List.mem_map, List.mem_filter, Prod.exists, Bool.and_eq_true,
    decide_eq_true_eq, Prod.mk.injEq, GrantMonitor.led_historical, Historical.CanonNow, Historical.Now]
  grind

private theorem mem_canonical [Config.InitialConfiguration] (history : List Model.State)
    (t : Nat) (l : List Entry) :
    (t, l) ∈ canonical Config.INITIAL_CONFIGURATION history ↔ Historical.Canon history t l := by
  induction history with
  | nil => simp [canonical, Historical.Canon, Historical.CanonNow, Historical.Now]
  | cons s h ih =>
    simp only [canonical, List.mem_append, mem_canonicalAt, ih, Historical.Canon, List.suffix_cons_iff]
    grind

private structure Rule where
  term : Nat
  log : List Entry
  base : Nat
  index : Nat

private def Rule.key (r : Rule) : Key := (r.term, r.log.take r.index)

private def Rule.certified (history : List Model.State) (r : Rule) : Bool :=
  isSignatureAt r.log r.index && decide (termAt r.log r.index = r.term) &&
    GrantMonitor.quorum ((activeConfigurations r.log r.base).filter (·.index ≤ r.index))
      (fun v => GrantMonitor.seenWhere history v r.term fun p => decide (r.log.take r.index <+: p))

private def rules (cfg : Finset NodeID) (history : List Model.State) : List Rule :=
  ((canonical cfg history).flatMap fun (term, log) =>
    (List.range (log.length + 1)).flatMap fun i =>
      (List.range (i + 1)).map fun base => ⟨term, log, base, i⟩).filter (Rule.certified history)

private theorem mem_rules [Config.InitialConfiguration] (s : Model.State) (h : List Model.State)
    (r : Rule) :
    r ∈ rules Config.INITIAL_CONFIGURATION (s :: h) ↔
      CommitFacts (StateCoverage.frame s h).logs r.log r.term r.base r.index := by
  have acks (v : NodeID) :
      GrantMonitor.seenWhere (s :: h) v r.term
          (fun p => decide (r.log.take r.index <+: p)) = true ↔
        ∃ p, (StateCoverage.frame s h).logs.seen v r.term p ∧ r.log.take r.index <+: p := by
    simp only [GrantMonitor.seenWhere_iff, decide_eq_true_eq, (Historical.frame_correct s h).seen]
    grind
  simp only [rules, List.mem_filter, List.mem_flatMap, List.mem_map, Prod.exists, List.mem_range,
    Nat.lt_succ_iff, mem_canonical, Rule.certified, Bool.and_eq_true, decide_eq_true_eq,
    GrantMonitor.quorum_iff, acks]
  constructor
  · rintro ⟨⟨t, l, canon, i, indexLe, b, baseLe, rfl⟩, ⟨sig, term⟩, votes⟩
    exact ⟨((Historical.frame_correct s h).canon t l).mpr canon, baseLe, indexLe, sig, term, votes⟩
  · intro facts
    exact ⟨⟨r.term, r.log, ((Historical.frame_correct s h).canon ..).mp facts.canon,
      r.index, facts.indexLe, r.base, facts.baseLe, by cases r; rfl⟩,
      ⟨facts.signature, facts.termAtIndex⟩, facts.acks⟩

private def supported (known : List Key) (log : List Entry) (base term : Nat) : Bool :=
  known.any fun (earlier, p) => decide (earlier ≤ term ∧ log.take base <+: p)

private theorem supported_iff (known : List Key) (log : List Entry) (base term : Nat) :
    supported known log base term = true ↔
      ∃ e p, (e, p) ∈ known ∧ e ≤ term ∧ log.take base <+: p := by
  simp only [supported, List.any_eq_true, Prod.exists, decide_eq_true_eq]

private def Rule.enabled (known : List Key) (r : Rule) : Bool :=
  supported known r.log r.base r.term

/-- Fire all ready rules simultaneously, and never reconsider a fired rule.
The rule count bounds the number of nonempty rounds. -/
private def close : Nat → List Rule → List Key → List Key
  | 0, _, known => known
  | fuel + 1, pending, known =>
    match pending.filter (Rule.enabled known) with
    | [] => known
    | r :: ready =>
      close fuel (pending.filter fun a => !(a.enabled known)) ((r :: ready).map Rule.key ++ known)

private theorem pending_length (pending : List Rule) (test : Rule → Bool)
    (nonempty : pending.filter test ≠ []) :
    (pending.filter fun r => !test r).length < pending.length := by
  induction pending with
  | nil => exact (nonempty rfl).elim
  | cons r rest ih =>
    cases yes : test r with
    | false =>
      simp only [List.filter_cons, yes, Bool.false_eq_true, ↓reduceIte] at nonempty
      simpa [yes] using Nat.succ_lt_succ (ih nonempty)
    | true =>
      simpa [yes] using Nat.lt_succ_of_le (List.length_filter_le (fun r => !test r) rest)

private def Sound (g : LogFacts.Ghost) (known : List Key) : Prop :=
  ∀ p ∈ known, Commit g p.1 p.2

private theorem close_spec (g : LogFacts.Ghost) (fuel : Nat) (pending : List Rule)
    (known : List Key) (bound : pending.length ≤ fuel)
    (certified : ∀ r ∈ pending, CommitFacts g r.log r.term r.base r.index)
    (sound : Sound g known) :
    known ⊆ close fuel pending known ∧ Sound g (close fuel pending known) ∧
      ∀ r ∈ pending, r.enabled (close fuel pending known) = true → r.key ∈ close fuel pending known := by
  induction fuel generalizing pending known with
  | zero =>
    have empty : pending = [] := List.length_eq_zero_iff.mp (Nat.eq_zero_of_le_zero bound)
    subst pending
    exact ⟨fun _ h => h, sound, by simp⟩
  | succ fuel ih =>
    cases eq : pending.filter (Rule.enabled known) with
    | nil =>
      simp only [close, eq]
      refine ⟨fun _ h => h, sound, fun r mem yes => ?_⟩
      have : r ∈ pending.filter (Rule.enabled known) := List.mem_filter.mpr ⟨mem, yes⟩
      simp [eq] at this
    | cons r ready =>
      let rest := pending.filter fun a => !(a.enabled known)
      let next := (r :: ready).map Rule.key ++ known
      have len : rest.length < pending.length := pending_length pending _ (by simp [eq])
      have soundNext : Sound g next := by
        intro p mem
        rcases List.mem_append.mp mem with new | old
        · obtain ⟨rule, fired, rfl⟩ := List.mem_map.mp new
          rw [← eq] at fired
          obtain ⟨member, enabled⟩ := List.mem_filter.mp fired
          obtain ⟨e, p, prior, le, within⟩ := (supported_iff ..).mp enabled
          exact .link (certified rule member) (sound (e, p) prior) le within
        · exact sound p old
      obtain ⟨includes, soundDone, stable⟩ :=
        ih rest next (by omega) (fun a mem => certified a (List.mem_filter.mp mem).1) soundNext
      simp only [close, eq]
      refine ⟨fun p mem => includes (List.mem_append_right _ mem), soundDone, fun rule mem enabled => ?_⟩
      cases fired : rule.enabled known with
      | false =>
        exact stable rule (List.mem_filter.mpr ⟨mem, by simp [fired]⟩) enabled
      | true =>
        apply includes
        apply List.mem_append_left
        exact List.mem_map.mpr ⟨rule, eq ▸ List.mem_filter.mpr ⟨mem, fired⟩, rfl⟩

/-- All committed `(term, prefix)` pairs, including the empty base key. -/
@[expose] public def keys (cfg : Finset NodeID) (history : List Model.State) : List Key :=
  let pending := rules cfg history
  (close pending.length pending [(0, [])]).eraseDups

private theorem mem_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (t : Nat) (p : List Entry) :
    (t, p) ∈ keys cfg (s :: h) ↔ Committed (@StateCoverage.frame ⟨cfg⟩ s h) t p := by
  letI : Config.InitialConfiguration := ⟨cfg⟩
  let g := (StateCoverage.frame s h).logs
  let pending := rules Config.INITIAL_CONFIGURATION (s :: h)
  let result := close pending.length pending [(0, [])]
  have seed : Sound g [(0, [])] := by
    intro a mem
    have : a = (0, []) := List.mem_singleton.mp mem
    subst a
    exact .base
  have cert (r : Rule) : r ∈ pending ↔ CommitFacts g r.log r.term r.base r.index :=
    mem_rules s h r
  obtain ⟨includes, sound, stable⟩ :=
    close_spec g pending.length pending [(0, [])] (Nat.le_refl _) (fun r => (cert r).mp) seed
  change (t, p) ∈ result.eraseDups ↔ Commit g t p
  rw [List.mem_eraseDups]
  constructor
  · exact sound (t, p)
  · intro proof
    induction proof with
    | base => exact includes (by simp)
    | @link l t b i e p facts _ le within ih =>
      let r : Rule := ⟨t, l, b, i⟩
      exact stable r ((cert r).mpr facts) ((supported_iff ..).mpr ⟨e, p, ih, le, within⟩)

@[expose] public def committed (cfg : Finset NodeID) (history : List Model.State)
    (term : Nat) (part : List Entry) : Bool :=
  (keys cfg history).contains (term, part)

private theorem committed_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (t : Nat) (p : List Entry) :
    committed cfg (s :: h) t p = true ↔ Committed (@StateCoverage.frame ⟨cfg⟩ s h) t p := by
  rw [committed, List.contains_iff_mem]
  exact mem_iff cfg s h t p

@[expose] public def backed (cfg : Finset NodeID) (history : List Model.State)
    (log : List Entry) (commit term : Nat) : Bool :=
  supported (keys cfg history) log commit term

private theorem backed_iff (cfg : Finset NodeID) (s : Model.State) (h : List Model.State)
    (log : List Entry) (commit term : Nat) :
    backed cfg (s :: h) log commit term = true ↔ Backed (@StateCoverage.frame ⟨cfg⟩ s h) log commit term := by
  simp only [backed, supported_iff, Backed, mem_iff]

/-- Whether a key appears in the successor frame but not the predecessor. -/
@[expose] public def fresh (cfg : Finset NodeID) (after : Model.State) (history : List Model.State)
    (term : Nat) (part : List Entry) : Bool :=
  committed cfg (after :: history) term part && !committed cfg history term part

private theorem fresh_iff (cfg : Finset NodeID) (after before : Model.State) (past : List Model.State)
    (t : Nat) (p : List Entry) :
    fresh cfg after (before :: past) t p = true ↔
      Committed (@StateCoverage.frame ⟨cfg⟩ after (before :: past)) t p ∧
        ¬ Committed (@StateCoverage.frame ⟨cfg⟩ before past) t p := by
  simp only [fresh, Bool.and_eq_true, Bool.not_eq_true', Bool.eq_false_iff, ne_eq, committed_iff]

/-- Whether the step adds any committed key. -/
@[expose] public def anyFresh (cfg : Finset NodeID) (after : Model.State) (history : List Model.State) : Bool :=
  let old := keys cfg history
  (keys cfg (after :: history)).any fun key => !old.contains key

private theorem anyFresh_iff (cfg : Finset NodeID) (after before : Model.State) (past : List Model.State) :
    anyFresh cfg after (before :: past) = true ↔
      ∃ t p, Committed (@StateCoverage.frame ⟨cfg⟩ after (before :: past)) t p ∧
        ¬ Committed (@StateCoverage.frame ⟨cfg⟩ before past) t p := by
  simp only [anyFresh, List.any_eq_true, Prod.exists, Bool.not_eq_true', Bool.eq_false_iff, ne_eq,
    List.contains_iff_mem, mem_iff]

-- The long key can already use the short key in the same snapshot, even though
-- only the smaller configuration acknowledges the long prefix.
private theorem same_snapshot_link :
    let cfg : Finset NodeID := {0, 1}
    let sig : Entry := ⟨BOOTSTRAP_TERM, .signature⟩
    let short := [⟨BOOTSTRAP_TERM, .transaction 0 {configuration := some cfg}⟩,
      ⟨BOOTSTRAP_TERM, .transaction 1 {configuration := some {0}}⟩, sig]
    let long := short ++ [sig]
    let snapshot : Model.State := {nodes := [(0, {initialNodeState cfg 0 with log := long}),
      (1, {initialNodeState cfg 1 with log := short})]}
    committed cfg [snapshot] BOOTSTRAP_TERM short = true ∧
      committed cfg [snapshot] BOOTSTRAP_TERM long = true := by
  decide +kernel

private def solo : Schedule :=
  ⟨{0}, [0], [.local 0 (.append [{content := .signature}])]⟩

private theorem solo_signature :
    let signed := (initialNodeState solo.cfg 0).log ++ [⟨BOOTSTRAP_TERM, .signature⟩]
    (solo.replay.map fun states => keys solo.cfg states.reverse) =
      some [(BOOTSTRAP_TERM, signed), (0, [])] := by
  decide +kernel

end ConsensusCoverage.CommitKeys
