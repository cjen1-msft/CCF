module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.ReplayAnswers
import all ConsensusCoverage.GuardedQuestions
import all ConsensusCoverage.ReducedQuestions

namespace ConsensusCoverage.ScaleCensus

/-- Outside the unconditional projection, partial replay answers need only
these finite flags, not the guarded view, payloads, or stored node records. -/
public structure Context where
  tag : EventSupport.Tag
  ack : Option Bool
  nomination : Bool
  inert : Bool
  support : EvidenceSupport.Evidence
  delta : DeltaSupport.Evidence

public def context (e : ReplayAnswers.Evidence) : Context :=
  ⟨e.tag, e.ackAdvance, e.nomination, e.inert, e.support, e.delta⟩

private def push (n : Nat) (v : Bool) : Nat := 2 * n + v.toNat

private def tagCode (t : EventSupport.Tag) (a : Option Bool) : Nat :=
  3 * t.ctorIdx + a.elim 0 (fun b => b.toNat + 1)

public def Context.code (c : Context) : Nat :=
  [c.nomination, c.inert, c.support.pending, c.support.now, c.support.seen, c.support.grant,
    c.support.elected, c.support.canon, c.support.committed, c.delta.pending, c.delta.now,
    c.delta.election, c.delta.commit].foldl push (tagCode c.tag c.ack)

private theorem push_eq (m n : Nat) (a b : Bool) :
    push m a = push n b ↔ m = n ∧ a = b := by
  cases a <;> cases b <;> simp [push] <;> omega

private theorem prefix_eq (t u : EventSupport.Tag) (a b : Option Bool) :
    tagCode t a = tagCode u b ↔ t = u ∧ a = b := by
  have tag : t.ctorIdx = u.ctorIdx ↔ t = u := by cases t <;> cases u <;> decide
  rw [← tag]
  cases a with
  | none => cases b with
    | none => simp [tagCode]; omega
    | some z => cases z <;> simp [tagCode] <;> omega
  | some x => cases b with
    | none => cases x <;> simp [tagCode] <;> omega
    | some y => cases x <;> cases y <;> simp [tagCode] <;> omega

public theorem code_injective (a b : Context) (h : a.code = b.code) : a = b := by
  obtain ⟨t, k, n, i, ⟨p, w, s, g, e, c, m⟩, ⟨dp, dn, de, dc⟩⟩ := a
  obtain ⟨t', k', n', i', ⟨p', w', s', g', e', c', m'⟩, ⟨dp', dn', de', dc'⟩⟩ := b
  simp only [Context.code, List.foldl_cons, List.foldl_nil, push_eq, prefix_eq] at h
  grind

public def Context.other (c : Context) (b : Classes.StepBranch) : Option Bool :=
  if c.nomination then some (NominationRows.bits b) else
    (if b == .advance_backed_advance_inr then c.ack else none).orElse fun _ =>
      if c.inert || decide (c.tag ∉ EventSupport.allowed b) ||
          EvidenceSupport.excluded c.support b || DeltaSupport.excluded c.delta b then some false else none

private theorem dynamic_none (e : ReplayAnswers.Evidence) (b : Classes.StepBranch)
    (h : b ∉ ReplayAnswers.unconditional) :
    e.view.bind (GuardedQuestions.answer · b) = none ∧
      ReducedQuestions.readFrom? e.fresh b = none := by
  have hg : b ∉ GuardedQuestions.covered := fun mem => h (List.mem_append_left _ mem)
  have hr : b ∉ ReducedQuestions.covered := by
    intro mem
    exact h (List.mem_append_right _ (List.mem_append_left _ (List.mem_append_left _ mem)))
  constructor
  · cases e.view with
    | none => rfl
    | some v =>
      change GuardedQuestions.readView v b = none
      have hx := GuardedQuestions.supported v b
      simp [hg] at hx
      exact hx
  · unfold ReducedQuestions.readFrom?
    have hn : (ReducedQuestions.columns.find? fun k => decide (k.branch = b)) = none := by
      apply List.find?_eq_none.mpr
      intro x mem
      have ne : x.branch ≠ b := fun eq => hr (List.mem_map.mpr ⟨x, mem, eq⟩)
      simp [ne]
    rw [hn]
    rfl

set_option maxRecDepth 8192 in
set_option maxHeartbeats 2000000 in
private theorem direct_other (e : ReplayAnswers.Evidence) (b : Classes.StepBranch)
    (h : b ∉ ReplayAnswers.unconditional) :
    ReplayAnswers.direct e.key e.backing e.ackAdvance e.view b =
      (if b == .advance_backed_advance_inr then e.ackAdvance else none) := by
  cases b <;> first | rfl | exact (h (by decide)).elim

public theorem other_eq (e : ReplayAnswers.Evidence) (b : Classes.StepBranch)
    (h : b ∉ ReplayAnswers.unconditional) :
    (context e).other b = ReplayAnswers.answer e (.step b) := by
  obtain ⟨hg, hr⟩ := dynamic_none e b h
  by_cases tag : e.tag ∈ EventSupport.allowed b <;>
    simp [Context.other, context, ReplayAnswers.answer, hg, hr, direct_other e b h, tag]

end ConsensusCoverage.ScaleCensus
