-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicBounds

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

def ScalarShape : Ty → Bool
  | .nat | .bool | .unit => true
  | .pair a b | .sum a b => ScalarShape a && ScalarShape b
  | .seq _ => false

theorem scalar_fits (cap : Capacities) (s : Ty) (h : ScalarShape s = true) (v : s.Value) :
    Fits cap s v := by
  induction s with
  | nat | bool | unit => trivial
  | pair a b ha hb =>
      have hab : ScalarShape a = true ∧ ScalarShape b = true := by simpa [ScalarShape] using h
      exact ⟨ha hab.1 _, hb hab.2 _⟩
  | sum a b ha hb =>
      have hab : ScalarShape a = true ∧ ScalarShape b = true := by simpa [ScalarShape] using h
      cases v with
      | inl x => exact ha hab.1 x
      | inr y => exact hb hab.2 y
  | seq a _ => contradiction

theorem vector_fits (cap : Capacities) (n : Nat) (a : Ty) (v : (vectorTy n a).Value) :
    Fits cap (vectorTy n a) v ↔ ∀ i, Fits cap a (vectorGet v i) := by
  induction n with
  | zero => simp [Fits]
  | succ n ih =>
      rcases v with ⟨x, xs⟩
      simp [Fits, vectorGet, Fin.forall_fin_succ, ih]

abbrev InShape {α : Type} (cap : Capacities) (c : Codec α) (v : α) :=
  Fits cap c.ty (c.equiv.symm v)

theorem inShape_scalar {α : Type} (cap : Capacities) (c : Codec α)
    (h : ScalarShape c.ty = true) (v : α) : InShape cap c v :=
  scalar_fits cap c.ty h _

theorem inShape_prod {α β : Type} (cap : Capacities) (a : Codec α) (b : Codec β) (x : α) (y : β) :
    InShape cap (a.prod b) (x, y) ↔ InShape cap a x ∧ InShape cap b y := Iff.rfl

theorem inShape_option {α : Type} (cap : Capacities) (c : Codec α) (v : Option α) :
    InShape cap c.option v ↔ ∀ x ∈ v, InShape cap c x := by
  cases v <;> simp [InShape, Codec.option, Fits]

theorem inShape_list {α : Type} (cap : Capacities) (c : Codec α) (xs : List α) :
    InShape cap c.list xs ↔ xs.length ≤ cap c.list.ty ∧ ∀ x ∈ xs, InShape cap c x := by
  simp [InShape, Codec.list, Fits]

theorem inShape_nodeTable {α : Type} (cap : Capacities) (c : Codec α)
    (values : BoundedState.NodeTable α) :
    InShape cap (nodeTableCodec c) values ↔ ∀ node, InShape cap c (values.get node) := by
  simp [InShape, nodeTableCodec, Codec.transport, Codec.table, vector_fits]

theorem inShape_finset (cap : Capacities) (n : Nat) (values : Finset (Fin n)) :
    InShape cap (Codec.finset n) values := by
  simp [InShape, Codec.finset, Codec.transport, Codec.table, vector_fits, Codec.bool, Fits]

theorem inShape_log (bounds : BoundedState.Bounds) (xs : List (Entry Node Nat))
    (bound : xs.length ≤ bounds.logCapacity) :
    InShape (capacities bounds) logCodec xs := by
  rw [inShape_list]
  constructor
  · simpa [capacities, logCodec, queueCodec, Codec.list, messageCodec, Codec.transport,
      Codec.sum, entryCodec, Codec.prod] using bound
  · intro x _
    exact inShape_scalar _ entryCodec (by decide) x

theorem inShape_message (bounds : BoundedState.Bounds) (message : Message Node Nat)
    (bound : BoundedState.MessageWithin bounds message) :
    InShape (capacities bounds) messageCodec message := by
  cases message with
  | appendEntriesRequest r =>
      have logs := inShape_log bounds r.entries bound.2.2.2.1
      change InShape (capacities bounds)
        (Codec.nat.prod (Codec.nat.prod (Codec.nat.prod
          (logCodec.prod (Codec.nat.prod (nodeCodec.prod nodeCodec))))))
          (r.term, r.prevLogIndex, r.prevLogTerm, r.entries, r.leaderCommit, r.source, r.destination)
      simp only [inShape_prod]
      refine ⟨trivial, trivial, trivial, logs, trivial, ?_, ?_⟩ <;>
        exact inShape_scalar _ nodeCodec (by decide) _
  | appendEntriesResponse r =>
      exact inShape_scalar _ appendResponseCodec (by decide) r
  | requestVoteRequest r =>
      exact inShape_scalar _ voteRequestCodec (by decide) r
  | requestVoteResponse r =>
      exact inShape_scalar _ voteResponseCodec (by decide) r
  | requestPreVote r =>
      exact inShape_scalar _ preVoteRequestCodec (by decide) r
  | requestPreVoteResponse r =>
      exact inShape_scalar _ preVoteResponseCodec (by decide) r
  | proposeVoteRequest r =>
      exact inShape_scalar _ proposeCodec (by decide) r

theorem inShape_local (bounds : BoundedState.Bounds) (v : BoundedState.LocalStateData)
    (bound : BoundedState.LocalDataWithin bounds v) :
    InShape (capacities bounds) localCodec v := by
  have logs := inShape_log bounds v.log bound.2.1
  change InShape (capacities bounds)
    (roleCodec.prod (Codec.nat.prod (logCodec.prod (Codec.nat.prod
      ((nodeTableCodec Codec.nat).prod ((nodeTableCodec Codec.nat).prod
        (Codec.bool.prod (nodeCodec.option.prod (nodeSetCodec.prod
          (nodeSetCodec.prod (membershipCodec.prod (Codec.nat.option.prod
            (Codec.nat.option.prod Codec.nat.option))))))))))))) _
  refine ⟨?_, trivial, logs, trivial, ?_, ?_, trivial, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · exact inShape_scalar _ roleCodec (by decide) _
  · exact (inShape_nodeTable _ Codec.nat v.sentIndex).mpr (fun _ => trivial)
  · exact (inShape_nodeTable _ Codec.nat v.matchIndex).mpr (fun _ => trivial)
  · exact inShape_scalar _ nodeCodec.option (by decide) _
  · exact inShape_finset _ NODE_COUNT _
  · exact inShape_finset _ NODE_COUNT _
  · exact inShape_scalar _ membershipCodec (by decide) _
  all_goals exact inShape_scalar _ Codec.nat.option (by decide) _

theorem inShape_entry (bounds : BoundedState.Bounds) (v : EntryData bounds.transactionCount)
    (bound : BoundedState.DataWithinBounds bounds v.toData) :
    InShape (capacities bounds) (stateCodec bounds.transactionCount) v := by
  rcases v with ⟨nodes, network, submitted, joined, preVote, retired⟩
  simp only [stateCodec, inShape_prod]
  refine ⟨?_, ?_, inShape_finset _ _ _, inShape_finset _ _ _, ?_, ?_⟩
  · rw [inShape_nodeTable]
    intro node
    rw [inShape_option]
    intro value hv
    have hb := bound.1 node
    simp only [EntryData.toData, BoundedState.OptionalLocalDataWithin] at hb
    cases hn : nodes.get node with
    | none => simp [hn] at hv
    | some localState =>
        simp [hn] at hv
        subst value
        exact inShape_local bounds localState (by simpa [hn] using hb)
  · rw [inShape_nodeTable]
    intro node
    rw [inShape_list]
    have hb := bound.2.1 node
    refine ⟨?_, ?_⟩
    · simpa [capacities, EntryData.toData] using hb.1
    · intro message hm
      exact inShape_message bounds message ((List.forall_iff_forall_mem.mp hb.2) _ hm)
  · rw [inShape_nodeTable]
    intro node
    exact inShape_scalar _ preVoteCodec (by decide) _
  · rw [inShape_nodeTable]
    intro node
    exact inShape_finset _ _ _

def importEntry (bounds : BoundedState.Bounds) (state : CCFRaft.State Node Nat) :
    EntryData bounds.transactionCount :=
  let data := BoundedState.encode state
  (data.nodes, data.network,
    Finset.univ.filter (fun i : Fin bounds.transactionCount => i.val ∈ state.submittedTxIds),
    data.hasJoined, data.preVoteStatus, data.retirementCompleted)

theorem importEntry_toData (bounds : BoundedState.Bounds) (state : CCFRaft.State Node Nat)
    (bound : BoundedState.WithinBounds bounds state) :
    (importEntry bounds state).toData = BoundedState.encode state := by
  have submitted :
      (Finset.univ.filter (fun i : Fin bounds.transactionCount =>
        i.val ∈ state.submittedTxIds)).image Fin.val = state.submittedTxIds := by
    ext tx
    simp only [Finset.mem_image, Finset.mem_filter, Finset.mem_univ, true_and]
    constructor
    · rintro ⟨i, hi, rfl⟩; exact hi
    · intro hi
      exact ⟨⟨tx, bound.2.2 tx hi⟩, hi, rfl⟩
  simp [importEntry, EntryData.toData, submitted]
  rfl

theorem withinBounds_fits (bounds : BoundedState.Bounds) (state : CCFRaft.State Node Nat)
    (bound : BoundedState.WithinBounds bounds state) :
    InShape (capacities bounds) (stateCodec bounds.transactionCount) (importEntry bounds state) := by
  apply inShape_entry
  rw [importEntry_toData bounds state bound, BoundedState.DataWithinBounds_encode_iff]
  exact bound

theorem freshEntry_complete_model (bounds : BoundedState.Bounds) (start : Nat)
    (state : CCFRaft.State Node Nat) (bound : BoundedState.WithinBounds bounds state) :
    ∃ ρ : Assignment, evalEntry bounds ρ (freshEntry bounds start) = state := by
  obtain ⟨ρ, hρ⟩ := freshEntry_complete bounds start (importEntry bounds state)
    (withinBounds_fits bounds state bound)
  refine ⟨ρ, ?_⟩
  simpa [importEntry_toData bounds state bound] using hρ

end CCFRaft.SymbolicTransition
