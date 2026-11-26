module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.BatchArmsB
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.HandReadersABatch
import all ConsensusCoverage.DeepInputCases
import all ConsensusCoverage.LeaderEffect
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant

namespace ConsensusCoverage.HandReadersTrunkA.Batch

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety ActionProfile
open HandReadersA SolvedWitnesses

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false

private def seed [Config.InitialConfiguration] {f : Frame} {t : State} (c : Ctx f t) {xs}
    (ev : c.event = .internal (.append xs)) : BatchArmsB.Seed c := by
  have ran : (appendBatch (CCF.Capabilities.record c.actor) c.actor c.pre xs).run {} =
      some (c.post,c.tr.outputs) := by
    change (step _ _ _ (.internal (.append xs))).run {} = _
    rw [← ev]
    exact c.tr.ran
  have guard : c.pre.role = .primary ∧ ¬c.pre.isRetiredCommitted c.actor ∧ xs ≠ [] := by
    apply Classical.byContradiction
    intro no
    simp [appendBatch,_root_.guard,no,Bind.bind,StateT.bind,StateT.run,failure,StateT.failure] at ran
  have grow : c.pre.log.length < c.post.log.length := by
    obtain ⟨_,_,h⟩ := LeaderEffect.appendBatch_grows c.actor c.pre xs _ _ _ ran
    exact h
  have root := DeepInputCases.summary c fun old => (Nat.lt_irrefl _) ((c.now_pre old) ▸ grow)
  exact ⟨c.actor,c.pre,xs,
    ⟨c.event,⟨_,c.tr,root,rfl,rfl,rfl⟩,_,ev,ev,rfl⟩,
    ⟨c.event,⟨_,c.tr,root,rfl⟩,_,ev,ev,_,rfl⟩,guard⟩

private def exactOfSeed (b : Classes.StepBranch) (onlyAppend : EventSupport.allowed b = [.append])
    (onAppend : ∀ [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t},
      BatchArmsB.Seed c → sig c b) : Exact b where
  eval := Append.reader
  eq_label s := by
    letI : Config.InitialConfiguration := ⟨s.cfg⟩
    apply Bool.eq_iff_iff.mpr
    rw [show Append.reader = (Append.exactReader .cons).eval from rfl,
      ← (Append.exactReader .cons).eq_label s, label_true, label_true,
      show holds s (.step (Append.column .cons)) ↔ sig s.context (Append.column .cons) from sig_iff _ _,
      Append.iff_append]
    constructor
    · intro yes
      have tag := EventSupport.sig_support s.context b yes
      rw [onlyAppend, List.mem_singleton, EventSupport.actionTag_eq] at tag
      change ∃ xs, s.context.tr.event = .internal (.append xs)
      cases e : s.context.tr.event with
      | internal i => cases i <;> simp_all [EventSupport.eventTag, EventSupport.inputTag]
      | receive n m => cases m <;> simp_all [EventSupport.eventTag, EventSupport.messageTag]
    · rintro ⟨_,ev⟩
      exact (sig_iff _ _).mpr (onAppend (seed s.context ev))

private theorem nilOfSeed [Config.InitialConfiguration] {f : Frame} {t : State} {c : Ctx f t}
    (s : BatchArmsB.Seed c) : step_foldlM__items_nil_2 f t c := by
  iterate 6 right
  exact Or.inl (Or.inr (Or.inl s.erased))

def peersNone := exactOfSeed .appendEntry_batch_peers_none (by decide +kernel) (fun s => (BatchArmsB.peers s).1)
def peersSome := exactOfSeed .appendEntry_batch_peers_some (by decide +kernel) (fun s => (BatchArmsB.peers s).2)
def pushOld := exactOfSeed .push_mem_append_inl (by decide +kernel) (fun s => (BatchArmsB.pushed s).1)
def pushNew := exactOfSeed .push_mem_append_inr (by decide +kernel) (fun s => (BatchArmsB.pushed s).2)
def foldNil := exactOfSeed .foldlM__items_nil_2 (by decide +kernel) nilOfSeed
def foldCons := exactOfSeed .foldlM__items_cons_2 (by decide +kernel) BatchArmsB.folded

end ConsensusCoverage.HandReadersTrunkA.Batch
