module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import all ConsensusCoverage.HandReadersElectionBKeys
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallA.TermMonoExact

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety
open Consensus.Proofs.Ledger
open SolvedWitnesses HandReadersElectionB

set_option maxRecDepth 8192
set_option maxHeartbeats 2000000

private theorem entered_completion [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n v st term base i log commit} (cert : CommitStep (f.advance t) n st term base i)
    (backing : Backed f st.log base term) (fresh : ¬ Committed f term (st.log.take i))
    (election : Elected (f.advance t) v (term+1) log commit) :
    (reach% step_canon_mono_now_after_inl[2,0,0]) f t c c n st term base i := by
  have newCommit : Committed (f.advance t) term (st.log.take i) :=
    .inr ⟨n,st,base,i,cert,rfl,backing⟩
  have lt : term < term+1 := Nat.lt_succ_self term
  reach_unfold step_canon_mono_now_after_inl[2,0,0]
  refine ⟨st.log.take i,v,term+1,log,commit,
    ⟨newCommit,election,lt,fun old => fresh old.1,rfl⟩,
    ⟨n,st,base,i,cert,rfl,backing⟩,⟨st,base,i,cert,rfl,backing⟩,
    ⟨base,i,cert,rfl,backing⟩,⟨i,cert,rfl,backing⟩,
    ?_⟩
  repeat' first
    | exact cert
    | exact backing
    | exact newCommit
    | exact lt
    | exact election
    | rfl
    | constructor

theorem delayed_source [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {n v st term base i log commit} (cert : CommitStep (f.advance t) n st term base i)
    (backing : Backed f st.log base term) (fresh : ¬ Committed f term (st.log.take i))
    (election : Elected (f.advance t) v (term+1) log commit)
    (covered : commit ≤ base) (same : st.log.take base = log.take base)
    (floor : 2 ≤ term) : Keys.Source c := by
  have lt : term < term+1 := Nat.lt_succ_self term
  have entered := entered_completion c cert backing fresh election
  have signature := take_signature cert.2.2.2.1
  have campaign := c.rankedElections v (term+1) log commit election
  have earlier (m : Nat) (h : m < term+1) (v' : NodeID) (log' : List Entry) (commit' : Nat)
      (_ : Elected (f.advance t) v' m log' commit') (above : term < m) :
      st.log.take i <+: log' := by omega
  have clean (e : Nat) (a : List Entry) (above : term < e) (below : e ≤ term+1-1)
      (_ : (f.advance t).logs.canon e a) : st.log.take i <+: a := by omega
  have low (_ : commit ≤ base) : st.log.take base <+: log := same ▸ List.take_prefix _ _
  have high (h : base < commit) :
      ∃ part, log.take commit <+: part ∧ (st.log.take i <+: part ∨ part <+: st.log.take i) := by omega
  have agree := And.intro same (And.intro (Nat.le_refl base) covered)
  have source : (reach% step_canon_mono_now_after_inl[2,0]) f t c c := .inr
    ⟨n,st,term,base,i,entered,term+1,earlier,v,log,commit,election,lt,⟨base,agree⟩,
      base,agree,same,agree.2,agree.2.1,covered,cert,backing,cert.facts floor c.rooted c.sorted,
      signature,election,campaign,clean,low,high,floor,rfl⟩
  exact .inr (.inr (.inl (.inl ⟨source,rfl⟩)))

theorem delayed_floor [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)
    {v st base i log commit}
    (cert : CommitStep (f.advance t) Config.INITIAL_PRIMARY st BOOTSTRAP_TERM base i)
    (backing : Backed f st.log base BOOTSTRAP_TERM)
    (fresh : ¬ Committed f BOOTSTRAP_TERM (st.log.take i))
    (election : Elected (f.advance t) v (BOOTSTRAP_TERM+1) log commit)
    (covered : commit ≤ base) (same : st.log.take base = log.take base) :
    sig c .leader_floor_led_inl := by
  have newCommit : Committed (f.advance t) BOOTSTRAP_TERM (st.log.take i) :=
    .inr ⟨_,st,base,i,cert,rfl,backing⟩
  have lt : BOOTSTRAP_TERM < BOOTSTRAP_TERM+1 := by decide
  have entered : (reach% step_leader_floor_led_inl[6,1]) f t c
      Config.INITIAL_PRIMARY st BOOTSTRAP_TERM base i := by
    reach_unfold step_leader_floor_led_inl[6,1]
    refine ⟨st.log.take i,v,BOOTSTRAP_TERM+1,log,commit,
      ⟨newCommit,election,lt,fun old => fresh old.1⟩,
      ⟨_,st,base,i,cert,rfl,backing⟩,⟨st,base,i,cert,rfl,backing⟩,
      ⟨base,i,cert,rfl,backing⟩,⟨i,cert,rfl,backing⟩,?_⟩
    repeat' first
      | exact cert
      | exact backing
      | exact newCommit
      | exact lt
      | exact election
      | rfl
      | constructor
  have signature := take_signature cert.2.2.2.1
  have campaign := c.rankedElections v (BOOTSTRAP_TERM+1) log commit election
  have earlier (m : Nat) (h : m < BOOTSTRAP_TERM+1) (v' : NodeID) (log' : List Entry) (commit' : Nat)
      (_ : Elected (f.advance t) v' m log' commit') (above : BOOTSTRAP_TERM < m) :
      st.log.take i <+: log' := by omega
  have clean (e : Nat) (a : List Entry) (above : BOOTSTRAP_TERM < e) (below : e ≤ BOOTSTRAP_TERM+1-1)
      (_ : (f.advance t).logs.canon e a) : st.log.take i <+: a := by omega
  have low (_ : commit ≤ base) : st.log.take base <+: log := same ▸ List.take_prefix _ _
  have high (h : base < commit) :
      ∃ part, log.take commit <+: part ∧ (st.log.take i <+: part ∨ part <+: st.log.take i) := by omega
  have agree := And.intro same (And.intro (Nat.le_refl base) covered)
  have leader : Led f Config.INITIAL_PRIMARY BOOTSTRAP_TERM := .inl ⟨rfl,rfl⟩
  have src : (reach% step_leader_floor_led_inl[6]) f t c Config.INITIAL_PRIMARY BOOTSTRAP_TERM := by
    reach_unfold step_leader_floor_led_inl[6]
    iterate 4 right
    left
    exact ⟨st,base,i,entered,BOOTSTRAP_TERM+1,earlier,v,log,commit,election,lt,⟨base,agree⟩,
      base,agree,same,agree.2,agree.2.1,covered,leader,cert,backing,signature,election,campaign,clean,low,high⟩
  change step_leader_floor_led_inl _ _ _
  iterate 6 right
  exact .inl ⟨src,leader⟩

end ConsensusCoverage.ClauseSmallA.TermMonoExact
