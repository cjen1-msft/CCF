-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicTransitionScans
import MachineGenerated.SymbolicTransitionState

set_option autoImplicit false

namespace CCFRaft.SymbolicTransition

open Symbolic SymbolicModel

theorem configurations_length (index : Nat) (log : List (Entry Node Nat)) :
    (configurationsInLogFrom index log).length ≤ log.length := by
  induction log generalizing index with
  | nil => simp [configurationsInLogFrom]
  | cons entry entries ih =>
      cases hc : entry.content <;> simp [configurationsInLogFrom, hc] <;>
        have h := ih (index + 1) <;> omega

def currentConfigurationStep (commit : Expr .nat)
    (current configuration : Expr configurationCodec.ty) : Expr configurationCodec.ty :=
  .ite (configuration.fst.le commit) configuration current

theorem currentConfigurationStep_correct (ρ : Assignment) (commit : Expr .nat)
    (current configuration : Expr configurationCodec.ty) :
    configurationCodec.decode ρ (currentConfigurationStep commit current configuration) =
      if (configurationCodec.decode ρ configuration).index ≤ commit.eval ρ then
        configurationCodec.decode ρ configuration else configurationCodec.decode ρ current := by
  rw [currentConfigurationStep, decode_choose]
  simp only [eval_le, decide_eq_true_eq]
  rfl

def currentConfigurationExpr (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr configurationCodec.ty :=
  foldl (currentConfigurationStep commit) capacity (configurationCodec.literal implicitConfiguration)
    (configurationsFrom capacity (.nat 1) log).normalizeMemo

theorem configurationList_bound (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    ((configurationsFrom capacity (.nat 1) log).eval ρ).length ≤ capacity := by
  have h := (configurations_length 1 (logCodec.decode ρ log)).trans bound
  have hc := configurationsFrom_correct ρ capacity (.nat 1) log bound
  simp only [Expr.eval] at hc
  rw [← hc] at h
  simpa [Codec.decode, Codec.list] using h

def allConfigurationExpr (capacity : Nat) (log : Expr logCodec.ty) :
    Expr configurationCodec.list.ty :=
  .cons (configurationCodec.literal implicitConfiguration) (configurationsFrom capacity (.nat 1) log).normalizeMemo

theorem allConfigurationExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.list.decode ρ (allConfigurationExpr capacity log) =
      allConfigurations (logCodec.decode ρ log) := by
  change configurationCodec.decode ρ (configurationCodec.literal implicitConfiguration) ::
    configurationCodec.list.decode ρ (configurationsFrom capacity (.nat 1) log).normalizeMemo = _
  rw [Codec.decode_literal, decode_normalizeMemo, configurationsFrom_correct ρ capacity (.nat 1) log bound]
  rfl

theorem allConfigurationExpr_bound (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (configurationCodec.list.decode ρ (allConfigurationExpr capacity log)).length ≤ capacity + 1 := by
  rw [allConfigurationExpr_correct ρ capacity log bound]
  have h := (configurations_length 1 (logCodec.decode ρ log)).trans bound
  simpa [allConfigurations, configurationsInLog] using Nat.succ_le_succ h

def latestConfigurationExpr (capacity : Nat) (log : Expr logCodec.ty) :
    Expr configurationCodec.ty :=
  foldl (fun _ configuration => configuration) capacity
    (configurationCodec.literal implicitConfiguration) (configurationsFrom capacity (.nat 1) log).normalizeMemo

theorem latestConfigurationExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (state : NodeState Node Nat)
    (hlog : logCodec.decode ρ log = state.log) (bound : state.log.length ≤ capacity) :
    configurationCodec.decode ρ (latestConfigurationExpr capacity log) = latestConfiguration state := by
  have hb : (logCodec.decode ρ log).length ≤ capacity := by simpa [hlog] using bound
  have h := foldl_correct ρ configurationCodec.equiv configurationCodec.equiv
    (fun _ configuration => configuration) (fun _ configuration => configuration)
    (fun _ _ => rfl) capacity (configurationCodec.literal implicitConfiguration)
    (configurationsFrom capacity (.nat 1) log).normalizeMemo
    (by simpa only [Expr.normalizeMemo_correct] using configurationList_bound ρ capacity log hb)
  change configurationCodec.decode ρ (latestConfigurationExpr capacity log) =
    (configurationCodec.list.decode ρ (configurationsFrom capacity (.nat 1) log).normalizeMemo).foldl _
      (configurationCodec.decode ρ (configurationCodec.literal implicitConfiguration)) at h
  rw [decode_normalizeMemo, configurationsFrom_correct ρ capacity (.nat 1) log hb,
    Codec.decode_literal, hlog] at h
  exact h

theorem currentConfigurationExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (commit : Expr .nat)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.decode ρ (currentConfigurationExpr capacity log commit) =
      currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ) := by
  have h := foldl_correct ρ configurationCodec.equiv configurationCodec.equiv
    (currentConfigurationStep commit)
    (fun current configuration =>
      if configuration.index ≤ commit.eval ρ then configuration else current)
    (currentConfigurationStep_correct ρ commit) capacity
    (configurationCodec.literal implicitConfiguration) (configurationsFrom capacity (.nat 1) log).normalizeMemo
    (by simpa only [Expr.normalizeMemo_correct] using configurationList_bound ρ capacity log bound)
  change configurationCodec.decode ρ (currentConfigurationExpr capacity log commit) =
    (configurationCodec.list.decode ρ (configurationsFrom capacity (.nat 1) log).normalizeMemo).foldl _
      (configurationCodec.decode ρ (configurationCodec.literal implicitConfiguration)) at h
  rw [decode_normalizeMemo, configurationsFrom_correct ρ capacity (.nat 1) log bound, Codec.decode_literal] at h
  exact h

def activeConfigurationExpr (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr configurationCodec.list.ty :=
  let current := (currentConfigurationExpr capacity log commit).normalizeMemo
  Container.filter (capacity + 1) (fun configuration => current.fst.le configuration.fst)
    (allConfigurationExpr capacity log)

theorem filter_decode {α : Type} (c : Codec α) (ρ : Assignment) (capacity : Nat)
    (p : Expr c.ty → Expr .bool) (q : α → Bool)
    (correct : ∀ x, (p x).eval ρ = q (c.decode ρ x))
    (values : Expr c.list.ty) (bound : (c.list.decode ρ values).length ≤ capacity) :
    c.list.decode ρ (Container.filter capacity p values) =
      (c.list.decode ρ values).filter q := by
  have hb : (values.eval ρ).length ≤ capacity := by
    simpa [Codec.decode, Codec.list] using bound
  have h := Container.filter_correct ρ capacity p (fun v => q (c.equiv v)) correct values hb
  simp only [Codec.decode, Codec.list]
  rw [h]
  change ((values.eval ρ).filter (fun v => q (c.equiv v))).map c.equiv =
    ((values.eval ρ).map c.equiv).filter q
  induction values.eval ρ with
  | nil => rfl
  | cons v vs ih =>
      cases hq : q (c.equiv v) <;> simp [hq, ih]

theorem activeConfigurationExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (commit : Expr .nat) (state : NodeState Node Nat)
    (hlog : logCodec.decode ρ log = state.log) (hcommit : commit.eval ρ = state.commitIndex)
    (bound : state.log.length ≤ capacity) :
    configurationCodec.list.decode ρ (activeConfigurationExpr capacity log commit) =
      activeConfigurations state := by
  have hb : (logCodec.decode ρ log).length ≤ capacity := by simpa [hlog] using bound
  have current := currentConfigurationExpr_correct ρ capacity log commit hb
  have predicate (configuration : Expr configurationCodec.ty) :
      (Expr.le (currentConfigurationExpr capacity log commit).normalizeMemo.fst configuration.fst).eval ρ =
        decide ((currentConfiguration state).index ≤ (configurationCodec.decode ρ configuration).index) := by
    simp only [eval_le, Expr.eval, Expr.normalizeMemo_correct]
    change decide ((configurationCodec.decode ρ (currentConfigurationExpr capacity log commit)).index ≤
      (configurationCodec.decode ρ configuration).index) = _
    rw [current, hlog, hcommit]
    rfl
  have configs :
      configurationCodec.list.decode ρ (allConfigurationExpr capacity log) =
        allConfigurations state.log := by
    rw [allConfigurationExpr_correct ρ capacity log hb, hlog]
  have hlength : (allConfigurations state.log).length ≤ capacity + 1 := by
    have h := (configurations_length 1 state.log).trans bound
    simpa [allConfigurations, configurationsInLog] using Nat.succ_le_succ h
  rw [activeConfigurationExpr, filter_decode configurationCodec ρ (capacity + 1) _
    (fun configuration => decide ((currentConfiguration state).index ≤ configuration.index))
    predicate _ (by simpa [configs] using hlength), configs]
  rfl

def activeNodeUnionExpr (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr nodeSetCodec.ty :=
  foldl (fun nodes configuration => setUnion nodes configuration.snd) (capacity + 1)
    (nodeSetCodec.literal ∅) (activeConfigurationExpr capacity log commit).normalizeMemo

theorem activeNodeUnionExpr_correct (ρ : Assignment) (capacity : Nat)
    (log : Expr logCodec.ty) (commit : Expr .nat) (state : NodeState Node Nat)
    (hlog : logCodec.decode ρ log = state.log) (hcommit : commit.eval ρ = state.commitIndex)
    (bound : state.log.length ≤ capacity) :
    nodeSetCodec.decode ρ (activeNodeUnionExpr capacity log commit) = activeNodeUnion state := by
  have hc := activeConfigurationExpr_correct ρ capacity log commit state hlog hcommit bound
  have hlength : (activeConfigurations state).length ≤ capacity + 1 := by
    have h := (configurations_length 1 state.log).trans bound
    exact (List.length_filter_le _ _).trans (by
      simpa [allConfigurations, configurationsInLog] using Nat.succ_le_succ h)
  have step (nodes : Expr nodeSetCodec.ty) (configuration : Expr configurationCodec.ty) :
      nodeSetCodec.decode ρ (setUnion nodes configuration.snd) =
        nodeSetCodec.decode ρ nodes ∪ (configurationCodec.decode ρ configuration).nodes := by
    rw [setUnion_correct]
    rfl
  have h := foldl_correct ρ configurationCodec.equiv nodeSetCodec.equiv
    (fun nodes configuration => setUnion nodes configuration.snd)
    (fun nodes configuration => nodes ∪ configuration.nodes) step (capacity + 1)
    (nodeSetCodec.literal ∅) (activeConfigurationExpr capacity log commit).normalizeMemo
    (by simpa [← hc, Codec.decode, Codec.list, Expr.normalizeMemo_correct] using hlength)
  change nodeSetCodec.decode ρ (activeNodeUnionExpr capacity log commit) =
    (configurationCodec.list.decode ρ (activeConfigurationExpr capacity log commit).normalizeMemo).foldl _
      (nodeSetCodec.decode ρ (nodeSetCodec.literal ∅)) at h
  rw [decode_normalizeMemo, hc, Codec.decode_literal] at h
  exact h

def nodeSetContains (nodes : Expr nodeSetCodec.ty) (node : Expr nodeCodec.ty) : Expr .bool :=
  tableSelect nodes node

theorem nodeSetContains_correct (ρ : Assignment)
    (nodes : Expr nodeSetCodec.ty) (node : Expr nodeCodec.ty) :
    (nodeSetContains nodes node).eval ρ = true ↔
      nodeCodec.decode ρ node ∈ nodeSetCodec.decode ρ nodes := by
  simp [nodeSetContains, tableSelect_correct, Codec.decode, Codec.finset,
    Codec.transport, Codec.table, Codec.bool, Codec.fin]
  rfl

def retirementFrom (node : Expr nodeCodec.ty) :
    Nat → Expr .bool → Expr configurationCodec.list.ty → Expr Codec.nat.option.ty
  | 0, _, _ => .inl .unit
  | capacity + 1, previous, configurations =>
      let configuration := Container.head configurations
      let included := nodeSetContains configuration.snd node
      .ite (.eq configurations.length (.nat 0)) (.inl .unit)
        (.ite (.and previous (.not included)) (.inr configuration.fst)
          (retirementFrom node capacity included (.drop (.nat 1) configurations)))

theorem retirementFrom_correct (ρ : Assignment) (capacity : Nat) (node : Expr nodeCodec.ty)
    (previous : Expr .bool) (configurations : Expr configurationCodec.list.ty)
    (bound : (configurationCodec.list.decode ρ configurations).length ≤ capacity) :
    Codec.nat.option.decode ρ (retirementFrom node capacity previous configurations) =
      retirementIndexFromConfigurations (nodeCodec.decode ρ node) (previous.eval ρ)
        (configurationCodec.list.decode ρ configurations) := by
  induction capacity generalizing previous configurations with
  | zero =>
      have hn : configurationCodec.list.decode ρ configurations = [] :=
        List.length_eq_zero_iff.mp (by omega)
      rw [hn]
      rfl
  | succ capacity ih =>
      cases hs : configurations.eval ρ with
      | nil =>
          simp [retirementFrom, Codec.decode, Codec.list, Codec.option, Expr.eval, hs,
            retirementIndexFromConfigurations]
      | cons c cs =>
          have hb : (configurationCodec.list.decode ρ (.drop (.nat 1) configurations)).length ≤
              capacity := by simp [Codec.decode, Codec.list, Expr.eval, hs] at bound ⊢; omega
          have hi := ih (nodeSetContains (Container.head configurations).snd node)
            (.drop (.nat 1) configurations) hb
          have member := nodeSetContains_correct ρ (Container.head configurations).snd node
          have hm : (nodeSetContains (Container.head configurations).snd node).eval ρ =
              decide (nodeCodec.decode ρ node ∈ (configurationCodec.equiv c).nodes) := by
            apply Bool.eq_iff_iff.mpr
            simpa [Container.head, Expr.eval, hs, Codec.decode, Codec.prod,
              Codec.transport, decide_eq_true_iff] using member
          have nonempty : (Expr.eq configurations.length (.nat 0)).eval ρ = false := by
            simp [Expr.eval, hs]
          have hconfigs : configurationCodec.list.decode ρ configurations =
              configurationCodec.equiv c :: cs.map configurationCodec.equiv := by
            simp [Codec.decode, Codec.list, hs]
          have htail : configurationCodec.list.decode ρ (.drop (.nat 1) configurations) =
              cs.map configurationCodec.equiv := by
            simp [Codec.decode, Codec.list, Expr.eval, hs]
          have hindex : Codec.nat.option.decode ρ (.inr (Container.head configurations).fst) =
              some (configurationCodec.equiv c).index := by
            simp [Container.head, Codec.decode, Codec.option, Codec.nat, Expr.eval, hs]
            rfl
          simp only [retirementFrom, decode_choose, nonempty, Bool.false_eq_true, if_false]
          rw [hi, hconfigs, htail, hindex]
          change (if previous.eval ρ && !(nodeSetContains (Container.head configurations).snd node).eval ρ
            then some (configurationCodec.equiv c).index else _) = _
          rw [hm]
          cases hp : previous.eval ρ <;>
            by_cases hn : nodeCodec.decode ρ node ∈ (configurationCodec.equiv c).nodes <;>
            simp [hn, retirementIndexFromConfigurations]

def retirementIndexExpr (capacity : Nat) (node : Expr nodeCodec.ty) (log : Expr logCodec.ty) :
    Expr Codec.nat.option.ty :=
  retirementFrom node (capacity + 1) (.bool false) (allConfigurationExpr capacity log)

theorem retirementIndexExpr_correct (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    Codec.nat.option.decode ρ (retirementIndexExpr capacity node log) =
      retirementIndexInLog (nodeCodec.decode ρ node) (logCodec.decode ρ log) := by
  rw [retirementIndexExpr, retirementFrom_correct ρ (capacity + 1) node _ _
    (allConfigurationExpr_bound ρ capacity log bound), allConfigurationExpr_correct ρ capacity log bound]
  rfl

end CCFRaft.SymbolicTransition
