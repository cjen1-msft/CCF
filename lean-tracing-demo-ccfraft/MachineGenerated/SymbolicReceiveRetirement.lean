-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.SymbolicReceiveAppend
import MachineGenerated.SymbolicReceiveNormalize
import MachineGenerated.SymbolicReceiveScans

set_option autoImplicit false

namespace CCFRaft.SymbolicReceive

open Symbolic SymbolicModel SymbolicTransition

theorem configurations_length (log : List (Entry Node Nat)) (index : Nat) :
    (configurationsInLogFrom index log).length ≤ log.length := by
  induction log generalizing index with
  | nil => simp [configurationsInLogFrom]
  | cons e es ih =>
    cases h : e.content <;> simp [configurationsInLogFrom, h]
    all_goals have bound := ih (index + 1); omega

def configurations (capacity : Nat) (log : Expr logCodec.ty) : Expr configurationCodec.list.ty :=
  .cons (configurationCodec.literal implicitConfiguration) (rawConfigurationsFrom capacity (.nat 1) log)

theorem configurations_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.list.decode ρ (configurations capacity log) =
      allConfigurations (logCodec.decode ρ log) := by
  unfold configurations
  change implicitConfiguration :: configurationCodec.list.decode ρ
    (rawConfigurationsFrom capacity (.nat 1) log) = _
  rw [rawConfigurationsFrom_correct ρ capacity _ log bound]
  rfl

theorem configurations_bound (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (bound : (logCodec.decode ρ log).length ≤ capacity) :
    (configurationCodec.list.decode ρ (configurations capacity log)).length ≤ capacity + 1 := by
  rw [configurations_correct ρ capacity log bound]
  simp only [allConfigurations, configurationsInLog, List.length_cons]
  exact Nat.add_le_add_right (le_trans (configurations_length _ 1) bound) 1

theorem decode_foldl {A B : Type} (a : Codec A) (b : Codec B) (ρ : Assignment)
    (capacity : Nat) (step : Expr b.ty → Expr a.ty → Expr b.ty)
    (base : Expr b.ty) (xs : Expr a.list.ty) (f : B → A → B)
    (correct : ∀ acc x, b.decode ρ (step acc x) = f (b.decode ρ acc) (a.decode ρ x))
    (bound : (a.list.decode ρ xs).length ≤ capacity) :
    b.decode ρ (foldl step capacity base xs) =
      (a.list.decode ρ xs).foldl f (b.decode ρ base) := by
  exact foldl_correct ρ a.equiv b.equiv step f correct capacity base xs
    (by simpa [Codec.decode, Codec.list] using bound)

def currentConfig (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr configurationCodec.ty :=
  foldl (fun current cfg => .ite (cfg.fst.le commit) cfg current) capacity
    (configurationCodec.literal implicitConfiguration) (rawConfigurationsFrom capacity (.nat 1) log)

theorem currentConfig_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (commit : Expr .nat) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    configurationCodec.decode ρ (currentConfig capacity log commit) =
      currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ) := by
  have cfgBound :
      (configurationCodec.list.decode ρ (rawConfigurationsFrom capacity (.nat 1) log)).length ≤ capacity := by
    rw [rawConfigurationsFrom_correct ρ capacity _ log bound]
    exact le_trans (configurations_length _ _) bound
  have h := decode_foldl configurationCodec configurationCodec ρ capacity
    (fun current cfg => .ite (cfg.fst.le commit) cfg current)
    (configurationCodec.literal implicitConfiguration) (rawConfigurationsFrom capacity (.nat 1) log)
    (fun current cfg => if cfg.index ≤ commit.eval ρ then cfg else current) (by
      intro current cfg
      simp only [decode_choose, eval_le, decide_eq_true_eq]
      rfl) cfgBound
  simpa only [currentConfig, rawConfigurationsFrom_correct ρ capacity _ log bound,
    Codec.decode_literal, Expr.eval, currentConfigurationAt, configurationsInLog] using h

abbrev retirementPairCodec : Codec (Option Nat × Option Nat) :=
  Codec.nat.option.prod Codec.nat.option

def retirementPairStep (node : Expr nodeCodec.ty) (_ : Expr .nat)
    (cfg : Expr configurationCodec.ty) (rest : Expr retirementPairCodec.ty) :
    Expr retirementPairCodec.ty :=
  .ite (tableSelect cfg.snd node) (.pair rest.snd rest.snd) (.pair rest.fst (.inr cfg.fst))

theorem retirementPairStep_correct (ρ : Assignment) (node : Expr nodeCodec.ty) (i : Expr .nat)
    (cfg : Expr configurationCodec.ty) (rest : Expr retirementPairCodec.ty) :
    retirementPairCodec.decode ρ (retirementPairStep node i cfg rest) =
      if nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ cfg).nodes then
        ((retirementPairCodec.decode ρ rest).2, (retirementPairCodec.decode ρ rest).2)
      else ((retirementPairCodec.decode ρ rest).1, some (configurationCodec.decode ρ cfg).index) := by
  simp only [retirementPairStep, decode_choose, decode_pair, decode_some]
  have member : (tableSelect cfg.snd node).eval ρ = true ↔
      nodeCodec.decode ρ node ∈ (configurationCodec.decode ρ cfg).nodes := by
    simp [tableSelect_correct, Codec.decode, Codec.finset, Codec.transport, Codec.table,
      Codec.prod, Codec.bool, Codec.fin]
    rfl
  simp only [member]
  rfl

def retirement (capacity : Nat) (node : Expr nodeCodec.ty) (log : Expr logCodec.ty) :
    Expr Codec.nat.option.ty :=
  (foldrFrom (retirementPairStep node) (.pair (.inl .unit) (.inl .unit))
    (capacity + 1) (.nat 0) (configurations capacity log)).fst

theorem retirement_correct (ρ : Assignment) (capacity : Nat) (node : Expr nodeCodec.ty)
    (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    Codec.nat.option.decode ρ (retirement capacity node log) =
      retirementIndexInLog (nodeCodec.decode ρ node) (logCodec.decode ρ log) := by
  let f := fun (_ : Nat) (cfg : Configuration Node) (rest : Option Nat × Option Nat) =>
    if nodeCodec.decode ρ node ∈ cfg.nodes then (rest.2, rest.2) else (rest.1, some cfg.index)
  have h := foldrFrom_correct ρ configurationCodec.equiv retirementPairCodec.equiv
    (retirementPairStep node) (.pair (.inl .unit) (.inl .unit)) f
    (retirementPairStep_correct ρ node) (capacity + 1) (.nat 0) (configurations capacity log)
    (by
      have h := configurations_bound ρ capacity log bound
      simpa [Codec.decode, Codec.list] using h)
  have scan (cs : List (Configuration Node)) (i : Nat) :
      indexedFold f (none, none) i cs =
        (retirementIndexFromConfigurations (nodeCodec.decode ρ node) false cs,
          retirementIndexFromConfigurations (nodeCodec.decode ρ node) true cs) := by
    induction cs generalizing i with
    | nil => rfl
    | cons c cs ih =>
      by_cases member : nodeCodec.decode ρ node ∈ c.nodes <;>
        simp [indexedFold, f, ih, retirementIndexFromConfigurations, member]
  change (retirementPairCodec.decode ρ
    (foldrFrom (retirementPairStep node) (.pair (.inl .unit) (.inl .unit))
      (capacity + 1) (.nat 0) (configurations capacity log))).1 = _
  have result : retirementPairCodec.decode ρ
      (foldrFrom (retirementPairStep node) (.pair (.inl .unit) (.inl .unit))
        (capacity + 1) (.nat 0) (configurations capacity log)) =
      indexedFold f (none, none) 0
        (configurationCodec.list.decode ρ (configurations capacity log)) := h
  rw [result, scan, configurations_correct ρ capacity log bound]
  rfl

def committedRetired (capacity : Nat) (node : Expr nodeCodec.ty) (state : Local) :
    Expr Codec.nat.option.ty :=
  rawOptionCases (retiredIndex capacity node (.nat 1) state.log) (.inl .unit)
    (fun index => .ite (index.le state.commitIndex) (.inr index) (.inl .unit))

theorem committedRetired_correct (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (state : Local) (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    Codec.nat.option.decode ρ (committedRetired capacity node state) =
      (retiredCommittedIndexInLog (nodeCodec.decode ρ node) (state.eval ρ).log).filter
        (fun index => index ≤ (state.eval ρ).commitIndex) := by
  rw [committedRetired, rawOptionCases_correct Codec.nat Codec.nat.option ρ _ _ _
    (fun index => if index ≤ state.commitIndex.eval ρ then some index else none) (by
      intro index
      simp only [decode_choose, eval_le, decode_some, decode_none, decide_eq_true_eq]
      rfl)]
  rw [retiredIndex_correct ρ capacity node _ state.log bound, decode_none]
  simp only [Local.eval]
  change (retiredCommittedIndexInLog _ _).elim _ _ = _
  cases retiredCommittedIndexInLog (nodeCodec.decode ρ node) (logCodec.decode ρ state.log) <;>
    simp [Option.filter]

def retirementSignature (capacity : Nat) (node : Expr nodeCodec.ty) (log : Expr logCodec.ty) :
    Expr Codec.nat.option.ty :=
  optionBind Codec.nat Codec.nat (retirement capacity node log)
    (fun index => signatureAfter capacity index (.nat 1) log)

theorem retirementSignature_correct (ρ : Assignment) (capacity : Nat)
    (node : Expr nodeCodec.ty) (log : Expr logCodec.ty) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    Codec.nat.option.decode ρ (retirementSignature capacity node log) =
      (retirementIndexInLog (nodeCodec.decode ρ node) (logCodec.decode ρ log)).bind
        (retirementCommittableIndexInLog (logCodec.decode ρ log)) := by
  rw [retirementSignature, optionBind_correct Codec.nat Codec.nat ρ _ _
    (retirementCommittableIndexInLog (logCodec.decode ρ log)) (by
      intro index
      exact signatureAfter_correct ρ capacity index (.nat 1) log bound),
    retirement_correct ρ capacity node log bound]

def refresh (capacity : Nat) (node : Expr nodeCodec.ty) (state : Local) : Local :=
  let retired := retirement capacity node state.log
  let signed := retirementSignature capacity node state.log
  let committed := committedRetired capacity node state
  let membership := rawOptionCases retired (membershipCodec.literal .active) fun index =>
    .ite (isSome committed) (membershipCodec.literal .retiredCommitted)
      (.ite (index.le state.commitIndex) (membershipCodec.literal .retirementCompleted)
        (.ite (isSome signed) (membershipCodec.literal .retirementSigned)
          (membershipCodec.literal .retirementOrdered)))
  { state with
    membershipState := membership
    retirementIndex := retired
    retirementCommittableIndex := signed
    retiredCommittedIndex := committed }

theorem refresh_correct (ρ : Assignment) (capacity : Nat) (node : Expr nodeCodec.ty)
    (state : Local) (bound : (logCodec.decode ρ state.log).length ≤ capacity) :
    (refresh capacity node state).eval ρ =
      refreshRetirementState (nodeCodec.decode ρ node) (state.eval ρ) := by
  have membership := rawOptionCases_correct Codec.nat membershipCodec ρ
    (retirement capacity node state.log) (membershipCodec.literal .active)
    (fun index => Expr.ite (isSome (committedRetired capacity node state))
      (membershipCodec.literal .retiredCommitted)
      (.ite (index.le state.commitIndex) (membershipCodec.literal .retirementCompleted)
        (.ite (isSome (retirementSignature capacity node state.log))
          (membershipCodec.literal .retirementSigned) (membershipCodec.literal .retirementOrdered))))
    (fun index => if (Codec.nat.option.decode ρ (committedRetired capacity node state)).isSome then
      .retiredCommitted else if index ≤ state.commitIndex.eval ρ then .retirementCompleted
      else if (Codec.nat.option.decode ρ (retirementSignature capacity node state.log)).isSome then
        .retirementSigned else .retirementOrdered) (by
      intro index
      simp only [decode_choose, isSome_correct Codec.nat ρ, Codec.decode_literal, eval_le, decide_eq_true_eq]
      rfl)
  simp only [refresh, Local.eval, membership, Codec.decode_literal,
    retirement_correct ρ capacity node state.log bound,
    retirementSignature_correct ρ capacity node state.log bound,
    committedRetired_correct ρ capacity node state bound]
  unfold refreshRetirementState
  simp only [Local.eval]
  cases retirementIndexInLog (nodeCodec.decode ρ node) (logCodec.decode ρ state.log) <;> rfl

def priorNodes (capacity : Nat) (log : Expr logCodec.ty) (current : Expr .nat) :
    Expr nodeSetCodec.ty :=
  foldl (fun nodes cfg => .ite (.lt cfg.fst current) (setUnion nodes cfg.snd) nodes)
    (capacity + 1) (nodeSetCodec.literal ∅) (configurations capacity log)

theorem priorNodes_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (current : Expr .nat) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (priorNodes capacity log current) =
      (allConfigurations (logCodec.decode ρ log)).foldl
        (fun nodes cfg => if cfg.index < current.eval ρ then nodes ∪ cfg.nodes else nodes) ∅ := by
  have h := decode_foldl configurationCodec nodeSetCodec ρ (capacity + 1)
    (fun nodes cfg => .ite (.lt cfg.fst current) (setUnion nodes cfg.snd) nodes)
    (nodeSetCodec.literal ∅) (configurations capacity log)
    (fun nodes cfg => if cfg.index < current.eval ρ then nodes ∪ cfg.nodes else nodes) (by
      intro nodes cfg
      simp only [decode_choose, setUnion_correct, Expr.eval, decide_eq_true_eq]
      rfl) (configurations_bound ρ capacity log bound)
  simpa only [priorNodes, configurations_correct ρ capacity log bound, Codec.decode_literal] using h

def retiredSet (entry : Expr entryCodec.ty) : Expr nodeSetCodec.ty :=
  matchSum entry.snd (fun _ => nodeSetCodec.literal ∅) fun other =>
    matchSum other (fun _ => nodeSetCodec.literal ∅) fun sets =>
      matchSum sets (fun _ => nodeSetCodec.literal ∅) id

theorem retiredSet_correct (ρ : Assignment) (entry : Expr entryCodec.ty) :
    nodeSetCodec.decode ρ (retiredSet entry) =
      match (entryCodec.decode ρ entry).content with
      | .retiredCommitted nodes => nodes
      | _ => ∅ := by
  generalize he : entry.eval ρ = v
  rcases v with ⟨term, tx | (_ | (nodes | nodes))⟩ <;>
    simp [retiredSet, matchSum, Expr.eval, Codec.decode, he,
      Codec.transport, Codec.prod, Codec.sum, Codec.literal]

def retiredNodesStep (commit index : Expr .nat) (entry : Expr entryCodec.ty)
    (rest : Expr nodeSetCodec.ty) : Expr nodeSetCodec.ty :=
  .ite (index.le commit) (setUnion (retiredSet entry) rest) rest

theorem retiredNodesStep_correct (ρ : Assignment) (commit index : Expr .nat)
    (entry : Expr entryCodec.ty) (rest : Expr nodeSetCodec.ty) :
    nodeSetCodec.decode ρ (retiredNodesStep commit index entry rest) =
      if index.eval ρ ≤ commit.eval ρ then
        match (entryCodec.decode ρ entry).content with
        | .retiredCommitted nodes => nodes ∪ nodeSetCodec.decode ρ rest
        | _ => nodeSetCodec.decode ρ rest
      else nodeSetCodec.decode ρ rest := by
  simp only [retiredNodesStep, decode_choose, eval_le, decide_eq_true_eq,
    setUnion_correct, retiredSet_correct]
  cases (entryCodec.decode ρ entry).content <;> simp

def retiredNodes (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr nodeSetCodec.ty :=
  foldrFrom (retiredNodesStep commit) (nodeSetCodec.literal ∅) capacity (.nat 1) log

theorem retiredNodes_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (commit : Expr .nat) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (retiredNodes capacity log commit) =
      retiredCommittedNodesUpTo (logCodec.decode ρ log) (commit.eval ρ) := by
  let f := fun index (entry : Entry Node Nat) (rest : Finset Node) =>
    if index ≤ commit.eval ρ then
      match entry.content with | .retiredCommitted nodes => nodes ∪ rest | _ => rest
    else rest
  have h := foldrFrom_correct ρ entryCodec.equiv nodeSetCodec.equiv
    (retiredNodesStep commit) (nodeSetCodec.literal ∅) f
    (retiredNodesStep_correct ρ commit) capacity (.nat 1) log
    (by simpa [Codec.decode, Codec.list] using bound)
  have scan (xs : List (Entry Node Nat)) (index : Nat) :
      indexedFold f ∅ index xs = retiredCommittedNodesUpToFrom (commit.eval ρ) index xs := by
    induction xs generalizing index with
    | nil => rfl
    | cons x xs ih =>
      simp only [indexedFold, f, retiredCommittedNodesUpToFrom, ih]
      cases x.content <;> rfl
  unfold retiredNodes
  change nodeSetCodec.equiv _ = _
  rw [h]
  change indexedFold f (nodeSetCodec.decode ρ (nodeSetCodec.literal ∅)) 1
    (logCodec.decode ρ log) = _
  rw [Codec.decode_literal, scan]
  rfl

theorem tableSet_member (ρ : Assignment) (f : Node → Expr .bool) (node : Node) :
    node ∈ nodeSetCodec.decode ρ (tableExpr f) ↔ (f node).eval ρ = true := by
  simp [Codec.decode, Codec.finset, Codec.transport, Codec.table, Codec.bool]

def completedNodes (capacity : Nat) (log : Expr logCodec.ty) (commit : Expr .nat) :
    Expr nodeSetCodec.ty :=
  let current := currentConfig capacity log commit
  setIntersection
    (setDifference (setDifference (priorNodes capacity log current.fst) current.snd)
      (retiredNodes capacity log commit))
    (tableExpr fun node =>
      isSome (retirement capacity (nodeCodec.literal node) (.take commit log)))

theorem completedNodes_correct (ρ : Assignment) (capacity : Nat) (log : Expr logCodec.ty)
    (commit : Expr .nat) (bound : (logCodec.decode ρ log).length ≤ capacity) :
    nodeSetCodec.decode ρ (completedNodes capacity log commit) =
      retirementCompletedNodes (logCodec.decode ρ log) (commit.eval ρ) := by
  have takeBound : (logCodec.decode ρ (.take commit log)).length ≤ capacity := by
    simp only [log_take, List.length_take]
    exact le_trans (Nat.min_le_right _ _) bound
  have index : (currentConfig capacity log commit).fst.eval ρ =
      (currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ)).index :=
    congrArg Configuration.index (currentConfig_correct ρ capacity log commit bound)
  have nodes : nodeSetCodec.decode ρ (currentConfig capacity log commit).snd =
      (currentConfigurationAt (logCodec.decode ρ log) (commit.eval ρ)).nodes :=
    congrArg Configuration.nodes (currentConfig_correct ρ capacity log commit bound)
  simp only [completedNodes, setIntersection_correct, setDifference_correct,
    priorNodes_correct ρ capacity log _ bound, retiredNodes_correct ρ capacity log commit bound,
    index, nodes]
  ext node
  simp only [Finset.mem_inter, tableSet_member, isSome_correct Codec.nat ρ,
    retirement_correct ρ capacity _ (.take commit log) takeBound, Codec.decode_literal, log_take,
    retirementCompletedNodes, Finset.mem_filter]

end CCFRaft.SymbolicReceive
