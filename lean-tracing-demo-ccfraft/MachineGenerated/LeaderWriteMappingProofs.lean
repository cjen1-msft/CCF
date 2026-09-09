-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import MachineGenerated.TransactionMappingProofs

set_option autoImplicit false

/-!
# Transaction mapping for leader writes

Generic commutation and enabledness lemmas for leader writes whose actions do
not carry transaction identifiers.
-/

namespace CCFRaft.TransactionMapping

open CCFRaft

variable {Node TxId OtherTxId : Type}

@[simp]
theorem latestConfiguration_mapNodeState
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    latestConfiguration (mapNodeState f state) =
      latestConfiguration state := by
  simp [latestConfiguration, mapNodeState]

@[simp]
theorem allRetiredCommittedNodes_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId)) :
    allRetiredCommittedNodes (log.map (mapEntry f)) =
      allRetiredCommittedNodes log := by
  simp [allRetiredCommittedNodes]

@[simp]
theorem pendingRetiredCommittedNodes_mapState
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (leader : Node) :
    pendingRetiredCommittedNodes (mapState f state) leader =
      pendingRetiredCommittedNodes state leader := by
  simp [pendingRetiredCommittedNodes, mapState, mapNodeState]

@[simp]
theorem mapNodeState_append_signature
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    mapNodeState f
        { state with
          log := state.log ++
            [{ term := state.currentTerm, content := .signature }] } =
      { mapNodeState f state with
        log := (mapNodeState f state).log ++
          [{ term := (mapNodeState f state).currentTerm,
             content := .signature }] } := by
  cases state
  simp [mapNodeState, mapEntry, mapEntryContent]

@[simp]
theorem mapNodeState_append_reconfiguration
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId)
    (configuration : Finset Node)
    (sentIndex : Node -> Nat) :
    mapNodeState f
        { state with
          log := state.log ++
            [{ term := state.currentTerm,
               content := .reconfiguration configuration }]
          sentIndex } =
      { mapNodeState f state with
        log := (mapNodeState f state).log ++
          [{ term := (mapNodeState f state).currentTerm,
             content := .reconfiguration configuration }]
        sentIndex } := by
  cases state
  simp [mapNodeState, mapEntry, mapEntryContent]

@[simp]
theorem mapNodeState_append_retiredCommitted
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId)
    (nodes : Finset Node) :
    mapNodeState f
        { state with
          log := state.log ++
            [{ term := state.currentTerm,
               content := .retiredCommitted nodes }] } =
      { mapNodeState f state with
        log := (mapNodeState f state).log ++
          [{ term := (mapNodeState f state).currentTerm,
             content := .retiredCommitted nodes }] } := by
  cases state
  simp [mapNodeState, mapEntry, mapEntryContent]

theorem NodeStore.node?_allocate_of_not_allocated_of_not_mem
    [DecidableEq Node]
    (nodes : NodeStore Node TxId)
    (added : Finset Node)
    (node : Node)
    (notAllocated : Not (nodes.allocated node))
    (notMember : node ∉ added) :
    (nodes.allocate added).node? node = none := by
  have missing : nodes.node? node = none := by
    cases found : nodes.node? node <;>
      simp_all [NodeStore.allocated]
  have notIn : node ∉ nodes.entries := by
    rw [← Finmap.lookup_eq_none]
    exact missing
  simp only [NodeStore.node?, NodeStore.allocate]
  rw [Finmap.lookup_union_right notIn]
  exact NodeStore.node?_ofFinset_of_not_mem added
    (fun _ => freshNodeState) node notMember

@[simp]
theorem mapNodeStore_allocate
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId)
    (added : Finset Node) :
    mapNodeStore f (nodes.allocate added) =
      (mapNodeStore f nodes).allocate added := by
  apply mapNodeStore_ext
  intro node
  by_cases allocated : nodes.allocated node
  · have mappedAllocated :
        (mapNodeStore f nodes).allocated node :=
      (mapNodeStore_allocated f nodes node).2 allocated
    rw [mapNodeStore_node?, NodeStore.node?_allocate_of_allocated,
      NodeStore.node?_allocate_of_allocated]
    · exact (mapNodeStore_node? f nodes node).symm
    · exact mappedAllocated
    · exact allocated
  · by_cases member : node ∈ added
    · rw [mapNodeStore_node?,
        NodeStore.node?_allocate_of_not_allocated_of_mem]
      · rw [NodeStore.node?_allocate_of_not_allocated_of_mem]
        · rfl
        · exact fun mapped =>
            allocated ((mapNodeStore_allocated f nodes node).1 mapped)
        · exact member
      · exact allocated
      · exact member
    · rw [mapNodeStore_node?,
        NodeStore.node?_allocate_of_not_allocated_of_not_mem]
      · rw [NodeStore.node?_allocate_of_not_allocated_of_not_mem]
        · rfl
        · exact fun mapped =>
            allocated ((mapNodeStore_allocated f nodes node).1 mapped)
        · exact member
      · exact allocated
      · exact member

@[simp]
theorem refreshRetirementState_append_signature_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId) :
    refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log ++
            [{ term := (mapNodeState f state).currentTerm,
               content := .signature }] } =
      mapNodeState f
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm, content := .signature }] }) := by
  rw [← mapNodeState_append_signature]
  rw [mapNodeState_refreshRetirementState]

@[simp]
theorem refreshRetirementState_append_reconfiguration_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId)
    (configuration : Finset Node)
    (sentIndex : Node -> Nat) :
    refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log ++
            [{ term := (mapNodeState f state).currentTerm,
               content := .reconfiguration configuration }]
          sentIndex } =
      mapNodeState f
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm,
                 content := .reconfiguration configuration }]
            sentIndex }) := by
  rw [← mapNodeState_append_reconfiguration]
  rw [mapNodeState_refreshRetirementState]

@[simp]
theorem refreshRetirementState_append_retiredCommitted_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId)
    (nodes : Finset Node) :
    refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log ++
            [{ term := (mapNodeState f state).currentTerm,
               content := .retiredCommitted nodes }] } =
      mapNodeState f
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm,
                 content := .retiredCommitted nodes }] }) := by
  rw [← mapNodeState_append_retiredCommitted]
  rw [mapNodeState_refreshRetirementState]

@[simp]
theorem refreshRetirementCompleted_append_signature_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (retirementCompleted : Node -> Finset Node)
    (node : Node)
    (state : NodeState Node TxId) :
    refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { mapNodeState f state with
            log := (mapNodeState f state).log ++
              [{ term := (mapNodeState f state).currentTerm,
                 content := .signature }] }) =
      refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm, content := .signature }] }) := by
  rw [refreshRetirementState_append_signature_map]
  apply refreshRetirementCompleted_mapNodeState

@[simp]
theorem refreshRetirementCompleted_append_reconfiguration_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (retirementCompleted : Node -> Finset Node)
    (node : Node)
    (state : NodeState Node TxId)
    (configuration : Finset Node)
    (sentIndex : Node -> Nat) :
    refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { mapNodeState f state with
            log := (mapNodeState f state).log ++
              [{ term := (mapNodeState f state).currentTerm,
                 content := .reconfiguration configuration }]
            sentIndex }) =
      refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm,
                 content := .reconfiguration configuration }]
            sentIndex }) := by
  rw [refreshRetirementState_append_reconfiguration_map]
  apply refreshRetirementCompleted_mapNodeState

@[simp]
theorem refreshRetirementCompleted_append_retiredCommitted_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (retirementCompleted : Node -> Finset Node)
    (node : Node)
    (state : NodeState Node TxId)
    (nodes : Finset Node) :
    refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { mapNodeState f state with
            log := (mapNodeState f state).log ++
              [{ term := (mapNodeState f state).currentTerm,
                 content := .retiredCommitted nodes }] }) =
      refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm,
                 content := .retiredCommitted nodes }] }) := by
  rw [refreshRetirementState_append_retiredCommitted_map]
  apply refreshRetirementCompleted_mapNodeState

/-- Transaction mapping commutes with appending a committable signature. -/
theorem mapState_signCommittableMessages
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (next state (.signCommittableMessages node)) =
      next (mapState f state) (.signCommittableMessages node) := by
  unfold next
  simp only [mapState, mapNodeStore_get]
  congr 1
  · rw [mapNodeStore_updateNode]
    congr 1
    exact
      (refreshRetirementState_append_signature_map
        f node (state.nodes node)).symm
  · exact
      (refreshRetirementCompleted_append_signature_map
        f state.retirementCompleted node (state.nodes node)).symm

/-- Signature-write enabledness is invariant under transaction mapping. -/
theorem enabled_mapState_signCommittableMessages_iff
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    Enabled (mapState f state) (.signCommittableMessages node) ↔
      Enabled state (.signCommittableMessages node) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get]
  rw [refreshRetirementState_append_signature_map]
  simp [mapNodeState]

/-- Transaction mapping commutes with recording retired-completed nodes. -/
theorem mapState_appendRetiredCommitted
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    mapState f (next state (.appendRetiredCommitted node)) =
      next (mapState f state) (.appendRetiredCommitted node) := by
  simp only [next]
  rw [pendingRetiredCommittedNodes_mapState]
  simp only [mapState, mapNodeStore_get]
  congr 1
  · rw [mapNodeStore_updateNode]
    congr 1
    exact
      (refreshRetirementState_append_retiredCommitted_map
        f node (state.nodes node)
          (pendingRetiredCommittedNodes state node)).symm
  · exact
      (refreshRetirementCompleted_append_retiredCommitted_map
        f state.retirementCompleted node (state.nodes node)
          (pendingRetiredCommittedNodes state node)).symm

/-- Retired-committed-write enabledness is invariant under transaction mapping. -/
theorem enabled_mapState_appendRetiredCommitted_iff
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    Enabled (mapState f state) (.appendRetiredCommitted node) ↔
      Enabled state (.appendRetiredCommitted node) := by
  simp only [Enabled]
  rw [pendingRetiredCommittedNodes_mapState]
  simp only [mapState_allocated, mapState_nodes_get]
  rw [refreshRetirementState_append_retiredCommitted_map]
  simp [mapNodeState]

/-- Transaction mapping commutes with a complete configuration write. -/
theorem mapState_changeConfiguration
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source : Node)
    (newConfiguration : Finset Node) :
    mapState f (next state (.changeConfiguration source newConfiguration)) =
      next (mapState f state)
        (.changeConfiguration source newConfiguration) := by
  simp only [next]
  simp only [mapState, mapNodeStore_get]
  rw [latestConfiguration_mapNodeState]
  have sentIndexMap :
      (fun peer =>
        if peer ∈
            newConfiguration \
              (latestConfiguration (state.nodes source)).nodes then
          (mapNodeState f (state.nodes source)).log.length
        else
          (mapNodeState f (state.nodes source)).sentIndex peer) =
      (fun peer =>
        if peer ∈
            newConfiguration \
              (latestConfiguration (state.nodes source)).nodes then
          (state.nodes source).log.length
        else
          (state.nodes source).sentIndex peer) := by
    funext peer
    simp [mapNodeState]
  rw [sentIndexMap]
  congr 1
  · rw [mapNodeStore_updateNode, mapNodeStore_allocate]
    congr 1
    exact
      (refreshRetirementState_append_reconfiguration_map
        f source (state.nodes source) newConfiguration
          (fun peer =>
            if peer ∈
                newConfiguration \
                  (latestConfiguration (state.nodes source)).nodes then
              (state.nodes source).log.length
            else
              (state.nodes source).sentIndex peer)).symm
  · exact
      (refreshRetirementCompleted_append_reconfiguration_map
        f state.retirementCompleted source (state.nodes source)
          newConfiguration
          (fun peer =>
            if peer ∈
                newConfiguration \
                  (latestConfiguration (state.nodes source)).nodes then
              (state.nodes source).log.length
            else
              (state.nodes source).sentIndex peer)).symm

/-- Configuration-write enabledness is invariant under transaction mapping. -/
theorem enabled_mapState_changeConfiguration_iff
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (source : Node)
    (newConfiguration : Finset Node) :
    Enabled (mapState f state)
        (.changeConfiguration source newConfiguration) ↔
      Enabled state (.changeConfiguration source newConfiguration) := by
  simp only [Enabled, mapState_allocated, mapState_nodes_get,
    latestConfiguration_mapNodeState]
  rw [refreshRetirementState_append_reconfiguration_map]
  simp [mapNodeState, mapState]

end CCFRaft.TransactionMapping
