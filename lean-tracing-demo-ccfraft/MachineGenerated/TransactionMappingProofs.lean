-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import TransactionMapping
import MachineGenerated.ModelProofs

set_option autoImplicit false

/-!
# Transaction mapping proofs

Generic evaluation and `clientRequest` commutation results for complete Raft
states.
-/

namespace CCFRaft.TransactionMapping

open CCFRaft

variable {Node TxId OtherTxId ThirdTxId : Type}

@[simp]
theorem mapEntryContent_id
    (content : EntryContent Node TxId) :
    mapEntryContent id content = content := by
  cases content <;> rfl

@[simp]
theorem mapEntryContent_comp
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (content : EntryContent Node TxId) :
    mapEntryContent g (mapEntryContent f content) =
      mapEntryContent (g ∘ f) content := by
  cases content <;> rfl

@[simp]
theorem mapEntry_id
    (entry : Entry Node TxId) :
    mapEntry id entry = entry := by
  cases entry
  simp [mapEntry]

@[simp]
theorem mapEntry_comp
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (entry : Entry Node TxId) :
    mapEntry g (mapEntry f entry) = mapEntry (g ∘ f) entry := by
  cases entry
  simp [mapEntry]

@[simp]
theorem mapEntry_list_id
    (entries : List (Entry Node TxId)) :
    entries.map (mapEntry id) = entries := by
  induction entries <;> simp_all

@[simp]
theorem mapEntry_list_comp
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (entries : List (Entry Node TxId)) :
    (entries.map (mapEntry f)).map (mapEntry g) =
      entries.map (mapEntry (g ∘ f)) := by
  induction entries <;> simp_all

@[simp]
theorem mapMessage_id
    (message : Message Node TxId) :
    mapMessage id message = message := by
  cases message <;> simp [mapMessage]

@[simp]
theorem mapMessage_comp
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (message : Message Node TxId) :
    mapMessage g (mapMessage f message) = mapMessage (g ∘ f) message := by
  cases message <;> simp [mapMessage, List.map_map]

@[simp]
theorem mapMessage_list_id
    (messages : List (Message Node TxId)) :
    messages.map (mapMessage id) = messages := by
  induction messages <;> simp_all

@[simp]
theorem mapNodeState_id
    (state : NodeState Node TxId) :
    mapNodeState id state = state := by
  cases state
  simp [mapNodeState]

@[simp]
theorem mapNodeState_comp
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (state : NodeState Node TxId) :
    mapNodeState g (mapNodeState f state) = mapNodeState (g ∘ f) state := by
  cases state
  simp [mapNodeState, List.map_map]

@[simp]
theorem mapNodeState_fresh
    (f : TxId -> OtherTxId) :
    mapNodeState (Node := Node) f freshNodeState = freshNodeState := by
  rfl

@[simp]
theorem mapNodeState_log_length
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    (mapNodeState f state).log.length = state.log.length := by
  simp [mapNodeState]

@[simp]
theorem mem_allocatedNodes
    [DecidableEq Node]
    (nodes : NodeStore Node TxId)
    (node : Node) :
    node ∈ allocatedNodes nodes ↔ nodes.allocated node := by
  simp [allocatedNodes, NodeStore.allocated, NodeStore.node?,
    Finmap.lookup_isSome, Finmap.mem_def, Multiset.keys]

@[simp]
theorem mapNodeStore_node?
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId)
    (node : Node) :
    (mapNodeStore f nodes).node? node =
      (nodes.node? node).map (mapNodeState f) := by
  by_cases allocated : nodes.allocated node
  · have found : ∃ state, nodes.node? node = some state := by
      change (nodes.node? node).isSome at allocated
      rw [Option.isSome_iff_exists] at allocated
      exact allocated
    unfold mapNodeStore
    rw [NodeStore.node?_ofFinset_of_mem]
    · rcases found with ⟨state, found⟩
      simp [NodeStore.get, found]
    · exact (mem_allocatedNodes nodes node).2 allocated
  · unfold mapNodeStore
    rw [NodeStore.node?_ofFinset_of_not_mem]
    · have missing : nodes.node? node = none := by
        cases found : nodes.node? node <;>
          simp_all [NodeStore.allocated]
      simp [missing]
    · exact fun member => allocated ((mem_allocatedNodes nodes node).1 member)

@[simp]
theorem mapNodeStore_get
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId)
    (node : Node) :
    mapNodeStore f nodes node = mapNodeState f (nodes node) := by
  simp only [NodeStore.get, mapNodeStore_node?]
  cases found : nodes.node? node <;> simp

@[simp]
theorem mapNodeStore_allocated
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId)
    (node : Node) :
    (mapNodeStore f nodes).allocated node ↔ nodes.allocated node := by
  simp [NodeStore.allocated]

theorem mapNodeStore_ext
    [DecidableEq Node]
    {left right : NodeStore Node TxId}
    (same : ∀ node, left.node? node = right.node? node) :
    left = right := by
  apply congrArg NodeStore.mk
  exact Finmap.ext_lookup same

@[simp]
theorem mapNodeStore_id
    [DecidableEq Node]
    (nodes : NodeStore Node TxId) :
    mapNodeStore id nodes = nodes := by
  apply mapNodeStore_ext
  intro node
  rw [mapNodeStore_node?]
  cases nodes.node? node <;> simp

@[simp]
theorem mapNodeStore_comp
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (nodes : NodeStore Node TxId) :
    mapNodeStore g (mapNodeStore f nodes) =
      mapNodeStore (g ∘ f) nodes := by
  apply mapNodeStore_ext
  intro node
  simp only [mapNodeStore_node?]
  cases nodes.node? node <;> simp

@[simp]
theorem mapState_nodes_get
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    (mapState f state).nodes node = mapNodeState f (state.nodes node) := by
  simp [mapState]

@[simp]
theorem mapState_allocated
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    (mapState f state).allocated node ↔ state.allocated node := by
  simp [State.allocated, mapState]

@[simp]
theorem mapState_log_length
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node) :
    ((mapState f state).nodes node).log.length =
      (state.nodes node).log.length := by
  simp

@[simp]
theorem mapState_submittedTxIds
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (state : State Node TxId) :
    (mapState f state).submittedTxIds = state.submittedTxIds.image f := rfl

@[simp]
theorem mapState_id
    [DecidableEq Node]
    [DecidableEq TxId]
    (state : State Node TxId) :
    mapState id state = state := by
  cases state
  simp [mapState]

@[simp]
theorem mapState_comp
    [DecidableEq Node]
    [DecidableEq OtherTxId]
    [DecidableEq ThirdTxId]
    (f : TxId -> OtherTxId)
    (g : OtherTxId -> ThirdTxId)
    (state : State Node TxId) :
    mapState g (mapState f state) = mapState (g ∘ f) state := by
  cases state
  simp [mapState, List.map_map, Finset.image_image, funext_iff]

@[simp]
theorem configurationsInLogFrom_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (index : Nat)
    (log : List (Entry Node TxId)) :
    configurationsInLogFrom index (log.map (mapEntry f)) =
      configurationsInLogFrom index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry log inductionHypothesis =>
      cases entry with
      | mk term content =>
          cases content <;>
            simp [mapEntry, mapEntryContent, configurationsInLogFrom,
              inductionHypothesis]

@[simp]
theorem configurationsInLog_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId)) :
    configurationsInLog (log.map (mapEntry f)) =
      configurationsInLog log := by
  simp [configurationsInLog]

@[simp]
theorem allConfigurations_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId)) :
    allConfigurations (log.map (mapEntry f)) = allConfigurations log := by
  simp [allConfigurations]

@[simp]
theorem retirementIndexInLog_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (log : List (Entry Node TxId)) :
    retirementIndexInLog node (log.map (mapEntry f)) =
      retirementIndexInLog node log := by
  simp [retirementIndexInLog]

@[simp]
theorem signatureIndexAfterFrom_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (retirementIndex index : Nat)
    (log : List (Entry Node TxId)) :
    signatureIndexAfterFrom retirementIndex index
        (log.map (mapEntry f)) =
      signatureIndexAfterFrom retirementIndex index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry log inductionHypothesis =>
      cases entry with
      | mk term content =>
          cases content <;>
            simp [mapEntry, mapEntryContent, signatureIndexAfterFrom,
              inductionHypothesis]

@[simp]
theorem retirementCommittableIndexInLog_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (retirementIndex : Nat) :
    retirementCommittableIndexInLog (log.map (mapEntry f)) retirementIndex =
      retirementCommittableIndexInLog log retirementIndex := by
  simp [retirementCommittableIndexInLog]

@[simp]
theorem retiredCommittedIndexFrom_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (index : Nat)
    (log : List (Entry Node TxId)) :
    retiredCommittedIndexFrom node index (log.map (mapEntry f)) =
      retiredCommittedIndexFrom node index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry log inductionHypothesis =>
      cases entry with
      | mk term content =>
          cases content <;>
            simp [mapEntry, mapEntryContent, retiredCommittedIndexFrom,
              inductionHypothesis]

@[simp]
theorem retiredCommittedIndexInLog_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (log : List (Entry Node TxId)) :
    retiredCommittedIndexInLog node (log.map (mapEntry f)) =
      retiredCommittedIndexInLog node log := by
  simp [retiredCommittedIndexInLog]

@[simp]
theorem retiredCommittedNodesUpToFrom_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (commitIndex index : Nat)
    (log : List (Entry Node TxId)) :
    retiredCommittedNodesUpToFrom commitIndex index
        (log.map (mapEntry f)) =
      retiredCommittedNodesUpToFrom commitIndex index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry log inductionHypothesis =>
      cases entry with
      | mk term content =>
          cases content <;>
            simp [mapEntry, mapEntryContent, retiredCommittedNodesUpToFrom,
              inductionHypothesis]

@[simp]
theorem retiredCommittedNodesUpTo_map
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (commitIndex : Nat) :
    retiredCommittedNodesUpTo (log.map (mapEntry f)) commitIndex =
      retiredCommittedNodesUpTo log commitIndex := by
  simp [retiredCommittedNodesUpTo]

@[simp]
theorem currentConfigurationAt_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (commitIndex : Nat) :
    currentConfigurationAt (log.map (mapEntry f)) commitIndex =
      currentConfigurationAt log commitIndex := by
  simp [currentConfigurationAt]

@[simp]
theorem retirementCompletedNodes_map
    [DecidableEq Node]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (log : List (Entry Node TxId))
    (commitIndex : Nat) :
    retirementCompletedNodes (log.map (mapEntry f)) commitIndex =
      retirementCompletedNodes log commitIndex := by
  unfold retirementCompletedNodes
  simp only [currentConfigurationAt_map, allConfigurations_map,
    retiredCommittedNodesUpTo_map]
  apply Finset.filter_congr
  intro node _
  have takeMapped :
      (log.map (mapEntry f)).take commitIndex =
        (log.take commitIndex).map (mapEntry f) :=
    List.map_take.symm
  rw [takeMapped, retirementIndexInLog_map]

@[simp]
theorem mapNodeState_refreshRetirementState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId) :
    mapNodeState f (refreshRetirementState node state) =
      refreshRetirementState node (mapNodeState f state) := by
  cases state
  simp [mapNodeState, refreshRetirementState]

@[simp]
theorem refreshRetirementCompleted_mapNodeState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (retirementCompleted : Node -> Finset Node)
    (observer : Node)
    (state : NodeState Node TxId) :
    refreshRetirementCompleted retirementCompleted observer
        (mapNodeState f state) =
      refreshRetirementCompleted retirementCompleted observer state := by
  funext node
  by_cases same : node = observer
  · subst node
    simp [refreshRetirementCompleted, mapNodeState]
  · simp [refreshRetirementCompleted, same]

@[simp]
theorem mapNodeState_append_transaction
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId)
    (txId : TxId) :
    mapNodeState f
        { state with
          log := state.log ++
            [{ term := state.currentTerm
               content := .transaction txId }] } =
      { mapNodeState f state with
        log := (mapNodeState f state).log ++
          [{ term := state.currentTerm
             content := .transaction (f txId) }] } := by
  cases state
  simp [mapNodeState, mapEntry, mapEntryContent]

@[simp] theorem mapNodeState_role
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    (mapNodeState f state).role = state.role := rfl

@[simp] theorem mapNodeState_currentTerm
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    (mapNodeState f state).currentTerm = state.currentTerm := rfl

@[simp] theorem mapNodeState_membershipState
    (f : TxId -> OtherTxId)
    (state : NodeState Node TxId) :
    (mapNodeState f state).membershipState = state.membershipState := rfl

@[simp]
theorem refreshRetirementState_append_transaction_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId)
    (txId : TxId) :
    refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log ++
            [{ term := (mapNodeState f state).currentTerm
               content := .transaction (f txId) }] } =
      mapNodeState f
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm
                 content := .transaction txId }] }) := by
  rw [mapNodeState_currentTerm]
  rw [← mapNodeState_append_transaction]
  rw [mapNodeState_refreshRetirementState]

@[simp]
theorem refreshRetirementCompleted_append_transaction_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (retirementCompleted : Node -> Finset Node)
    (node : Node)
    (state : NodeState Node TxId)
    (txId : TxId) :
    refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { mapNodeState f state with
            log := (mapNodeState f state).log ++
              [{ term := (mapNodeState f state).currentTerm
                 content := .transaction (f txId) }] }) =
      refreshRetirementCompleted retirementCompleted node
        (refreshRetirementState node
          { state with
            log := state.log ++
              [{ term := state.currentTerm
                 content := .transaction txId }] }) := by
  rw [refreshRetirementState_append_transaction_map]
  apply refreshRetirementCompleted_mapNodeState

@[simp]
theorem refreshRetirementMembership_append_transaction_map
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (node : Node)
    (state : NodeState Node TxId)
    (txId : TxId) :
    (refreshRetirementState node
        { mapNodeState f state with
          log := (mapNodeState f state).log ++
            [{ term := (mapNodeState f state).currentTerm
               content := .transaction (f txId) }] }).membershipState =
      (refreshRetirementState node
        { state with
          log := state.log ++
            [{ term := state.currentTerm
               content := .transaction txId }] }).membershipState := by
  rw [refreshRetirementState_append_transaction_map]
  rfl

@[simp]
theorem mapNodeStore_updateNode
    [DecidableEq Node]
    (f : TxId -> OtherTxId)
    (nodes : NodeStore Node TxId)
    (node : Node)
    (value : NodeState Node TxId) :
    mapNodeStore f (updateNode nodes node value) =
      updateNode (mapNodeStore f nodes) node (mapNodeState f value) := by
  apply mapNodeStore_ext
  intro candidate
  by_cases same : candidate = node
  · subst candidate
    simp [updateNode]
  · simp [updateNode, same]

/--
Evaluating every transaction ID commutes with the actual `clientRequest`
transition for an arbitrary complete state. No injectivity assumption is
required.
-/
theorem mapState_clientRequest
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node)
    (txId : TxId) :
    mapState f (next state (.clientRequest node txId)) =
      next (mapState f state) (.clientRequest node (f txId)) := by
  unfold next
  simp only [mapState, mapNodeStore_get]
  congr 1
  · rw [mapNodeStore_updateNode]
    congr 1
    exact
      (refreshRetirementState_append_transaction_map
        f node (state.nodes node) txId).symm
  · exact Finset.image_insert f txId state.submittedTxIds
  · exact
      (refreshRetirementCompleted_append_transaction_map
        f state.retirementCompleted node (state.nodes node) txId).symm

/-- Mapping preserves exactly the structural `clientRequest` guard. -/
theorem structuralClientRequestEnabled_mapState
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node)
    (txId : TxId) :
    structuralClientRequestEnabled (mapState f state) node (f txId) ↔
      structuralClientRequestEnabled state node txId := by
  simp only [structuralClientRequestEnabled, mapState_allocated,
    mapState_nodes_get]
  rw [refreshRetirementMembership_append_transaction_map]
  simp

/--
The real enabledness guard after evaluation is the concrete structural guard
plus freshness in the evaluated submitted-ID image.
-/
theorem enabled_mapState_clientRequest_iff
    [DecidableEq Node]
    [DecidableEq TxId]
    [DecidableEq OtherTxId]
    [Bootstrap Node]
    (f : TxId -> OtherTxId)
    (state : State Node TxId)
    (node : Node)
    (txId : TxId) :
    Enabled (mapState f state) (.clientRequest node (f txId)) ↔
      structuralClientRequestEnabled state node txId /\
        f txId ∉ state.submittedTxIds.image f := by
  rw [← structuralClientRequestEnabled_mapState f state node txId]
  simp only [Enabled, structuralClientRequestEnabled, mapState_submittedTxIds]
  tauto

end CCFRaft.TransactionMapping
