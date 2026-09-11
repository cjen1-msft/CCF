-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.StateFrame
import Sparse.SymbolBounds

set_option autoImplicit false

/-!
Canonical initial metadata and proof-only witnesses for arbitrary Model states.
There are 585 Int, 30 Bool, and 47 Nodes constants, with disjoint numeric IDs.
Concrete log encoding is never part of the executable metadata initializer.
-/

namespace CCFRaft.Sparse.StateFrameInitial

open Smt (Ty Symbol Assignment)
open StateFrame

def highWater (base : Nat) : Nat := base + 662

def intRef (base : Nat) (node : Node) (column : Fin 39) : ConstRef .int :=
  { id := base + (39 * node.val + column.val) }

def boolRef (base : Nat) (index : Fin 30) : ConstRef .bool :=
  { id := base + (585 + index.val) }

def nodesRef (base : Nat) (index : Fin 47) : ConstRef .nodes :=
  { id := base + (615 + index.val) }

def rootSlot (prior : Nat) (node : Node) : Fin (prior + NODE_COUNT) :=
  Fin.mk (prior + node.val) (by have bound := node.isLt; omega)

def localFrame (base prior versions : Nat) (node : Node) : LocalRefs (prior + NODE_COUNT) versions where
  role := intRef base node 0
  currentTerm := intRef base node 1
  log := { length := intRef base node 2, address := .root (rootSlot prior node) }
  commitIndex := intRef base node 3
  votedFor := intRef base node 4
  membershipState := intRef base node 5
  retirementIndex := intRef base node 6
  retirementCommittableIndex := intRef base node 7
  retiredCommittedIndex := intRef base node 8
  sentIndex := Vector.ofFn fun peer : Node =>
    intRef base node (Fin.mk (9 + peer.val) (by have bound := peer.isLt; unfold NODE_COUNT at bound; omega))
  matchIndex := Vector.ofFn fun peer : Node =>
    intRef base node (Fin.mk (24 + peer.val) (by have bound := peer.isLt; unfold NODE_COUNT at bound; omega))
  isNewFollower := boolRef base (Fin.mk node.val (by have bound := node.isLt; unfold NODE_COUNT at bound; omega))
  votesGranted := nodesRef base (Fin.mk (2 + node.val) (by have bound := node.isLt; unfold NODE_COUNT at bound; omega))
  preVotesGranted := nodesRef base (Fin.mk (17 + node.val) (by have bound := node.isLt; unfold NODE_COUNT at bound; omega))

def frame (base prior versions : Nat) : Frame (prior + NODE_COUNT) versions where
  allocated := nodesRef base 0
  hasJoined := nodesRef base 1
  locals := Vector.ofFn (localFrame base prior versions)
  preVoteEnabled := Vector.ofFn fun node : Node =>
    boolRef base (Fin.mk (15 + node.val) (by have bound := node.isLt; unfold NODE_COUNT at bound; omega))
  retirementCompleted := Vector.ofFn fun node : Node =>
    nodesRef base (Fin.mk (32 + node.val) (by have bound := node.isLt; unfold NODE_COUNT at bound; omega))

def shiftSymbol (base : Nat) : Symbol -> Symbol
  | .constant ty id => .constant ty (base + id)
  | .unary domain result id => .unary domain result (base + id)

def Owned (base : Nat) : Symbol -> Prop
  | .constant .int id => base <= id /\ id < base + 585
  | .constant .bool id => base + 585 <= id /\ id < base + 615
  | .constant .nodes id => base + 615 <= id /\ id < highWater base
  | _ => False

instance (base : Nat) (symbol : Symbol) : Decidable (Owned base symbol) := by
  cases symbol with
  | constant ty id => cases ty <;> unfold Owned <;> infer_instance
  | unary _ _ _ => unfold Owned; infer_instance

theorem root_slot_disjoint (prior : Nat) (node : Node) :
    prior <= (rootSlot prior node).val /\ (rootSlot prior node).val < prior + NODE_COUNT := by
  exact And.intro (Nat.le_add_right _ _) (rootSlot prior node).isLt

theorem root_slot_injective (prior : Nat) : Function.Injective (rootSlot prior) := by
  intro left right equal
  apply Fin.ext
  have := congrArg Fin.val equal
  simpa [rootSlot] using this

theorem root_slots_exact (prior : Nat) :
    Finset.univ.image (fun node : Node => (rootSlot prior node).val) =
      Finset.Ico prior (prior + NODE_COUNT) := by
  ext index
  constructor
  next =>
    intro member
    cases Finset.mem_image.mp member with
    | intro node evidence =>
      rw [<- evidence.2]
      exact Finset.mem_Ico.mpr (root_slot_disjoint prior node)
  next =>
    intro member
    have bounds := Finset.mem_Ico.mp member
    let node : Node := Fin.mk (index - prior) (by omega)
    apply Finset.mem_image.mpr
    refine Exists.intro node (And.intro (Finset.mem_univ _) ?_)
    change prior + (index - prior) = index
    omega

theorem int_slot_injective (base : Nat) (left right : Node) (a b : Fin 39) :
    (intRef base left a).id = (intRef base right b).id <-> left = right /\ a = b := by
  constructor
  next =>
    intro equal
    have ha := a.isLt
    have hb := b.isLt
    change base + (39 * left.val + a.val) = base + (39 * right.val + b.val) at equal
    have nodes : left.val = right.val := by omega
    have columns : a.val = b.val := by omega
    exact And.intro (Fin.ext nodes) (Fin.ext columns)
  next => intro equal; rw [equal.1, equal.2]

theorem local_symbols_shift (base prior versions : Nat) (node : Node) :
    (localFrame base prior versions node).symbols =
      (localFrame 0 0 0 node).symbols.map (shiftSymbol base) := by
  simp [localFrame, LocalRefs.symbols, LocalRefs.naturals, Vector.toList_ofFn,
    ConstRef.symbol, intRef, boolRef, nodesRef, shiftSymbol]

theorem symbols_shift (base prior versions : Nat) :
    (frame base prior versions).symbols = (frame 0 0 0).symbols.map (shiftSymbol base) := by
  simp only [frame, Frame.symbols, Vector.toList_ofFn, List.map_append, List.map_flatMap,
    List.map_cons, List.map_nil]
  have asMap {A : Type} (f : Node -> A) :
      List.ofFn f = (List.ofFn (fun node : Node => node)).map f := by
    simpa only [Function.comp_def] using (List.map_ofFn (fun node : Node => node) f).symm
  rw [asMap (localFrame base prior versions), asMap (localFrame 0 0 0)]
  simp [local_symbols_shift base prior versions, ConstRef.symbol, boolRef, nodesRef, shiftSymbol]

theorem zero_ids_nodup :
    ((frame 0 0 0).symbols.map SymbolBounds.symbolId).Nodup := by
  decide +kernel

theorem zero_symbols_owned :
    forall symbol, Membership.mem (frame 0 0 0).symbols symbol -> Owned 0 symbol := by
  decide +kernel

theorem shift_id (base : Nat) (symbol : Symbol) :
    SymbolBounds.symbolId (shiftSymbol base symbol) = base + SymbolBounds.symbolId symbol := by
  cases symbol <;> rfl

theorem owned_shift (base : Nat) (symbol : Symbol) :
    Owned base (shiftSymbol base symbol) <-> Owned 0 symbol := by
  cases symbol with
  | constant ty id => cases ty <;> simp [Owned, shiftSymbol, highWater]
  | unary _ _ _ => rfl

theorem ids_nodup (base prior versions : Nat) :
    ((frame base prior versions).symbols.map SymbolBounds.symbolId).Nodup := by
  rw [symbols_shift]
  have translated :
      ((frame 0 0 0).symbols.map (shiftSymbol base)).map SymbolBounds.symbolId =
        ((frame 0 0 0).symbols.map SymbolBounds.symbolId).map (fun value => base + value) := by
    simp [List.map_map, Function.comp_def, shift_id]
  rw [translated]
  exact zero_ids_nodup.map (fun _ _ equal => Nat.add_left_cancel equal)

theorem symbols_card (base prior versions : Nat) :
    (frame base prior versions).symbols.toFinset.card = 662 := by
  rw [List.toFinset_card_of_nodup
    (List.Nodup.of_map SymbolBounds.symbolId (ids_nodup base prior versions))]
  exact StateFrame.frame_symbol_occurrences _

theorem symbols_owned (base prior versions : Nat) (symbol : Symbol)
    (member : Membership.mem (frame base prior versions).symbols symbol) : Owned base symbol := by
  rw [symbols_shift] at member
  cases List.mem_map.mp member with
  | intro original witness =>
    rw [<- witness.2]
    exact (owned_shift base original).mpr (zero_symbols_owned original witness.1)

theorem owned_bounds (base : Nat) (symbol : Symbol) (owned : Owned base symbol) :
    base <= SymbolBounds.symbolId symbol /\ SymbolBounds.symbolId symbol < highWater base := by
  cases symbol with
  | constant ty id =>
    cases ty <;> simp only [Owned, SymbolBounds.symbolId, highWater] at * <;> omega
  | unary _ _ _ => exact False.elim owned

theorem owned_unique (base : Nat) (left right : Symbol) (hl : Owned base left) (hr : Owned base right)
    (same : SymbolBounds.symbolId left = SymbolBounds.symbolId right) : left = right := by
  cases left with
  | unary _ _ _ => exact False.elim hl
  | constant lt li =>
    cases right with
    | unary _ _ _ => exact False.elim hr
    | constant rt ri =>
      cases lt <;> cases rt <;>
        simp_all [Owned, SymbolBounds.symbolId, highWater] <;> omega

theorem ids_exact (base prior versions : Nat) :
    ((frame base prior versions).symbols.map SymbolBounds.symbolId).toFinset =
      Finset.Ico base (highWater base) := by
  apply Finset.eq_of_subset_of_card_le
  next =>
    intro id member
    cases List.mem_map.mp (List.mem_toFinset.mp member) with
    | intro symbol evidence =>
      have bounds := owned_bounds base symbol (symbols_owned base prior versions symbol evidence.1)
      simpa [evidence.2] using bounds
  next =>
    rw [List.toFinset_card_of_nodup (ids_nodup base prior versions)]
    simp [StateFrame.frame_symbol_occurrences, highWater]

theorem owned_iff_member (base prior versions : Nat) (symbol : Symbol) :
    Owned base symbol <-> Membership.mem (frame base prior versions).symbols symbol := by
  constructor
  next =>
    intro owned
    have bounds := owned_bounds base symbol owned
    have member : Membership.mem
        ((frame base prior versions).symbols.map SymbolBounds.symbolId).toFinset
        (SymbolBounds.symbolId symbol) := by
      rw [ids_exact]
      exact Finset.mem_Ico.mpr bounds
    cases List.mem_map.mp (List.mem_toFinset.mp member) with
    | intro other evidence =>
      have same := owned_unique base other symbol
        (symbols_owned base prior versions other evidence.1) owned evidence.2
      simpa [same] using evidence.1
  next => exact symbols_owned base prior versions symbol

def indexAt (start count id : Nat) : Option (Fin count) :=
  if within : start <= id /\ id < start + count then
    some (Fin.mk (id - start) (by omega))
  else none

theorem index_at (start count : Nat) (index : Fin count) :
    indexAt start count (start + index.val) = some index := by
  simp [indexAt, index.isLt]

def allocatedSet (state : ModelState) : Finset Node :=
  Finset.univ.filter fun node => state.allocated node

-- These values and the assignment below are coverage witnesses, not initializers.
noncomputable def intValue (state : NodeState Node Nat) (column : Fin 39) : Int :=
  match hc : column.val with
  | 0 => roleCode state.role
  | 1 => state.currentTerm
  | 2 => state.log.length
  | 3 => state.commitIndex
  | 4 => optionNodeCode state.votedFor
  | 5 => membershipCode state.membershipState
  | 6 => optionNatCode state.retirementIndex
  | 7 => optionNatCode state.retirementCommittableIndex
  | 8 => optionNatCode state.retiredCommittedIndex
  | index + 9 =>
    if small : index < NODE_COUNT then state.sentIndex (Fin.mk index small)
    else state.matchIndex (Fin.mk (index - NODE_COUNT)
      (by have bound := column.isLt; unfold NODE_COUNT at *; omega))

def boolValue (state : ModelState) (index : Fin 30) : Bool :=
  if small : index.val < NODE_COUNT then (state.nodes (Fin.mk index.val small)).isNewFollower
  else decide (state.preVoteStatus (Fin.mk (index.val - NODE_COUNT)
    (by have bound := index.isLt; unfold NODE_COUNT at *; omega)) = .enabled)

def nodesValue (state : ModelState) (index : Fin 47) : BitVec NODE_COUNT :=
  NodeSetCodec.encodeNodes <| match hi : index.val with
  | 0 => allocatedSet state
  | 1 => state.hasJoined
  | offset + 2 =>
    if small : offset < NODE_COUNT then (state.nodes (Fin.mk offset small)).votesGranted
    else if middle : offset < 2 * NODE_COUNT then
      (state.nodes (Fin.mk (offset - NODE_COUNT) (by omega))).preVotesGranted
    else state.retirementCompleted (Fin.mk (offset - 2 * NODE_COUNT)
      (by have bound := index.isLt; unfold NODE_COUNT at *; omega))

noncomputable def install (original : Assignment) (state : ModelState) (base : Nat) : Assignment where
  constant := fun ty id => match ty with
    | .int => match indexAt base 585 id with
      | none => original.constant .int id
      | some index =>
        intValue (state.nodes (Fin.mk (index.val / 39)
          (by have bound := index.isLt; unfold NODE_COUNT; omega)))
          (Fin.mk (index.val % 39) (Nat.mod_lt _ (by decide)))
    | .bool => match indexAt (base + 585) 30 id with
      | none => original.constant .bool id
      | some index => boolValue state index
    | .nodes => match indexAt (base + 615) 47 id with
      | none => original.constant .nodes id
      | some index => nodesValue state index
    | .content => original.constant .content id
    | .entry => original.constant .entry id
  unary := original.unary
  selectors := original.selectors

theorem install_int (original : Assignment) (state : ModelState) (base : Nat)
    (node : Node) (column : Fin 39) :
    (intRef base node column).eval (install original state base) = intValue (state.nodes node) column := by
  have hn := node.isLt
  have hc := column.isLt
  have within : base <= base + (39 * node.val + column.val) /\
      base + (39 * node.val + column.val) < base + 585 := by
    unfold NODE_COUNT at hn
    omega
  have quotient : (39 * node.val + column.val) / 39 = node.val := by omega
  have remainder : (39 * node.val + column.val) % 39 = column.val := by omega
  simp [ConstRef.eval, install, intRef, indexAt, within, quotient, remainder]

theorem install_bool (original : Assignment) (state : ModelState) (base : Nat) (index : Fin 30) :
    (boolRef base index).eval (install original state base) = boolValue state index := by
  simp only [ConstRef.eval, install, boolRef, <- Nat.add_assoc, index_at]

theorem install_nodes (original : Assignment) (state : ModelState) (base : Nat) (index : Fin 47) :
    (nodesRef base index).eval (install original state base) = nodesValue state index := by
  simp only [ConstRef.eval, install, nodesRef, <- Nat.add_assoc, index_at]

theorem outside_constants (original : Assignment) (state : ModelState) (base : Nat) (ty : Ty) (id : Nat)
    (outside : Not (Owned base (.constant ty id))) :
    (install original state base).constant ty id = original.constant ty id := by
  cases ty with
  | int => simp only [Owned] at outside; simp only [install, indexAt, dif_neg outside]
  | bool =>
    have absent : Not (base + 585 <= id /\ id < (base + 585) + 30) := by
      simpa only [Owned, Nat.add_assoc] using outside
    simp only [install, indexAt, dif_neg absent]
  | nodes =>
    have absent : Not (base + 615 <= id /\ id < (base + 615) + 47) := by
      simpa only [Owned, highWater, Nat.add_assoc] using outside
    simp only [install, indexAt, dif_neg absent]
  | content => rfl
  | entry => rfl

theorem unary_preserved (original : Assignment) (state : ModelState) (base : Nat) :
    (install original state base).unary = original.unary := rfl

theorem selectors_preserved (original : Assignment) (state : ModelState) (base : Nat) :
    (install original state base).selectors = original.selectors := rfl

theorem int_value_sent (state : NodeState Node Nat) (peer : Node) :
    intValue state (Fin.mk (9 + peer.val)
      (by have bound := peer.isLt; unfold NODE_COUNT at bound; omega)) = (state.sentIndex peer : Int) := by
  simp only [show 9 + peer.val = peer.val + 9 by omega]
  simp [intValue, peer.isLt]

theorem int_value_match (state : NodeState Node Nat) (peer : Node) :
    intValue state (Fin.mk (24 + peer.val)
      (by have bound := peer.isLt; unfold NODE_COUNT at bound; omega)) = (state.matchIndex peer : Int) := by
  simp only [show 24 + peer.val = (peer.val + 15) + 9 by omega]
  simp [intValue, NODE_COUNT]

theorem bool_value_follower (state : ModelState) (node : Node) :
    boolValue state (Fin.mk node.val
      (by have bound := node.isLt; unfold NODE_COUNT at bound; omega)) = (state.nodes node).isNewFollower := by
  simp [boolValue, node.isLt]

theorem bool_value_prevote (state : ModelState) (node : Node) :
    boolValue state (Fin.mk (15 + node.val)
      (by have bound := node.isLt; unfold NODE_COUNT at bound; omega)) =
      decide (state.preVoteStatus node = .enabled) := by
  simp [boolValue, NODE_COUNT]

theorem nodes_value_votes (state : ModelState) (node : Node) :
    nodesValue state (Fin.mk (2 + node.val)
      (by have bound := node.isLt; unfold NODE_COUNT at bound; omega)) =
      NodeSetCodec.encodeNodes (state.nodes node).votesGranted := by
  simp only [show 2 + node.val = node.val + 2 by omega]
  simp [nodesValue, node.isLt]

theorem nodes_value_prevotes (state : ModelState) (node : Node) :
    nodesValue state (Fin.mk (17 + node.val)
      (by have bound := node.isLt; unfold NODE_COUNT at bound; omega)) =
      NodeSetCodec.encodeNodes (state.nodes node).preVotesGranted := by
  simp only [show 17 + node.val = (node.val + 15) + 2 by omega]
  have small : node.val + 15 < 30 := by have bound := node.isLt; unfold NODE_COUNT at bound; omega
  simp [nodesValue, small, NODE_COUNT]

theorem nodes_value_completed (state : ModelState) (node : Node) :
    nodesValue state (Fin.mk (32 + node.val)
      (by have bound := node.isLt; unfold NODE_COUNT at bound; omega)) =
      NodeSetCodec.encodeNodes (state.retirementCompleted node) := by
  simp only [show 32 + node.val = (node.val + 30) + 2 by omega]
  have large : Not (node.val + 30 < 15) := by omega
  simp [nodesValue, large, NODE_COUNT]

noncomputable def logRoot (log : List ArrayLog.LogEntry) : Nat -> EntryValue.Entry :=
  (EntryValue.arrayEquiv Nat).symm
    (ArrayLog.ArrayLog.ofList log { term := 0, content := .signature }).entries

noncomputable def extendRoots {prior : Nat} (old : Roots prior) (state : ModelState) :
    Roots (prior + NODE_COUNT) :=
  fun root index =>
    if before : root.val < prior then old (Fin.mk root.val before) index
    else logRoot (state.nodes (Fin.mk (root.val - prior)
      (by have bound := root.isLt; omega))).log index

theorem prefix_roots_preserved {prior : Nat} (old : Roots prior) (state : ModelState)
    (root : Fin prior) :
    extendRoots old state (Fin.mk root.val (by have bound := root.isLt; omega)) = old root := by
  funext index
  simp [extendRoots, root.isLt]

theorem fresh_root_read {prior : Nat} (old : Roots prior) (state : ModelState) (node : Node) :
    extendRoots old state (rootSlot prior node) = logRoot (state.nodes node).log := by
  funext index
  simp [extendRoots, rootSlot]

def CompatibleRoots (prior : Nat) (state : ModelState) (arrays : Roots (prior + NODE_COUNT)) : Prop :=
  forall node : Node,
    ArrayLog.ArrayLog.decode
      { length := (state.nodes node).log.length
        entries := fun index => EntryValue.decodeEntry (arrays (rootSlot prior node) index) } =
      (state.nodes node).log

theorem log_root_roundtrip (log : List ArrayLog.LogEntry) :
    ArrayLog.ArrayLog.decode
      { length := log.length, entries := fun index => EntryValue.decodeEntry (logRoot log index) } = log := by
  have entries :
      (fun index => EntryValue.decodeEntry (logRoot log index)) =
        (ArrayLog.ArrayLog.ofList log { term := 0, content := .signature }).entries :=
    (EntryValue.arrayEquiv Nat).apply_symm_apply _
  rw [entries]
  exact ArrayLog.decode_ofList log _

theorem extended_roots_compatible {prior : Nat} (old : Roots prior) (state : ModelState) :
    CompatibleRoots prior state (extendRoots old state) := by
  intro node
  simp only [fresh_root_read]
  exact log_root_roundtrip _

theorem relative_local_rep (original : Assignment) (state : ModelState) (base prior versions : Nat)
    (graph : Graph (prior + NODE_COUNT) versions) (arrays : Roots (prior + NODE_COUNT))
    (compatible : CompatibleRoots prior state arrays) (node : Node) :
    LocalRep (install original state base) graph arrays (localFrame base prior versions node)
      (state.nodes node) := by
  constructor
  all_goals try (solve | simp [localFrame, install_int, intValue])
  case log =>
    simpa [decodeLog, localFrame, install_int, intValue, IntervalReadback.actual] using
      (compatible node).symm
  case sentIndex =>
    intro peer
    simp only [localFrame, Vector.getElem_ofFn, install_int]
    exact int_value_sent _ _
  case matchIndex =>
    intro peer
    simp only [localFrame, Vector.getElem_ofFn, install_int]
    exact int_value_match _ _
  case isNewFollower => simp [localFrame, install_bool, bool_value_follower]
  case votesGranted => simp [localFrame, install_nodes, nodes_value_votes]
  case preVotesGranted => simp [localFrame, install_nodes, nodes_value_prevotes]

theorem relative_rep (original : Assignment) (state : ModelState) (base prior versions : Nat)
    (graph : Graph (prior + NODE_COUNT) versions) (arrays : Roots (prior + NODE_COUNT))
    (compatible : CompatibleRoots prior state arrays) :
    Rep (install original state base) graph arrays state.submittedTxIds (frame base prior versions) state := by
  refine { allocation := ?_, locals := ?_, joined := ?_, preVoteStatus := ?_
           retirementCompleted := ?_, submittedTxIds := rfl }
  next =>
    intro node
    simp [allocatedNodes, frame, install_nodes, nodesValue, allocatedSet]
  next =>
    intro node _
    simpa [frame] using relative_local_rep original state base prior versions graph arrays compatible node
  next => simp [frame, install_nodes, nodesValue]
  next =>
    intro node
    simp only [frame, Vector.getElem_ofFn, install_bool, bool_value_prevote]
    cases state.preVoteStatus node <;> rfl
  next =>
    intro node
    simp [frame, install_nodes, nodes_value_completed]

theorem arbitrary_state_coverage (original : Assignment) (state : ModelState)
    (base prior versions : Nat) (old : Roots prior) (graph : Graph (prior + NODE_COUNT) versions) :
    Rep (install original state base) graph (extendRoots old state) state.submittedTxIds
      (frame base prior versions) state :=
  relative_rep original state base prior versions graph _ (extended_roots_compatible old state)

theorem decode_original (original : Assignment) (state : ModelState)
    (base prior versions : Nat) (old : Roots prior) (graph : Graph (prior + NODE_COUNT) versions)
    (valid : Domains (install original state base) (frame base prior versions)) :
    { decodeFrame (install original state base) graph (extendRoots old state)
        state.submittedTxIds (frame base prior versions) valid with network := state.network } = state :=
  rep_unique_with_network
    ((decode_rep _ _ _ _ _ valid).with_network state.network)
    (arbitrary_state_coverage original state base prior versions old graph) rfl rfl

theorem canonical_scoped (base prior versions : Nat) :
    WellScoped (frame base prior versions).symbols.toFinset (frame base prior versions) := by
  intro symbol member
  exact List.mem_toFinset.mpr member

theorem coverage_checks (original : Assignment) (state : ModelState) (base prior versions : Nat)
    (old : Roots prior) (graph : Graph (prior + NODE_COUNT) versions) :
    checkFrame (frame base prior versions).symbols.toFinset
      (install original state base) (frame base prior versions) = true :=
  (check_frame_iff _ _ _).mpr (And.intro (canonical_scoped base prior versions)
    (arbitrary_state_coverage original state base prior versions old graph).domains)

theorem outside_scope (original : Assignment) (state : ModelState) (base prior versions : Nat)
    (ty : Ty) (id : Nat) (absent : Not (Membership.mem (frame base prior versions).symbols (.constant ty id))) :
    (install original state base).constant ty id = original.constant ty id :=
  outside_constants original state base ty id
    (fun owned => absent ((owned_iff_member base prior versions _).mp owned))

def regressionNode0 : Node := Fin.mk 0 (by decide)
def regressionNode1 : Node := Fin.mk 1 (by decide)
def regressionNode2 : Node := Fin.mk 2 (by decide)

def regressionState : ModelState where
  nodes := NodeStore.ofFinset {regressionNode0, regressionNode1} fun node =>
    if node = regressionNode0 then
      { (freshNodeState : NodeState Node Nat) with
        role := .leader
        log := [{ term := 0, content := .transaction 5 }]
        commitIndex := 1000000
        sentIndex := fun peer => if peer = regressionNode1 then 11 else 22
        matchIndex := fun peer => if peer = regressionNode1 then 44 else 55 }
    else
      { (freshNodeState : NodeState Node Nat) with
        role := .candidate
        log := [{ term := 9, content := .reconfiguration {} }]
        sentIndex := fun _ => 33
        membershipState := .retiredCommitted
        retirementIndex := some 0 }
  network := fun _ =>
    [.proposeVoteRequest { term := 99, source := regressionNode2, destination := regressionNode1 },
      .proposeVoteRequest { term := 99, source := regressionNode2, destination := regressionNode1 }]
  submittedTxIds := {3, 999999}
  hasJoined := {regressionNode2}
  preVoteStatus := fun _ => .enabled
  retirementCompleted := fun _ => {regressionNode1}

def regressionOriginal : Assignment where
  constant := fun ty id => match ty with
    | .int => -(id : Int) - 1
    | .bool => true
    | .nodes => 0
    | .content => .signature
    | .entry => { term := -1, content := .signature }
  unary := fun _ result _ _ => StateFrame.fixtureDefault result

def regressionRoots : Roots 7 :=
  fun root index => { term := (root.val : Int), content := .transaction (index : Int) }

theorem nonzero_layout_regression :
    highWater 1000 = 1662 /\
      (frame 1000 7 0).allocated.id = 1615 /\
      (frame 1000 7 0).locals[regressionNode1.val].sentIndex[regressionNode2.val].id = 1050 /\
      (rootSlot 7 regressionNode1).val = 8 := by
  decide +kernel

theorem independent_peer_regression :
    (localFrame 1000 7 0 regressionNode0).sentIndex[regressionNode1.val].eval
        (install regressionOriginal regressionState 1000) = 11 /\
      (localFrame 1000 7 0 regressionNode0).sentIndex[regressionNode2.val].eval
        (install regressionOriginal regressionState 1000) = 22 /\
      (localFrame 1000 7 0 regressionNode1).sentIndex[regressionNode1.val].eval
        (install regressionOriginal regressionState 1000) = 33 /\
      (localFrame 1000 7 0 regressionNode0).matchIndex[regressionNode1.val].eval
        (install regressionOriginal regressionState 1000) = 44 := by
  decide +kernel

theorem allocation_joined_option_regression :
    (frame 1000 7 0).allocated.eval (install regressionOriginal regressionState 1000) =
        NodeSetCodec.encodeNodes {regressionNode0, regressionNode1} /\
      (frame 1000 7 0).hasJoined.eval (install regressionOriginal regressionState 1000) =
        NodeSetCodec.encodeNodes {regressionNode2} /\
      (localFrame 1000 7 0 regressionNode0).retirementIndex.eval
        (install regressionOriginal regressionState 1000) = 0 /\
      (localFrame 1000 7 0 regressionNode1).retirementIndex.eval
        (install regressionOriginal regressionState 1000) = 1 := by
  decide +kernel

theorem outside_type_regression :
    (install regressionOriginal regressionState 1000).constant .int 1585 = -1586 /\
      (install regressionOriginal regressionState 1000).constant .bool 1000 = true /\
      (install regressionOriginal regressionState 1000).constant .int 1662 = -1663 := by
  decide +kernel

theorem prefix_regression :
    extendRoots regressionRoots regressionState (Fin.mk 3 (by decide)) 1000000 =
      regressionRoots (Fin.mk 3 (by decide)) 1000000 :=
  congrFun (prefix_roots_preserved regressionRoots regressionState (Fin.mk 3 (by decide))) 1000000

theorem regression_checks :
    checkFrame (frame 1000 7 0).symbols.toFinset
      (install regressionOriginal regressionState 1000) (frame 1000 7 0) = true :=
  coverage_checks regressionOriginal regressionState 1000 7 0 regressionRoots .empty

end CCFRaft.Sparse.StateFrameInitial

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.StateFrameInitial).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit StateFrameInitial axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"StateFrameInitial: {checked} declarations passed the allowed-axiom gate."
