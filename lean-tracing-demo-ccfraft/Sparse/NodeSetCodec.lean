import Model

set_option autoImplicit false

namespace CCFRaft.Sparse.NodeSetCodec

-- Bit positions are the existing Model nodes, not allocated node states.
def encodeNodes (nodes : Finset Node) : BitVec NODE_COUNT :=
  (BitVec.ofBoolListLE
    (List.ofFn fun node : Node => decide (Membership.mem nodes node))).cast
      List.length_ofFn

def decodeNodes (bits : BitVec NODE_COUNT) : Finset Node :=
  Finset.univ.filter fun node : Node => bits.getLsbD node.val = true

theorem node_card : Fintype.card Node = NODE_COUNT :=
  Fintype.card_fin NODE_COUNT

@[simp] theorem encode_bit (nodes : Finset Node) (node : Node) :
    (encodeNodes nodes).getLsbD node.val = decide (Membership.mem nodes node) := by
  rw [encodeNodes, BitVec.getLsbD_cast, BitVec.getLsbD_ofBoolListLE,
    List.getD_eq_getElem?_getD]
  simp only [List.getElem?_ofFn, dif_pos node.isLt, Option.getD_some]

@[simp] theorem decode_member (bits : BitVec NODE_COUNT) (node : Node) :
    Membership.mem (decodeNodes bits) node <-> bits.getLsbD node.val = true := by
  simp [decodeNodes]

theorem encode_member (nodes : Finset Node) (node : Node) :
    (encodeNodes nodes).getLsbD node.val = true <-> Membership.mem nodes node := by
  simp only [encode_bit, decide_eq_true_eq]

@[simp] theorem decode_encode_nodes (nodes : Finset Node) :
    decodeNodes (encodeNodes nodes) = nodes := by
  ext node
  rw [decode_member, encode_member]

@[simp] theorem encode_decode_bits (bits : BitVec NODE_COUNT) :
    encodeNodes (decodeNodes bits) = bits := by
  apply BitVec.eq_of_getLsbD_eq
  intro index within
  simpa using encode_bit (decodeNodes bits) (Fin.mk index within)

def nodeSetEquiv : Equiv (BitVec NODE_COUNT) (Finset Node) where
  toFun := decodeNodes
  invFun := encodeNodes
  left_inv := encode_decode_bits
  right_inv := decode_encode_nodes

theorem bits_eq_iff (left right : BitVec NODE_COUNT) :
    decodeNodes left = decodeNodes right <-> left = right :=
  nodeSetEquiv.injective.eq_iff

theorem bits_ne_iff (left right : BitVec NODE_COUNT) :
    Not (decodeNodes left = decodeNodes right) <-> Not (left = right) :=
  not_congr (bits_eq_iff left right)

theorem nodes_eq_iff (left right : Finset Node) :
    encodeNodes left = encodeNodes right <-> left = right :=
  nodeSetEquiv.symm.injective.eq_iff

theorem nodes_ne_iff (left right : Finset Node) :
    Not (encodeNodes left = encodeNodes right) <-> Not (left = right) :=
  not_congr (nodes_eq_iff left right)

@[simp] theorem decode_zero : decodeNodes 0 = ({} : Finset Node) := by
  ext node
  simp

@[simp] theorem encode_empty : encodeNodes {} = 0 := by
  apply nodeSetEquiv.injective
  change decodeNodes (encodeNodes {}) = decodeNodes 0
  rw [decode_encode_nodes, decode_zero]

@[simp] theorem decode_or (left right : BitVec NODE_COUNT) :
    decodeNodes (left ||| right) = Union.union (decodeNodes left) (decodeNodes right) := by
  ext node
  simp

theorem encode_union (left right : Finset Node) :
    encodeNodes (Union.union left right) = encodeNodes left ||| encodeNodes right := by
  apply nodeSetEquiv.injective
  change decodeNodes (encodeNodes (Union.union left right)) =
    decodeNodes (encodeNodes left ||| encodeNodes right)
  simp

theorem encode_insert (nodes : Finset Node) (node : Node) :
    encodeNodes (insert node nodes) = encodeNodes {node} ||| encodeNodes nodes := by
  rw [<- encode_union]
  simp

theorem decode_insert (bits : BitVec NODE_COUNT) (node : Node) :
    decodeNodes (encodeNodes {node} ||| bits) = insert node (decodeNodes bits) := by
  simp

def setBitCount (bits : BitVec NODE_COUNT) : Nat :=
  Finset.univ.sum fun node : Node => if bits.getLsbD node.val = true then 1 else 0

theorem decode_card (bits : BitVec NODE_COUNT) :
    (decodeNodes bits).card = setBitCount bits := by
  simp [decodeNodes, setBitCount]

theorem encode_card (nodes : Finset Node) :
    setBitCount (encodeNodes nodes) = nodes.card := by
  rw [<- decode_card, decode_encode_nodes]

end CCFRaft.Sparse.NodeSetCodec

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.NodeSetCodec).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse node-set codec audit passed: {checked} declarations."
