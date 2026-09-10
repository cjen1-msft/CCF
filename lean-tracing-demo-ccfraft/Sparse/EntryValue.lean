import Sparse.BijectiveIntegerLog
import Sparse.NodeSetCodec

set_option autoImplicit false

namespace CCFRaft.Sparse.EntryValue

open ArrayLog

-- Value-domain preparation only: no SMT syntax or whole-packet identity.
inductive Content where
  | transaction (txId : Int)
  | signature
  | reconfiguration (nodes : BitVec NODE_COUNT)
  | retiredCommitted (nodes : BitVec NODE_COUNT)
  deriving DecidableEq

structure Entry where
  term : Int
  content : Content
  deriving DecidableEq

def toRawContent : Content -> EntryContent Node Int
  | .transaction tx => .transaction tx
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration (NodeSetCodec.decodeNodes nodes)
  | .retiredCommitted nodes => .retiredCommitted (NodeSetCodec.decodeNodes nodes)

def fromRawContent : EntryContent Node Int -> Content
  | .transaction tx => .transaction tx
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration (NodeSetCodec.encodeNodes nodes)
  | .retiredCommitted nodes => .retiredCommitted (NodeSetCodec.encodeNodes nodes)

@[simp] theorem to_from_raw_content (content : EntryContent Node Int) :
    toRawContent (fromRawContent content) = content := by
  cases content <;> simp [toRawContent, fromRawContent]

@[simp] theorem from_to_raw_content (content : Content) :
    fromRawContent (toRawContent content) = content := by
  cases content <;> simp [toRawContent, fromRawContent]

def rawContentEquiv : Equiv Content (EntryContent Node Int) where
  toFun := toRawContent
  invFun := fromRawContent
  left_inv := from_to_raw_content
  right_inv := to_from_raw_content

def contentEquiv : Equiv Content (EntryContent Node Nat) :=
  rawContentEquiv.trans BijectiveIntegerLog.contentEquiv

def decodeContent (content : Content) : EntryContent Node Nat := contentEquiv content
def encodeContent (content : EntryContent Node Nat) : Content := contentEquiv.symm content

@[simp] theorem decode_encode_content (content : EntryContent Node Nat) :
    decodeContent (encodeContent content) = content :=
  contentEquiv.apply_symm_apply content

@[simp] theorem encode_decode_content (content : Content) :
    encodeContent (decodeContent content) = content :=
  contentEquiv.symm_apply_apply content

theorem decode_content_eq_iff (left right : Content) :
    decodeContent left = decodeContent right <-> left = right :=
  contentEquiv.injective.eq_iff

theorem decode_content_ne_iff (left right : Content) :
    Not (decodeContent left = decodeContent right) <-> Not (left = right) :=
  not_congr (decode_content_eq_iff left right)

theorem encode_content_eq_iff (left right : EntryContent Node Nat) :
    encodeContent left = encodeContent right <-> left = right :=
  contentEquiv.symm.injective.eq_iff

theorem encode_content_ne_iff (left right : EntryContent Node Nat) :
    Not (encodeContent left = encodeContent right) <-> Not (left = right) :=
  not_congr (encode_content_eq_iff left right)

@[simp] theorem decode_transaction (tx : Int) :
    decodeContent (.transaction tx) =
      .transaction (BijectiveIntegerLog.decodeNat tx) := rfl

@[simp] theorem decode_signature : decodeContent .signature = .signature := rfl

@[simp] theorem decode_reconfiguration (nodes : BitVec NODE_COUNT) :
    decodeContent (.reconfiguration nodes) =
      .reconfiguration (NodeSetCodec.decodeNodes nodes) := rfl

@[simp] theorem decode_retiredCommitted (nodes : BitVec NODE_COUNT) :
    decodeContent (.retiredCommitted nodes) =
      .retiredCommitted (NodeSetCodec.decodeNodes nodes) := rfl

def toRawEntry (entry : Entry) : BijectiveIntegerLog.RawEntry :=
  { term := entry.term, content := toRawContent entry.content }

def fromRawEntry (entry : BijectiveIntegerLog.RawEntry) : Entry :=
  { term := entry.term, content := fromRawContent entry.content }

@[simp] theorem to_from_raw_entry (entry : BijectiveIntegerLog.RawEntry) :
    toRawEntry (fromRawEntry entry) = entry := by
  cases entry
  simp [toRawEntry, fromRawEntry]

@[simp] theorem from_to_raw_entry (entry : Entry) :
    fromRawEntry (toRawEntry entry) = entry := by
  cases entry
  simp [toRawEntry, fromRawEntry]

def rawEntryEquiv : Equiv Entry BijectiveIntegerLog.RawEntry where
  toFun := toRawEntry
  invFun := fromRawEntry
  left_inv := from_to_raw_entry
  right_inv := to_from_raw_entry

def entryEquiv : Equiv Entry LogEntry :=
  rawEntryEquiv.trans BijectiveIntegerLog.entryEquiv

def decodeEntry (entry : Entry) : LogEntry := entryEquiv entry
def encodeEntry (entry : LogEntry) : Entry := entryEquiv.symm entry

@[simp] theorem decode_encode_entry (entry : LogEntry) :
    decodeEntry (encodeEntry entry) = entry := entryEquiv.apply_symm_apply entry

@[simp] theorem encode_decode_entry (entry : Entry) :
    encodeEntry (decodeEntry entry) = entry := entryEquiv.symm_apply_apply entry

theorem decode_entry_eq_iff (left right : Entry) :
    decodeEntry left = decodeEntry right <-> left = right :=
  entryEquiv.injective.eq_iff

theorem decode_entry_ne_iff (left right : Entry) :
    Not (decodeEntry left = decodeEntry right) <-> Not (left = right) :=
  not_congr (decode_entry_eq_iff left right)

theorem encode_entry_eq_iff (left right : LogEntry) :
    encodeEntry left = encodeEntry right <-> left = right :=
  entryEquiv.symm.injective.eq_iff

theorem encode_entry_ne_iff (left right : LogEntry) :
    Not (encodeEntry left = encodeEntry right) <-> Not (left = right) :=
  not_congr (encode_entry_eq_iff left right)

@[simp] theorem decode_entry_term (entry : Entry) :
    (decodeEntry entry).term = BijectiveIntegerLog.decodeNat entry.term := rfl

@[simp] theorem decode_entry_content (entry : Entry) :
    (decodeEntry entry).content = decodeContent entry.content := rfl

theorem term_lt_iff (left right : Entry) :
    (decodeEntry left).term < (decodeEntry right).term <->
      BijectiveIntegerLog.smtDecode left.term < BijectiveIntegerLog.smtDecode right.term :=
  BijectiveIntegerLog.decoded_order_iff left.term right.term

theorem term_le_iff (left right : Entry) :
    (decodeEntry left).term <= (decodeEntry right).term <->
      BijectiveIntegerLog.smtDecode left.term <= BijectiveIntegerLog.smtDecode right.term := by
  rw [<- BijectiveIntegerLog.decode_formula, <- BijectiveIntegerLog.decode_formula]
  simp

theorem term_bound_iff (entry : Entry) (current : Nat) :
    (decodeEntry entry).term <= current <->
      BijectiveIntegerLog.smtDecode entry.term <= (current : Int) := by
  rw [<- BijectiveIntegerLog.decode_formula]
  simp

-- These are guarded views, not unguarded SMT selectors with invented defaults.
def Content.transaction? : Content -> Option Int
  | .transaction tx => some tx
  | _ => none

def Content.reconfiguration? : Content -> Option (BitVec NODE_COUNT)
  | .reconfiguration nodes => some nodes
  | _ => none

def Content.retiredCommitted? : Content -> Option (BitVec NODE_COUNT)
  | .retiredCommitted nodes => some nodes
  | _ => none

def Content.isTransaction (content : Content) : Bool := content.transaction?.isSome
def Content.isReconfiguration (content : Content) : Bool := content.reconfiguration?.isSome
def Content.isRetiredCommitted (content : Content) : Bool := content.retiredCommitted?.isSome

def Content.isSignature : Content -> Bool
  | .signature => true
  | _ => false

@[simp] theorem transaction_some_iff (content : Content) (tx : Int) :
    content.transaction? = some tx <-> content = .transaction tx := by
  cases content <;> simp [Content.transaction?]

@[simp] theorem reconfiguration_some_iff (content : Content) (nodes : BitVec NODE_COUNT) :
    content.reconfiguration? = some nodes <-> content = .reconfiguration nodes := by
  cases content <;> simp [Content.reconfiguration?]

@[simp] theorem retiredCommitted_some_iff (content : Content) (nodes : BitVec NODE_COUNT) :
    content.retiredCommitted? = some nodes <-> content = .retiredCommitted nodes := by
  cases content <;> simp [Content.retiredCommitted?]

theorem isTransaction_iff (content : Content) :
    content.isTransaction = true <-> exists tx, content = .transaction tx := by
  cases content <;> simp [Content.isTransaction, Content.transaction?]

theorem isReconfiguration_iff (content : Content) :
    content.isReconfiguration = true <-> exists nodes, content = .reconfiguration nodes := by
  cases content <;> simp [Content.isReconfiguration, Content.reconfiguration?]

theorem isRetiredCommitted_iff (content : Content) :
    content.isRetiredCommitted = true <-> exists nodes, content = .retiredCommitted nodes := by
  cases content <;> simp [Content.isRetiredCommitted, Content.retiredCommitted?]

@[simp] theorem isSignature_iff (content : Content) :
    content.isSignature = true <-> content = .signature := by
  cases content <;> simp [Content.isSignature]

def arrayEquiv (Index : Type) : Equiv (Index -> Entry) (Index -> LogEntry) :=
  Equiv.arrowCongr (Equiv.refl Index) entryEquiv

theorem decode_array_eq_iff {Index : Type} (left right : Index -> Entry) :
    (fun index => decodeEntry (left index)) = (fun index => decodeEntry (right index)) <->
      left = right :=
  (arrayEquiv Index).injective.eq_iff

theorem decode_array_ne_iff {Index : Type} (left right : Index -> Entry) :
    Not ((fun index => decodeEntry (left index)) = (fun index => decodeEntry (right index))) <->
      Not (left = right) :=
  not_congr (decode_array_eq_iff left right)

theorem encode_array_eq_iff {Index : Type} (left right : Index -> LogEntry) :
    (fun index => encodeEntry (left index)) = (fun index => encodeEntry (right index)) <->
      left = right :=
  (arrayEquiv Index).symm.injective.eq_iff

theorem encode_array_ne_iff {Index : Type} (left right : Index -> LogEntry) :
    Not ((fun index => encodeEntry (left index)) = (fun index => encodeEntry (right index))) <->
      Not (left = right) :=
  not_congr (encode_array_eq_iff left right)

theorem zero_mask :
    decodeContent (.reconfiguration 0) = .reconfiguration ({} : Finset Node) := by
  rw [decode_reconfiguration, NodeSetCodec.decode_zero]

theorem all_node_mask :
    decodeContent (.reconfiguration 32767) = .reconfiguration Finset.univ := by decide

theorem equal_content_identity (left right : BitVec NODE_COUNT) :
    decodeContent (.reconfiguration left) = decodeContent (.reconfiguration right) <->
      left = right := by
  rw [decode_content_eq_iff]
  simp

theorem equal_entry_identity (leftTerm rightTerm leftTx rightTx : Int) :
    decodeEntry { term := leftTerm, content := .transaction leftTx } =
      decodeEntry { term := rightTerm, content := .transaction rightTx } <->
      leftTerm = rightTerm /\ leftTx = rightTx := by
  rw [decode_entry_eq_iff]
  simp

theorem configuration_retired_distinct (configuration retired : BitVec NODE_COUNT) :
    Not (decodeContent (.reconfiguration configuration) =
      decodeContent (.retiredCommitted retired)) := by
  rw [decode_content_ne_iff]
  intro same
  cases same

theorem negative_encoded_entry :
    encodeEntry { term := 1, content := .transaction 3 } =
      { term := -1, content := .transaction (-2) } := by decide

theorem negative_raw_order :
    (-1 : Int) < 0 /\
      (decodeEntry { term := 0, content := .signature }).term <
        (decodeEntry { term := -1, content := .signature }).term :=
  BijectiveIntegerLog.raw_order_not_preserved

end CCFRaft.Sparse.EntryValue

run_cmd do
  let namespaceName := `CCFRaft.Sparse.EntryValue
  let environment <- Lean.getEnv
  let mut count := 0
  for (name, _) in environment.constants.toList do
    if namespaceName.isPrefixOf name then
      count := count + 1
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"EntryValue: audited {count} declarations; only propext, Classical.choice, Quot.sound"
