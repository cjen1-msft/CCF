import Sparse.MessageCodec
import Sparse.EntryValue

set_option autoImplicit false

namespace CCFRaft.Sparse.PacketIdentity

open MessageCodec

-- Header Ints are bijective Nat codes. Lengths and positions below are ordinary Nat.
structure AppendHeader where
  term : Int
  prevLogIndex : Int
  prevLogTerm : Int
  leaderCommit : Int
  source : Node
  destination : Node
  deriving DecidableEq

inductive Header where
  | appendEntriesRequest (request : AppendHeader)
  | appendEntriesResponse (response : RawAppendEntriesResponse)
  | requestVoteRequest (request : RawRequestVoteRequest)
  | requestVoteResponse (response : RawRequestVoteResponse)
  | requestPreVote (request : RawRequestPreVote)
  | requestPreVoteResponse (response : RawRequestPreVoteResponse)
  | proposeVoteRequest (request : RawProposeVoteRequest)
  deriving DecidableEq

def header : RawMessage -> Header
  | .appendEntriesRequest (.mk term previous previousTerm _ commit source destination) =>
    .appendEntriesRequest (.mk term previous previousTerm commit source destination)
  | .appendEntriesResponse response => .appendEntriesResponse response
  | .requestVoteRequest request => .requestVoteRequest request
  | .requestVoteResponse response => .requestVoteResponse response
  | .requestPreVote request => .requestPreVote request
  | .requestPreVoteResponse response => .requestPreVoteResponse response
  | .proposeVoteRequest request => .proposeVoteRequest request

def rawEntries : RawMessage -> List BijectiveIntegerLog.RawEntry
  | .appendEntriesRequest request => request.entries
  | _ => []

-- These are views of existing finite packet values, not sparse-array materialization.
def payload (message : RawMessage) : List EntryValue.Entry :=
  (rawEntries message).map EntryValue.fromRawEntry

def payloadLength (message : RawMessage) : Nat := (rawEntries message).length

@[simp] theorem payload_length (message : RawMessage) :
    (payload message).length = payloadLength message := by
  simp [payload, payloadLength]

theorem payload_eq_iff (left right : RawMessage) :
    payload left = payload right <-> rawEntries left = rawEntries right :=
  (List.map_injective_iff.mpr EntryValue.rawEntryEquiv.symm.injective).eq_iff

theorem raw_eq_iff_parts (left right : RawMessage) :
    left = right <-> header left = header right /\ payload left = payload right := by
  rw [payload_eq_iff]
  cases left <;> cases right <;> simp [header, rawEntries]
  rename_i left right
  cases left
  cases right
  simp [and_assoc, and_comm]

theorem list_eq_iff {A : Type} (left right : List A) :
    left = right <-> left.length = right.length /\
      (forall index, index < left.length -> index < right.length ->
        left[index]? = right[index]?) := by
  constructor
  next =>
    intro same
    subst right
    exact And.intro rfl (fun _ _ _ => rfl)
  next =>
    intro same
    apply List.ext_getElem?
    intro index
    by_cases within : index < left.length
    next => exact same.2 index within (by omega)
    next =>
      have left_out : left.length <= index := by omega
      have right_out : right.length <= index := by omega
      simp [List.getElem?_eq_none left_out, List.getElem?_eq_none right_out]

def Same (left right : RawMessage) : Prop :=
  header left = header right /\ payloadLength left = payloadLength right /\
    (forall index, index < payloadLength left -> index < payloadLength right ->
      (payload left)[index]? = (payload right)[index]?)

def PayloadMismatch (left right : RawMessage) : Prop :=
  exists index, index < payloadLength left /\ index < payloadLength right /\
    Not ((payload left)[index]? = (payload right)[index]?)

def Different (left right : RawMessage) : Prop :=
  Not (header left = header right) \/ Not (payloadLength left = payloadLength right) \/
    PayloadMismatch left right

theorem raw_eq_iff (left right : RawMessage) : left = right <-> Same left right := by
  rw [raw_eq_iff_parts, list_eq_iff]
  simp only [payload_length, Same]

theorem raw_ne_iff (left right : RawMessage) : Not (left = right) <-> Different left right := by
  classical
  rw [raw_eq_iff]
  simp only [Same, Different, PayloadMismatch, not_and_or, not_forall, exists_prop]

theorem decoded_eq_iff (left right : RawMessage) :
    decodeMessage left = decodeMessage right <-> Same left right := by
  rw [message_eq_iff, raw_eq_iff]

theorem decoded_ne_iff (left right : RawMessage) :
    Not (decodeMessage left = decodeMessage right) <-> Different left right := by
  rw [message_ne_iff, raw_ne_iff]

theorem matching_header_length_ne_iff (left right : RawMessage)
    (headers : header left = header right) (lengths : payloadLength left = payloadLength right) :
    Not (decodeMessage left = decodeMessage right) <-> PayloadMismatch left right := by
  rw [decoded_ne_iff]
  simp [Different, headers, lengths]

theorem model_eq_iff (left right : Packet) :
    left = right <-> Same (encodeMessage left) (encodeMessage right) := by
  rw [<- encoded_message_eq_iff, raw_eq_iff]

theorem model_ne_iff (left right : Packet) :
    Not (left = right) <-> Different (encodeMessage left) (encodeMessage right) := by
  rw [<- encoded_message_ne_iff, raw_ne_iff]

def modelEntries : Packet -> List ArrayLog.LogEntry
  | .appendEntriesRequest request => request.entries
  | _ => []

theorem decode_raw_entry (entry : BijectiveIntegerLog.RawEntry) :
    EntryValue.decodeEntry (EntryValue.fromRawEntry entry) =
      BijectiveIntegerLog.decodeEntry entry := by
  change BijectiveIntegerLog.decodeEntry
    (EntryValue.toRawEntry (EntryValue.fromRawEntry entry)) = _
  rw [EntryValue.to_from_raw_entry]

theorem decode_payload (message : RawMessage) :
    (payload message).map EntryValue.decodeEntry = modelEntries (decodeMessage message) := by
  cases message with
  | appendEntriesRequest request =>
    cases request
    simp [payload, rawEntries, decodeMessage, decodeAppendEntriesRequest, modelEntries,
      decodeEntries, List.map_map, Function.comp_def, decode_raw_entry]
  | appendEntriesResponse response => rfl
  | requestVoteRequest request => rfl
  | requestVoteResponse response => rfl
  | requestPreVote request => rfl
  | requestPreVoteResponse response => rfl
  | proposeVoteRequest request => rfl

theorem decoded_length (message : RawMessage) :
    (modelEntries (decodeMessage message)).length = payloadLength message := by
  rw [<- decode_payload, List.length_map, payload_length]

theorem bounded_entries (left right : RawMessage) (index : Nat)
    (left_bound : index < payloadLength left) (right_bound : index < payloadLength right) :
    (payload left)[index]? = (payload right)[index]? <->
      EntryValue.decodeEntry ((payload left)[index]'(by simpa using left_bound)) =
        EntryValue.decodeEntry ((payload right)[index]'(by simpa using right_bound)) := by
  rw [List.getElem?_eq_getElem (by simpa using left_bound),
    List.getElem?_eq_getElem (by simpa using right_bound), Option.some.injEq,
    EntryValue.decode_entry_eq_iff]

theorem mismatch_is_payload (left right : RawMessage) (mismatch : PayloadMismatch left right) :
    (exists request, left = .appendEntriesRequest request) /\
      (exists request, right = .appendEntriesRequest request) := by
  cases mismatch with
  | intro index bounds =>
    cases left <;> cases right <;> simp_all [payloadLength, rawEntries]

theorem empty_identity (left right : RawMessage)
    (left_empty : payloadLength left = 0) (right_empty : payloadLength right = 0) :
    decodeMessage left = decodeMessage right <-> header left = header right := by
  rw [decoded_eq_iff]
  simp [Same, left_empty, right_empty]

-- Obligations cover only these finitely many occurrences, never every Int.
structure IdentityFacts {count : Nat} (keys : Fin count -> Int)
    (messages : Fin count -> RawMessage) : Prop where
  sameKey : forall left right, keys left = keys right -> Same (messages left) (messages right)
  differentKeys : forall left right, Not (keys left = keys right) ->
    Different (messages left) (messages right)

theorem key_eq_iff {count : Nat} (keys : Fin count -> Int) (messages : Fin count -> RawMessage)
    (facts : IdentityFacts keys messages) (left right : Fin count) :
    keys left = keys right <-> decodeMessage (messages left) = decodeMessage (messages right) := by
  constructor
  next => exact fun same => (decoded_eq_iff _ _).mpr (facts.sameKey left right same)
  next =>
    intro same
    by_contra different
    exact ((decoded_ne_iff _ _).mpr (facts.differentKeys left right different)) same

theorem identity_facts_iff {count : Nat} (keys : Fin count -> Int) (messages : Fin count -> RawMessage) :
    IdentityFacts keys messages <->
      (forall left right, keys left = keys right <->
        decodeMessage (messages left) = decodeMessage (messages right)) := by
  constructor
  next => exact fun facts => key_eq_iff keys messages facts
  next =>
    intro exact_keys
    constructor
    next => exact fun left right same => (decoded_eq_iff _ _).mp ((exact_keys left right).mp same)
    next =>
      intro left right different
      apply (decoded_ne_iff _ _).mp
      exact fun same => different ((exact_keys left right).mpr same)

def keySetoid {count : Nat} (keys : Fin count -> Int) : Setoid (Fin count) where
  r left right := keys left = keys right
  iseqv :=
    { refl := fun _ => rfl
      symm := Eq.symm
      trans := Eq.trans }

def classPacket {count : Nat} (keys : Fin count -> Int) (messages : Fin count -> RawMessage)
    (facts : IdentityFacts keys messages) : Quotient (keySetoid keys) -> Packet :=
  Quotient.lift (fun index => decodeMessage (messages index))
    (fun left right same => (decoded_eq_iff _ _).mpr (facts.sameKey left right same))

@[simp] theorem classPacket_mk {count : Nat} (keys : Fin count -> Int)
    (messages : Fin count -> RawMessage) (facts : IdentityFacts keys messages) (index : Fin count) :
    classPacket keys messages facts (Quotient.mk (keySetoid keys) index) =
      decodeMessage (messages index) := rfl

theorem key_classes_finite {count : Nat} (keys : Fin count -> Int) :
    Finite (Quotient (keySetoid keys)) := inferInstance

theorem classPacket_injective {count : Nat} (keys : Fin count -> Int)
    (messages : Fin count -> RawMessage) (facts : IdentityFacts keys messages) :
    Function.Injective (classPacket keys messages facts) := by
  intro left right
  refine Quotient.inductionOn left ?_
  intro left
  refine Quotient.inductionOn right ?_
  intro right same
  apply Quotient.sound
  exact (key_eq_iff keys messages facts left right).mpr same

namespace Regression

local instance : NeZero NODE_COUNT := { out := by decide }

def appendPacket (entries : List EntryValue.Entry) : RawMessage :=
  .appendEntriesRequest
    (.mk (-1) (-1) (-1) (entries.map EntryValue.toRawEntry) (-1) 0 1)

@[simp] theorem append_payload (entries : List EntryValue.Entry) :
    payload (appendPacket entries) = entries := by
  simp [payload, rawEntries, appendPacket, List.map_map, Function.comp_def]

def signature : EntryValue.Entry := { term := -1, content := .signature }
def transaction : EntryValue.Entry := { term := -1, content := .transaction (-1) }

def tags : List RawMessage :=
  [appendPacket [],
   .appendEntriesResponse (.mk (-1) true (-1) 0 1),
   .requestVoteRequest (.mk (-1) (-1) (-1) 0 1),
   .requestVoteResponse (.mk (-1) true 0 1),
   .requestPreVote (.mk (-1) (-1) (-1) 0 1),
   .requestPreVoteResponse (.mk (-1) true 0 1),
   .proposeVoteRequest (.mk (-1) 0 1)]

theorem kernel_seven_empty_tags :
    tags.length = 7 /\
    tags.Pairwise (fun left right => Not (header left = header right)) /\
    tags.all (fun message => payloadLength message == 0) = true := by
  decide +kernel

theorem kernel_signed_codes :
    (decodeMessage (appendPacket [transaction])).term = 1 /\
    (payloadLength (appendPacket [transaction]) : Int) = 1 /\
    header (appendPacket [transaction]) = .appendEntriesRequest (.mk (-1) (-1) (-1) (-1) 0 1) /\
    (payload (appendPacket [transaction]))[0]? =
      some { term := -1, content := .transaction (-1) } := by
  decide +kernel

theorem kernel_ordered_duplicates :
    payload (appendPacket [signature, signature, transaction]) = [signature, signature, transaction] /\
    header (appendPacket [signature, signature, transaction]) =
      header (appendPacket [signature, transaction, signature]) /\
    payloadLength (appendPacket [signature, signature, transaction]) =
      payloadLength (appendPacket [signature, transaction, signature]) /\
    PayloadMismatch (appendPacket [signature, signature, transaction])
      (appendPacket [signature, transaction, signature]) := by
  refine And.intro (by decide +kernel) (And.intro (by decide +kernel)
    (And.intro (by decide +kernel) (Exists.intro 1 ?_)))
  decide +kernel

theorem kernel_duplicate_multiplicity :
    Not (decodeMessage (appendPacket [signature, signature]) =
      decodeMessage (appendPacket [signature])) := by
  decide +kernel

theorem kernel_complete_entry_term :
    PayloadMismatch (appendPacket [{ term := -1, content := .signature }])
      (appendPacket [{ term := 0, content := .signature }]) := by
  exact Exists.intro 0 (by decide +kernel)

theorem arbitrary_configuration_masks (left right : BitVec NODE_COUNT) :
    decodeMessage (appendPacket [{ term := -1, content := .reconfiguration left }]) =
      decodeMessage (appendPacket [{ term := -1, content := .reconfiguration right }]) <->
        left = right := by
  rw [message_eq_iff, raw_eq_iff_parts, append_payload, append_payload]
  simp [header, appendPacket]

theorem configuration_retired_distinct (left right : BitVec NODE_COUNT) :
    Not (decodeMessage (appendPacket [{ term := -1, content := .reconfiguration left }]) =
      decodeMessage (appendPacket [{ term := -1, content := .retiredCommitted right }])) := by
  rw [message_eq_iff, raw_eq_iff_parts, append_payload, append_payload]
  simp

theorem kernel_all_content_forms :
    payload (appendPacket [transaction, signature,
      { term := -1, content := .reconfiguration 0 },
      { term := -1, content := .retiredCommitted 32767 }]) =
      [transaction, signature, { term := -1, content := .reconfiguration 0 },
        { term := -1, content := .retiredCommitted 32767 }] := by
  decide +kernel

def aliasKeys : Fin 3 -> Int := ![7, 7, -4]
def aliasPackets : Fin 3 -> RawMessage :=
  ![appendPacket [], appendPacket [], appendPacket [signature]]

theorem kernel_alias_facts : IdentityFacts aliasKeys aliasPackets := by
  apply (identity_facts_iff _ _).mpr
  decide +kernel

theorem kernel_alias_injection :
    Function.Injective (classPacket aliasKeys aliasPackets kernel_alias_facts) :=
  classPacket_injective _ _ kernel_alias_facts

theorem forward_only_allows_split :
    (forall left right : Fin 2, (left.val : Int) = (right.val : Int) ->
      Same (appendPacket []) (appendPacket [])) /\
    Not (IdentityFacts (fun index : Fin 2 => (index.val : Int)) (fun _ => appendPacket [])) := by
  refine And.intro (fun _ _ _ => (raw_eq_iff _ _).mp rfl) ?_
  intro facts
  have invalid := (key_eq_iff _ _ facts 0 1).mpr rfl
  exact (by decide +kernel : Not (((0 : Fin 2).val : Int) = ((1 : Fin 2).val : Int))) invalid

theorem equal_keys_cannot_merge_payloads :
    Not (IdentityFacts (fun _ : Fin 2 => (0 : Int))
      ![appendPacket [], appendPacket [signature]]) := by
  intro facts
  have invalid := (key_eq_iff _ _ facts 0 1).mp rfl
  exact (by decide +kernel :
    Not (decodeMessage (appendPacket []) = decodeMessage (appendPacket [signature]))) invalid

theorem no_occurrences :
    IdentityFacts (fun _ : Fin 0 => (0 : Int)) (fun _ => appendPacket []) := by
  apply (identity_facts_iff _ _).mpr
  intro left
  exact Fin.elim0 left

end Regression

end CCFRaft.Sparse.PacketIdentity

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.PacketIdentity).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit packet identity axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  if checked = 0 then
    throwError "no packet identity declarations audited"
  Lean.logInfo m!"PacketIdentity: {checked} declarations passed the allowed-axiom gate."
