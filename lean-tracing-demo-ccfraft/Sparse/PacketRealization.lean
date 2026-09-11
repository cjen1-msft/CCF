import Sparse.PacketIdentity
import Sparse.IntervalReadback

set_option autoImplicit false

namespace CCFRaft.Sparse.PacketRealization

open MessageCodec (RawMessage decodeMessage)
open PacketIdentity (Header header payload payloadLength)
open IntervalReadback (Address Reads)

variable {roots size count : Nat}

structure Descriptor (roots size : Nat) where
  header : Header
  payloadLength : Nat
  address : Option (Address roots size)

def origin : Header -> Nat
  | .appendEntriesRequest request => BijectiveIntegerLog.decodeNat request.prevLogIndex
  | _ => 0

def LengthAllowed : Header -> Nat -> Prop
  | .appendEntriesRequest _, _ => True
  | _, length => length = 0

def Valid (descriptor : Descriptor roots size) : Prop :=
  LengthAllowed descriptor.header descriptor.payloadLength /\
    (descriptor.address = none -> descriptor.payloadLength = 0)

def entryAt (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size) (index : Nat) : Option EntryValue.Entry :=
  descriptor.address.map (fun address => reads address (origin descriptor.header + index))

def Realizes (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size) (message : RawMessage) : Prop :=
  header message = descriptor.header /\ payloadLength message = descriptor.payloadLength /\
    (forall index, index < descriptor.payloadLength -> (payload message)[index]? = entryAt reads descriptor index)

theorem header_length_allowed (message : RawMessage) :
    LengthAllowed (header message) (payloadLength message) := by
  cases message <;> simp [LengthAllowed, header, payloadLength, PacketIdentity.rawEntries]

theorem realizes_valid (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size)
    (message : RawMessage) (realized : Realizes reads descriptor message) : Valid descriptor := by
  refine And.intro ?_ ?_
  next =>
    rw [<- realized.1, <- realized.2.1]
    exact header_length_allowed message
  next =>
    intro missing
    by_contra nonempty
    have bound : 0 < descriptor.payloadLength := Nat.pos_of_ne_zero nonempty
    have first := realized.2.2 0 bound
    have live : 0 < (payload message).length := by
      rw [PacketIdentity.payload_length, realized.2.1]
      exact bound
    rw [List.getElem?_eq_getElem live] at first
    simp [entryAt, missing] at first

-- Finite lists are constructed only inside existence proofs.
theorem header_payload_exists (packetHeader : Header) (entries : List EntryValue.Entry)
    (allowed : LengthAllowed packetHeader entries.length) :
    exists message : RawMessage, header message = packetHeader /\ payload message = entries := by
  cases packetHeader with
  | appendEntriesRequest request =>
    refine Exists.intro (.appendEntriesRequest
      (.mk request.term request.prevLogIndex request.prevLogTerm (entries.map EntryValue.toRawEntry)
        request.leaderCommit request.source request.destination)) (And.intro ?_ ?_)
    next => cases request; rfl
    next => simp [payload, PacketIdentity.rawEntries, List.map_map, Function.comp_def]
  | appendEntriesResponse response =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.appendEntriesResponse response) (And.intro rfl empty.symm)
  | requestVoteRequest request =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.requestVoteRequest request) (And.intro rfl empty.symm)
  | requestVoteResponse response =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.requestVoteResponse response) (And.intro rfl empty.symm)
  | requestPreVote request =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.requestPreVote request) (And.intro rfl empty.symm)
  | requestPreVoteResponse response =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.requestPreVoteResponse response) (And.intro rfl empty.symm)
  | proposeVoteRequest request =>
    have empty := List.length_eq_zero_iff.mp allowed
    exact Exists.intro (.proposeVoteRequest request) (And.intro rfl empty.symm)

theorem valid_iff (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size) :
    Valid descriptor <-> exists message : RawMessage, Realizes reads descriptor message := by
  constructor
  next =>
    intro valid
    have present (index : Fin descriptor.payloadLength) : descriptor.address.isSome := by
      cases address_eq : descriptor.address with
      | none =>
        have empty := valid.2 address_eq
        have bound := index.isLt
        omega
      | some address => rfl
    let values : Fin descriptor.payloadLength -> EntryValue.Entry :=
      fun index => reads (descriptor.address.get (present index)) (origin descriptor.header + index.val)
    let entries := List.ofFn values
    have length_eq : entries.length = descriptor.payloadLength := List.length_ofFn
    cases header_payload_exists descriptor.header entries (by rw [length_eq]; exact valid.1) with
    | intro message parts =>
      refine Exists.intro message (And.intro parts.1 (And.intro ?_ ?_))
      next => rw [<- PacketIdentity.payload_length, parts.2, length_eq]
      next =>
        intro index bound
        rw [parts.2, List.getElem?_eq_getElem (by simpa only [length_eq] using bound)]
        simp only [entries, List.getElem_ofFn]
        cases address_eq : descriptor.address with
        | none => have empty := valid.2 address_eq; omega
        | some address => simp [values, entryAt, address_eq]
  next =>
    intro witness
    cases witness with
    | intro message realized => exact realizes_valid reads descriptor message realized

def FamilyRealizes (reads : Reads roots size EntryValue.Entry) (descriptors : Fin count -> Descriptor roots size)
    (messages : Fin count -> RawMessage) : Prop :=
  forall index, Realizes reads (descriptors index) (messages index)

theorem family_valid_iff (reads : Reads roots size EntryValue.Entry) (descriptors : Fin count -> Descriptor roots size) :
    (forall index, Valid (descriptors index)) <->
      exists messages : Fin count -> RawMessage, FamilyRealizes reads descriptors messages := by
  constructor
  next =>
    intro valid
    have witnesses := fun index => (valid_iff reads (descriptors index)).mp (valid index)
    exact Exists.intro (fun index => Classical.choose (witnesses index))
      (fun index => Classical.choose_spec (witnesses index))
  next =>
    intro witness
    cases witness with
    | intro messages realized => exact fun index => realizes_valid reads _ _ (realized index)

def Same (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size) : Prop :=
  left.header = right.header /\ left.payloadLength = right.payloadLength /\
    (forall index, index < left.payloadLength -> index < right.payloadLength ->
      entryAt reads left index = entryAt reads right index)

def PayloadMismatch (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size) : Prop :=
  exists index, index < left.payloadLength /\ index < right.payloadLength /\
    Not (entryAt reads left index = entryAt reads right index)

def Different (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size) : Prop :=
  Not (left.header = right.header) \/ Not (left.payloadLength = right.payloadLength) \/
    PayloadMismatch reads left right

theorem realized_eq_iff (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size)
    (leftMessage rightMessage : RawMessage)
    (left_realized : Realizes reads left leftMessage) (right_realized : Realizes reads right rightMessage) :
    leftMessage = rightMessage <-> Same reads left right := by
  rw [PacketIdentity.raw_eq_iff]
  simp only [PacketIdentity.Same, Same, left_realized.1, right_realized.1,
    left_realized.2.1, right_realized.2.1]
  apply and_congr Iff.rfl (and_congr Iff.rfl ?_)
  apply forall_congr'
  intro index
  apply forall_congr'
  intro left_bound
  apply forall_congr'
  intro right_bound
  rw [left_realized.2.2 index left_bound, right_realized.2.2 index right_bound]

theorem realized_ne_iff (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size)
    (leftMessage rightMessage : RawMessage)
    (left_realized : Realizes reads left leftMessage) (right_realized : Realizes reads right rightMessage) :
    Not (leftMessage = rightMessage) <-> Different reads left right := by
  rw [PacketIdentity.raw_ne_iff]
  simp only [PacketIdentity.Different, PacketIdentity.PayloadMismatch, Different, PayloadMismatch,
    left_realized.1, right_realized.1, left_realized.2.1, right_realized.2.1]
  apply or_congr Iff.rfl (or_congr Iff.rfl ?_)
  apply exists_congr
  intro index
  constructor
  next =>
    intro mismatch
    refine And.intro mismatch.1 (And.intro mismatch.2.1 ?_)
    simpa only [left_realized.2.2 index mismatch.1, right_realized.2.2 index mismatch.2.1] using mismatch.2.2
  next =>
    intro mismatch
    refine And.intro mismatch.1 (And.intro mismatch.2.1 ?_)
    simpa only [left_realized.2.2 index mismatch.1, right_realized.2.2 index mismatch.2.1] using mismatch.2.2

theorem decoded_eq_iff (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size)
    (leftMessage rightMessage : RawMessage)
    (left_realized : Realizes reads left leftMessage) (right_realized : Realizes reads right rightMessage) :
    decodeMessage leftMessage = decodeMessage rightMessage <-> Same reads left right := by
  rw [MessageCodec.message_eq_iff]
  exact realized_eq_iff reads left right leftMessage rightMessage left_realized right_realized

theorem decoded_ne_iff (reads : Reads roots size EntryValue.Entry) (left right : Descriptor roots size)
    (leftMessage rightMessage : RawMessage)
    (left_realized : Realizes reads left leftMessage) (right_realized : Realizes reads right rightMessage) :
    Not (decodeMessage leftMessage = decodeMessage rightMessage) <-> Different reads left right := by
  rw [MessageCodec.message_ne_iff]
  exact realized_ne_iff reads left right leftMessage rightMessage left_realized right_realized

theorem realization_unique (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size)
    (left right : RawMessage) (left_realized : Realizes reads descriptor left)
    (right_realized : Realizes reads descriptor right) : left = right :=
  (realized_eq_iff reads descriptor descriptor left right left_realized right_realized).mpr
    (And.intro rfl (And.intro rfl (fun _ _ _ => rfl)))

theorem family_unique (reads : Reads roots size EntryValue.Entry) (descriptors : Fin count -> Descriptor roots size)
    (left right : Fin count -> RawMessage) (left_realized : FamilyRealizes reads descriptors left)
    (right_realized : FamilyRealizes reads descriptors right) : left = right :=
  funext (fun index => realization_unique reads _ _ _ (left_realized index) (right_realized index))

theorem entry_at (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size)
    (message : RawMessage) (realized : Realizes reads descriptor message)
    (address : Address roots size) (present : descriptor.address = some address)
    (index : Nat) (bound : index < descriptor.payloadLength) :
    (payload message)[index]? = some (reads address (origin descriptor.header + index)) := by
  simpa only [entryAt, present, Option.map_some] using realized.2.2 index bound

theorem decoded_entry_at (reads : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size)
    (message : RawMessage) (realized : Realizes reads descriptor message)
    (address : Address roots size) (present : descriptor.address = some address)
    (index : Nat) (bound : index < descriptor.payloadLength) :
    (PacketIdentity.modelEntries (decodeMessage message))[index]? =
      some (EntryValue.decodeEntry (reads address (origin descriptor.header + index))) := by
  rw [<- PacketIdentity.decode_payload, List.getElem?_map, entry_at reads descriptor message realized address present index bound]
  rfl

theorem realizes_congr (left right : Reads roots size EntryValue.Entry) (descriptor : Descriptor roots size)
    (agree : forall index, index < descriptor.payloadLength -> entryAt left descriptor index = entryAt right descriptor index)
    (message : RawMessage) : Realizes left descriptor message <-> Realizes right descriptor message := by
  unfold Realizes
  apply and_congr Iff.rfl (and_congr Iff.rfl ?_)
  apply forall_congr'
  intro index
  apply forall_congr'
  intro bound
  rw [agree index bound]

namespace Regression

local instance : NeZero NODE_COUNT := { out := by decide }

def appendHeader : Header :=
  .appendEntriesRequest (.mk (-1) (-1) (-1) (-1) 0 1)

def description (address : Address 1 1) : Descriptor 1 1 :=
  { header := appendHeader, payloadLength := 3, address := some address }

def reads : Reads 1 1 EntryValue.Entry
  | .root _, position =>
    if position = 3 then PacketIdentity.Regression.transaction else PacketIdentity.Regression.signature
  | .version _, position =>
    if position = 3 \/ position = 4 then PacketIdentity.Regression.transaction else PacketIdentity.Regression.signature

def emptyReads : Reads 0 0 EntryValue.Entry
  | .root root => Fin.elim0 root
  | .version version => Fin.elim0 version

theorem signed_origin : origin appendHeader = 1 := by
  decide +kernel

theorem ordered_duplicates :
    Realizes reads (description (.root 0))
      (PacketIdentity.Regression.appendPacket
        [PacketIdentity.Regression.signature, PacketIdentity.Regression.signature, PacketIdentity.Regression.transaction]) := by
  refine And.intro rfl (And.intro (by decide +kernel) ?_)
  intro index bound
  change index < 3 at bound
  have cases : index = 0 \/ index = 1 \/ index = 2 := by omega
  rcases cases with same | same | same <;> subst index <;> decide +kernel

theorem unequal_tails_equal_packets :
    Not (reads (.root 0) 4 = reads (.version 0) 4) /\
      Same reads (description (.root 0)) (description (.version 0)) := by
  refine And.intro (by decide +kernel) (And.intro rfl (And.intro rfl ?_))
  intro index bound _
  change index < 3 at bound
  have cases : index = 0 \/ index = 1 \/ index = 2 := by omega
  rcases cases with same | same | same <;> subst index <;> decide +kernel

theorem one_shared_family :
    exists messages : Fin 2 -> RawMessage,
      FamilyRealizes reads
        (fun index => if index = 0 then description (.root 0) else description (.version 0)) messages /\
        messages 0 = messages 1 := by
  have valid : forall index : Fin 2,
      Valid (if index = 0 then description (.root 0) else description (.version 0)) := by
    intro index
    split <;> simp [Valid, description, appendHeader, LengthAllowed]
  cases (family_valid_iff reads _).mp valid with
  | intro messages realized =>
    refine Exists.intro messages (And.intro realized ?_)
    exact (realized_eq_iff reads _ _ _ _ (realized 0) (realized 1)).mpr unequal_tails_equal_packets.2

theorem arbitrary_complete_entry (entry : EntryValue.Entry) :
    Realizes (fun _ _ => entry)
      ({ header := appendHeader, payloadLength := 1, address := some (.root 0) } : Descriptor 1 0)
      (PacketIdentity.Regression.appendPacket [entry]) := by
  refine And.intro rfl (And.intro ?_ ?_)
  next => simp [payloadLength, PacketIdentity.rawEntries, PacketIdentity.Regression.appendPacket]
  next =>
    intro index bound
    have zero : index = 0 := by change index < 1 at bound; omega
    subst index
    simp [PacketIdentity.Regression.append_payload, entryAt]

theorem seven_tags_without_arrays (message : RawMessage)
    (member : Membership.mem PacketIdentity.Regression.tags message) :
    Realizes emptyReads ({ header := header message, payloadLength := 0, address := none } : Descriptor 0 0) message := by
  refine And.intro rfl (And.intro ?_ ?_)
  next =>
    have empty := List.all_eq_true.mp PacketIdentity.Regression.kernel_seven_empty_tags.2.2 message member
    simpa using empty
  next => intro index bound; exact False.elim (Nat.not_lt_zero index bound)

theorem nonappend_nonzero_impossible :
    Not (exists message : RawMessage,
      Realizes reads
        { header := .requestVoteResponse (.mk (-1) true 0 1), payloadLength := 1, address := some (.root 0) }
        message) := by
  rw [<- valid_iff]
  simp [Valid, LengthAllowed]

theorem missing_live_address_impossible :
    Not (exists message : RawMessage,
      Realizes emptyReads { header := appendHeader, payloadLength := 1, address := none } message) := by
  rw [<- valid_iff]
  simp [Valid]

theorem empty_family :
    exists messages : Fin 0 -> RawMessage,
      FamilyRealizes emptyReads (fun index => Fin.elim0 index) messages := by
  apply (family_valid_iff emptyReads _).mp
  exact fun index => Fin.elim0 index

end Regression

end CCFRaft.Sparse.PacketRealization

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.PacketRealization).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.PacketRealization: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.PacketRealization.valid_iff
#print axioms CCFRaft.Sparse.PacketRealization.family_valid_iff
#print axioms CCFRaft.Sparse.PacketRealization.realized_eq_iff
#print axioms CCFRaft.Sparse.PacketRealization.realized_ne_iff
