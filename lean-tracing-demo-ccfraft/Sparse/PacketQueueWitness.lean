import Sparse.PacketRealization
import Sparse.PacketQueue
import Sparse.FiniteQueueTransport
import Sparse.QueueTraceEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.PacketQueueWitness

open QueueStream (Event concreteFollows)
open FiniteQueueTransport (mapTrace)
open PacketQueue (RawPacketFrom)

variable {count roots size : Nat}

section FiniteImage

variable {A B C : Type}

def support [DecidableEq A] (values : Fin count -> A) : Finset A :=
  Finset.univ.image values

theorem support_member [DecidableEq A] (values : Fin count -> A) (index : Fin count) :
    Membership.mem (support values) (values index) :=
  Finset.mem_image.mpr (Exists.intro index (And.intro (Finset.mem_univ index) rfl))

theorem support_equiv_exists [DecidableEq A] [DecidableEq B]
    (left : Fin count -> A) (right : Fin count -> B)
    (fibers : forall i j, left i = left j <-> right i = right j) :
    exists equiv : Equiv { value : A // Membership.mem (support left) value }
        { value : B // Membership.mem (support right) value },
      forall index, (equiv (Subtype.mk (left index) (support_member left index))).val = right index := by
  classical
  have preimage (value : { value : A // Membership.mem (support left) value }) :
      exists index, left index = value.val := by
    cases Finset.mem_image.mp value.property with
    | intro index spec => exact Exists.intro index spec.2
  let representative := fun value => Classical.choose (preimage value)
  have representative_value := fun value => Classical.choose_spec (preimage value)
  let forward : { value : A // Membership.mem (support left) value } ->
      { value : B // Membership.mem (support right) value } :=
    fun value => Subtype.mk (right (representative value)) (support_member right _)
  have on_occurrence (index : Fin count) :
      (forward (Subtype.mk (left index) (support_member left index))).val = right index :=
    (fibers _ index).mp (representative_value _)
  have bijective : Function.Bijective forward := by
    constructor
    next =>
      intro first second same
      apply Subtype.ext
      rw [<- representative_value first, <- representative_value second]
      exact (fibers _ _).mpr (congrArg Subtype.val same)
    next =>
      intro value
      cases Finset.mem_image.mp value.property with
      | intro index spec =>
        exact Exists.intro (Subtype.mk (left index) (support_member left index))
          (Subtype.ext ((on_occurrence index).trans spec.2))
  exact Exists.intro (Equiv.ofBijective forward bijective) on_occurrence

theorem trace_uses_support [DecidableEq A] (values : Fin count -> A) (trace : List (Event (Fin count))) :
    CountedQueue.Uses (support values) (mapTrace values trace) := by
  induction trace with
  | nil => trivial
  | cons event rest ih =>
    cases event with
    | send index | pop index | peek index => exact And.intro (support_member values index) ih
    | length length => exact ih

theorem mapTrace_comp_on (first : A -> B) (second : B -> C) (direct : A -> C)
    (agree : forall value, second (first value) = direct value) (trace : List (Event A)) :
    mapTrace second (mapTrace first trace) = mapTrace direct trace := by
  simp only [mapTrace, List.map_map]
  apply congrArg (fun f => trace.map f)
  funext event
  cases event <;> simp [FiniteQueueTransport.mapEvent, agree]

end FiniteImage

theorem queue_exists_iff (source : Node) (keys : Fin count -> Int) (packets : Fin count -> RawPacketFrom source)
    (fibers : forall i j, keys i = keys j <-> packets i = packets j)
    (length : Int) (trace : List (Event (Fin count))) :
    (exists queue : List Int, (queue.length : Int) = length /\ concreteFollows queue (mapTrace keys trace)) <->
    (exists queue : List (RawPacketFrom source), (queue.length : Int) = length /\
      concreteFollows queue (mapTrace packets trace)) := by
  cases support_equiv_exists keys packets fibers with
  | intro equiv on_occurrence =>
    cases PacketQueue.fresh_raw_packet source (support packets) with
    | intro filler fresh =>
      have mapped :
          mapTrace (FiniteQueueTransport.supportMap (support keys) (support packets) equiv filler)
            (mapTrace keys trace) = mapTrace packets trace := by
        apply mapTrace_comp_on
        intro index
        rw [FiniteQueueTransport.support_map_tracked _ _ equiv filler _ (support_member keys index)]
        exact on_occurrence index
      have bridge := FiniteQueueTransport.concrete_exists_support_iff
        (support keys) (support packets) equiv
        (QueueTraceEncoding.freshFiller (support keys)) (QueueTraceEncoding.filler_fresh _)
        filler fresh length (mapTrace keys trace) (trace_uses_support keys trace)
      simpa only [mapped] using bridge

theorem fibers_iff_identity (source : Node) (keys : Fin count -> Int) (packets : Fin count -> RawPacketFrom source) :
    (forall i j, keys i = keys j <-> packets i = packets j) <->
      PacketIdentity.IdentityFacts keys (fun index => (packets index).val) := by
  rw [PacketIdentity.identity_facts_iff]
  apply forall_congr'
  intro i
  apply forall_congr'
  intro j
  rw [MessageCodec.message_eq_iff, Subtype.ext_iff]

theorem identity_queue_exists_iff (source : Node) (keys : Fin count -> Int)
    (packets : Fin count -> RawPacketFrom source)
    (identity : PacketIdentity.IdentityFacts keys (fun index => (packets index).val))
    (length : Int) (trace : List (Event (Fin count))) :
    (exists queue : List Int, (queue.length : Int) = length /\ concreteFollows queue (mapTrace keys trace)) <->
    (exists queue : List (RawPacketFrom source), (queue.length : Int) = length /\
      concreteFollows queue (mapTrace packets trace)) :=
  queue_exists_iff source keys packets ((fibers_iff_identity source keys packets).mpr identity) length trace

def headerSource : PacketIdentity.Header -> Node
  | .appendEntriesRequest request => request.source
  | .appendEntriesResponse response => response.source
  | .requestVoteRequest request => request.source
  | .requestVoteResponse response => response.source
  | .requestPreVote request => request.source
  | .requestPreVoteResponse response => response.source
  | .proposeVoteRequest request => request.source

theorem header_source (message : MessageCodec.RawMessage) :
    headerSource (PacketIdentity.header message) = message.source := by
  cases message <;> rfl

theorem realized_fibers (source : Node) (keys : Fin count -> Int)
    (reads : IntervalReadback.Reads roots size EntryValue.Entry)
    (descriptors : Fin count -> PacketRealization.Descriptor roots size)
    (packets : Fin count -> RawPacketFrom source)
    (realized : PacketRealization.FamilyRealizes reads descriptors (fun index => (packets index).val))
    (identity : forall i j, keys i = keys j <-> PacketRealization.Same reads (descriptors i) (descriptors j)) :
    forall i j, keys i = keys j <-> packets i = packets j := by
  intro i j
  rw [identity i j, Subtype.ext_iff]
  exact (PacketRealization.realized_eq_iff reads _ _ _ _ (realized i) (realized j)).symm

theorem realized_queue_exists_iff (source : Node) (keys : Fin count -> Int)
    (reads : IntervalReadback.Reads roots size EntryValue.Entry)
    (descriptors : Fin count -> PacketRealization.Descriptor roots size)
    (valid : forall index, PacketRealization.Valid (descriptors index))
    (sources : forall index, headerSource (descriptors index).header = source)
    (identity : forall i j, keys i = keys j <-> PacketRealization.Same reads (descriptors i) (descriptors j))
    (length : Int) (trace : List (Event (Fin count))) :
    (exists queue : List Int, (queue.length : Int) = length /\ concreteFollows queue (mapTrace keys trace)) <->
    (exists packets : Fin count -> RawPacketFrom source,
      PacketRealization.FamilyRealizes reads descriptors (fun index => (packets index).val) /\
      exists queue : List (RawPacketFrom source), (queue.length : Int) = length /\
        concreteFollows queue (mapTrace packets trace)) := by
  constructor
  next =>
    intro witness
    cases (PacketRealization.family_valid_iff reads descriptors).mp valid with
    | intro messages realized =>
      have packet_sources (index : Fin count) : (messages index).source = source := by
        rw [<- header_source, (realized index).1]
        exact sources index
      let packets : Fin count -> RawPacketFrom source := fun index => Subtype.mk (messages index) (packet_sources index)
      exact Exists.intro packets (And.intro realized
        ((queue_exists_iff source keys packets (realized_fibers source keys reads descriptors packets realized identity)
          length trace).mp witness))
  next =>
    intro witness
    cases witness with
    | intro packets spec =>
      exact (queue_exists_iff source keys packets
        (realized_fibers source keys reads descriptors packets spec.1 identity) length trace).mpr spec.2

namespace Regression

local instance : NeZero NODE_COUNT := { out := by decide }

def foreignDestination : RawPacketFrom 0 :=
  Subtype.mk (.requestVoteResponse (.mk (-1) true 0 1)) rfl

def aliasKeys : Fin 2 -> Int := fun _ => -3

def aliasTrace : List (Event (Fin 2)) :=
  [.send 0, .send 1, .length 5, .peek 1, .pop 0, .length 4,
    .peek 0, .pop 1, .length 3, .send 1, .length 4]

theorem int_alias_trace :
    concreteFollows [-3, -3, 99, 100, 99] (mapTrace aliasKeys aliasTrace) := by
  simp [mapTrace, aliasKeys, aliasTrace, FiniteQueueTransport.mapEvent, concreteFollows]

theorem duplicates_outside_positions_and_foreign_destination :
    foreignDestination.val.destination = 1 /\
    exists queue : List (RawPacketFrom 0), (queue.length : Int) = 5 /\
      concreteFollows queue (mapTrace (fun _ => foreignDestination) aliasTrace) := by
  refine And.intro rfl ?_
  apply (queue_exists_iff 0 aliasKeys (fun _ => foreignDestination)
    (fun _ _ => Iff.intro (fun _ => rfl) (fun _ => rfl)) 5 aliasTrace).mp
  exact Exists.intro [-3, -3, 99, 100, 99] (And.intro rfl int_alias_trace)

theorem empty_support_arbitrary_length (source : Node) (length : Nat) :
    exists queue : List (RawPacketFrom source), (queue.length : Int) = length /\
      concreteFollows queue [.length length] := by
  have bridge := queue_exists_iff source (fun index : Fin 0 => Fin.elim0 index)
    (fun index : Fin 0 => Fin.elim0 index) (fun index => Fin.elim0 index)
    length [Event.length length]
  apply bridge.mp
  refine Exists.intro (List.replicate length (0 : Int)) (And.intro ?_ ?_)
  next => simp
  next => simp [mapTrace, FiniteQueueTransport.mapEvent, concreteFollows]

theorem different_keys_same_packet_rejected :
    Not (PacketIdentity.IdentityFacts (fun index : Fin 2 => (index.val : Int))
      (fun _ => foreignDestination.val)) := by
  intro identity
  have fibers := (fibers_iff_identity 0 (fun index : Fin 2 => (index.val : Int))
    (fun _ => foreignDestination)).mpr identity
  have impossible : (0 : Int) = 1 := (fibers 0 1).mpr rfl
  contradiction

theorem same_key_different_destinations_rejected :
    Not (forall i j : Fin 2, (0 : Int) = 0 <->
      (Subtype.mk (.requestVoteResponse (.mk (-1) true 0 (if i = 0 then 1 else 2))) rfl : RawPacketFrom 0) =
      (Subtype.mk (.requestVoteResponse (.mk (-1) true 0 (if j = 0 then 1 else 2))) rfl : RawPacketFrom 0)) := by
  intro fibers
  have different : Not
      ((Subtype.mk (.requestVoteResponse (.mk (-1) true 0 1)) rfl : RawPacketFrom 0) =
        (Subtype.mk (.requestVoteResponse (.mk (-1) true 0 2)) rfl : RawPacketFrom 0)) := by
    decide +kernel
  exact different ((fibers 0 1).mp rfl)

theorem realized_payload_family :
    exists packets : Fin 2 -> RawPacketFrom 0,
      PacketRealization.FamilyRealizes PacketRealization.Regression.reads
        (fun _ => PacketRealization.Regression.description (.root 0)) (fun index => (packets index).val) /\
      exists queue : List (RawPacketFrom 0), (queue.length : Int) = 5 /\
        concreteFollows queue (mapTrace packets aliasTrace) := by
  refine (realized_queue_exists_iff 0 aliasKeys PacketRealization.Regression.reads
    (fun _ => PacketRealization.Regression.description (.root 0)) ?_ (fun _ => rfl) ?_ 5 aliasTrace).mp ?_
  next =>
    intro index
    simp [PacketRealization.Valid, PacketRealization.Regression.description,
      PacketRealization.LengthAllowed, PacketRealization.Regression.appendHeader]
  next =>
    intro i j
    exact Iff.intro (fun _ => And.intro rfl (And.intro rfl (fun _ _ _ => rfl))) (fun _ => rfl)
  next => exact Exists.intro [-3, -3, 99, 100, 99] (And.intro rfl int_alias_trace)

end Regression

end CCFRaft.Sparse.PacketQueueWitness

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.PacketQueueWitness).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse.PacketQueueWitness: allowed-axiom gate passed for {checked} declarations."

#print axioms CCFRaft.Sparse.PacketQueueWitness.queue_exists_iff
#print axioms CCFRaft.Sparse.PacketQueueWitness.realized_queue_exists_iff
