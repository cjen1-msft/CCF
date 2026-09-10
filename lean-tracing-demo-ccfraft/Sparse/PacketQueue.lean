import Sparse.MessageCodec
import Sparse.QueueClause

set_option autoImplicit false

namespace CCFRaft.Sparse.PacketQueue

open Sparse.MessageCodec
open Sparse.QueueCounts (PacketFrom fresh_source_packet)
open Sparse.QueueStream (Event concreteFollows)
open Sparse.CountedQueue (Uses)
open Sparse.IntegerQueue (RawInitialFacts)
open Sparse.QueueClause (Heap Holds compile)

abbrev RawPacketFrom (source : Node) :=
  { message : RawMessage // message.source = source }

def packetEquiv (source : Node) : Equiv (RawPacketFrom source) (PacketFrom source) where
  toFun packet := Subtype.mk (decodeMessage packet.val)
    ((decode_source packet.val).trans packet.property)
  invFun packet := Subtype.mk (encodeMessage packet.val)
    ((encode_source packet.val).trans packet.property)
  left_inv packet := Subtype.ext (encode_decode_message packet.val)
  right_inv packet := Subtype.ext (decode_encode_message packet.val)

@[simp] theorem packet_value (source : Node) (packet : RawPacketFrom source) :
    (packetEquiv source packet).val = decodeMessage packet.val := rfl

theorem packet_eq_iff (source : Node) (a b : RawPacketFrom source) :
    packetEquiv source a = packetEquiv source b <-> a = b :=
  (packetEquiv source).injective.eq_iff

theorem packet_ne_iff (source : Node) (a b : RawPacketFrom source) :
    Not (packetEquiv source a = packetEquiv source b) <-> Not (a = b) :=
  not_congr (packet_eq_iff source a b)

section Transport

variable {A B : Type}

def mapEvent (equiv : Equiv A B) : Event A -> Event B
  | .send message => .send (equiv message)
  | .pop message => .pop (equiv message)
  | .peek message => .peek (equiv message)
  | .length length => .length length

def mapTrace (equiv : Equiv A B) (trace : List (Event A)) : List (Event B) :=
  trace.map (mapEvent equiv)

@[simp] theorem mapEvent_inverse (equiv : Equiv A B) (event : Event A) :
    mapEvent equiv.symm (mapEvent equiv event) = event := by
  cases event <;> simp [mapEvent]

@[simp] theorem mapTrace_inverse (equiv : Equiv A B) (trace : List (Event A)) :
    mapTrace equiv.symm (mapTrace equiv trace) = trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    simpa [mapTrace] using congrArg (List.cons event) ih

theorem list_roundtrip (equiv : Equiv A B) (queue : List A) :
    (queue.map equiv).map equiv.symm = queue := by
  simp [List.map_map, Function.comp_def]

theorem map_mem_iff (equiv : Equiv A B) (queue : List A) (message : A) :
    Membership.mem (queue.map equiv) (equiv message) <->
      Membership.mem queue message := by
  simp [List.mem_map, equiv.injective.eq_iff]

theorem map_head_iff (equiv : Equiv A B) (queue : List A) (message : A) :
    (queue.map equiv).head? = some (equiv message) <-> queue.head? = some message := by
  cases queue <;> simp [equiv.injective.eq_iff]

variable [DecidableEq A] [DecidableEq B]

theorem concreteFollows_map (equiv : Equiv A B) (queue : List A)
    (trace : List (Event A)) :
    concreteFollows (queue.map equiv) (mapTrace equiv trace) <->
      concreteFollows queue trace := by
  induction trace generalizing queue with
  | nil => rfl
  | cons event rest ih =>
    cases event with
    | send message =>
      by_cases present : Membership.mem queue message
      next =>
        have mapped := (map_mem_iff equiv queue message).mpr present
        simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
          present, mapped, if_true] using ih queue
      next =>
        have absent : Not (Membership.mem (queue.map equiv) (equiv message)) :=
          fun h => present ((map_mem_iff equiv queue message).mp h)
        simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
          present, absent, if_false, List.map_append, List.map_nil] using
          ih (queue ++ [message])
    | pop message =>
      have tails : (queue.map equiv).tail = queue.tail.map equiv := by
        cases queue <;> rfl
      simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
        tails] using and_congr (map_head_iff equiv queue message) (ih queue.tail)
    | peek message =>
      exact and_congr (map_head_iff equiv queue message) (ih queue)
    | length length =>
      simpa only [mapTrace, List.map_cons, mapEvent, concreteFollows,
        List.length_map] using and_congr (Iff.rfl : queue.length = length <->
          queue.length = length) (ih queue)

theorem concrete_exists_map_iff (equiv : Equiv A B) (length : Int)
    (trace : List (Event A)) :
    (exists queue : List A, (queue.length : Int) = length /\ concreteFollows queue trace) <->
    (exists queue : List B, (queue.length : Int) = length /\
      concreteFollows queue (mapTrace equiv trace)) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      exact Exists.intro (queue.map equiv)
        (And.intro (by simpa using spec.1)
          ((concreteFollows_map equiv queue trace).mpr spec.2))
  next =>
    intro witness
    cases witness with
    | intro queue spec =>
      refine Exists.intro (queue.map equiv.symm) (And.intro (by simpa using spec.1) ?_)
      apply (concreteFollows_map equiv (queue.map equiv.symm) trace).mp
      simpa [List.map_map, Function.comp_def] using spec.2

def mapKeys (equiv : Equiv A B) (keys : Finset A) : Finset B :=
  keys.map equiv.toEmbedding

omit [DecidableEq A] [DecidableEq B] in
@[simp] theorem mapKeys_mem_iff (equiv : Equiv A B) (keys : Finset A) (message : A) :
    Membership.mem (mapKeys equiv keys) (equiv message) <->
      Membership.mem keys message := by
  simp [mapKeys]

omit [DecidableEq A] [DecidableEq B] in
theorem uses_map_iff (equiv : Equiv A B) (keys : Finset A) (trace : List (Event A)) :
    Uses (mapKeys equiv keys) (mapTrace equiv trace) <-> Uses keys trace := by
  induction trace with
  | nil => rfl
  | cons event rest ih =>
    cases event <;> simpa only [mapTrace, List.map_cons, mapEvent, Uses,
      mapKeys_mem_iff] using (by first | exact and_congr Iff.rfl ih | exact ih)

end Transport

def decodeKeys (source : Node) (keys : Finset (RawPacketFrom source)) :
    Finset (PacketFrom source) :=
  mapKeys (packetEquiv source) keys

def decodeTrace (source : Node) (trace : List (Event (RawPacketFrom source))) :
    List (Event (PacketFrom source)) :=
  mapTrace (packetEquiv source) trace

theorem fresh_raw_packet (source : Node) (keys : Finset (RawPacketFrom source)) :
    exists filler : RawPacketFrom source, Not (Membership.mem keys filler) := by
  cases fresh_source_packet source source (decodeKeys source keys) with
  | intro filler fresh =>
    refine Exists.intro ((packetEquiv source).symm filler) ?_
    intro present
    apply fresh
    have member := (mapKeys_mem_iff (packetEquiv source) keys
      ((packetEquiv source).symm filler)).mpr present
    simpa only [Equiv.apply_symm_apply] using member

theorem decoded_uses_iff (source : Node) (keys : Finset (RawPacketFrom source))
    (trace : List (Event (RawPacketFrom source))) :
    Uses (decodeKeys source keys) (decodeTrace source trace) <-> Uses keys trace :=
  uses_map_iff (packetEquiv source) keys trace

-- One order array and one heap describe one execution from one whole queue.
theorem compiled_exists_iff (source : Node) (keys : Finset (RawPacketFrom source))
    (length : Int) (trace : List (Event (RawPacketFrom source))) (uses : Uses keys trace) :
    (0 <= length /\
      exists order : Int -> RawPacketFrom source,
      exists heap : Heap (RawPacketFrom source),
        (heap 0).window = { head := 0, tail := length } /\
        RawInitialFacts keys (heap 0).counts length.toNat trace /\
        Holds order heap (compile 0 1 trace)) <->
    (exists queue : List (PacketFrom source), (queue.length : Int) = length /\
      concreteFollows queue (decodeTrace source trace)) := by
  cases fresh_raw_packet source keys with
  | intro filler fresh =>
    have bridge (nonnegative : 0 <= length) :=
      (Sparse.QueueClause.compiled_exists_iff keys length nonnegative trace
        uses filler fresh).trans (concrete_exists_map_iff (packetEquiv source) length trace)
    constructor
    next =>
      intro spec
      exact (bridge spec.1).mp spec.2
    next =>
      intro witness
      have nonnegative : 0 <= length := by
        cases witness with
        | intro queue spec => omega
      exact And.intro nonnegative ((bridge nonnegative).mpr witness)

end CCFRaft.Sparse.PacketQueue

run_cmd do
  let mut checked := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.PacketQueue).isPrefixOf name then
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
      checked := checked + 1
  Lean.logInfo m!"Sparse packet queue audit passed: {checked} declarations."
