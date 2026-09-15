-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.PacketQueueWitness
import Sparse.StateFrameEncoding

set_option autoImplicit false

/-!
Relative header and descriptor encoding with existing scalar UFs. Header Nat
projections are ordinary nonnegative Ints; PacketIdentity.Header keeps its
bijective signed codes. Payload addresses are supplied metadata, not identity.
No source-UF installer, payload enumeration, or packet/queue identity compiler.
-/

namespace CCFRaft.Sparse.PacketHeaderEncoding

open Smt (Assignment Term Symbol Ty)
open PacketIdentity (Header)
open IntervalReadback (Address Reads)
open StateFrameEncoding (conjoin)
open BijectiveIntegerLog (decodeNat encodeNat)

structure Columns where
  tag : Nat
  source : Nat
  destination : Nat
  term : Nat
  prevLogIndex : Nat
  prevLogTerm : Nat
  leaderCommit : Nat
  lastLogIndex : Nat
  lastCommittableTerm : Nat
  lastCommittableIndex : Nat
  payloadLength : Nat
  success : Nat
  voteGranted : Nat
  deriving DecidableEq

def intField (id : Nat) (key : Term .int) : Term .int := .app .int .int id key
def boolField (id : Nat) (key : Term .int) : Term .bool := .app .int .bool id key
def isTag (columns : Columns) (key : Term .int) (tag : Int) : Term .bool :=
  .equal (intField columns.tag key) (.integer tag)

private def nonnegative (id : Nat) (key : Term .int) : Term .bool :=
  .le (.integer 0) (intField id key)

private def below (id : Nat) (key : Term .int) (bound : Int) : Term .bool :=
  .not (.le (.integer bound) (intField id key))

def NodeDomain (value : Int) : Prop := 0 <= value /\ value < (NODE_COUNT : Int)

structure HeaderDomains (assignment : Assignment) (columns : Columns) (key : Term .int) : Prop where
  tag : 0 <= (intField columns.tag key).eval assignment /\
    (intField columns.tag key).eval assignment < 7
  source : NodeDomain ((intField columns.source key).eval assignment)
  destination : NodeDomain ((intField columns.destination key).eval assignment)
  term : 0 <= (intField columns.term key).eval assignment
  append : (intField columns.tag key).eval assignment = 0 ->
    0 <= (intField columns.prevLogIndex key).eval assignment /\
    0 <= (intField columns.prevLogTerm key).eval assignment /\
    0 <= (intField columns.leaderCommit key).eval assignment
  response : (intField columns.tag key).eval assignment = 1 ->
    0 <= (intField columns.lastLogIndex key).eval assignment
  vote : (intField columns.tag key).eval assignment = 2 ->
    0 <= (intField columns.lastCommittableTerm key).eval assignment /\
    0 <= (intField columns.lastCommittableIndex key).eval assignment
  preVote : (intField columns.tag key).eval assignment = 4 ->
    0 <= (intField columns.lastCommittableTerm key).eval assignment /\
    0 <= (intField columns.lastCommittableIndex key).eval assignment

def headerDomain (columns : Columns) (key : Term .int) : SmtScript.Formula :=
  [nonnegative columns.tag key, below columns.tag key 7,
   nonnegative columns.source key, below columns.source key NODE_COUNT,
   nonnegative columns.destination key, below columns.destination key NODE_COUNT,
   nonnegative columns.term key,
   .implies (isTag columns key 0) (conjoin
     [nonnegative columns.prevLogIndex key, nonnegative columns.prevLogTerm key,
      nonnegative columns.leaderCommit key]),
   .implies (isTag columns key 1) (nonnegative columns.lastLogIndex key),
   .implies (isTag columns key 2) (conjoin
     [nonnegative columns.lastCommittableTerm key, nonnegative columns.lastCommittableIndex key]),
   .implies (isTag columns key 4) (conjoin
     [nonnegative columns.lastCommittableTerm key, nonnegative columns.lastCommittableIndex key])]

theorem header_formula_correct (assignment : Assignment) (columns : Columns) (key : Term .int) :
    SmtScript.Holds assignment (headerDomain columns key) <-> HeaderDomains assignment columns key := by
  constructor
  next =>
    intro holds
    simp [SmtScript.Holds, headerDomain, nonnegative, below, isTag, conjoin, Term.eval] at holds
    constructor <;> simp_all [NodeDomain, intField] <;> tauto
  next =>
    intro valid
    cases valid
    simp_all [SmtScript.Holds, headerDomain, nonnegative, below, isTag, conjoin, Term.eval,
      NodeDomain, intField]
    tauto

def headerTag : Header -> Int
  | .appendEntriesRequest _ => 0
  | .appendEntriesResponse _ => 1
  | .requestVoteRequest _ => 2
  | .requestVoteResponse _ => 3
  | .requestPreVote _ => 4
  | .requestPreVoteResponse _ => 5
  | .proposeVoteRequest _ => 6

private def CommonRep (assignment : Assignment) (columns : Columns) (key : Term .int)
    (tag rawTerm : Int) (source destination : Node) : Prop :=
  (intField columns.tag key).eval assignment = tag /\
  (intField columns.source key).eval assignment = (source.val : Int) /\
  (intField columns.destination key).eval assignment = (destination.val : Int) /\
  (intField columns.term key).eval assignment = (decodeNat rawTerm : Int)

def HeaderRep (assignment : Assignment) (columns : Columns) (key : Term .int) : Header -> Prop
  | .appendEntriesRequest value =>
    CommonRep assignment columns key 0 value.term value.source value.destination /\
    (intField columns.prevLogIndex key).eval assignment = (decodeNat value.prevLogIndex : Int) /\
    (intField columns.prevLogTerm key).eval assignment = (decodeNat value.prevLogTerm : Int) /\
    (intField columns.leaderCommit key).eval assignment = (decodeNat value.leaderCommit : Int)
  | .appendEntriesResponse value =>
    CommonRep assignment columns key 1 value.term value.source value.destination /\
    (boolField columns.success key).eval assignment = value.success /\
    (intField columns.lastLogIndex key).eval assignment = (decodeNat value.lastLogIndex : Int)
  | .requestVoteRequest value =>
    CommonRep assignment columns key 2 value.term value.source value.destination /\
    (intField columns.lastCommittableTerm key).eval assignment = (decodeNat value.lastCommittableTerm : Int) /\
    (intField columns.lastCommittableIndex key).eval assignment = (decodeNat value.lastCommittableIndex : Int)
  | .requestVoteResponse value =>
    CommonRep assignment columns key 3 value.term value.source value.destination /\
    (boolField columns.voteGranted key).eval assignment = value.voteGranted
  | .requestPreVote value =>
    CommonRep assignment columns key 4 value.term value.source value.destination /\
    (intField columns.lastCommittableTerm key).eval assignment = (decodeNat value.lastCommittableTerm : Int) /\
    (intField columns.lastCommittableIndex key).eval assignment = (decodeNat value.lastCommittableIndex : Int)
  | .requestPreVoteResponse value =>
    CommonRep assignment columns key 5 value.term value.source value.destination /\
    (boolField columns.voteGranted key).eval assignment = value.voteGranted
  | .proposeVoteRequest value =>
    CommonRep assignment columns key 6 value.term value.source value.destination

private def nodeOf (value : Int) (valid : NodeDomain value) : Node :=
  Fin.mk value.toNat (by unfold NodeDomain at valid; omega)

private theorem node_of_value (value : Int) (valid : NodeDomain value) :
    ((nodeOf value valid).val : Int) = value :=
  Int.toNat_of_nonneg valid.1

private theorem ordinary_encode (value : Int) (valid : 0 <= value) :
    (decodeNat (encodeNat value.toNat) : Int) = value := by
  rw [BijectiveIntegerLog.decode_encode_nat, Int.toNat_of_nonneg valid]

theorem header_exists (assignment : Assignment) (columns : Columns) (key : Term .int)
    (valid : HeaderDomains assignment columns key) :
    exists header, HeaderRep assignment columns key header := by
  let source := nodeOf _ valid.source
  let destination := nodeOf _ valid.destination
  let raw := fun id => encodeNat ((intField id key).eval assignment).toNat
  have nodeSource : (source.val : Int) = (intField columns.source key).eval assignment :=
    node_of_value _ valid.source
  have nodeDestination : (destination.val : Int) = (intField columns.destination key).eval assignment :=
    node_of_value _ valid.destination
  have term : (decodeNat (raw columns.term) : Int) = (intField columns.term key).eval assignment :=
    ordinary_encode _ valid.term
  have tags : (intField columns.tag key).eval assignment = 0 \/
      (intField columns.tag key).eval assignment = 1 \/
      (intField columns.tag key).eval assignment = 2 \/
      (intField columns.tag key).eval assignment = 3 \/
      (intField columns.tag key).eval assignment = 4 \/
      (intField columns.tag key).eval assignment = 5 \/
      (intField columns.tag key).eval assignment = 6 := by
    exact (by omega : forall value : Int, 0 <= value /\ value < 7 ->
      value = 0 \/ value = 1 \/ value = 2 \/ value = 3 \/
      value = 4 \/ value = 5 \/ value = 6) _ valid.tag
  rcases tags with tag | tag | tag | tag | tag | tag | tag
  next =>
    refine Exists.intro (.appendEntriesRequest
      (.mk (raw columns.term) (raw columns.prevLogIndex) (raw columns.prevLogTerm)
        (raw columns.leaderCommit) source destination)) ?_
    have active := valid.append tag
    simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and]
    exact And.intro (ordinary_encode _ active.1).symm
      (And.intro (ordinary_encode _ active.2.1).symm (ordinary_encode _ active.2.2).symm)
  next =>
    refine Exists.intro (.appendEntriesResponse
      (.mk (raw columns.term) ((boolField columns.success key).eval assignment)
        (raw columns.lastLogIndex) source destination)) ?_
    simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and]
    exact (ordinary_encode _ (valid.response tag)).symm
  next =>
    refine Exists.intro (.requestVoteRequest
      (.mk (raw columns.term) (raw columns.lastCommittableTerm)
        (raw columns.lastCommittableIndex) source destination)) ?_
    have active := valid.vote tag
    simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and]
    exact And.intro (ordinary_encode _ active.1).symm (ordinary_encode _ active.2).symm
  next =>
    exact Exists.intro (.requestVoteResponse
      (.mk (raw columns.term) ((boolField columns.voteGranted key).eval assignment) source destination))
      (by simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and])
  next =>
    refine Exists.intro (.requestPreVote
      (.mk (raw columns.term) (raw columns.lastCommittableTerm)
        (raw columns.lastCommittableIndex) source destination)) ?_
    have active := valid.preVote tag
    simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and]
    exact And.intro (ordinary_encode _ active.1).symm (ordinary_encode _ active.2).symm
  next =>
    exact Exists.intro (.requestPreVoteResponse
      (.mk (raw columns.term) ((boolField columns.voteGranted key).eval assignment) source destination))
      (by simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and])
  next =>
    exact Exists.intro (.proposeVoteRequest (.mk (raw columns.term) source destination))
      (by simp only [HeaderRep, CommonRep, tag, nodeSource, nodeDestination, term, true_and])

theorem header_rep_domains (assignment : Assignment) (columns : Columns) (key : Term .int)
    (header : Header) (rep : HeaderRep assignment columns key header) :
    HeaderDomains assignment columns key := by
  cases header <;> rename_i value <;> cases value <;>
    simp only [HeaderRep, CommonRep] at rep <;>
    constructor <;> simp_all [NodeDomain]

theorem header_domain_iff (assignment : Assignment) (columns : Columns) (key : Term .int) :
    SmtScript.Holds assignment (headerDomain columns key) <->
      exists header, HeaderRep assignment columns key header := by
  rw [header_formula_correct]
  exact Iff.intro (header_exists assignment columns key)
    (fun witness => witness.elim (header_rep_domains assignment columns key))

private def eqInt (id : Nat) (left right : Term .int) : Term .bool :=
  .equal (intField id left) (intField id right)

private def eqBool (id : Nat) (left right : Term .int) : Term .bool :=
  .equal (boolField id left) (boolField id right)

def headerEq (columns : Columns) (left right : Term .int) : Term .bool :=
  conjoin [
    eqInt columns.tag left right, eqInt columns.source left right,
    eqInt columns.destination left right, eqInt columns.term left right,
    .implies (isTag columns left 0) (conjoin
      [eqInt columns.prevLogIndex left right, eqInt columns.prevLogTerm left right,
       eqInt columns.leaderCommit left right]),
    .implies (isTag columns left 1) (conjoin
      [eqBool columns.success left right, eqInt columns.lastLogIndex left right]),
    .implies (isTag columns left 2) (conjoin
      [eqInt columns.lastCommittableTerm left right, eqInt columns.lastCommittableIndex left right]),
    .implies (isTag columns left 3) (eqBool columns.voteGranted left right),
    .implies (isTag columns left 4) (conjoin
      [eqInt columns.lastCommittableTerm left right, eqInt columns.lastCommittableIndex left right]),
    .implies (isTag columns left 5) (eqBool columns.voteGranted left right)]

theorem header_eq_correct (assignment : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (left right : Header) (hl : HeaderRep assignment columns leftKey left)
    (hr : HeaderRep assignment columns rightKey right) :
    (headerEq columns leftKey rightKey).eval assignment = true <-> left = right := by
  cases left <;> cases right <;> rename_i left right <;> cases left <;> cases right <;>
    simp_all [HeaderRep, CommonRep, headerEq, eqInt, eqBool, isTag, conjoin, Term.eval,
      BijectiveIntegerLog.scalar_eq_iff, Fin.ext_iff] <;> tauto

theorem header_eq_refl (assignment : Assignment) (columns : Columns) (key : Term .int) :
    (headerEq columns key key).eval assignment = true := by
  simp [headerEq, eqInt, eqBool, isTag, conjoin, Term.eval]

theorem header_unique (assignment : Assignment) (columns : Columns) (key : Term .int)
    (left right : Header) (hl : HeaderRep assignment columns key left)
    (hr : HeaderRep assignment columns key right) : left = right :=
  (header_eq_correct assignment columns key key left right hl hr).mp
    (header_eq_refl assignment columns key)

def originTerm (columns : Columns) (key : Term .int) : Term .int :=
  .ite (isTag columns key 0) (intField columns.prevLogIndex key) (.integer 0)

theorem tag_agreement (assignment : Assignment) (columns : Columns) (key : Term .int)
    (header : Header) (rep : HeaderRep assignment columns key header) :
    (intField columns.tag key).eval assignment = headerTag header := by
  cases header <;> simp_all [HeaderRep, CommonRep, headerTag]

theorem source_agreement (assignment : Assignment) (columns : Columns) (key : Term .int)
    (header : Header) (rep : HeaderRep assignment columns key header) :
    (intField columns.source key).eval assignment =
      ((PacketQueueWitness.headerSource header).val : Int) := by
  cases header <;> simp_all [HeaderRep, CommonRep, PacketQueueWitness.headerSource]

theorem origin_agreement (assignment : Assignment) (columns : Columns) (key : Term .int)
    (header : Header) (rep : HeaderRep assignment columns key header) :
    (originTerm columns key).eval assignment = (PacketRealization.origin header : Int) := by
  cases header <;>
    simp_all [HeaderRep, CommonRep, originTerm, isTag, Term.eval, PacketRealization.origin]

def activeIntIds (columns : Columns) (tag : Int) : List Nat :=
  [columns.tag, columns.source, columns.destination, columns.term] ++
    if tag = 0 then [columns.prevLogIndex, columns.prevLogTerm, columns.leaderCommit]
    else if tag = 1 then [columns.lastLogIndex]
    else if tag = 2 \/ tag = 4 then [columns.lastCommittableTerm, columns.lastCommittableIndex]
    else []

def activeBoolIds (columns : Columns) (tag : Int) : List Nat :=
  if tag = 1 then [columns.success]
  else if tag = 3 \/ tag = 5 then [columns.voteGranted]
  else []

def ActiveAgree (left right : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (header : Header) : Prop :=
  (forall id, Membership.mem (activeIntIds columns (headerTag header)) id ->
    (intField id leftKey).eval left = (intField id rightKey).eval right) /\
  (forall id, Membership.mem (activeBoolIds columns (headerTag header)) id ->
    (boolField id leftKey).eval left = (boolField id rightKey).eval right)

theorem header_rep_congr (left right : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (header : Header) (agree : ActiveAgree left right columns leftKey rightKey header) :
    HeaderRep left columns leftKey header <-> HeaderRep right columns rightKey header := by
  cases header <;>
    simp [ActiveAgree, activeIntIds, activeBoolIds, headerTag] at agree <;>
    simp_all [HeaderRep, CommonRep]

theorem same_key_header (assignment : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (same : leftKey.eval assignment = rightKey.eval assignment) (left right : Header)
    (hl : HeaderRep assignment columns leftKey left) (hr : HeaderRep assignment columns rightKey right) :
    left = right := by
  have agree : ActiveAgree assignment assignment columns leftKey rightKey left := by
    constructor <;> intro id member <;> simp [intField, boolField, Term.eval, same]
  exact header_unique assignment columns rightKey left right
    ((header_rep_congr _ _ _ _ _ _ agree).mp hl) hr

variable {roots size count : Nat}

structure DescriptorRep (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (descriptor : PacketRealization.Descriptor roots size) : Prop where
  header : HeaderRep assignment columns key descriptor.header
  length : (intField columns.payloadLength key).eval assignment = (descriptor.payloadLength : Int)
  address : descriptor.address = address

structure DescriptorDomains (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) : Prop where
  header : HeaderDomains assignment columns key
  length : 0 <= (intField columns.payloadLength key).eval assignment
  noPayload : Not ((intField columns.tag key).eval assignment = 0) ->
    (intField columns.payloadLength key).eval assignment = 0
  noAddress : address = none -> (intField columns.payloadLength key).eval assignment = 0

def descriptorDomain (columns : Columns) (key : Term .int) (address : Option (Address roots size)) :
    SmtScript.Formula :=
  headerDomain columns key ++
    [nonnegative columns.payloadLength key,
     .implies (.not (isTag columns key 0)) (.equal (intField columns.payloadLength key) (.integer 0))] ++
    match address with
    | none => [.equal (intField columns.payloadLength key) (.integer 0)]
    | some _ => []

theorem descriptor_formula_correct (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) :
    SmtScript.Holds assignment (descriptorDomain columns key address) <->
      DescriptorDomains assignment columns key address := by
  have split : SmtScript.Holds assignment (descriptorDomain columns key address) <->
      SmtScript.Holds assignment (headerDomain columns key) /\
      0 <= (intField columns.payloadLength key).eval assignment /\
      (Not ((intField columns.tag key).eval assignment = 0) ->
        (intField columns.payloadLength key).eval assignment = 0) /\
      (address = none -> (intField columns.payloadLength key).eval assignment = 0) := by
    cases address <;>
      simp [descriptorDomain, SmtScript.Holds, nonnegative, isTag, Term.eval, or_imp, forall_and] <;> tauto
  rw [split, header_formula_correct]
  constructor
  next => intro h; exact { header := h.1, length := h.2.1, noPayload := h.2.2.1, noAddress := h.2.2.2 }
  next => intro h; exact And.intro h.header (And.intro h.length (And.intro h.noPayload h.noAddress))

theorem length_allowed_iff (header : Header) (length : Nat) :
    PacketRealization.LengthAllowed header length <-> (Not (headerTag header = 0) -> length = 0) := by
  cases header <;> simp [PacketRealization.LengthAllowed, headerTag]

theorem descriptor_exists (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (valid : DescriptorDomains assignment columns key address) :
    exists descriptor, DescriptorRep assignment columns key address descriptor /\
      PacketRealization.Valid descriptor := by
  cases header_exists assignment columns key valid.header with
  | intro header represented =>
    let descriptor : PacketRealization.Descriptor roots size :=
      { header, payloadLength := ((intField columns.payloadLength key).eval assignment).toNat, address }
    have length : (intField columns.payloadLength key).eval assignment = (descriptor.payloadLength : Int) :=
      (Int.toNat_of_nonneg valid.length).symm
    refine Exists.intro descriptor (And.intro
      { header := represented, length, address := rfl } (And.intro ?_ ?_))
    next =>
      apply (length_allowed_iff header _).mpr
      intro notAppend
      have zero := valid.noPayload (by rwa [tag_agreement assignment columns key header represented])
      simp [descriptor, zero]
    next =>
      intro missing
      have zero := valid.noAddress missing
      simp [descriptor, zero]

theorem descriptor_rep_domains (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (descriptor : PacketRealization.Descriptor roots size)
    (rep : DescriptorRep assignment columns key address descriptor) (valid : PacketRealization.Valid descriptor) :
    DescriptorDomains assignment columns key address := by
  refine { header := header_rep_domains assignment columns key descriptor.header rep.header
           length := ?_, noPayload := ?_, noAddress := ?_ }
  next => rw [rep.length]; exact Int.natCast_nonneg _
  next =>
    intro notAppend
    have zero := (length_allowed_iff descriptor.header descriptor.payloadLength).mp valid.1
      (by rwa [<- tag_agreement assignment columns key descriptor.header rep.header])
    rw [rep.length, zero]
    rfl
  next =>
    intro missing
    rw [rep.length, valid.2 (rep.address.trans missing)]
    rfl

theorem descriptor_domain_iff (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) :
    SmtScript.Holds assignment (descriptorDomain columns key address) <->
      exists descriptor, DescriptorRep assignment columns key address descriptor /\
        PacketRealization.Valid descriptor := by
  rw [descriptor_formula_correct]
  constructor
  next => exact descriptor_exists assignment columns key address
  next => intro found; exact found.elim (fun descriptor spec =>
    descriptor_rep_domains assignment columns key address descriptor spec.1 spec.2)

theorem same_key_metadata (assignment : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (leftAddress rightAddress : Option (Address roots size))
    (left right : PacketRealization.Descriptor roots size)
    (same : leftKey.eval assignment = rightKey.eval assignment)
    (hl : DescriptorRep assignment columns leftKey leftAddress left)
    (hr : DescriptorRep assignment columns rightKey rightAddress right) :
    left.header = right.header /\ left.payloadLength = right.payloadLength := by
  refine And.intro (same_key_header assignment columns leftKey rightKey same _ _ hl.header hr.header) ?_
  apply Int.ofNat_inj.mp
  exact hl.length.symm.trans ((congrArg (assignment.unary .int .int columns.payloadLength) same).trans hr.length)

theorem descriptor_unique (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (left right : PacketRealization.Descriptor roots size)
    (hl : DescriptorRep assignment columns key address left)
    (hr : DescriptorRep assignment columns key address right) : left = right := by
  have same := same_key_metadata assignment columns key key address address left right rfl hl hr
  have addresses := hl.address.trans hr.address.symm
  cases left
  cases right
  simp_all

theorem descriptor_unique_iff (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) :
    SmtScript.Holds assignment (descriptorDomain columns key address) <->
      ExistsUnique (fun descriptor => DescriptorRep assignment columns key address descriptor /\
        PacketRealization.Valid descriptor) := by
  constructor
  next =>
    intro holds
    cases (descriptor_domain_iff assignment columns key address).mp holds with
    | intro descriptor spec =>
      exact Exists.intro descriptor (And.intro spec
        (fun other otherSpec => descriptor_unique assignment columns key address other descriptor otherSpec.1 spec.1))
  next => intro unique; exact (descriptor_domain_iff assignment columns key address).mpr unique.exists

def familyDomain (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) : SmtScript.Formula :=
  (List.finRange count).flatMap fun index => descriptorDomain columns (keys index) (addresses index)

def FamilyRep (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size))
    (descriptors : Fin count -> PacketRealization.Descriptor roots size) : Prop :=
  forall index, DescriptorRep assignment columns (keys index) (addresses index) (descriptors index)

theorem family_formula_correct (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) :
    SmtScript.Holds assignment (familyDomain columns keys addresses) <->
      forall index, SmtScript.Holds assignment (descriptorDomain columns (keys index) (addresses index)) := by
  simp [familyDomain, SmtScript.Holds]
  exact forall_comm

theorem family_descriptors_iff (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) :
    SmtScript.Holds assignment (familyDomain columns keys addresses) <->
      exists descriptors, FamilyRep assignment columns keys addresses descriptors /\
        forall index, PacketRealization.Valid (descriptors index) := by
  rw [family_formula_correct]
  constructor
  next =>
    intro holds
    have found := fun index => (descriptor_domain_iff assignment columns (keys index) (addresses index)).mp (holds index)
    exact Exists.intro (fun index => Classical.choose (found index))
      (And.intro (fun index => (Classical.choose_spec (found index)).1)
        (fun index => (Classical.choose_spec (found index)).2))
  next =>
    intro found index
    exact found.elim (fun descriptors spec =>
      (descriptor_domain_iff assignment columns (keys index) (addresses index)).mpr
        (Exists.intro (descriptors index) (And.intro (spec.1 index) (spec.2 index))))

theorem family_realization_iff (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) (reads : Reads roots size EntryValue.Entry) :
    SmtScript.Holds assignment (familyDomain columns keys addresses) <->
      exists descriptors messages, FamilyRep assignment columns keys addresses descriptors /\
        PacketRealization.FamilyRealizes reads descriptors messages := by
  rw [family_descriptors_iff]
  constructor
  next =>
    intro found
    cases found with
    | intro descriptors spec =>
      cases (PacketRealization.family_valid_iff reads descriptors).mp spec.2 with
      | intro messages realized => exact Exists.intro descriptors (Exists.intro messages (And.intro spec.1 realized))
  next =>
    intro found
    cases found with
    | intro descriptors found =>
      cases found with
      | intro messages spec =>
        exact Exists.intro descriptors (And.intro spec.1
          (fun index => PacketRealization.realizes_valid reads _ _ (spec.2 index)))

theorem family_actual_realization (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size))
    (graph : VersionedIntervals.Graph roots EntryValue.Entry size)
    (arrays : VersionedIntervals.RootArrays roots EntryValue.Entry) :
    SmtScript.Holds assignment (familyDomain columns keys addresses) <->
      exists descriptors messages, FamilyRep assignment columns keys addresses descriptors /\
        PacketRealization.FamilyRealizes (IntervalReadback.actual graph arrays) descriptors messages :=
  family_realization_iff assignment columns keys addresses (IntervalReadback.actual graph arrays)

theorem family_realization_unique (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) (reads : Reads roots size EntryValue.Entry)
    (left right : Fin count -> PacketRealization.Descriptor roots size)
    (leftMessages rightMessages : Fin count -> MessageCodec.RawMessage)
    (hl : FamilyRep assignment columns keys addresses left)
    (hr : FamilyRep assignment columns keys addresses right)
    (ml : PacketRealization.FamilyRealizes reads left leftMessages)
    (mr : PacketRealization.FamilyRealizes reads right rightMessages) :
    left = right /\ leftMessages = rightMessages := by
  have same : left = right := funext fun index =>
    descriptor_unique assignment columns (keys index) (addresses index) _ _ (hl index) (hr index)
  subst right
  exact And.intro rfl (PacketRealization.family_unique reads left leftMessages rightMessages ml mr)

theorem header_text_iff (assignment : Assignment) (columns : Columns) (key : Term .int) :
    SmtScriptText.runText assignment (SmtScript.render (headerDomain columns key)) = some true <->
      exists header, HeaderRep assignment columns key header :=
  (SmtScriptText.formula_text_iff assignment _).symm.trans
    (header_domain_iff assignment columns key)

theorem header_eq_text_iff (assignment : Assignment) (columns : Columns) (leftKey rightKey : Term .int)
    (left right : Header) (hl : HeaderRep assignment columns leftKey left)
    (hr : HeaderRep assignment columns rightKey right) :
    SmtScriptText.runText assignment (SmtScript.render [headerEq columns leftKey rightKey]) = some true <->
      left = right := by
  rw [<- SmtScriptText.formula_text_iff]
  simpa [SmtScript.Holds] using header_eq_correct assignment columns leftKey rightKey left right hl hr

theorem descriptor_text_iff (assignment : Assignment) (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) :
    SmtScriptText.runText assignment (SmtScript.render (descriptorDomain columns key address)) = some true <->
      exists descriptor, DescriptorRep assignment columns key address descriptor /\
        PacketRealization.Valid descriptor :=
  (SmtScriptText.formula_text_iff assignment _).symm.trans
    (descriptor_domain_iff assignment columns key address)

theorem family_text_iff (assignment : Assignment) (columns : Columns) (keys : Fin count -> Term .int)
    (addresses : Fin count -> Option (Address roots size)) (reads : Reads roots size EntryValue.Entry) :
    SmtScriptText.runText assignment (SmtScript.render (familyDomain columns keys addresses)) = some true <->
      exists descriptors messages, FamilyRep assignment columns keys addresses descriptors /\
        PacketRealization.FamilyRealizes reads descriptors messages :=
  (SmtScriptText.formula_text_iff assignment _).symm.trans
    (family_realization_iff assignment columns keys addresses reads)

def Columns.headerIntIds (columns : Columns) : List Nat :=
  [columns.tag, columns.source, columns.destination, columns.term,
   columns.prevLogIndex, columns.prevLogTerm, columns.leaderCommit,
   columns.lastLogIndex, columns.lastCommittableTerm, columns.lastCommittableIndex]

def Columns.intIds (columns : Columns) : List Nat :=
  columns.headerIntIds ++ [columns.payloadLength]

def Columns.boolIds (columns : Columns) : List Nat :=
  [columns.success, columns.voteGranted]

def Columns.symbols (columns : Columns) : List Symbol :=
  columns.intIds.map (.unary .int .int) ++ columns.boolIds.map (.unary .int .bool)

def Columns.maximum (columns : Columns) : Nat :=
  max (columns.intIds.foldr max 0) (columns.boolIds.foldr max 0)

def metadataSymbols (columns : Columns) (key : Term .int) : List Symbol :=
  columns.symbols ++ SmtScript.termSymbols key

def metadataMax (columns : Columns) (key : Term .int) : Nat :=
  max columns.maximum (SymbolBounds.termMax key)

theorem column_occurrences (columns : Columns) :
    columns.intIds.length = 11 /\ columns.boolIds.length = 2 /\ columns.symbols.length = 13 := by
  simp [Columns.intIds, Columns.headerIntIds, Columns.boolIds, Columns.symbols]

theorem descriptor_symbols (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (symbol : Symbol) :
    Membership.mem (SmtScript.symbols (descriptorDomain columns key address)) symbol <->
      Membership.mem (SmtScript.termSymbols key) symbol \/
        Membership.mem (columns.intIds.map (.unary .int .int)) symbol := by
  cases address <;>
    simp [descriptorDomain, headerDomain, nonnegative, below, isTag, conjoin,
      SmtScript.symbols, SmtScript.termSymbols, intField,
      Columns.intIds, Columns.headerIntIds, or_left_comm, or_comm]

theorem header_eq_symbols (columns : Columns) (left right : Term .int) (symbol : Symbol) :
    Membership.mem (SmtScript.termSymbols (headerEq columns left right)) symbol <->
      Membership.mem (SmtScript.termSymbols left) symbol \/
      Membership.mem (SmtScript.termSymbols right) symbol \/
      Membership.mem
        (columns.headerIntIds.map (.unary .int .int) ++ columns.boolIds.map (.unary .int .bool)) symbol := by
  simp [headerEq, eqInt, eqBool, isTag, conjoin, intField, boolField, SmtScript.termSymbols,
    Columns.headerIntIds, Columns.boolIds, or_assoc, or_left_comm, or_comm]

private theorem projection_max (ids : List Nat) (ty : Ty) :
    (ids.map (Symbol.unary .int ty)).toFinset.sup SymbolBounds.symbolId = ids.foldr max 0 := by
  induction ids with
  | nil => rfl
  | cons id rest ih =>
    simp only [List.map_cons, List.toFinset_cons, Finset.sup_insert, SymbolBounds.symbolId,
      List.foldr_cons, ih]

theorem metadata_max_correct (columns : Columns) (key : Term .int) :
    metadataMax columns key = (metadataSymbols columns key).toFinset.sup SymbolBounds.symbolId := by
  simp only [metadataMax, metadataSymbols, Columns.symbols, Columns.maximum, List.toFinset_append,
    Finset.sup_union, projection_max, <- SymbolBounds.termMax_correct]

theorem reserved_symbol_bound (columns : Columns) (key : Term .int) (symbol : Symbol)
    (member : Membership.mem (metadataSymbols columns key) symbol) :
    SymbolBounds.symbolId symbol < metadataMax columns key + 1 := by
  rw [metadata_max_correct]
  exact Nat.lt_succ_of_le (Finset.le_sup (f := SymbolBounds.symbolId) (List.mem_toFinset.mpr member))

theorem descriptor_symbol_bound (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) (symbol : Symbol)
    (member : Membership.mem (SmtScript.symbols (descriptorDomain columns key address)) symbol) :
    SymbolBounds.symbolId symbol < metadataMax columns key + 1 := by
  apply reserved_symbol_bound columns key symbol
  cases (descriptor_symbols columns key address symbol).mp member with
  | inl used => exact List.mem_append.mpr (Or.inr used)
  | inr column =>
    exact List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inl column)))

theorem descriptor_formula_length (columns : Columns) (key : Term .int)
    (address : Option (Address roots size)) :
    (descriptorDomain columns key address).length = if address.isNone then 14 else 13 := by
  cases address <;> rfl

theorem parse_descriptor (columns : Columns) (key : Term .int) (address : Option (Address roots size)) :
    SmtScriptText.parse (SmtScript.render (descriptorDomain columns key address)) =
      some (SmtScript.compile (descriptorDomain columns key address)) :=
  SmtScriptText.parse_render _

theorem source_partition_iff (assignment : Assignment) (columns : Columns) (key : Term .int)
    (header : Header) (rep : HeaderRep assignment columns key header) (source : Node) :
    (.equal (intField columns.source key) (.integer (source.val : Int)) : Term .bool).eval assignment = true <->
      PacketQueueWitness.headerSource header = source := by
  simp only [Term.eval, source_agreement assignment columns key header rep, decide_eq_true_eq]
  simp [Fin.ext_iff]

namespace Regression

local instance : NeZero NODE_COUNT := { out := by decide }

def columns : Columns :=
  { tag := 0, source := 1, destination := 2, term := 3,
    prevLogIndex := 4, prevLogTerm := 5, leaderCommit := 6, lastLogIndex := 7,
    lastCommittableTerm := 8, lastCommittableIndex := 9, payloadLength := 10,
    success := 11, voteGranted := 12 }

def sample (codes : Nat -> Int -> Int) (flags : Nat -> Int -> Bool) : Assignment where
  constant := fun ty _ => StateFrame.fixtureDefault ty
  unary := fun domain result id argument => match domain, result with
    | .int, .int => codes id argument
    | .int, .bool => flags id argument
    | _, ty => StateFrame.fixtureDefault ty

def codes (tag length source destination : Int) : Nat -> Int
  | 0 => tag
  | 1 => source
  | 2 => destination
  | 3 => 1
  | 4 | 5 | 6 => if tag = 0 then 1 else -9
  | 7 => if tag = 1 then 1 else -9
  | 8 | 9 => if tag = 2 \/ tag = 4 then 1 else -9
  | 10 => length
  | _ => -9

def fixture (tag length source destination : Int) : Assignment :=
  sample (fun id _ => codes tag length source destination id) (fun id _ => id == 11)

def rootAddress : Option (Address 1 0) := some (.root 0)
def negativeKey : Term .int := .integer (-23)

theorem all_seven_tags :
    forall tag : Fin 7,
      (conjoin (descriptorDomain columns negativeKey rootAddress)).eval
        (fixture tag.val (if tag.val = 0 then 1 else 0) 0 14) = true := by
  decide +kernel

theorem all_seven_realizable (tag : Fin 7) :
    exists descriptor, DescriptorRep
      (fixture tag.val (if tag.val = 0 then 1 else 0) 0 14)
      columns negativeKey rootAddress descriptor /\ PacketRealization.Valid descriptor :=
  (descriptor_domain_iff _ _ _ _).mp
    ((StateFrameEncoding.conjoin_correct _ _).mp (all_seven_tags tag))

theorem invalid_tags_and_nodes :
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture (-1) 0 0 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 7 0 0 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 (-1) 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 15 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 0 15) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 14 14) = true := by
  decide +kernel

theorem inactive_negative_and_active_negative :
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 0 14) = true /\
    (intField columns.prevLogIndex negativeKey).eval (fixture 6 0 0 14) = -9 /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval
      (sample (fun id _ => if id = 4 then -9 else codes 0 1 0 14 id) (fun _ _ => false)) = false := by
  decide +kernel

theorem payload_address_rules :
    (conjoin (descriptorDomain columns negativeKey (none : Option (Address 1 0)))).eval
      (fixture 0 1 0 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 1 0 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 0 (-1) 0 14) = false /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 6 0 0 14) = true /\
    (conjoin (descriptorDomain columns negativeKey (none : Option (Address 1 0)))).eval
      (fixture 6 0 0 14) = true := by
  decide +kernel

def proposal : Header := .proposeVoteRequest (.mk (-1) 0 14)

theorem ordinary_one_raw_minus_one :
    HeaderRep (fixture 6 0 0 14) columns negativeKey proposal /\
    (intField columns.term negativeKey).eval (fixture 6 0 0 14) = 1 /\
    (decodeNat (-1) : Int) = 1 /\
    (originTerm columns negativeKey).eval (fixture 6 0 0 14) = 0 /\
    (originTerm columns negativeKey).eval (fixture 0 1 0 14) = 1 := by
  simp only [proposal, HeaderRep, CommonRep]
  decide +kernel

theorem active_bool_difference :
    (headerEq columns (.integer (-2)) (.integer (-3))).eval
      (sample (fun id _ => codes 1 0 0 14 id) (fun _ key => decide (key = -2))) = false := by
  decide +kernel

theorem inactive_values_do_not_distinguish :
    (headerEq columns (.integer (-2)) (.integer (-3))).eval
      (sample (fun id key => if 4 <= id /\ id <= 9 then key else codes 6 0 0 14 id)
        (fun _ key => decide (key = -2))) = true := by
  decide +kernel

theorem distinct_keys_equal_headers_allowed :
    (headerEq columns (.integer (-2)) (.integer (-3))).eval (fixture 6 0 0 14) = true := by
  decide +kernel

def aliased : Columns :=
  { tag := 0, source := 0, destination := 0, term := 0,
    prevLogIndex := 0, prevLogTerm := 0, leaderCommit := 0, lastLogIndex := 0,
    lastCommittableTerm := 0, lastCommittableIndex := 0, payloadLength := 0,
    success := 0, voteGranted := 0 }

theorem aliased_column_ids :
    (conjoin (descriptorDomain aliased negativeKey rootAddress)).eval
      (sample (fun _ _ => 0) (fun _ _ => false)) = true /\
    aliased.symbols.length = 13 /\ aliased.symbols.toFinset.card = 2 := by
  decide +kernel

theorem unused_bool_reservation :
    metadataMax { columns with success := 1000, voteGranted := 1001 } negativeKey = 1001 /\
    SymbolBounds.formulaMax
      (descriptorDomain { columns with success := 1000, voteGranted := 1001 } negativeKey rootAddress) = 10 := by
  decide +kernel

theorem million_length_constant_shape :
    (descriptorDomain columns negativeKey rootAddress).length = 13 /\
    (conjoin (descriptorDomain columns negativeKey rootAddress)).eval (fixture 0 1000000 0 14) = true := by
  decide +kernel

theorem repeated_occurrences :
    (conjoin (familyDomain columns (fun _ : Fin 2 => negativeKey) (fun _ => rootAddress))).eval
      (fixture 6 0 0 14) = true /\
    (familyDomain columns (fun _ : Fin 2 => negativeKey) (fun _ => rootAddress)).length = 26 := by
  decide +kernel

theorem self_header :
    HeaderRep (fixture 6 0 14 14) columns negativeKey
      (.proposeVoteRequest (.mk (-1) 14 14)) := by
  simp only [HeaderRep, CommonRep]
  decide +kernel

def foreignPacket : MessageCodec.RawMessage := .proposeVoteRequest (.mk (-1) 0 14)

theorem foreign_destination_duplicates :
    HeaderRep (fixture 6 0 0 14) columns negativeKey (PacketIdentity.header foreignPacket) /\
    (MessageCodec.decodeMessage foreignPacket).source = (0 : Node) /\
    Not ((MessageCodec.decodeMessage foreignPacket).destination = (0 : Node)) /\
    [MessageCodec.decodeMessage foreignPacket, MessageCodec.decodeMessage foreignPacket].length = 2 := by
  simp only [foreignPacket, PacketIdentity.header, HeaderRep, CommonRep]
  decide +kernel

def emptyDescriptor (address : Address 2 0) : PacketRealization.Descriptor 2 0 :=
  { header := proposal, payloadLength := 0, address := some address }

theorem zero_length_different_addresses (reads : Reads 2 0 EntryValue.Entry) :
    DescriptorRep (fixture 6 0 0 14) columns negativeKey (some (.root 0)) (emptyDescriptor (.root 0)) /\
    DescriptorRep (fixture 6 0 0 14) columns negativeKey (some (.root 1)) (emptyDescriptor (.root 1)) /\
    PacketRealization.Same reads (emptyDescriptor (.root 0)) (emptyDescriptor (.root 1)) := by
  refine And.intro ?_ (And.intro ?_ ?_)
  next => constructor <;> simp only [emptyDescriptor, proposal, HeaderRep, CommonRep] <;> decide +kernel
  next => constructor <;> simp only [emptyDescriptor, proposal, HeaderRep, CommonRep] <;> decide +kernel
  next => simp [PacketRealization.Same, emptyDescriptor]

end Regression

end CCFRaft.Sparse.PacketHeaderEncoding

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.PacketHeaderEncoding).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit PacketHeaderEncoding axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"PacketHeaderEncoding: {checked} declarations passed the transitive axiom gate."
