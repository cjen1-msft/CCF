-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.ModelTrace

set_option autoImplicit false

namespace CCFRaft.Sparse.ModelInputSyntax

open ModelTrace (UnknownNatAssignment)

variable {n : Nat} {left right : UnknownNatAssignment}

inductive NatAtom (n : Nat) where
  | literal (value : Nat)
  | unknown (index : Fin n)
  deriving DecidableEq

def NatAtom.eval (rho : UnknownNatAssignment) : NatAtom n -> Nat
  | .literal value => value
  | .unknown index => rho index.val

def NatAtom.quote (value : Nat) : NatAtom n := .literal value
def NatAtom.atoms (value : NatAtom n) : List (NatAtom n) := [value]
def NatAtom.indices : NatAtom n -> List (Fin n)
  | .literal _ => []
  | .unknown index => [index]

def Same (left right : UnknownNatAssignment) (atoms : List (NatAtom n)) : Prop :=
  forall atom, Membership.mem atoms atom -> atom.eval left = atom.eval right

theorem Same.restrict {atoms subset : List (NatAtom n)} (same : Same left right atoms)
    (contained : forall atom, Membership.mem subset atom -> Membership.mem atoms atom) :
    Same left right subset :=
  fun atom member => same atom (contained atom member)

theorem NatAtom.eval_congr (value : NatAtom n) (same : Same left right value.atoms) :
    value.eval left = value.eval right :=
  same value (by simp [atoms])

@[simp] theorem NatAtom.eval_quote (rho : UnknownNatAssignment) (value : Nat) :
    (NatAtom.quote (n := n) value).eval rho = value := rfl

inductive BoolAtom (n : Nat) where
  | literal (value : Bool)
  | isZero (value : NatAtom n)
  deriving DecidableEq

def BoolAtom.eval (rho : UnknownNatAssignment) : BoolAtom n -> Bool
  | .literal value => value
  | .isZero value => decide (value.eval rho = 0)

def BoolAtom.quote (value : Bool) : BoolAtom n := .literal value
def BoolAtom.atoms : BoolAtom n -> List (NatAtom n)
  | .literal _ => []
  | .isZero value => value.atoms

theorem BoolAtom.eval_congr (value : BoolAtom n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | literal _ => rfl
  | isZero value => simp only [eval, NatAtom.eval_congr value same]

@[simp] theorem BoolAtom.eval_quote (rho : UnknownNatAssignment) (value : Bool) :
    (BoolAtom.quote (n := n) value).eval rho = value := rfl

def optionAtoms {A : Type} (atoms : A -> List (NatAtom n)) : Option A -> List (NatAtom n)
  | none => []
  | some value => atoms value

theorem option_congr {A B : Type} (atoms : A -> List (NatAtom n))
    (eval : UnknownNatAssignment -> A -> B)
    (congruent : forall value, Same left right (atoms value) -> eval left value = eval right value)
    (value : Option A) (same : Same left right (optionAtoms atoms value)) :
    value.map (eval left) = value.map (eval right) := by
  cases value with
  | none => rfl
  | some value => exact congrArg some (congruent value same)

theorem list_congr {A B : Type} (atoms : A -> List (NatAtom n))
    (eval : UnknownNatAssignment -> A -> B)
    (congruent : forall value, Same left right (atoms value) -> eval left value = eval right value)
    (values : List A) (same : Same left right (values.flatMap atoms)) :
    values.map (eval left) = values.map (eval right) := by
  apply List.map_congr_left
  intro value member
  apply congruent value
  exact same.restrict (fun atom present =>
    List.mem_flatMap.mpr (Exists.intro value (And.intro member present)))

def atomSupport (atoms : List (NatAtom n)) : Finset (Fin n) :=
  (atoms.flatMap NatAtom.indices).toFinset

theorem same_of_support (atoms : List (NatAtom n))
    (agree : forall index, Membership.mem (atomSupport atoms) index -> left index.val = right index.val) :
    Same left right atoms := by
  intro atom member
  cases atom with
  | literal _ => rfl
  | unknown index =>
    apply agree index
    exact List.mem_toFinset.mpr (List.mem_flatMap.mpr
      (Exists.intro (.unknown index) (And.intro member (by simp [NatAtom.indices]))))

inductive ContentSyntax (n : Nat) where
  | transaction (txId : NatAtom n)
  | signature
  | reconfiguration (nodes : Finset Node)
  | retiredCommitted (nodes : Finset Node)
  deriving DecidableEq

def ContentSyntax.eval (rho : UnknownNatAssignment) : ContentSyntax n -> EntryContent Node Nat
  | .transaction txId => .transaction ((NatAtom.eval rho) (txId))
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration (nodes)
  | .retiredCommitted nodes => .retiredCommitted (nodes)

def ContentSyntax.quote : EntryContent Node Nat -> ContentSyntax n
  | .transaction txId => .transaction ((NatAtom.quote) (txId))
  | .signature => .signature
  | .reconfiguration nodes => .reconfiguration (nodes)
  | .retiredCommitted nodes => .retiredCommitted (nodes)

def ContentSyntax.atoms : ContentSyntax n -> List (NatAtom n)
  | .transaction txId => ((txId).atoms)
  | .signature => []
  | .reconfiguration _ => []
  | .retiredCommitted _ => []

theorem ContentSyntax.eval_congr (value : ContentSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | transaction txId =>
    have h0 := NatAtom.eval_congr (txId) (same.restrict (by
      intro atom member
      simp [ContentSyntax.atoms, member]))
    simp only [ContentSyntax.eval, h0]
  | signature =>
    rfl
  | reconfiguration nodes =>
    rfl
  | retiredCommitted nodes =>
    rfl

@[simp] theorem ContentSyntax.eval_quote (rho : UnknownNatAssignment) (value : EntryContent Node Nat) :
    (ContentSyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [ContentSyntax.quote, ContentSyntax.eval]

structure EntrySyntax (n : Nat) where
  term : NatAtom n
  content : ContentSyntax n
  deriving DecidableEq

def EntrySyntax.eval (rho : UnknownNatAssignment) (value : EntrySyntax n) : Entry Node Nat where
  term := (NatAtom.eval rho) (value.term)
  content := (ContentSyntax.eval rho) (value.content)

def EntrySyntax.quote (value : Entry Node Nat) : EntrySyntax n where
  term := (NatAtom.quote) (value.term)
  content := (ContentSyntax.quote) (value.content)

def EntrySyntax.atoms (value : EntrySyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.content).atoms)

theorem EntrySyntax.eval_congr (value : EntrySyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [EntrySyntax.atoms, member]))
  have h1 := ContentSyntax.eval_congr (value.content) (same.restrict (by
    intro atom member
    simp [EntrySyntax.atoms, member]))
  simp only [EntrySyntax.eval, h0, h1]

@[simp] theorem EntrySyntax.eval_quote (rho : UnknownNatAssignment) (value : Entry Node Nat) :
    (EntrySyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [EntrySyntax.quote, EntrySyntax.eval]

structure ConfigurationSyntax (n : Nat) where
  index : NatAtom n
  nodes : Finset Node
  deriving DecidableEq

def ConfigurationSyntax.eval (rho : UnknownNatAssignment) (value : ConfigurationSyntax n) : Configuration Node where
  index := (NatAtom.eval rho) (value.index)
  nodes := value.nodes

def ConfigurationSyntax.quote (value : Configuration Node) : ConfigurationSyntax n where
  index := (NatAtom.quote) (value.index)
  nodes := value.nodes

def ConfigurationSyntax.atoms (value : ConfigurationSyntax n) : List (NatAtom n) :=
  ((value.index).atoms)

theorem ConfigurationSyntax.eval_congr (value : ConfigurationSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.index) (same.restrict (by
    intro atom member
    simp [ConfigurationSyntax.atoms, member]))
  simp only [ConfigurationSyntax.eval, h0]

@[simp] theorem ConfigurationSyntax.eval_quote (rho : UnknownNatAssignment) (value : Configuration Node) :
    (ConfigurationSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [ConfigurationSyntax.quote, ConfigurationSyntax.eval]

structure AppendRequestSyntax (n : Nat) where
  term : NatAtom n
  prevLogIndex : NatAtom n
  prevLogTerm : NatAtom n
  entries : List (EntrySyntax n)
  leaderCommit : NatAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def AppendRequestSyntax.eval (rho : UnknownNatAssignment) (value : AppendRequestSyntax n) : AppendEntriesRequest Node Nat where
  term := (NatAtom.eval rho) (value.term)
  prevLogIndex := (NatAtom.eval rho) (value.prevLogIndex)
  prevLogTerm := (NatAtom.eval rho) (value.prevLogTerm)
  entries := (value.entries).map (EntrySyntax.eval rho)
  leaderCommit := (NatAtom.eval rho) (value.leaderCommit)
  source := value.source
  destination := value.destination

def AppendRequestSyntax.quote (value : AppendEntriesRequest Node Nat) : AppendRequestSyntax n where
  term := (NatAtom.quote) (value.term)
  prevLogIndex := (NatAtom.quote) (value.prevLogIndex)
  prevLogTerm := (NatAtom.quote) (value.prevLogTerm)
  entries := (value.entries).map (EntrySyntax.quote)
  leaderCommit := (NatAtom.quote) (value.leaderCommit)
  source := value.source
  destination := value.destination

def AppendRequestSyntax.atoms (value : AppendRequestSyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.prevLogIndex).atoms) ++ ((value.prevLogTerm).atoms) ++ ((value.entries).flatMap EntrySyntax.atoms) ++ ((value.leaderCommit).atoms)

theorem AppendRequestSyntax.eval_congr (value : AppendRequestSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [AppendRequestSyntax.atoms, member]))
  have h1 := NatAtom.eval_congr (value.prevLogIndex) (same.restrict (by
    intro atom member
    simp [AppendRequestSyntax.atoms, member]))
  have h2 := NatAtom.eval_congr (value.prevLogTerm) (same.restrict (by
    intro atom member
    simp [AppendRequestSyntax.atoms, member]))
  have h3 := list_congr EntrySyntax.atoms EntrySyntax.eval EntrySyntax.eval_congr (value.entries) (same.restrict (by
    intro atom member
    simp [AppendRequestSyntax.atoms, member]))
  have h4 := NatAtom.eval_congr (value.leaderCommit) (same.restrict (by
    intro atom member
    simp [AppendRequestSyntax.atoms, member]))
  simp only [AppendRequestSyntax.eval, h0, h1, h2, h3, h4]

@[simp] theorem AppendRequestSyntax.eval_quote (rho : UnknownNatAssignment) (value : AppendEntriesRequest Node Nat) :
    (AppendRequestSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [AppendRequestSyntax.quote, AppendRequestSyntax.eval, List.map_map, Function.comp_def]

structure AppendResponseSyntax (n : Nat) where
  term : NatAtom n
  success : BoolAtom n
  lastLogIndex : NatAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def AppendResponseSyntax.eval (rho : UnknownNatAssignment) (value : AppendResponseSyntax n) : AppendEntriesResponse Node where
  term := (NatAtom.eval rho) (value.term)
  success := (BoolAtom.eval rho) (value.success)
  lastLogIndex := (NatAtom.eval rho) (value.lastLogIndex)
  source := value.source
  destination := value.destination

def AppendResponseSyntax.quote (value : AppendEntriesResponse Node) : AppendResponseSyntax n where
  term := (NatAtom.quote) (value.term)
  success := (BoolAtom.quote) (value.success)
  lastLogIndex := (NatAtom.quote) (value.lastLogIndex)
  source := value.source
  destination := value.destination

def AppendResponseSyntax.atoms (value : AppendResponseSyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.success).atoms) ++ ((value.lastLogIndex).atoms)

theorem AppendResponseSyntax.eval_congr (value : AppendResponseSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [AppendResponseSyntax.atoms, member]))
  have h1 := BoolAtom.eval_congr (value.success) (same.restrict (by
    intro atom member
    simp [AppendResponseSyntax.atoms, member]))
  have h2 := NatAtom.eval_congr (value.lastLogIndex) (same.restrict (by
    intro atom member
    simp [AppendResponseSyntax.atoms, member]))
  simp only [AppendResponseSyntax.eval, h0, h1, h2]

@[simp] theorem AppendResponseSyntax.eval_quote (rho : UnknownNatAssignment) (value : AppendEntriesResponse Node) :
    (AppendResponseSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [AppendResponseSyntax.quote, AppendResponseSyntax.eval]

structure VoteRequestSyntax (n : Nat) where
  term : NatAtom n
  lastCommittableTerm : NatAtom n
  lastCommittableIndex : NatAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def VoteRequestSyntax.eval (rho : UnknownNatAssignment) (value : VoteRequestSyntax n) : RequestVoteRequest Node where
  term := (NatAtom.eval rho) (value.term)
  lastCommittableTerm := (NatAtom.eval rho) (value.lastCommittableTerm)
  lastCommittableIndex := (NatAtom.eval rho) (value.lastCommittableIndex)
  source := value.source
  destination := value.destination

def VoteRequestSyntax.quote (value : RequestVoteRequest Node) : VoteRequestSyntax n where
  term := (NatAtom.quote) (value.term)
  lastCommittableTerm := (NatAtom.quote) (value.lastCommittableTerm)
  lastCommittableIndex := (NatAtom.quote) (value.lastCommittableIndex)
  source := value.source
  destination := value.destination

def VoteRequestSyntax.atoms (value : VoteRequestSyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.lastCommittableTerm).atoms) ++ ((value.lastCommittableIndex).atoms)

theorem VoteRequestSyntax.eval_congr (value : VoteRequestSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [VoteRequestSyntax.atoms, member]))
  have h1 := NatAtom.eval_congr (value.lastCommittableTerm) (same.restrict (by
    intro atom member
    simp [VoteRequestSyntax.atoms, member]))
  have h2 := NatAtom.eval_congr (value.lastCommittableIndex) (same.restrict (by
    intro atom member
    simp [VoteRequestSyntax.atoms, member]))
  simp only [VoteRequestSyntax.eval, h0, h1, h2]

@[simp] theorem VoteRequestSyntax.eval_quote (rho : UnknownNatAssignment) (value : RequestVoteRequest Node) :
    (VoteRequestSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [VoteRequestSyntax.quote, VoteRequestSyntax.eval]

def VoteRequestSyntax.evalPreVote (rho : UnknownNatAssignment) (value : VoteRequestSyntax n) : RequestPreVote Node :=
  let decoded := value.eval rho
  { term := decoded.term, lastCommittableTerm := decoded.lastCommittableTerm, lastCommittableIndex := decoded.lastCommittableIndex, source := decoded.source, destination := decoded.destination }

def VoteRequestSyntax.quotePreVote (value : RequestPreVote Node) : VoteRequestSyntax n :=
  VoteRequestSyntax.quote { term := value.term, lastCommittableTerm := value.lastCommittableTerm, lastCommittableIndex := value.lastCommittableIndex, source := value.source, destination := value.destination }

@[simp] theorem VoteRequestSyntax.eval_quotePreVote (rho : UnknownNatAssignment) (value : RequestPreVote Node) :
    VoteRequestSyntax.evalPreVote rho (VoteRequestSyntax.quotePreVote (n := n) value) = value := by
  cases value
  simp [evalPreVote, quotePreVote]

structure VoteResponseSyntax (n : Nat) where
  term : NatAtom n
  voteGranted : BoolAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def VoteResponseSyntax.eval (rho : UnknownNatAssignment) (value : VoteResponseSyntax n) : RequestVoteResponse Node where
  term := (NatAtom.eval rho) (value.term)
  voteGranted := (BoolAtom.eval rho) (value.voteGranted)
  source := value.source
  destination := value.destination

def VoteResponseSyntax.quote (value : RequestVoteResponse Node) : VoteResponseSyntax n where
  term := (NatAtom.quote) (value.term)
  voteGranted := (BoolAtom.quote) (value.voteGranted)
  source := value.source
  destination := value.destination

def VoteResponseSyntax.atoms (value : VoteResponseSyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.voteGranted).atoms)

theorem VoteResponseSyntax.eval_congr (value : VoteResponseSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [VoteResponseSyntax.atoms, member]))
  have h1 := BoolAtom.eval_congr (value.voteGranted) (same.restrict (by
    intro atom member
    simp [VoteResponseSyntax.atoms, member]))
  simp only [VoteResponseSyntax.eval, h0, h1]

@[simp] theorem VoteResponseSyntax.eval_quote (rho : UnknownNatAssignment) (value : RequestVoteResponse Node) :
    (VoteResponseSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [VoteResponseSyntax.quote, VoteResponseSyntax.eval]

def VoteResponseSyntax.evalPreVote (rho : UnknownNatAssignment) (value : VoteResponseSyntax n) : RequestPreVoteResponse Node :=
  let decoded := value.eval rho
  { term := decoded.term, voteGranted := decoded.voteGranted, source := decoded.source, destination := decoded.destination }

def VoteResponseSyntax.quotePreVote (value : RequestPreVoteResponse Node) : VoteResponseSyntax n :=
  VoteResponseSyntax.quote { term := value.term, voteGranted := value.voteGranted, source := value.source, destination := value.destination }

@[simp] theorem VoteResponseSyntax.eval_quotePreVote (rho : UnknownNatAssignment) (value : RequestPreVoteResponse Node) :
    VoteResponseSyntax.evalPreVote rho (VoteResponseSyntax.quotePreVote (n := n) value) = value := by
  cases value
  simp [evalPreVote, quotePreVote]

structure ProposeRequestSyntax (n : Nat) where
  term : NatAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def ProposeRequestSyntax.eval (rho : UnknownNatAssignment) (value : ProposeRequestSyntax n) : ProposeVoteRequest Node where
  term := (NatAtom.eval rho) (value.term)
  source := value.source
  destination := value.destination

def ProposeRequestSyntax.quote (value : ProposeVoteRequest Node) : ProposeRequestSyntax n where
  term := (NatAtom.quote) (value.term)
  source := value.source
  destination := value.destination

def ProposeRequestSyntax.atoms (value : ProposeRequestSyntax n) : List (NatAtom n) :=
  ((value.term).atoms)

theorem ProposeRequestSyntax.eval_congr (value : ProposeRequestSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [ProposeRequestSyntax.atoms, member]))
  simp only [ProposeRequestSyntax.eval, h0]

@[simp] theorem ProposeRequestSyntax.eval_quote (rho : UnknownNatAssignment) (value : ProposeVoteRequest Node) :
    (ProposeRequestSyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [ProposeRequestSyntax.quote, ProposeRequestSyntax.eval]

inductive MessageSyntax (n : Nat) where
  | appendEntriesRequest (request : AppendRequestSyntax n)
  | appendEntriesResponse (response : AppendResponseSyntax n)
  | requestVoteRequest (request : VoteRequestSyntax n)
  | requestVoteResponse (response : VoteResponseSyntax n)
  | requestPreVote (request : VoteRequestSyntax n)
  | requestPreVoteResponse (response : VoteResponseSyntax n)
  | proposeVoteRequest (request : ProposeRequestSyntax n)
  deriving DecidableEq

def MessageSyntax.eval (rho : UnknownNatAssignment) : MessageSyntax n -> Message Node Nat
  | .appendEntriesRequest request => .appendEntriesRequest ((AppendRequestSyntax.eval rho) (request))
  | .appendEntriesResponse response => .appendEntriesResponse ((AppendResponseSyntax.eval rho) (response))
  | .requestVoteRequest request => .requestVoteRequest ((VoteRequestSyntax.eval rho) (request))
  | .requestVoteResponse response => .requestVoteResponse ((VoteResponseSyntax.eval rho) (response))
  | .requestPreVote request => .requestPreVote (VoteRequestSyntax.evalPreVote rho request)
  | .requestPreVoteResponse response => .requestPreVoteResponse (VoteResponseSyntax.evalPreVote rho response)
  | .proposeVoteRequest request => .proposeVoteRequest ((ProposeRequestSyntax.eval rho) (request))

def MessageSyntax.quote : Message Node Nat -> MessageSyntax n
  | .appendEntriesRequest request => .appendEntriesRequest ((AppendRequestSyntax.quote) (request))
  | .appendEntriesResponse response => .appendEntriesResponse ((AppendResponseSyntax.quote) (response))
  | .requestVoteRequest request => .requestVoteRequest ((VoteRequestSyntax.quote) (request))
  | .requestVoteResponse response => .requestVoteResponse ((VoteResponseSyntax.quote) (response))
  | .requestPreVote request => .requestPreVote (VoteRequestSyntax.quotePreVote request)
  | .requestPreVoteResponse response => .requestPreVoteResponse (VoteResponseSyntax.quotePreVote response)
  | .proposeVoteRequest request => .proposeVoteRequest ((ProposeRequestSyntax.quote) (request))

def MessageSyntax.atoms : MessageSyntax n -> List (NatAtom n)
  | .appendEntriesRequest request => ((request).atoms)
  | .appendEntriesResponse response => ((response).atoms)
  | .requestVoteRequest request => ((request).atoms)
  | .requestVoteResponse response => ((response).atoms)
  | .requestPreVote request => ((request).atoms)
  | .requestPreVoteResponse response => ((response).atoms)
  | .proposeVoteRequest request => ((request).atoms)

theorem MessageSyntax.eval_congr (value : MessageSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | appendEntriesRequest request =>
    have h0 := AppendRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, h0]
  | appendEntriesResponse response =>
    have h0 := AppendResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, h0]
  | requestVoteRequest request =>
    have h0 := VoteRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, h0]
  | requestVoteResponse response =>
    have h0 := VoteResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, h0]
  | requestPreVote request =>
    have h0 := VoteRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, VoteRequestSyntax.evalPreVote, h0]
  | requestPreVoteResponse response =>
    have h0 := VoteResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, VoteResponseSyntax.evalPreVote, h0]
  | proposeVoteRequest request =>
    have h0 := ProposeRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [MessageSyntax.atoms, member]))
    simp only [MessageSyntax.eval, h0]

@[simp] theorem MessageSyntax.eval_quote (rho : UnknownNatAssignment) (value : Message Node Nat) :
    (MessageSyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [MessageSyntax.quote, MessageSyntax.eval]

structure AppendSummarySyntax (n : Nat) where
  term : NatAtom n
  prevLogIndex : NatAtom n
  entriesLength : NatAtom n
  leaderCommit : NatAtom n
  source : Node
  destination : Node
  deriving DecidableEq

def AppendSummarySyntax.eval (rho : UnknownNatAssignment) (value : AppendSummarySyntax n) : TraceMessageSummary.AppendEntriesSummary Node where
  term := (NatAtom.eval rho) (value.term)
  prevLogIndex := (NatAtom.eval rho) (value.prevLogIndex)
  entriesLength := (NatAtom.eval rho) (value.entriesLength)
  leaderCommit := (NatAtom.eval rho) (value.leaderCommit)
  source := value.source
  destination := value.destination

def AppendSummarySyntax.quote (value : TraceMessageSummary.AppendEntriesSummary Node) : AppendSummarySyntax n where
  term := (NatAtom.quote) (value.term)
  prevLogIndex := (NatAtom.quote) (value.prevLogIndex)
  entriesLength := (NatAtom.quote) (value.entriesLength)
  leaderCommit := (NatAtom.quote) (value.leaderCommit)
  source := value.source
  destination := value.destination

def AppendSummarySyntax.atoms (value : AppendSummarySyntax n) : List (NatAtom n) :=
  ((value.term).atoms) ++ ((value.prevLogIndex).atoms) ++ ((value.entriesLength).atoms) ++ ((value.leaderCommit).atoms)

theorem AppendSummarySyntax.eval_congr (value : AppendSummarySyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  have h0 := NatAtom.eval_congr (value.term) (same.restrict (by
    intro atom member
    simp [AppendSummarySyntax.atoms, member]))
  have h1 := NatAtom.eval_congr (value.prevLogIndex) (same.restrict (by
    intro atom member
    simp [AppendSummarySyntax.atoms, member]))
  have h2 := NatAtom.eval_congr (value.entriesLength) (same.restrict (by
    intro atom member
    simp [AppendSummarySyntax.atoms, member]))
  have h3 := NatAtom.eval_congr (value.leaderCommit) (same.restrict (by
    intro atom member
    simp [AppendSummarySyntax.atoms, member]))
  simp only [AppendSummarySyntax.eval, h0, h1, h2, h3]

@[simp] theorem AppendSummarySyntax.eval_quote (rho : UnknownNatAssignment) (value : TraceMessageSummary.AppendEntriesSummary Node) :
    (AppendSummarySyntax.quote (n := n) value).eval rho = value := by
  cases value
  simp [AppendSummarySyntax.quote, AppendSummarySyntax.eval]

inductive SummarySyntax (n : Nat) where
  | appendEntriesRequest (request : AppendSummarySyntax n)
  | appendEntriesResponse (response : AppendResponseSyntax n)
  | requestVoteRequest (request : VoteRequestSyntax n)
  | requestVoteResponse (response : VoteResponseSyntax n)
  | requestPreVote (request : VoteRequestSyntax n)
  | requestPreVoteResponse (response : VoteResponseSyntax n)
  | proposeVoteRequest (request : ProposeRequestSyntax n)
  deriving DecidableEq

def SummarySyntax.eval (rho : UnknownNatAssignment) : SummarySyntax n -> TraceMessageSummary.Summary Node
  | .appendEntriesRequest request => .appendEntriesRequest ((AppendSummarySyntax.eval rho) (request))
  | .appendEntriesResponse response => .appendEntriesResponse ((AppendResponseSyntax.eval rho) (response))
  | .requestVoteRequest request => .requestVoteRequest ((VoteRequestSyntax.eval rho) (request))
  | .requestVoteResponse response => .requestVoteResponse ((VoteResponseSyntax.eval rho) (response))
  | .requestPreVote request => .requestPreVote (VoteRequestSyntax.evalPreVote rho request)
  | .requestPreVoteResponse response => .requestPreVoteResponse (VoteResponseSyntax.evalPreVote rho response)
  | .proposeVoteRequest request => .proposeVoteRequest ((ProposeRequestSyntax.eval rho) (request))

def SummarySyntax.quote : TraceMessageSummary.Summary Node -> SummarySyntax n
  | .appendEntriesRequest request => .appendEntriesRequest ((AppendSummarySyntax.quote) (request))
  | .appendEntriesResponse response => .appendEntriesResponse ((AppendResponseSyntax.quote) (response))
  | .requestVoteRequest request => .requestVoteRequest ((VoteRequestSyntax.quote) (request))
  | .requestVoteResponse response => .requestVoteResponse ((VoteResponseSyntax.quote) (response))
  | .requestPreVote request => .requestPreVote (VoteRequestSyntax.quotePreVote request)
  | .requestPreVoteResponse response => .requestPreVoteResponse (VoteResponseSyntax.quotePreVote response)
  | .proposeVoteRequest request => .proposeVoteRequest ((ProposeRequestSyntax.quote) (request))

def SummarySyntax.atoms : SummarySyntax n -> List (NatAtom n)
  | .appendEntriesRequest request => ((request).atoms)
  | .appendEntriesResponse response => ((response).atoms)
  | .requestVoteRequest request => ((request).atoms)
  | .requestVoteResponse response => ((response).atoms)
  | .requestPreVote request => ((request).atoms)
  | .requestPreVoteResponse response => ((response).atoms)
  | .proposeVoteRequest request => ((request).atoms)

theorem SummarySyntax.eval_congr (value : SummarySyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | appendEntriesRequest request =>
    have h0 := AppendSummarySyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, h0]
  | appendEntriesResponse response =>
    have h0 := AppendResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, h0]
  | requestVoteRequest request =>
    have h0 := VoteRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, h0]
  | requestVoteResponse response =>
    have h0 := VoteResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, h0]
  | requestPreVote request =>
    have h0 := VoteRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, VoteRequestSyntax.evalPreVote, h0]
  | requestPreVoteResponse response =>
    have h0 := VoteResponseSyntax.eval_congr (response) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, VoteResponseSyntax.evalPreVote, h0]
  | proposeVoteRequest request =>
    have h0 := ProposeRequestSyntax.eval_congr (request) (same.restrict (by
      intro atom member
      simp [SummarySyntax.atoms, member]))
    simp only [SummarySyntax.eval, h0]

@[simp] theorem SummarySyntax.eval_quote (rho : UnknownNatAssignment) (value : TraceMessageSummary.Summary Node) :
    (SummarySyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [SummarySyntax.quote, SummarySyntax.eval]

inductive StateObservationSyntax (n : Nat) where
  | preVoteStatus (node : Node) (value : PreVoteStatus)
  | membershipState (node : Node) (value : MembershipState)
  | retirementIndex (node : Node) (value : Option (NatAtom n))
  | retirementCommittableIndex (node : Node) (value : Option (NatAtom n))
  | retiredCommittedIndex (node : Node) (value : Option (NatAtom n))
  | retirementCompleted (observer : Node) (retired : Node) (value : BoolAtom n)
  deriving DecidableEq

def StateObservationSyntax.eval (rho : UnknownNatAssignment) : StateObservationSyntax n -> TraceStateObservation.Observation Node
  | .preVoteStatus node value => .preVoteStatus (node) (value)
  | .membershipState node value => .membershipState (node) (value)
  | .retirementIndex node value => .retirementIndex (node) ((value).map (NatAtom.eval rho))
  | .retirementCommittableIndex node value => .retirementCommittableIndex (node) ((value).map (NatAtom.eval rho))
  | .retiredCommittedIndex node value => .retiredCommittedIndex (node) ((value).map (NatAtom.eval rho))
  | .retirementCompleted observer retired value => .retirementCompleted (observer) (retired) ((BoolAtom.eval rho) (value))

def StateObservationSyntax.quote : TraceStateObservation.Observation Node -> StateObservationSyntax n
  | .preVoteStatus node value => .preVoteStatus (node) (value)
  | .membershipState node value => .membershipState (node) (value)
  | .retirementIndex node value => .retirementIndex (node) ((value).map (NatAtom.quote))
  | .retirementCommittableIndex node value => .retirementCommittableIndex (node) ((value).map (NatAtom.quote))
  | .retiredCommittedIndex node value => .retiredCommittedIndex (node) ((value).map (NatAtom.quote))
  | .retirementCompleted observer retired value => .retirementCompleted (observer) (retired) ((BoolAtom.quote) (value))

def StateObservationSyntax.atoms : StateObservationSyntax n -> List (NatAtom n)
  | .preVoteStatus _ _ => []
  | .membershipState _ _ => []
  | .retirementIndex _ value => (optionAtoms NatAtom.atoms (value))
  | .retirementCommittableIndex _ value => (optionAtoms NatAtom.atoms (value))
  | .retiredCommittedIndex _ value => (optionAtoms NatAtom.atoms (value))
  | .retirementCompleted _ _ value => ((value).atoms)

theorem StateObservationSyntax.eval_congr (value : StateObservationSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | preVoteStatus node value =>
    rfl
  | membershipState node value =>
    rfl
  | retirementIndex node value =>
    have h1 := option_congr NatAtom.atoms NatAtom.eval NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [StateObservationSyntax.atoms, member]))
    simp only [StateObservationSyntax.eval, h1]
  | retirementCommittableIndex node value =>
    have h1 := option_congr NatAtom.atoms NatAtom.eval NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [StateObservationSyntax.atoms, member]))
    simp only [StateObservationSyntax.eval, h1]
  | retiredCommittedIndex node value =>
    have h1 := option_congr NatAtom.atoms NatAtom.eval NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [StateObservationSyntax.atoms, member]))
    simp only [StateObservationSyntax.eval, h1]
  | retirementCompleted observer retired value =>
    have h2 := BoolAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [StateObservationSyntax.atoms, member]))
    simp only [StateObservationSyntax.eval, h2]

@[simp] theorem StateObservationSyntax.eval_quote (rho : UnknownNatAssignment) (value : TraceStateObservation.Observation Node) :
    (StateObservationSyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [StateObservationSyntax.quote, StateObservationSyntax.eval, Function.comp_def]

inductive ActionSyntax (n : Nat) where
  | clientRequest (node : Node) (transaction : NatAtom n)
  | changeConfiguration (source : Node) (nodes : Finset Node)
  | appendRetiredCommitted (node : Node)
  | signCommittableMessages (node : Node)
  | appendEntries (source : Node) (destination : Node) (batchEnd : NatAtom n)
  | receive (source : Node) (destination : Node)
  | advanceCommitIndex (node : Node)
  | timeout (node : Node)
  | becomePreVoteCandidate (node : Node)
  | becomeCandidate (node : Node)
  | requestVote (source : Node) (destination : Node)
  | requestPreVote (source : Node) (destination : Node)
  | checkQuorum (node : Node)
  | updateTerm (source : Node) (destination : Node)
  | becomeLeader (node : Node)
  | proposeVote (source : Node) (destination : Node)
  | advanceCommitIndexAndProposeVote (source : Node) (destination : Node)
  deriving DecidableEq

def ActionSyntax.eval (rho : UnknownNatAssignment) : ActionSyntax n -> Action Node Nat
  | .clientRequest node transaction => .clientRequest (node) ((NatAtom.eval rho) (transaction))
  | .changeConfiguration source nodes => .changeConfiguration (source) (nodes)
  | .appendRetiredCommitted node => .appendRetiredCommitted (node)
  | .signCommittableMessages node => .signCommittableMessages (node)
  | .appendEntries source destination batchEnd => .appendEntries (source) (destination) ((NatAtom.eval rho) (batchEnd))
  | .receive source destination => .receive (source) (destination)
  | .advanceCommitIndex node => .advanceCommitIndex (node)
  | .timeout node => .timeout (node)
  | .becomePreVoteCandidate node => .becomePreVoteCandidate (node)
  | .becomeCandidate node => .becomeCandidate (node)
  | .requestVote source destination => .requestVote (source) (destination)
  | .requestPreVote source destination => .requestPreVote (source) (destination)
  | .checkQuorum node => .checkQuorum (node)
  | .updateTerm source destination => .updateTerm (source) (destination)
  | .becomeLeader node => .becomeLeader (node)
  | .proposeVote source destination => .proposeVote (source) (destination)
  | .advanceCommitIndexAndProposeVote source destination => .advanceCommitIndexAndProposeVote (source) (destination)

def ActionSyntax.quote : Action Node Nat -> ActionSyntax n
  | .clientRequest node transaction => .clientRequest (node) ((NatAtom.quote) (transaction))
  | .changeConfiguration source nodes => .changeConfiguration (source) (nodes)
  | .appendRetiredCommitted node => .appendRetiredCommitted (node)
  | .signCommittableMessages node => .signCommittableMessages (node)
  | .appendEntries source destination batchEnd => .appendEntries (source) (destination) ((NatAtom.quote) (batchEnd))
  | .receive source destination => .receive (source) (destination)
  | .advanceCommitIndex node => .advanceCommitIndex (node)
  | .timeout node => .timeout (node)
  | .becomePreVoteCandidate node => .becomePreVoteCandidate (node)
  | .becomeCandidate node => .becomeCandidate (node)
  | .requestVote source destination => .requestVote (source) (destination)
  | .requestPreVote source destination => .requestPreVote (source) (destination)
  | .checkQuorum node => .checkQuorum (node)
  | .updateTerm source destination => .updateTerm (source) (destination)
  | .becomeLeader node => .becomeLeader (node)
  | .proposeVote source destination => .proposeVote (source) (destination)
  | .advanceCommitIndexAndProposeVote source destination => .advanceCommitIndexAndProposeVote (source) (destination)

def ActionSyntax.atoms : ActionSyntax n -> List (NatAtom n)
  | .clientRequest _ transaction => ((transaction).atoms)
  | .changeConfiguration _ _ => []
  | .appendRetiredCommitted _ => []
  | .signCommittableMessages _ => []
  | .appendEntries _ _ batchEnd => ((batchEnd).atoms)
  | .receive _ _ => []
  | .advanceCommitIndex _ => []
  | .timeout _ => []
  | .becomePreVoteCandidate _ => []
  | .becomeCandidate _ => []
  | .requestVote _ _ => []
  | .requestPreVote _ _ => []
  | .checkQuorum _ => []
  | .updateTerm _ _ => []
  | .becomeLeader _ => []
  | .proposeVote _ _ => []
  | .advanceCommitIndexAndProposeVote _ _ => []

theorem ActionSyntax.eval_congr (value : ActionSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | clientRequest node transaction =>
    have h1 := NatAtom.eval_congr (transaction) (same.restrict (by
      intro atom member
      simp [ActionSyntax.atoms, member]))
    simp only [ActionSyntax.eval, h1]
  | changeConfiguration source nodes =>
    rfl
  | appendRetiredCommitted node =>
    rfl
  | signCommittableMessages node =>
    rfl
  | appendEntries source destination batchEnd =>
    have h2 := NatAtom.eval_congr (batchEnd) (same.restrict (by
      intro atom member
      simp [ActionSyntax.atoms, member]))
    simp only [ActionSyntax.eval, h2]
  | receive source destination =>
    rfl
  | advanceCommitIndex node =>
    rfl
  | timeout node =>
    rfl
  | becomePreVoteCandidate node =>
    rfl
  | becomeCandidate node =>
    rfl
  | requestVote source destination =>
    rfl
  | requestPreVote source destination =>
    rfl
  | checkQuorum node =>
    rfl
  | updateTerm source destination =>
    rfl
  | becomeLeader node =>
    rfl
  | proposeVote source destination =>
    rfl
  | advanceCommitIndexAndProposeVote source destination =>
    rfl

@[simp] theorem ActionSyntax.eval_quote (rho : UnknownNatAssignment) (value : Action Node Nat) :
    (ActionSyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [ActionSyntax.quote, ActionSyntax.eval]

inductive ObservationSyntax (n : Nat) where
  | allocated (node : Node) (value : BoolAtom n)
  | joined (node : Node) (value : BoolAtom n)
  | role (node : Node) (value : Role)
  | currentTerm (node : Node) (value : NatAtom n)
  | commitIndex (node : Node) (value : NatAtom n)
  | logLength (node : Node) (value : NatAtom n)
  | submitted (transaction : NatAtom n) (value : BoolAtom n)
  | state (value : StateObservationSyntax n)
  | firstMessage (source : Node) (destination : Node) (value : Option (MessageSyntax n))
  | messageSummary (value : SummarySyntax n)
  | queueLength (destination : Node) (value : NatAtom n)
  | configurationSnapshot (node : Node) (value : List (ConfigurationSyntax n))
  deriving DecidableEq

def ObservationSyntax.eval (rho : UnknownNatAssignment) : ObservationSyntax n -> ModelTrace.Observation
  | .allocated node value => .allocated (node) ((BoolAtom.eval rho) (value))
  | .joined node value => .joined (node) ((BoolAtom.eval rho) (value))
  | .role node value => .role (node) (value)
  | .currentTerm node value => .currentTerm (node) ((NatAtom.eval rho) (value))
  | .commitIndex node value => .commitIndex (node) ((NatAtom.eval rho) (value))
  | .logLength node value => .logLength (node) ((NatAtom.eval rho) (value))
  | .submitted transaction value => .submitted ((NatAtom.eval rho) (transaction)) ((BoolAtom.eval rho) (value))
  | .state value => .state ((StateObservationSyntax.eval rho) (value))
  | .firstMessage source destination value => .firstMessage (source) (destination) ((value).map (MessageSyntax.eval rho))
  | .messageSummary value => .messageSummary ((SummarySyntax.eval rho) (value))
  | .queueLength destination value => .queueLength (destination) ((NatAtom.eval rho) (value))
  | .configurationSnapshot node value => .configurationSnapshot (node) ((value).map (ConfigurationSyntax.eval rho))

def ObservationSyntax.quote : ModelTrace.Observation -> ObservationSyntax n
  | .allocated node value => .allocated (node) ((BoolAtom.quote) (value))
  | .joined node value => .joined (node) ((BoolAtom.quote) (value))
  | .role node value => .role (node) (value)
  | .currentTerm node value => .currentTerm (node) ((NatAtom.quote) (value))
  | .commitIndex node value => .commitIndex (node) ((NatAtom.quote) (value))
  | .logLength node value => .logLength (node) ((NatAtom.quote) (value))
  | .submitted transaction value => .submitted ((NatAtom.quote) (transaction)) ((BoolAtom.quote) (value))
  | .state value => .state ((StateObservationSyntax.quote) (value))
  | .firstMessage source destination value => .firstMessage (source) (destination) ((value).map (MessageSyntax.quote))
  | .messageSummary value => .messageSummary ((SummarySyntax.quote) (value))
  | .queueLength destination value => .queueLength (destination) ((NatAtom.quote) (value))
  | .configurationSnapshot node value => .configurationSnapshot (node) ((value).map (ConfigurationSyntax.quote))

def ObservationSyntax.atoms : ObservationSyntax n -> List (NatAtom n)
  | .allocated _ value => ((value).atoms)
  | .joined _ value => ((value).atoms)
  | .role _ _ => []
  | .currentTerm _ value => ((value).atoms)
  | .commitIndex _ value => ((value).atoms)
  | .logLength _ value => ((value).atoms)
  | .submitted transaction value => ((transaction).atoms) ++ ((value).atoms)
  | .state value => ((value).atoms)
  | .firstMessage _ _ value => (optionAtoms MessageSyntax.atoms (value))
  | .messageSummary value => ((value).atoms)
  | .queueLength _ value => ((value).atoms)
  | .configurationSnapshot _ value => ((value).flatMap ConfigurationSyntax.atoms)

theorem ObservationSyntax.eval_congr (value : ObservationSyntax n) (same : Same left right value.atoms) :
    value.eval left = value.eval right := by
  cases value with
  | allocated node value =>
    have h1 := BoolAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | joined node value =>
    have h1 := BoolAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | role node value =>
    rfl
  | currentTerm node value =>
    have h1 := NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | commitIndex node value =>
    have h1 := NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | logLength node value =>
    have h1 := NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | submitted transaction value =>
    have h0 := NatAtom.eval_congr (transaction) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    have h1 := BoolAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h0, h1]
  | state value =>
    have h0 := StateObservationSyntax.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h0]
  | firstMessage source destination value =>
    have h2 := option_congr MessageSyntax.atoms MessageSyntax.eval MessageSyntax.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h2]
  | messageSummary value =>
    have h0 := SummarySyntax.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h0]
  | queueLength destination value =>
    have h1 := NatAtom.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]
  | configurationSnapshot node value =>
    have h1 := list_congr ConfigurationSyntax.atoms ConfigurationSyntax.eval ConfigurationSyntax.eval_congr (value) (same.restrict (by
      intro atom member
      simp [ObservationSyntax.atoms, member]))
    simp only [ObservationSyntax.eval, h1]

@[simp] theorem ObservationSyntax.eval_quote (rho : UnknownNatAssignment) (value : ModelTrace.Observation) :
    (ObservationSyntax.quote (n := n) value).eval rho = value := by
  cases value <;> simp [ObservationSyntax.quote, ObservationSyntax.eval, List.map_map, Function.comp_def]

-- Trace boundary.

abbrev Instruction (n : Nat) :=
  _root_.TraceValidation.Instruction (ActionSyntax n) (ObservationSyntax n)

abbrev Trace (n : Nat) := List (Instruction n)

def evalInstruction (rho : UnknownNatAssignment) : Instruction n -> ModelTrace.Instruction
  | .action action => .action (action.eval rho)
  | .observation observation => .observation (observation.eval rho)

def instructionAtoms : Instruction n -> List (NatAtom n)
  | .action action => action.atoms
  | .observation observation => observation.atoms

theorem evalInstruction_congr (value : Instruction n) (same : Same left right (instructionAtoms value)) :
    evalInstruction left value = evalInstruction right value := by
  cases value with
  | action action => exact congrArg _root_.TraceValidation.Instruction.action (action.eval_congr same)
  | observation observation =>
    exact congrArg _root_.TraceValidation.Instruction.observation (observation.eval_congr same)

def evalTrace (rho : UnknownNatAssignment) (trace : Trace n) : ModelTrace.Trace :=
  trace.map (evalInstruction rho)

def support (trace : Trace n) : Finset (Fin n) :=
  atomSupport (trace.flatMap instructionAtoms)

theorem support_card (trace : Trace n) : (support trace).card <= n := by
  simpa using Finset.card_le_univ (support trace)

theorem support_iff (trace : Trace n) (index : Fin n) :
    Membership.mem (support trace) index <->
      exists instruction, Membership.mem trace instruction /\
        Membership.mem (instructionAtoms instruction) (NatAtom.unknown index) := by
  simp only [support, atomSupport, List.mem_toFinset, List.mem_flatMap]
  constructor
  next =>
    intro evidence
    cases evidence with
    | intro atom facts =>
      cases facts.1 with
      | intro instruction fields =>
        cases atom with
        | literal _ => simp [NatAtom.indices] at facts
        | unknown other =>
          have same : index = other := by simpa [NatAtom.indices] using facts.2
          subst other
          exact Exists.intro instruction fields
  next =>
    intro evidence
    cases evidence with
    | intro instruction fields =>
      exact Exists.intro (.unknown index) (And.intro (Exists.intro instruction fields)
        (by simp [NatAtom.indices]))

theorem evalTrace_congr (trace : Trace n)
    (agree : forall index, Membership.mem (support trace) index -> left index.val = right index.val) :
    evalTrace left trace = evalTrace right trace :=
  list_congr instructionAtoms evalInstruction evalInstruction_congr trace (same_of_support _ agree)

def toInputInstruction : Instruction n -> ModelTrace.InputInstruction
  | .action action => .action (fun rho => action.eval rho)
  | .observation observation => .observation (fun rho => observation.eval rho)

def toInputTrace (trace : Trace n) : ModelTrace.InputTrace := trace.map toInputInstruction

theorem instantiate_correct (rho : UnknownNatAssignment) (trace : Trace n) :
    ModelTrace.instantiate rho (toInputTrace trace) = evalTrace rho trace := by
  simp only [ModelTrace.instantiate, toInputTrace, evalTrace, List.map_map]
  apply List.map_congr_left
  intro instruction _
  cases instruction <;> rfl

theorem instantiate_congr (trace : Trace n)
    (agree : forall index, Membership.mem (support trace) index -> left index.val = right index.val) :
    ModelTrace.instantiate left (toInputTrace trace) = ModelTrace.instantiate right (toInputTrace trace) := by
  rw [instantiate_correct, instantiate_correct, evalTrace_congr trace agree]

def isAction {A O : Type} : _root_.TraceValidation.Instruction A O -> Bool
  | .action _ => true
  | .observation _ => false

def tags {A O : Type} (trace : List (_root_.TraceValidation.Instruction A O)) : List Bool :=
  trace.map isAction

def actionCount {A O : Type} (trace : List (_root_.TraceValidation.Instruction A O)) : Nat :=
  (tags trace).count true

def observationCount {A O : Type} (trace : List (_root_.TraceValidation.Instruction A O)) : Nat :=
  (tags trace).count false

theorem evalTrace_length (rho : UnknownNatAssignment) (trace : Trace n) :
    (evalTrace rho trace).length = trace.length := List.length_map _

theorem toInputTrace_length (trace : Trace n) : (toInputTrace trace).length = trace.length :=
  List.length_map _

theorem evalTrace_at (rho : UnknownNatAssignment) (instructions : Trace n) (index : Nat) :
    (evalTrace rho instructions)[index]? = instructions[index]?.map (evalInstruction rho) := by
  simp [evalTrace]

theorem evalTrace_tags (rho : UnknownNatAssignment) (trace : Trace n) :
    tags (evalTrace rho trace) = tags trace := by
  simp only [tags, evalTrace, List.map_map]
  apply List.map_congr_left
  intro instruction _
  cases instruction <;> rfl

theorem toInputTrace_tags (trace : Trace n) : tags (toInputTrace trace) = tags trace := by
  simp only [tags, toInputTrace, List.map_map]
  apply List.map_congr_left
  intro instruction _
  cases instruction <;> rfl

theorem evalTrace_counts (rho : UnknownNatAssignment) (trace : Trace n) :
    actionCount (evalTrace rho trace) = actionCount trace /\
      observationCount (evalTrace rho trace) = observationCount trace := by
  simp only [actionCount, observationCount, evalTrace_tags, and_self]

theorem toInputTrace_counts (trace : Trace n) :
    actionCount (toInputTrace trace) = actionCount trace /\
      observationCount (toInputTrace trace) = observationCount trace := by
  simp only [actionCount, observationCount, toInputTrace_tags, and_self]

def quoteInstruction : ModelTrace.Instruction -> Instruction 0
  | .action action => .action (ActionSyntax.quote action)
  | .observation observation => .observation (ObservationSyntax.quote observation)

def quoteTrace (trace : ModelTrace.Trace) : Trace 0 := trace.map quoteInstruction

@[simp] theorem eval_quoteInstruction (rho : UnknownNatAssignment) (instruction : ModelTrace.Instruction) :
    evalInstruction rho (quoteInstruction instruction) = instruction := by
  cases instruction <;> simp [quoteInstruction, evalInstruction]

@[simp] theorem eval_quoteTrace (rho : UnknownNatAssignment) (trace : ModelTrace.Trace) :
    evalTrace rho (quoteTrace trace) = trace := by
  simp [evalTrace, quoteTrace, List.map_map, Function.comp_def]

theorem quote_support (trace : ModelTrace.Trace) : support (quoteTrace trace) = {} := by
  apply Finset.ext
  intro index
  exact Fin.elim0 index

theorem instantiate_quote (rho : UnknownNatAssignment) (trace : ModelTrace.Trace) :
    ModelTrace.instantiate rho (toInputTrace (quoteTrace trace)) = trace := by
  rw [instantiate_correct, eval_quoteTrace]

theorem quote_injective : Function.Injective quoteTrace := by
  intro left right same
  simpa using congrArg (evalTrace (fun _ => 0)) same

section Execution

variable [Bootstrap Node]

def Follows (rho : UnknownNatAssignment) (state : ModelTrace.ModelState) (trace : Trace n) : Prop :=
  ModelTrace.Follows rho state (toInputTrace trace)

def Satisfiable (trace : Trace n) : Prop :=
  ModelTrace.Satisfiable (toInputTrace trace)

theorem follows_iff (rho : UnknownNatAssignment) (state : ModelTrace.ModelState) (trace : Trace n) :
    Follows rho state trace <-> ModelTrace.ConcreteFollows state (evalTrace rho trace) := by
  simp only [Follows, ModelTrace.Follows, instantiate_correct]

theorem satisfiable_iff (trace : Trace n) :
    Satisfiable trace <->
      exists rho : UnknownNatAssignment, exists state : ModelTrace.ModelState,
        ModelTrace.ConcreteFollows state (evalTrace rho trace) := by
  simp only [Satisfiable, ModelTrace.satisfiable_iff, ModelTrace.Follows, instantiate_correct]

theorem follows_congr (state : ModelTrace.ModelState) (trace : Trace n)
    (agree : forall index, Membership.mem (support trace) index -> left index.val = right index.val) :
    Follows left state trace <-> Follows right state trace := by
  rw [follows_iff, follows_iff, evalTrace_congr trace agree]

theorem follows_action (rho : UnknownNatAssignment) (state : ModelTrace.ModelState)
    (action : ActionSyntax n) (rest : Trace n) :
    Follows rho state (.action action :: rest) <->
      Enabled state (action.eval rho) /\ Follows rho (CCFRaft.next state (action.eval rho)) rest :=
  Iff.rfl

theorem follows_observation (rho : UnknownNatAssignment) (state : ModelTrace.ModelState)
    (observation : ObservationSyntax n) (rest : Trace n) :
    Follows rho state (.observation observation :: rest) <->
      (observation.eval rho).Holds state /\ Follows rho state rest :=
  Iff.rfl

theorem adjacent_observations (rho : UnknownNatAssignment) (state : ModelTrace.ModelState)
    (first second : ObservationSyntax n) (rest : Trace n) :
    Follows rho state (.observation first :: .observation second :: rest) <->
      (first.eval rho).Holds state /\ (second.eval rho).Holds state /\ Follows rho state rest :=
  Iff.rfl

theorem ground_follows_iff (rho : UnknownNatAssignment) (state : ModelTrace.ModelState)
    (trace : ModelTrace.Trace) :
    Follows rho state (quoteTrace trace) <-> ModelTrace.ConcreteFollows state trace := by
  rw [follows_iff, eval_quoteTrace]

theorem ground_satisfiable_iff (trace : ModelTrace.Trace) :
    Satisfiable (quoteTrace trace) <->
      exists state : ModelTrace.ModelState, ModelTrace.ConcreteFollows state trace := by
  rw [satisfiable_iff]
  simp only [eval_quoteTrace]
  constructor
  next =>
    intro evidence
    cases evidence with
    | intro rho witness => exact witness
  next =>
    intro witness
    exact Exists.intro (fun _ => 0) witness

end Execution

namespace Regression

theorem all_tag_quotes (rho : UnknownNatAssignment) (action : Action Node Nat)
    (observation : ModelTrace.Observation) (content : EntryContent Node Nat) (entry : Entry Node Nat)
    (packet : Message Node Nat) (summary : TraceMessageSummary.Summary Node)
    (stored : TraceStateObservation.Observation Node) (configuration : Configuration Node) :
    (ActionSyntax.quote (n := 2) action).eval rho = action /\
    (ObservationSyntax.quote (n := 2) observation).eval rho = observation /\
    (ContentSyntax.quote (n := 2) content).eval rho = content /\
    (EntrySyntax.quote (n := 2) entry).eval rho = entry /\
    (MessageSyntax.quote (n := 2) packet).eval rho = packet /\
    (SummarySyntax.quote (n := 2) summary).eval rho = summary /\
    (StateObservationSyntax.quote (n := 2) stored).eval rho = stored /\
    (ConfigurationSyntax.quote (n := 2) configuration).eval rho = configuration := by
  simp

def shared (node : Node) : Trace 1 :=
  [.action (.clientRequest node (.unknown 0)),
    .observation (.submitted (.unknown 0) (.isZero (.unknown 0)))]

theorem shared_nat_bool [Bootstrap Node] (rho : UnknownNatAssignment) (state : ModelTrace.ModelState) (node : Node)
    (enabled : Enabled state (.clientRequest node (rho 0))) :
    Follows rho state (shared node) <-> rho 0 = 0 := by
  change (Enabled state (.clientRequest node (rho 0)) /\
    (decide (Membership.mem (CCFRaft.next state (.clientRequest node (rho 0))).submittedTxIds (rho 0)) =
      decide (rho 0 = 0) /\ True)) <-> _
  simp [CCFRaft.next, enabled]

theorem nonbinary_bool (value : Nat) :
    (BoolAtom.isZero (.unknown 0) : BoolAtom 1).eval (fun _ => value) = decide (value = 0) := rfl

theorem bool_seven :
    (BoolAtom.isZero (.unknown 0) : BoolAtom 1).eval (fun _ => 7) = false := by
  decide +kernel

def aliases (node : Node) : Trace 3 :=
  [.observation (.currentTerm node (.unknown 0)), .observation (.currentTerm node (.unknown 1))]

theorem distinct_names_may_alias (node : Node) :
    evalTrace (fun _ => 7) (aliases node) =
      [.observation (.currentTerm node 7), .observation (.currentTerm node 7)] /\
      support (aliases node) = {0, 1} := by
  constructor
  next => rfl
  next =>
    simp [support, atomSupport, aliases, instructionAtoms, ObservationSyntax.atoms,
      NatAtom.atoms, NatAtom.indices]

theorem unused_index (rho : UnknownNatAssignment) (trace : Trace n) (index : Fin n)
    (unused : Not (Membership.mem (support trace) index)) (value : Nat) :
    evalTrace (Function.update rho index.val value) trace = evalTrace rho trace := by
  apply evalTrace_congr
  intro other member
  apply Function.update_of_ne
  intro equal
  have same : other = index := Fin.ext equal
  apply unused
  rw [<- same]
  exact member

theorem unused_name_example (rho : UnknownNatAssignment) (node : Node) :
    evalTrace (Function.update rho 2 1000000) (aliases node) = evalTrace rho (aliases node) := by
  apply unused_index rho (aliases node) (2 : Fin 3)
  rw [(distinct_names_may_alias node).2]
  decide +kernel

theorem some_zero (rho : UnknownNatAssignment) (node : Node) :
    (StateObservationSyntax.retirementIndex node (some (.literal 0)) : StateObservationSyntax 1).eval rho =
      .retirementIndex node (some 0) /\
    Not ((StateObservationSyntax.retirementIndex node (some (.literal 0)) : StateObservationSyntax 1).eval rho =
      (StateObservationSyntax.retirementIndex node none : StateObservationSyntax 1).eval rho) := by
  simp [StateObservationSyntax.eval, NatAtom.eval]

theorem adjacent_conflict [Bootstrap Node] (node : Node) (first second : Nat) (different : Not (first = second)) :
    Not (Satisfiable ([.observation (.commitIndex node (.literal first)),
      .observation (.commitIndex node (.literal second))] : Trace 0)) := by
  rw [satisfiable_iff]
  intro evidence
  cases evidence with
  | intro rho witness =>
    cases witness with
    | intro state follows =>
      change (state.nodes node).commitIndex = first /\ (state.nodes node).commitIndex = second /\ True at follows
      exact different (follows.1.symm.trans follows.2.1)

theorem empty_configuration_disabled [Bootstrap Node] (node : Node) :
    Not (Satisfiable ([.action (.changeConfiguration node {})] : Trace 0)) := by
  rw [satisfiable_iff]
  intro evidence
  cases evidence with
  | intro rho witness =>
    cases witness with
    | intro state follows =>
      change Enabled state (.changeConfiguration node {}) /\ True at follows
      simpa [Enabled] using follows.1

theorem malformed_destination [Bootstrap Node] (source other : Node) (different : Not (source = other)) :
    Satisfiable (quoteTrace [
      .observation (.allocated source false),
      .observation (.queueLength source 4),
      .observation (.firstMessage source source (some (ModelTrace.regressionPacket source other)))]) := by
  apply (ground_satisfiable_iff _).mpr
  cases ModelTrace.malformed_self_duplicates source other different with
  | intro state spec => exact Exists.intro state spec.2.2

theorem ordered_snapshot (rho : UnknownNatAssignment) (node : Node) :
    evalTrace rho (quoteTrace [.observation (.configurationSnapshot node
      [{ index := 0, nodes := {} }, { index := 2, nodes := {node} },
        { index := 2, nodes := {node} }, { index := 1, nodes := {} }])]) =
      [.observation (.configurationSnapshot node
        [{ index := 0, nodes := {} }, { index := 2, nodes := {node} },
          { index := 2, nodes := {node} }, { index := 1, nodes := {} }])] :=
  eval_quoteTrace rho _

def lengthSummary (source destination : Node) (length : NatAtom 1) : Trace 1 :=
  [.observation (.messageSummary (.appendEntriesRequest
    { term := .literal 0, prevLogIndex := .literal 0, entriesLength := length,
      leaderCommit := .literal 0, source, destination }))]

theorem summary_constant_shape (source destination : Node) (length : NatAtom 1) :
    (lengthSummary source destination length).length = 1 /\
      ((lengthSummary source destination length).flatMap instructionAtoms).length = 4 := by
  constructor <;> rfl

theorem million_summary (source destination : Node) :
    evalTrace (fun _ => 1000000) (lengthSummary source destination (.unknown 0)) =
      [.observation (.messageSummary (.appendEntriesRequest
        { term := 0, prevLogIndex := 0, entriesLength := 1000000,
          leaderCommit := 0, source, destination }))] /\
      support (lengthSummary source destination (.unknown 0)) = {0} := by
  constructor
  next => rfl
  next =>
    simp [support, atomSupport, lengthSummary, instructionAtoms, ObservationSyntax.atoms,
      SummarySyntax.atoms, AppendSummarySyntax.atoms, NatAtom.atoms, NatAtom.indices]

end Regression

end CCFRaft.Sparse.ModelInputSyntax

run_cmd do
  let mut checked := 0
  for (name, info) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ModelInputSyntax).isPrefixOf name then
      match info with
      | .axiomInfo _ => throwError "explicit ModelInputSyntax axiom: {name}"
      | _ =>
        checked := checked + 1
        for axiomName in (<- Lean.collectAxioms name) do
          unless axiomName == ``propext || axiomName == ``Classical.choice ||
              axiomName == ``Quot.sound do
            throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ModelInputSyntax: {checked} declarations passed the transitive axiom gate."
