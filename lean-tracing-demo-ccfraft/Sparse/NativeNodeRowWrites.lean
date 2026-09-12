-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeDefinitions

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure NodeRowTerms (width : PNat) where
  role : Expr .int
  newFollower : Expr .bool
  logLength : Expr .int
  commit : Expr .int
  currentTerm : Expr .int
  logEntries : Expr (.array .int (entryTy width))
  retirementIndex : Expr optionalIntTy
  retirementCommittableIndex : Expr optionalIntTy
  retiredCommittedIndex : Expr optionalIntTy
  votedFor : Expr optionalIntTy
  votesGranted : Expr (.bits width)
  preVotesGranted : Expr (.bits width)
  membershipState : Expr .int
  sentIndex : Expr (.array .int .int)
  matchIndex : Expr (.array .int .int)

def nodeRowSnapshot {width : PNat} (columns : Columns) (node : Fin width) : NodeRowTerms width :=
  { role := read columns columns.role node.val (.integer 0)
    newFollower := read columns columns.newFollower node.val (.boolean true)
    logLength := length columns node.val
    commit := NativeEncode.commit columns node.val
    currentTerm := read columns columns.currentTerm node.val (.integer 0)
    logEntries := .select (.free (.array .int (.array .int (entryTy width))) columns.logEntries) (.integer node.val)
    retirementIndex := read columns columns.retirementIndex node.val (.inl .unit)
    retirementCommittableIndex := read columns columns.retirementCommittableIndex node.val (.inl .unit)
    retiredCommittedIndex := read columns columns.retiredCommittedIndex node.val (.inl .unit)
    votedFor := read columns columns.votedFor node.val (.inl .unit)
    votesGranted := read columns columns.votesGranted node.val (.bits 0)
    preVotesGranted := read columns columns.preVotesGranted node.val (.bits 0)
    membershipState := read columns columns.membershipState node.val (.integer 0)
    sentIndex := read columns columns.sentIndex node.val (.defaultValue (.array .int .int))
    matchIndex := read columns columns.matchIndex node.val (.defaultValue (.array .int .int)) }

def nodeRowWriteDefinitions {width : PNat} (columns : Columns) (node : Fin width)
    (values : NodeRowTerms width) : List TypedDefinition :=
  let store {sort : Ty} (column : Nat) (value : Expr sort) : Expr (.array .int sort) :=
    .store (.free (.array .int sort) column) (.integer node.val) value
  [⟨_, store columns.allocated (.boolean true)⟩,
    ⟨_, store columns.role values.role⟩,
    ⟨_, store columns.newFollower values.newFollower⟩,
    ⟨_, store columns.logLength values.logLength⟩,
    ⟨_, store columns.commit values.commit⟩,
    ⟨_, store columns.currentTerm values.currentTerm⟩,
    ⟨_, store columns.logEntries values.logEntries⟩,
    ⟨_, store columns.retirementIndex values.retirementIndex⟩,
    ⟨_, store columns.retirementCommittableIndex values.retirementCommittableIndex⟩,
    ⟨_, store columns.retiredCommittedIndex values.retiredCommittedIndex⟩,
    ⟨_, store columns.votedFor values.votedFor⟩,
    ⟨_, store columns.votesGranted values.votesGranted⟩,
    ⟨_, store columns.preVotesGranted values.preVotesGranted⟩,
    ⟨_, store columns.membershipState values.membershipState⟩,
    ⟨_, store columns.sentIndex values.sentIndex⟩,
    ⟨_, store columns.matchIndex values.matchIndex⟩]

def nodeRowWriteColumns (columns : Columns) (base : Nat) : Columns :=
  { columns with
    allocated := base, role := base + 1, newFollower := base + 2,
    logLength := base + 3, commit := base + 4, currentTerm := base + 5,
    logEntries := base + 6, retirementIndex := base + 7,
    retirementCommittableIndex := base + 8, retiredCommittedIndex := base + 9,
    votedFor := base + 10, votesGranted := base + 11, preVotesGranted := base + 12,
    membershipState := base + 13, sentIndex := base + 14, matchIndex := base + 15 }

def writeNodeRow {width : PNat} (node : Fin width) (values : NodeRowTerms width) : EncodeM width Unit := do
  let before <- get
  let items := nodeRowWriteDefinitions before.toColumns node values
  if items.all (fun item => item.2.symbols.all (fun symbol => symbol.2 < before.next)) then
    let _ <- definitions items
    modify fun after => { after with toColumns := nodeRowWriteColumns before.toColumns before.next }
  else
    throw "internal encoder error: row write references an unallocated SMT symbol"

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
