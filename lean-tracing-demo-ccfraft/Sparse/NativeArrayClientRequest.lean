-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeArrayLeaderLogWrite
import Sparse.NativeArrayVoteState

set_option autoImplicit false

namespace CCFRaft.NativeArrayClientRequest

open NativeArrayCheckQuorum NativeArrayLeaderLogWrite

variable {N T : Type} [DecidableEq N] [DecidableEq T] [Bootstrap N]

def enabled (frame : NativeArrayVote.Frame N T) (source : N) (transaction : T)
    (output : Local N T) : Prop :=
  let row := get frame.nodes source
  (frame.nodes source).isSome = true /\
    row.role = .leader /\
    row.membershipState ≠ .retiredCommitted /\
    transaction ∉ frame.globals.submittedTxIds /\
    output.membershipState ≠ .retiredCommitted

def request (frame : NativeArrayVote.Frame N T) (source : N) (transaction : T)
    (output : Local N T) (completed : Finset N) : NativeArrayVote.Frame N T :=
  { frame with
    nodes := Function.update frame.nodes source (some output)
    globals :=
      { frame.globals with
        submittedTxIds := insert transaction frame.globals.submittedTxIds
        retirementCompleted := Function.update frame.globals.retirementCompleted source completed } }

inductive Request (frame : NativeArrayVote.Frame N T) (source : N) (transaction : T) :
    NativeArrayVote.Frame N T -> Prop where
  | submit (retirement signature retired : Option Nat) (completed : Finset N)
      (retirementCorrect :
        retirementIndexInLog source
          (appendRow (get frame.nodes source) (.transaction transaction)).log.decode = retirement)
      (signatureCorrect :
        retirement.bind
          (retirementCommittableIndexInLog
            (appendRow (get frame.nodes source) (.transaction transaction)).log.decode) = signature)
      (retiredCorrect :
        retiredCommittedIndexInLog source
          (appendRow (get frame.nodes source) (.transaction transaction)).log.decode = retired)
      (completedCorrect :
        retirementCompletedNodes
            (refreshRow (get frame.nodes source) (.transaction transaction)
              retirement signature retired).log.decode
            (refreshRow (get frame.nodes source) (.transaction transaction)
              retirement signature retired).commit =
          completed)
      (allowed :
        enabled frame source transaction
          (refreshRow (get frame.nodes source) (.transaction transaction)
            retirement signature retired)) :
      Request frame source transaction
        (request frame source transaction
          (refreshRow (get frame.nodes source) (.transaction transaction)
            retirement signature retired)
          completed)

end CCFRaft.NativeArrayClientRequest

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeArrayClientRequest).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
