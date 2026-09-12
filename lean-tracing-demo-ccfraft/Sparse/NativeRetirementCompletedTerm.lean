-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementIndexEncoding
import Sparse.NativeArrayRetirementCompleted

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementCompletedMemberTerm {context : List Ty} {width : PNat}
    (node : Fin width) (current : Term context .int) (members : Term context (.bits width))
    (first retirement retired : Term context .int) : Term context .bool :=
  all [
    .le (.integer 0) first,
    lt first current,
    .not (.bit members node),
    .equal retired (.integer (-1)),
    .le (.integer 0) retirement]

theorem retirement_completed_member_term_eval {context : List Ty} {width : PNat}
    (assignment : Assignment) (locals : Locals context) (node : Fin width)
    (current : Term context .int) (members : Term context (.bits width))
    (first retirement retired : Term context .int) (currentNat : Nat)
    (membersSet : Finset (Fin width))
    (firstChoice retirementChoice retiredChoice : Option Nat)
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameMembers : members.eval assignment locals = encodeBits membersSet)
    (sameFirst : first.eval assignment locals = firstMatchValue firstChoice)
    (sameRetirement : retirement.eval assignment locals = firstMatchValue retirementChoice)
    (sameRetired : retired.eval assignment locals = firstMatchValue retiredChoice) :
    (retirementCompletedMemberTerm node current members first retirement retired).eval
        assignment locals = true <->
      (exists firstIndex, firstChoice = some firstIndex /\ firstIndex < currentNat) /\
        node ∉ membersSet /\ retiredChoice = none /\ retirementChoice.isSome = true := by
  cases firstChoice <;> cases retirementChoice <;> cases retiredChoice <;>
    simp [retirementCompletedMemberTerm, all, Term.eval, lt, sameCurrent, sameMembers,
      sameFirst, sameRetirement, sameRetired, firstMatchValue]
  all_goals
    intro _
    change (encodeBits membersSet).getLsbD node.val = false <-> node ∉ membersSet
    rw [encode_bits_bit]
    simp

theorem retirement_completed_member_term_correct {context : List Ty} {width : PNat}
    [Bootstrap (Fin width)] (assignment : Assignment) (locals : Locals context)
    (node : Fin width) (current : Term context .int)
    (members : Term context (.bits width))
    (first retirement retired : Term context .int)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commit currentNat : Nat)
    (membersSet : Finset (Fin width))
    (firstChoice retirementChoice retiredChoice : Option Nat)
    (sameCurrent : current.eval assignment locals = (currentNat : Int))
    (sameMembers : members.eval assignment locals = encodeBits membersSet)
    (sameFirst : first.eval assignment locals = firstMatchValue firstChoice)
    (sameRetirement : retirement.eval assignment locals = firstMatchValue retirementChoice)
    (sameRetired : retired.eval assignment locals = firstMatchValue retiredChoice)
    (currentIndex : NativeArrayCheckQuorum.CurrentIndex log commit currentNat)
    (configuration : NativeArrayConfiguration.At log currentNat membersSet)
    (firstCorrect : NativeArrayFirstMatch.FirstMatch
      (NativeArrayRetirementIndex.virtualLog (NativeArrayLogWrite.take log commit))
      (NativeArrayRetirementIndex.includes node) firstChoice)
    (retirementCorrect :
      retirementIndexInLog node (NativeArrayLogWrite.take log commit).decode =
        retirementChoice)
    (retiredCorrect : NativeArrayFirstMatch.FirstMatch
      (NativeArrayLogWrite.take log commit)
      (fun _ entry => Sparse.RetirementScan.namesRetiredNode node entry) retiredChoice) :
    (retirementCompletedMemberTerm node current members first retirement retired).eval
        assignment locals = true <->
      node ∈ retirementCompletedNodes log.decode commit := by
  exact (retirement_completed_member_term_eval assignment locals node current members
    first retirement retired currentNat membersSet firstChoice retirementChoice retiredChoice
    sameCurrent sameMembers sameFirst sameRetirement sameRetired).trans
      (NativeArrayRetirementCompleted.completed_nodes_from_prefix_scans_correct
        log commit currentNat membersSet node firstChoice retirementChoice retiredChoice
        currentIndex configuration firstCorrect retirementCorrect retiredCorrect).symm

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
