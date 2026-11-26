module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import ConsensusCoverage.DelayedNominationRead
import all ConsensusCoverage.FrontierWitnesses
import all ConsensusCoverage.JointWitnesses
import all ConsensusCoverage.PairWitnesses

namespace ConsensusCoverage.DelayedNomination

open ActionProfile FrontierRows Consensus Consensus.Model Consensus.Model.Node

set_option maxRecDepth 8192

private def nominate : Command := .input 0 .nominateSuccessor

private def appendConfig (index : Nat) : Command :=
  .input 0 (.append [{content := .transaction 1 {configuration := some {0}}},
    {content := .signature, flushes := [(1, index)]}, {content := .signature}])

private def warmup : List Command := [
  .input 0 (.append [{content := .signature}]), .input 0 (.sendEntries 1 2),
  .deliver 0 1, .deliver 1 0, .input 0 (.sendEntries 1 2), .deliver 0 1, .deliver 1 0]

private def replayTwo (cmds : List Command) : List Step :=
  let r : Run := ⟨{0, 1}, [0, 1], cmds⟩
  ((JointWitnesses.recorded r (by
    change ({0, 1} : CCF.Finset NodeID).Nonempty ∧ ([0, 1] : List NodeID).Nodup
    decide)).getD []).map Subtype.val

private def observe (s : Step) : (Bool × Bool) × Bool × Bool × Bool :=
  (StateCoverage.read s.cfg s.before s.past, test s.cfg s.before s.act s.after s.past,
    sends s.before s.act, ReducedQuestions.answer s.before s.after .message)

private theorem coldFresh :
    ((replayTwo [appendConfig 3, .deliver 0 1, nominate]).getLast?).map observe =
      some ((true, true), true, true, true) := by decide +kernel

private theorem coldRepeated :
    ((replayTwo [appendConfig 3, nominate, .deliver 0 1, nominate]).getLast?).map observe =
      some ((true, true), true, true, false) := by decide +kernel

private theorem warmFresh :
    ((replayTwo (warmup ++ [appendConfig 4, .deliver 0 1, nominate])).getLast?).map observe =
      some ((false, true), true, true, true) := by decide +kernel

private theorem warmRepeated :
    ((replayTwo (warmup ++ [appendConfig 4, nominate, .deliver 0 1, nominate])).getLast?).map observe =
      some ((false, true), true, true, false) := by decide +kernel

end ConsensusCoverage.DelayedNomination
