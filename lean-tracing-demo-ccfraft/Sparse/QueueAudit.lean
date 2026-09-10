import Sparse.QueueModel

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.Queue.take_spec,
      ``CCFRaft.Sparse.Queue.enqueue_correct,
      ``CCFRaft.Sparse.Queue.realizability,
      ``CCFRaft.Sparse.Queue.sum_partition_length,
      ``CCFRaft.Sparse.Queue.reply_correct,
      ``CCFRaft.Sparse.Queue.malformed_receive_rejected,
      ``CCFRaft.Sparse.Queue.arbitrary_initial_witness,
      ``CCFRaft.Sparse.QueueModel.actual_action_bisimulation,
      ``CCFRaft.Sparse.QueueModel.runActions_lift,
      ``CCFRaft.Sparse.QueueModel.nonconsuming_stepdown,
      ``CCFRaft.Sparse.QueueModel.malformed_updateTerm_difference] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
  Lean.logInfo "Sparse queue correspondence audit passed."
