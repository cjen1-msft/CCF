import Sparse.QueueClause
import Sparse.QueueModel
import Sparse.BijectiveIntegerLog
import Sparse.QueueAccounting
import Sparse.MessageCodec
import Sparse.PartialQueue
import Sparse.Configuration
import Sparse.IntervalCompletion
import Sparse.ConfigSignature
import Sparse.Readback
import Sparse.NodeSetCodec
import Sparse.PacketQueue
import Sparse.QueueCountBounds

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.ArrayLog.compiled_exists_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.decode_formula,
      ``CCFRaft.Sparse.BijectiveIntegerLog.source_clause_iff,
      ``CCFRaft.Sparse.BijectiveIntegerLog.raw_compiled_exists_iff,
      ``CCFRaft.Sparse.Queue.arbitrary_initial_witness,
      ``CCFRaft.Sparse.QueueModel.actual_action_bisimulation,
      ``CCFRaft.Sparse.QueueModel.runActions_lift,
      ``CCFRaft.Sparse.QueueCounts.source_prefix_counts_exact,
      ``CCFRaft.Sparse.QueueStream.stream_exists_iff,
      ``CCFRaft.Sparse.CountedQueue.source_counted_exists_iff,
      ``CCFRaft.Sparse.IntegerQueue.raw_exists_iff,
      ``CCFRaft.Sparse.SignedQueue.signed_exists_iff,
      ``CCFRaft.Sparse.QueueClause.compile_length,
      ``CCFRaft.Sparse.QueueClause.clause_fields_iff,
      ``CCFRaft.Sparse.QueueAccounting.initial_accounts_exact,
      ``CCFRaft.Sparse.QueueAccounting.bounded_prefix_exact,
      ``CCFRaft.Sparse.MessageCodec.decode_encode_message,
      ``CCFRaft.Sparse.MessageCodec.encode_decode_message,
      ``CCFRaft.Sparse.MessageCodec.message_eq_iff,
      ``CCFRaft.Sparse.PartialQueue.partial_family_iff,
      ``CCFRaft.Sparse.Configuration.finite_completion_iff,
      ``CCFRaft.Sparse.IntervalCompletion.finite_completion_iff,
      ``CCFRaft.Sparse.IntervalCompletion.cuts_card_le,
      ``CCFRaft.Sparse.ConfigSignature.joint_finite_completion_iff,
      ``CCFRaft.Sparse.Readback.finite_readback_iff,
      ``CCFRaft.Sparse.Readback.compiled_readback_iff,
      ``CCFRaft.Sparse.NodeSetCodec.nodeSetEquiv,
      ``CCFRaft.Sparse.NodeSetCodec.encode_insert,
      ``CCFRaft.Sparse.NodeSetCodec.decode_card,
      ``CCFRaft.Sparse.PacketQueue.compiled_exists_iff,
      ``CCFRaft.Sparse.QueueCountBounds.bounded_holds_iff,
      ``CCFRaft.Sparse.QueueCountBounds.bounded_compiled_exists_iff,
      ``CCFRaft.Sparse.QueueClause.compiled_exists_iff] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom in {theoremName}: {name}"
  Lean.logInfo "Sparse foundation audit passed."
