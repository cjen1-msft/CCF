# Chunks

Made by `chunks.py 60` at commit 6961d0f6f.

## Chunk 1: SafetyInvariant.lean lines 3768-4727, 18 theorems, 63 splits (classes)

- `campaign_summary` (line 3768): 16
- `quiet_summary` (line 3830): 1
- `observe_bumping` (line 3908): 3
- `becomeCandidate_result` (line 3932): 2
- `canStartElection_engaged` (line 3948): 3
- `voteRequest_summary` (line 4044): 5
- `preVoteRequest_summary` (line 4102): 1
- `initAsBackup_summary` (line 4148): 5
- `elect_result` (line 4193): 1
- `voteResponse_summary` (line 4206): 2
- `preVoteResponse_summary` (line 4236): 1
- `observe_response` (line 4264): 2
- `appendEntriesResponse_summary` (line 4279): 4
- `aeReply_summary` (line 4529): 1
- `appendEntriesRequest_summary` (line 4562): 9
- `BatchState.push` (line 4596): 1
- `sendEntries_batch` (line 4655): 1
- `appendBatch_summary` (line 4673): 5

## Chunk 2: SafetyInvariant.lean lines 4816-5687, 28 theorems, 61 splits (classes)

- `Led.mono` (line 4816): 1
- `Committed.append` (line 4829): 1
- `Backed.mono` (line 4849): 1
- `Backed.weaken` (line 4856): 1
- `Seen.cons` (line 4894): 1
- `suffix_comparable` (line 4902): 1
- `led_single` (line 4965): 1
- `initial_canon` (line 4972): 1
- `inv_initial` (line 4982): 14
- `Everywhere.cons` (line 5100): 1
- `Now.nonempty` (line 5131): 1
- `termAt_mono` (line 5177): 2
- `termAt_le_of_mem` (line 5190): 1
- `signature_pos` (line 5198): 1
- `Led.two_le` (line 5226): 1
- `Led.elected` (line 5234): 1
- `canon_chain` (line 5241): 1
- `vote_unique` (line 5295): 7
- `Committed.shape` (line 5343): 1
- `committed_comparable` (line 5392): 5
- `backing_split` (line 5421): 6
- `Doomed.cons'` (line 5470): 1
- `primaryState_log_prefix` (line 5497): 1
- `Wins.facts` (line 5504): 2
- `Ctx.seen_after` (line 5582): 2
- `Ctx.received` (line 5599): 1
- `Ctx.snap_of_committed` (line 5634): 1
- `Ctx.post_two` (line 5674): 3

## Chunk 3: SafetyInvariant.lean lines 5689-6429, 22 theorems, 58 splits (classes)

- `Ctx.elected_after` (line 5689): 1
- `Ctx.electStep` (line 5699): 3
- `Ctx.led_after` (line 5723): 2
- `Ctx.led_other` (line 5733): 1
- `Ctx.canon_after` (line 5740): 1
- `Advance.facts` (line 5760): 1
- `vals_upToDate` (line 5773): 1
- `Ctx.rooted` (line 5924): 3
- `Ctx.sorted` (line 5965): 3
- `Ctx.active` (line 5986): 1
- `Ctx.term_mono` (line 5992): 3
- `Ctx.campaign_votes` (line 6050): 2
- `Ctx.wins_elect` (line 6097): 1
- `Ctx.led_cur` (line 6136): 6
- `Ctx.leader_led` (line 6154): 2
- `Ctx.doomed_absurd` (line 6163): 10
- `Ctx.pre_split` (line 6271): 1
- `Ctx.campaign_backed` (line 6292): 2
- `Ctx.candidate` (line 6313): 7
- `Ctx.elect_backed` (line 6350): 4
- `suffix_of_cons_suffix` (line 6403): 1
- `seen_split` (line 6411): 2

## Chunk 4: SafetyInvariant.lean lines 6438-6930, 12 theorems, 58 splits (classes)

- `core` (line 6438): 28
- `agree_or_contained` (line 6595): 4
- `Ctx.old_step_in_new` (line 6675): 2
- `Ctx.old_in_new` (line 6704): 1
- `Ctx.old_complete` (line 6721): 1
- `Ctx.new_old_unique` (line 6731): 4
- `Ctx.election_safety` (line 6770): 3
- `Ctx.keep_log` (line 6779): 2
- `Ctx.leader_logs` (line 6807): 3
- `Ctx.old_led_actor` (line 6831): 1
- `Ctx.canon_mono` (line 6839): 5
- `Ctx.anchor` (line 6887): 4

## Chunk 5: SafetyInvariant.lean lines 6932-7889, 19 theorems, 64 splits (classes)

- `Ctx.new_in_elected` (line 6932): 14
- `Ctx.completeness` (line 7042): 1
- `Backed.transfer` (line 7062): 1
- `Ctx.post_led` (line 7091): 1
- `Ctx.advance_backed` (line 7120): 6
- `Ctx.keep_backed` (line 7204): 2
- `Ctx.accept_backed` (line 7233): 3
- `Ctx.commit_backed` (line 7291): 13
- `Ctx.accept_persist` (line 7402): 5
- `Ctx.persist_pre` (line 7465): 1
- `Ctx.persist` (line 7497): 5
- `Ctx.match_ack` (line 7517): 3
- `Ctx.rv_stable` (line 7538): 2
- `Ctx.old_message` (line 7577): 1
- `Ctx.new_message` (line 7601): 1
- `Ctx.messages` (line 7655): 1
- `Ctx.message_terms` (line 7661): 2
- `CommittedLogs.committed_logs_prefix_of_le` (line 7844): 1
- `CommittedLogs.committed_logs_prefix` (line 7868): 1

## Chunk 6: SafetyInvariant.lean lines 1143-2358, 31 theorems, 63 splits

- `Concrete.mem_replaceNode` (line 1143): 1
- `Concrete.replaceNode_keys` (line 1158): 1
- `Concrete.observeTerm_commitIndex` (line 1192): 3
- `Ledger.entryAt_mem` (line 1234): 1
- `Ledger.isSignatureAtTrue` (line 1270): 1
- `Ledger.maxCommittableIndexPositiveIsSignature` (line 1324): 5
- `Ledger.signatureIndex_le_maxCommittableIndex` (line 1367): 4
- `Ledger.maxCommittableIndex_le_of_prefix` (line 1438): 1
- `Ledger.isSignatureAt_take_of_le` (line 1453): 2
- `Ledger.fromLeader_loop` (line 1568): 3
- `Ledger.handleAppendEntiresFromPrimary_eq` (line 1638): 1
- `NodeInvariant.reachable` (line 1709): 5
- `keys_nodup` (line 1744): 2
- `find_of_mem` (line 1761): 4
- `Keeps.guard'` (line 1807): 1
- `Keeps.ite'` (line 1840): 1
- `Keeps.foldlM'` (line 1848): 1
- `Sends.bind'` (line 1873): 1
- `Sends.ite'` (line 1900): 1
- `Sends.guard'` (line 1908): 1
- `Sends.forIn'` (line 1935): 3
- `Sends.foldlM'` (line 1958): 1
- `exec_of_reachable` (line 1984): 1
- `Exec.reachable` (line 1996): 1
- `Exec.suffix` (line 2008): 3
- `mem_removeOne` (line 2033): 3
- `LocalTransition.ofStep` (line 2046): 2
- `LocalTransition.mem_network` (line 2109): 1
- `take_eq_take_of_comparable` (line 2151): 1
- `termAt_take` (line 2168): 1
- `acceptLog_eq` (line 2186): 6

## Chunk 7: SafetyInvariant.lean lines 2375-3756, 31 theorems, 61 splits

- `configurationHistory_split` (line 2375): 1
- `getElem_le_of_lt_length_filter` (line 2469): 2
- `chosen_bound` (line 2497): 3
- `activeConfigurations_overlap` (line 2526): 3
- `Rooted.prefix` (line 2617): 2
- `Rooted.append` (line 2633): 1
- `Rooted.head` (line 2642): 1
- `rooted_overlap` (line 2659): 2
- `CommitFrontier.advance` (line 2788): 1
- `foldl_select_max` (line 2806): 4
- `foldl_select_max_pos` (line 2828): 1
- `CommitFrontier.handleAppendEntriesRequest` (line 2885): 6
- `CommitFrontier.promotedLog` (line 2959): 1
- `CommitFrontier.act` (line 3044): 3
- `CommitFrontier.receive` (line 3083): 2
- `commitFrontier_invariant` (line 3136): 1
- `Extends.handleAppendEntriesRequest` (line 3212): 6
- `Extends.becomePrimary` (line 3288): 1
- `Extends.act` (line 3331): 2
- `Extends.receive` (line 3370): 2
- `committed_log_step` (line 3424): 3
- `present_after_step` (line 3461): 3
- `committed_log_later` (line 3485): 1
- `Advance.term` (line 3575): 1
- `Advance.votedFor` (line 3580): 1
- `Advance.matchIndex` (line 3585): 1
- `Advance.sentIndex` (line 3590): 1
- `Advance.commit_le` (line 3600): 1
- `Advance.role` (line 3605): 1
- `becomePrimary_sends` (line 3681): 1
- `becomeCandidate_sends` (line 3722): 2

## Chunk 8: Direct.lean lines 783-831, 4 theorems, 4 splits

- `Keeps.guard'` (line 783): 1
- `Keeps.bind'` (line 792): 1
- `Keeps.ite'` (line 816): 1
- `Keeps.foldlM'` (line 824): 1

## Not in any chunk: Direct.lean twins (copied by `twins.py --apply`)

- `Concrete.mem_replaceNode`: 1
- `Concrete.observeTerm_commitIndex`: 3
- `CommitFrontier.act`: 3
- `CommitFrontier.advance`: 1
- `CommitFrontier.handleAppendEntriesRequest`: 6
- `CommitFrontier.promotedLog`: 1
- `CommitFrontier.receive`: 2
- `Extends.act`: 2
- `Extends.becomePrimary`: 1
- `Extends.handleAppendEntriesRequest`: 6
- `Extends.receive`: 2
- `NodeInvariant.reachable`: 5
- `commitFrontier_invariant`: 1
- `committed_log_step`: 3
- `find_of_mem`: 4
- `foldl_select_max`: 4
- `foldl_select_max_pos`: 1
- `Ledger.fromLeader_loop`: 3
- `Ledger.handleAppendEntiresFromPrimary_eq`: 1
- `Ledger.isSignatureAtTrue`: 1
- `Ledger.isSignatureAt_take_of_le`: 2
- `Ledger.maxCommittableIndexPositiveIsSignature`: 5
- `Ledger.maxCommittableIndex_le_of_prefix`: 1
- `Ledger.signatureIndex_le_maxCommittableIndex`: 4
