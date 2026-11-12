# Chunks

Made by `chunks.py 60` at commit 9758d13f9.

## Chunk 1: SafetyInvariant.lean lines 2940-3931, 22 theorems, 57 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `1`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `CommitFrontier.handleAppendEntriesRequest`
(line 2940) to theorem `quiet_summary` (ends line 3931); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `CommitFrontier.handleAppendEntriesRequest` (line 2940): 6
- `CommitFrontier.promotedLog` (line 3014): 1
- `CommitFrontier.act` (line 3099): 3
- `CommitFrontier.receive` (line 3138): 2
- `commitFrontier_invariant` (line 3191): 1
- `Extends.handleAppendEntriesRequest` (line 3267): 6
- `Extends.becomePrimary` (line 3343): 1
- `Extends.act` (line 3386): 2
- `Extends.receive` (line 3425): 2
- `committed_log_step` (line 3479): 3
- `present_after_step` (line 3516): 3
- `committed_log_later` (line 3540): 1
- `Advance.term` (line 3630): 1
- `Advance.votedFor` (line 3635): 1
- `Advance.matchIndex` (line 3640): 1
- `Advance.sentIndex` (line 3645): 1
- `Advance.commit_le` (line 3655): 1
- `Advance.role` (line 3660): 1
- `becomePrimary_sends` (line 3736): 1
- `becomeCandidate_sends` (line 3777): 2
- `campaign_summary` (line 3823): 16
- `quiet_summary` (line 3885): 1


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-1 /workspaces/ccf-mark-1 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-1`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-1 && python3 lean/consensus-coverage/scripts/check.py chunk 1

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-1 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 2: SafetyInvariant.lean lines 3963-5035, 24 theorems, 54 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `2`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `observe_bumping`
(line 3963) to theorem `initial_canon` (ends line 5035); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `observe_bumping` (line 3963): 3
- `becomeCandidate_result` (line 3987): 2
- `canStartElection_engaged` (line 4003): 3
- `voteRequest_summary` (line 4099): 5
- `preVoteRequest_summary` (line 4157): 1
- `initAsBackup_summary` (line 4203): 5
- `elect_result` (line 4248): 1
- `voteResponse_summary` (line 4261): 2
- `preVoteResponse_summary` (line 4291): 1
- `observe_response` (line 4319): 2
- `appendEntriesResponse_summary` (line 4334): 4
- `aeReply_summary` (line 4584): 1
- `appendEntriesRequest_summary` (line 4617): 9
- `BatchState.push` (line 4651): 1
- `sendEntries_batch` (line 4710): 1
- `appendBatch_summary` (line 4728): 5
- `Led.mono` (line 4871): 1
- `Committed.append` (line 4884): 1
- `Backed.mono` (line 4904): 1
- `Backed.weaken` (line 4911): 1
- `Seen.cons` (line 4949): 1
- `suffix_comparable` (line 4957): 1
- `led_single` (line 5020): 1
- `initial_canon` (line 5027): 1


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-2 /workspaces/ccf-mark-2 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-2`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-2 && python3 lean/consensus-coverage/scripts/check.py chunk 2

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-2 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 3: SafetyInvariant.lean lines 5037-5776, 22 theorems, 57 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `3`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `inv_initial`
(line 5037) to theorem `Ctx.electStep` (ends line 5776); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `inv_initial` (line 5037): 14
- `Everywhere.cons` (line 5155): 1
- `Now.nonempty` (line 5186): 1
- `termAt_mono` (line 5232): 2
- `termAt_le_of_mem` (line 5245): 1
- `signature_pos` (line 5253): 1
- `Led.two_le` (line 5281): 1
- `Led.elected` (line 5289): 1
- `canon_chain` (line 5296): 1
- `vote_unique` (line 5350): 7
- `Committed.shape` (line 5398): 1
- `committed_comparable` (line 5447): 5
- `backing_split` (line 5476): 6
- `Doomed.cons'` (line 5525): 1
- `primaryState_log_prefix` (line 5552): 1
- `Wins.facts` (line 5559): 2
- `Ctx.seen_after` (line 5637): 2
- `Ctx.received` (line 5654): 1
- `Ctx.snap_of_committed` (line 5689): 1
- `Ctx.post_two` (line 5729): 3
- `Ctx.elected_after` (line 5744): 1
- `Ctx.electStep` (line 5754): 3


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-3 /workspaces/ccf-mark-3 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-3`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-3 && python3 lean/consensus-coverage/scripts/check.py chunk 3

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-3 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 4: SafetyInvariant.lean lines 5778-6484, 20 theorems, 54 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `4`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `Ctx.led_after`
(line 5778) to theorem `seen_split` (ends line 6484); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `Ctx.led_after` (line 5778): 2
- `Ctx.led_other` (line 5788): 1
- `Ctx.canon_after` (line 5795): 1
- `Advance.facts` (line 5815): 1
- `vals_upToDate` (line 5828): 1
- `Ctx.rooted` (line 5979): 3
- `Ctx.sorted` (line 6020): 3
- `Ctx.active` (line 6041): 1
- `Ctx.term_mono` (line 6047): 3
- `Ctx.campaign_votes` (line 6105): 2
- `Ctx.wins_elect` (line 6152): 1
- `Ctx.led_cur` (line 6191): 6
- `Ctx.leader_led` (line 6209): 2
- `Ctx.doomed_absurd` (line 6218): 10
- `Ctx.pre_split` (line 6326): 1
- `Ctx.campaign_backed` (line 6347): 2
- `Ctx.candidate` (line 6368): 7
- `Ctx.elect_backed` (line 6405): 4
- `suffix_of_cons_suffix` (line 6458): 1
- `seen_split` (line 6466): 2


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-4 /workspaces/ccf-mark-4 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-4`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-4 && python3 lean/consensus-coverage/scripts/check.py chunk 4

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-4 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 5: SafetyInvariant.lean lines 6493-6985, 12 theorems, 58 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `5`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `core`
(line 6493) to theorem `Ctx.anchor` (ends line 6985); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `core` (line 6493): 28
- `agree_or_contained` (line 6650): 4
- `Ctx.old_step_in_new` (line 6730): 2
- `Ctx.old_in_new` (line 6759): 1
- `Ctx.old_complete` (line 6776): 1
- `Ctx.new_old_unique` (line 6786): 4
- `Ctx.election_safety` (line 6825): 3
- `Ctx.keep_log` (line 6834): 2
- `Ctx.leader_logs` (line 6862): 3
- `Ctx.old_led_actor` (line 6886): 1
- `Ctx.canon_mono` (line 6894): 5
- `Ctx.anchor` (line 6942): 4


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-5 /workspaces/ccf-mark-5 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-5`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-5 && python3 lean/consensus-coverage/scripts/check.py chunk 5

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-5 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 6: SafetyInvariant.lean lines 6987-7944, 19 theorems, 64 splits (classes)

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `6`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `Ctx.new_in_elected`
(line 6987) to theorem `CommittedLogs.committed_logs_prefix` (ends line 7944); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `Ctx.new_in_elected` (line 6987): 14
- `Ctx.completeness` (line 7097): 1
- `Backed.transfer` (line 7117): 1
- `Ctx.post_led` (line 7146): 1
- `Ctx.advance_backed` (line 7175): 6
- `Ctx.keep_backed` (line 7259): 2
- `Ctx.accept_backed` (line 7288): 3
- `Ctx.commit_backed` (line 7346): 13
- `Ctx.accept_persist` (line 7457): 5
- `Ctx.persist_pre` (line 7520): 1
- `Ctx.persist` (line 7552): 5
- `Ctx.match_ack` (line 7572): 3
- `Ctx.rv_stable` (line 7593): 2
- `Ctx.old_message` (line 7632): 1
- `Ctx.new_message` (line 7656): 1
- `Ctx.messages` (line 7710): 1
- `Ctx.message_terms` (line 7716): 2
- `CommittedLogs.committed_logs_prefix_of_le` (line 7899): 1
- `CommittedLogs.committed_logs_prefix` (line 7923): 1


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-6 /workspaces/ccf-mark-6 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-6`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-6 && python3 lean/consensus-coverage/scripts/check.py chunk 6

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-6 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 7: SafetyInvariant.lean lines 1799-2893, 30 theorems, 56 splits

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `7`. File: `lean/consensus/Consensus/Proofs/SafetyInvariant.lean`, from theorem `keys_nodup`
(line 1799) to theorem `foldl_select_max_pos` (ends line 2893); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `keys_nodup` (line 1799): 2
- `find_of_mem` (line 1816): 4
- `Keeps.guard'` (line 1862): 1
- `Keeps.ite'` (line 1895): 1
- `Keeps.foldlM'` (line 1903): 1
- `Sends.bind'` (line 1928): 1
- `Sends.ite'` (line 1955): 1
- `Sends.guard'` (line 1963): 1
- `Sends.forIn'` (line 1990): 3
- `Sends.foldlM'` (line 2013): 1
- `exec_of_reachable` (line 2039): 1
- `Exec.reachable` (line 2051): 1
- `Exec.suffix` (line 2063): 3
- `mem_removeOne` (line 2088): 3
- `LocalTransition.ofStep` (line 2101): 2
- `LocalTransition.mem_network` (line 2164): 1
- `take_eq_take_of_comparable` (line 2206): 1
- `termAt_take` (line 2223): 1
- `acceptLog_eq` (line 2241): 6
- `configurationHistory_split` (line 2430): 1
- `getElem_le_of_lt_length_filter` (line 2524): 2
- `chosen_bound` (line 2552): 3
- `activeConfigurations_overlap` (line 2581): 3
- `Rooted.prefix` (line 2672): 2
- `Rooted.append` (line 2688): 1
- `Rooted.head` (line 2697): 1
- `rooted_overlap` (line 2714): 2
- `CommitFrontier.advance` (line 2843): 1
- `foldl_select_max` (line 2861): 4
- `foldl_select_max_pos` (line 2883): 1


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-7 /workspaces/ccf-mark-7 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-7`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-7 && python3 lean/consensus-coverage/scripts/check.py chunk 7

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-7 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Chunk 8: Direct.lean lines 833-881, 4 theorems, 4 splits

You are a marking worker for a Lean 4 proof. You work alone and cannot ask questions.
First read this guide in full, then follow it literally: /root/.cache/paxos-bisim/research/proof-relevance/ccf/marking-guide.md

Your chunk: `8`. File: `lean/consensus/Consensus/Proofs/Direct.lean`, from theorem `Keeps.guard'`
(line 833) to theorem `Keeps.foldlM'` (ends line 881); line numbers at the start commit. Theorems
with unmarked splits (number of splits as compiled):

- `Keeps.guard'` (line 833): 1
- `Keeps.bind'` (line 842): 1
- `Keeps.ite'` (line 866): 1
- `Keeps.foldlM'` (line 874): 1


Set up once (creates your worktree and branch; the checker makes your own build directory
`/root/.cache/ccf-consensus-coverage/ws-<hash>/` from the worktree path on its first run):

    git -C /workspaces/ccf-consensus-coverage worktree add -b consensus-mark-8 /workspaces/ccf-mark-8 consensus-proof-coverage

Edit files only in `/workspaces/ccf-mark-8`. Run every command from there.
Check (after every one to three splits; it builds the proof first):

    cd /workspaces/ccf-mark-8 && python3 lean/consensus-coverage/scripts/check.py chunk 8

Commit (only after a `RESULT: PASS`):

    cd /workspaces/ccf-mark-8 && git commit -qam "mark <theorem name>"

Never push. Never touch another worktree or `/workspaces/CCF`. Do not write files to /tmp.
Do not run `lake update` or `lake clean`. When finished, reply with the hand-back note of
section 10 of the guide; in "guide problems", quote the guide sentence that was unclear or
wrong and say what happened.

## Not in any chunk: Direct.lean twins (copied by `twins.py --apply`)

- `CommitFrontier.act`: 3
- `CommitFrontier.advance`: 1
- `CommitFrontier.handleAppendEntriesRequest`: 6
- `CommitFrontier.promotedLog`: 1
- `CommitFrontier.receive`: 2
- `Extends.act`: 2
- `Extends.becomePrimary`: 1
- `Extends.handleAppendEntriesRequest`: 6
- `Extends.receive`: 2
- `commitFrontier_invariant`: 1
- `committed_log_step`: 3
- `find_of_mem`: 4
- `foldl_select_max`: 4
- `foldl_select_max_pos`: 1
