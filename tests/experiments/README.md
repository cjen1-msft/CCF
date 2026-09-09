# Raft trace experiments

These runners use the Basic C++ blocking endpoint, two nodes, two worker threads per node, and 1,000 warmed HTTP connections. Nodes use 100 ms signatures. Each offered-rate plateau has a settling phase followed by a measured request cohort.

## Build the demo

```bash
cmake -S . -B build-tracing -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCCF_RAFT_TRACING=ON
ninja -C build-tracing -j "$(( ($(nproc) + 1) >> 1 ))" basic
cd build-tracing
./tests.sh -N
cd ..
```

The executable is `build-tracing/samples/apps/basic/basic`. No executable is checked into this repository.

The node's `observability.fluentd` configuration selects the exporter:

| Runner mode    | `buffered`          | `discard`           | Work performed                                |
| -------------- | ------------------- | ------------------- | --------------------------------------------- |
| `off`          | Destination omitted | Destination omitted | No trace construction                         |
| `discard`      | `false`             | `true`              | Serialize, then discard on producer           |
| `tcp`          | `false`             | `false`             | Serialize and send TCP on producer            |
| `ring_discard` | `true`              | `true`              | Serialize, enqueue, then discard on consumer  |
| `buffered`     | `true`              | `false`             | Serialize, enqueue, then send TCP on consumer |

Both `host` and string-valued `port` are required when a destination is configured. Buffered mode preallocates SPSC queues and binds producers before use. Its consumer polls at 1 ms when idle; producers do not allocate, lock, log, or issue wakeup syscalls while enqueuing. Full queues drop complete records.

## Run the five-way sweep

Create a dedicated RAM-backed directory first. The runner refuses a `--workspace-root` that is not on tmpfs.

```bash
mkdir /tmp/ccf-trace-ram
sudo mount -t tmpfs -o nosuid,nodev tmpfs /tmp/ccf-trace-ram
build-tracing/env/bin/python tests/experiments/raft_trace_sweep.py --repo . --build build-tracing --output /tmp/ccf-trace-results --workspace-root /tmp/ccf-trace-ram/sweep --modes off discard tcp ring_discard buffered --implementation-name preallocated-spsc-poll
```

Use `--rates` to select offered RPS values and `--seconds` to select the measurement duration. Existing results directories are not overwritten. The runner invokes `tests.sh` and archives metrics, node configuration, and logs outside the RAM-backed workspace.

After the run finishes and the artifacts are archived:

```bash
sudo umount /tmp/ccf-trace-ram
rmdir /tmp/ccf-trace-ram
```

The TCP receiver drains bytes without Fluentd processing. RAM-backed ledger storage excludes durable-storage costs. The client cap and scheduling lag can limit achieved throughput; inspect missed arrivals alongside latency rather than treating every point as fully delivered offered load.

## Reproduce the individual-change ablation

Predictions and the three-repeat order were registered in commit `bd4d76d20`, before individual-change measurements. See `raft_trace_ablation_predictions.json`.

Apply the diagnostic patch in a separate worktree. It restores selected legacy costs behind `benchmark_variant`, and writes mechanism counters after shutdown. Those diagnostic controls are not part of the production implementation.

```bash
git worktree add --detach /tmp/ccf-enqueue-ablation HEAD
git -C /tmp/ccf-enqueue-ablation apply "$PWD/tests/experiments/raft_trace_enqueue_ablation.patch"
cmake -S /tmp/ccf-enqueue-ablation -B /tmp/ccf-enqueue-ablation/build -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCCF_RAFT_TRACING=ON
ninja -C /tmp/ccf-enqueue-ablation/build -j "$(( ($(nproc) + 1) >> 1 ))" basic
git show bd4d76d20:tests/experiments/raft_trace_ablation_predictions.json > /tmp/ccf-ablation-preregistration.json
mkdir /tmp/ccf-trace-ram
sudo mount -t tmpfs -o nosuid,nodev tmpfs /tmp/ccf-trace-ram
build-tracing/env/bin/python tests/experiments/raft_enqueue_ablation.py --repo /tmp/ccf-enqueue-ablation --build /tmp/ccf-enqueue-ablation/build --output /tmp/ccf-ablation-results --workspace-root /tmp/ccf-trace-ram/ablation --preregistration /tmp/ccf-ablation-preregistration.json
```

The study restores one hot-path cost at a time and includes a combined-legacy control. All variants use consumer discard to exclude TCP work. Counters include actual producer notifications, consumer wakeups, empty scans, and read batch sizes. Each variant is measured three times at 10,000 offered RPS.

Startup allocation is outside the warmed measurement window. Drop logging cannot explain healthy-run differences when no traces drop. Neither has an independently measurable steady-state effect in this protocol.

## Recorded result

See `raft_trace_ablation_results.csv` for all 18 runs and `raft_trace_ablation_summary.json` for medians and provenance.

Restoring the notification policy alone reduced median completed throughput by 20.2%, from 8,656 to 6,904 RPS. Restoring MPSC reservation, per-message allocation, or consumer queue-list copying individually changed throughput by less than 0.2%, within observed run variation. The combined legacy control lost 19.6%. All results fell within the preregistered impact bands.

The notification variant reduced records per nonempty read from about 20 to 1.5 and increased consumer wait/poll cycles from about 26,000 to 348,000 over the node run. Those are not all kernel wakeups: independently sampled voluntary context switches across the nodes increased from about 11,600/s to 22,800/s. The study isolates the notification policy and resulting scheduling/batching behavior, not the mutex alone.
