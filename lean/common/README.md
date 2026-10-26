# Common Lean transition infrastructure

The `ccf_common` Lake package exposes protocol-independent definitions in the `CCF` namespace.

| Module                          | Purpose                                                      |
| ------------------------------- | ------------------------------------------------------------ |
| `CCF.Capabilities`              | Envelopes, ordered outputs, effects, and recording callbacks |
| `CCF.TransitionSystem`          | Initial states, enabled transitions, and reachability        |
| `CCF.MultiNodeTransitionSystem` | Local protocols composed into a message-passing network      |
| `CCF.Execution`                 | Finite runs and initial-state/action traces                  |

`CCF.Execution.Trace State Action` records an explicit `initial` state and a finite or infinite `actions : Stream'.Seq Action`, so the package depends on Mathlib.
`trace.actionAt index` reads a recorded action.
`trace.stateAt system index` computes the state before that action by replay, with index zero referring to the initial state.
`trace.stepAt system index` returns the computed before-state, recorded action, and after-state when the action succeeds.
`trace.states system` exposes the successful replay prefix, including the initial state.

`trace.Valid system` requires valid initialization and successful execution of every recorded action, not merely the actions in the successful replay prefix.
A disabled action therefore invalidates the trace rather than silently truncating it.
A finite recording of `n` enabled actions has `n + 1` derived states; a zero-action trace retains its initial state.
`Trace.Valid.reachable_stateAt`, `Trace.Valid.reachable` and `reachable_iff_trace` relate valid traces to reachable states by replay.

## Transition systems

`CCF.TransitionSystem` bundles the `State` and `Action` types with the initial-state predicate `init` and the partial transition function `step`.
Define a model as `system : TransitionSystem`, setting `State` and `Action` in the structure rather than supplying type parameters.
Use `abbrev` for concrete systems so Lean can unfold their bundled types during typeclass inference.
Generic helpers use `system.State` and `system.Action`, while `system.Reachable state` and `Execution.Run system start actions final` describe executions.
Traces keep their type parameters, as `Execution.Trace system.State system.Action`; the replay functions take the system first, so `Execution.Trace.Valid system trace` is also written `trace.Valid system`.

## Import coverage

After `lake build`, run `lake exe check-imports` from any package using `ccf_common`.
The command reads that package's library roots from Lake, loads their compiled transitive imports (including private imports), and scans the corresponding source directories.
It fails if any source module is missing from the imported modules, without requiring every module to be listed directly in the library root.
