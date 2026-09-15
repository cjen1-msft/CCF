-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeParameterizedFrame

set_option autoImplicit false

namespace CCFRaft.CellsNative

open Lean NativeEncode NativeSmt

def extents {width : PNat} (ledger queue : Nat) : EncodeM width Unit := do
  let state <- get
  for node in List.range width.val do
    assertion (.le (length state.toColumns node) (.integer ledger))
    for source in List.range width.val do
      let head := queueScalarTerm state.queueHead (.integer node) (.integer source)
      let size := queueScalarTerm state.queueLength (.integer node) (.integer source)
      assertion (.le (.add head size) (.integer queue))

def encode (envelope : Json) : Except String Json := do
  fields envelope ["input", "ledger", "queue"]
  let document <- field envelope "input"
  let ledger <- natural (← field envelope "ledger")
  let queue <- natural (← field envelope "queue")
  let input <- decodeParameterizedFrameDocument document
  let (_, initial) <- (initialFrameDomains input.frame.width).run
    (initialEncoding input.frame.width input.frame.bootstrap)
  let (_, parameters) <- (declareNatParameters input.unknowns.size).run initial
  let (_, started) <- (extents ledger queue).run parameters
  let mut state := started
  let mut groups := #[{ instruction := none, start := 0, stop := state.assertions.size : Group }]
  for index in List.finRange input.frame.instructions.size do
    let start := state.assertions.size
    let (_, next) <- (do
      parameterizedFrameInstruction initial.next input.frame.instructions[index.val]
      extents ledger queue).run state
    state := next
    groups := groups.push { instruction := some index.val, start, stop := state.assertions.size }
  return compiledDetails document { assertions := state.assertions, groups }

end CCFRaft.CellsNative

def main : IO UInt32 := do
  let text <- (← IO.getStdin).readToEnd
  match Lean.Json.parse text >>= CCFRaft.CellsNative.encode with
  | .ok output => IO.println output.compress; return 0
  | .error error => (← IO.getStderr).putStrLn error; return 2
