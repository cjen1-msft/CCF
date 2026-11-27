module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter
public import Lean.Data.Json
public import Std.Data.HashSet

@[expose] public section

/-!
Reduced groups as NDJSON: one `Replay.Group` per line. A line names every node it refers to
rather than numbering it, so any slice of lines, such as `tail -n 100`, decodes on its own:
the decoder numbers the names it reads in lexical order.
-/

namespace Consensus.MidTrace

open Lean Model.Node Replay

deriving instance FromJson for StateSnapshot

deriving instance ToJson, FromJson
for
  Origin, Packet.AppendEntries, Packet.AppendEntriesResponse, Packet.RequestVote, Packet.RequestVoteResponse, Packet.ProposeRequestVote

namespace GroupJson

def tagged (kind : String) (fields : List (String × Json)) : Json :=
  Json.mkObj (("kind", toJson kind) :: fields)

/-- The name of a declared node; blank, which no decoder accepts, if undeclared. -/
def nodeName (header : Header) (id : NodeID) : String :=
  header.declared[id]?.getD ""

def encodeNodes (header : Header) (nodes : CCF.Finset NodeID) : Json :=
  toJson (nodes.sort.map (nodeName header))

def encodeContent (header : Header) : EntryContent → Json
  | .signature => tagged "signature" []
  | .transaction reqId metadata =>
      tagged "transaction"
        ([("reqId", toJson reqId)]
          ++ (metadata.configuration.map
                fun nodes => [("configuration", encodeNodes header nodes)]).getD
              []
          ++ [(
                "retirementConfirmations",
                encodeNodes header metadata.retirementConfirmations
              )])

def encodeEntry (header : Header) (entry : Entry) : Json :=
  Json.mkObj
    [("term", toJson entry.term), ("content", encodeContent header entry.content)]

def encodeInput (header : Header) : Input → Json
  | .append entries =>
      tagged "append"
        [(
          "entries",
          toJson
            (entries.map
              fun e =>
                Json.mkObj
                  [
                    ("content", encodeContent header e.content),
                    (
                      "flushes",
                      toJson (e.flushes.map fun (d, i) => (nodeName header d, i))
                    )
                  ])
        )]
  | .sendEntries destination endIndex =>
      tagged "sendEntries"
        [
          ("destination", toJson (nodeName header destination)),
          ("endIndex", toJson endIndex)
        ]
  | .timeout .election => tagged "timeout" [("timeout", toJson "election")]
  | .timeout .checkQuorum => tagged "timeout" [("timeout", toJson "checkQuorum")]
  | .nominateSuccessor => tagged "nominateSuccessor" []
  | .initAsBackup entries =>
      tagged "initAsBackup" [("entries", toJson (entries.map (encodeEntry header)))]

/-- A packet as its native fields, with `msg` naming its kind. -/
def encodePacket (packet : Packet) : Json :=
  let fields :=
    match packet with
    | .appendEntries p => toJson p
    | .appendEntriesResponse p => toJson p
    | .requestVote p | .requestPreVote p => toJson p
    | .requestVoteResponse p | .requestPreVoteResponse p => toJson p
    | .proposeRequestVote p => toJson p
  fields.setObjVal! "msg" (toJson packet.msg)

def encodeStep (header : Header) : Step → Json
  | .local node input =>
      tagged "local" [("node", toJson node), ("input", encodeInput header input)]
  | .receive source destination packet =>
      tagged "receive"
        [
          ("source", toJson source),
          ("destination", toJson destination),
          ("packet", encodePacket packet)
        ]
  | .initAsBackup node index view =>
      tagged "initAsBackup"
        [("node", toJson node), ("index", toJson index), ("view", toJson view)]

/-- A snapshot without the fields it does not observe. -/
def encodeSnapshot (s : StateSnapshot) : Json :=
  Json.mkObj
    ([("node_id", toJson s.node_id)]
      ++ Json.opt "current_view" s.current_view
      ++ Json.opt "last_idx" s.last_idx
      ++ Json.opt "commit_idx" s.commit_idx
      ++ Json.opt "leadership_state" s.leadership_state
      ++ Json.opt "membership_state" s.membership_state
      ++ Json.opt "committable_indices" s.committable_indices
      ++ Json.opt "retirement_phase" s.retirement_phase
      ++ Json.opt "retirement_idx" s.retirement_idx
      ++ Json.opt "retirement_committable_idx" s.retirement_committable_idx
      ++ Json.opt "retired_committed_idx" s.retired_committed_idx)

def encodeInstruction (header : Header) : Instruction → Json
  | .action step origin =>
      tagged "action" [("step", encodeStep header step), ("origin", toJson origin)]
  | .observeNodeState node expected origin =>
      tagged "observeNodeState"
        [
          ("node", toJson node),
          ("expected", encodeSnapshot expected),
          ("origin", toJson origin)
        ]
  | .observeSends sends origin =>
      tagged "observeSends"
        [
          (
            "sends",
            toJson
              (sends.map
                fun s =>
                  Json.mkObj
                    [
                      ("target", toJson s.target),
                      ("packet", encodePacket s.packet),
                      ("origin", toJson s.origin)
                    ])
          ),
          ("origin", toJson origin)
        ]

/--
The decoder runs twice: first to collect the node names a line refers to, then to number
them. `node` sees each name.
-/
abbrev Decoder := StateT (Std.HashSet String) (Except String)

/-- What the decoder does with each node name it reads. -/
abbrev Resolve := String → Decoder NodeID

def field (j : Json) (α : Type) [FromJson α] (key : String) : Decoder α :=
  StateT.lift (j.getObjValAs? α key)

/-- A node name, which `node` sees. -/
def nameField (node : Resolve) (j : Json) (key : String) : Decoder String := do
  let name ← field j String key
  discard <| node name
  return name

def decodeNodes (node : Resolve) (j : Json) : Decoder (CCF.Finset NodeID) := do
  let names : List String ← StateT.lift (fromJson? j)
  return CCF.Finset.ofList (← names.mapM node)

def decodeContent (node : Resolve) (j : Json) : Decoder EntryContent := do
  match ← field j String "kind" with
  | "signature" => return .signature
  | "transaction" =>
      let configuration ←
        match j.getObjValD "configuration" with
        | .null => pure none
        | nodes => some <$> decodeNodes node nodes
      return .transaction (← field j Nat "reqId")
        {
          configuration,
          retirementConfirmations :=
            ← decodeNodes node (j.getObjValD "retirementConfirmations")
        }
  | kind => throw s!"unknown entry content '{kind}'"

def decodeEntry (node : Resolve) (j : Json) : Decoder Entry := do
  return {
    term := ← field j Nat "term", content := ← decodeContent node (j.getObjValD "content")
  }

def decodeInput (node : Resolve) (j : Json) : Decoder Input := do
  match ← field j String "kind" with
  | "append" =>
      let entries ← field j (List Json) "entries"
      .append
      <$> entries.mapM
            fun e => do
              let flushes ← field e (List (String × Nat)) "flushes"
              return {
                content := ← decodeContent node (e.getObjValD "content")
                flushes := ← flushes.mapM fun (d, i) => (·, i) <$> node d
              }
  | "sendEntries" =>
      return .sendEntries (← node (← field j String "destination"))
        (← field j Nat "endIndex")
  | "timeout" =>
      match ← field j String "timeout" with
      | "election" => return .timeout .election
      | "checkQuorum" => return .timeout .checkQuorum
      | kind => throw s!"unknown timeout '{kind}'"
  | "nominateSuccessor" => return .nominateSuccessor
  | "initAsBackup" =>
      .initAsBackup <$> (← field j (List Json) "entries").mapM (decodeEntry node)
  | kind => throw s!"unknown input '{kind}'"

def decodePacket (j : Json) : Except String Packet := do
  match ← j.getObjValAs? String "msg" with
  | "append_entries" => .appendEntries <$> fromJson? j
  | "append_entries_response" => .appendEntriesResponse <$> fromJson? j
  | "request_vote" => .requestVote <$> fromJson? j
  | "request_pre_vote" => .requestPreVote <$> fromJson? j
  | "request_vote_response" => .requestVoteResponse <$> fromJson? j
  | "request_pre_vote_response" => .requestPreVoteResponse <$> fromJson? j
  | "propose_request_vote" => .proposeRequestVote <$> fromJson? j
  | msg => throw s!"unknown packet '{msg}'"

def decodeStep (node : Resolve) (j : Json) : Decoder Step := do
  match ← field j String "kind" with
  | "local" =>
      return .local (← nameField node j "node")
        (← decodeInput node (j.getObjValD "input"))
  | "receive" =>
      return .receive (← nameField node j "source") (← nameField node j "destination")
        (← decodePacket (j.getObjValD "packet"))
  | "initAsBackup" =>
      return .initAsBackup (← nameField node j "node") (← field j Nat "index")
        (← field j Nat "view")
  | kind => throw s!"unknown step '{kind}'"

def decodeInstruction (node : Resolve) (j : Json) : Decoder Instruction := do
  let origin ← field j Origin "origin"
  match ← field j String "kind" with
  | "action" => return .action (← decodeStep node (j.getObjValD "step")) origin
  | "observeNodeState" =>
      let expected ← field j StateSnapshot "expected"
      discard <| node expected.node_id
      return .observeNodeState (← nameField node j "node") expected origin
  | "observeSends" =>
      let sends ←
        (← field j (List Json) "sends").mapM
          fun s => do
            return {
              target := ← nameField node s "target"
              packet := ← decodePacket (s.getObjValD "packet")
              origin := ← field s Origin "origin"
            }
      return .observeSends sends origin
  | kind => throw s!"unknown instruction '{kind}'"

def decodeGroup (node : Resolve) (j : Json) : Decoder Group := do
  return {
    node := ← nameField node j "node"
    start := ← field j Nat "start"
    m_ts := ← field j Nat "m_ts"
    ts := ← field j (Option Nat) "ts"
    instructions :=
      ← (← field j (Array Json) "instructions").mapM (decodeInstruction node)
  }

end GroupJson

open GroupJson

/-- One group as a self-contained JSON object: one NDJSON line, once compressed. -/
def encodeGroup (header : Header) (group : Group) : Json :=
  Json.mkObj
    ([
        ("node", toJson group.node),
        ("start", toJson group.start),
        ("m_ts", toJson group.m_ts)
      ]
      ++ Json.opt "ts" group.ts
      ++ [("instructions", toJson (group.instructions.map (encodeInstruction header)))])

/--
Decode NDJSON groups, skipping blank lines. The header declares, in lexical order, every node
the groups name, `bootstrap`, and `nodes`; its bootstrap membership is `bootstrap`.
-/
def decodeGroups (ndjson : String) (bootstrap : List String := [])
    (nodes : List String := [])
    : Except String (Header × Array Group) := do
  let mut lines := #[]
  for (line, i) in (ndjson.splitOn "\n").zipIdx 1 do
    unless line.trimAscii.isEmpty do
      lines := lines.push (i, ← (Json.parse line).mapError (s!"line {i}: " ++ ·))
  if lines.isEmpty then throw "empty input: no groups"
  let collect : Resolve :=
    fun name => do
      modify (·.insert name)
      return 0
  let mut names : Std.HashSet String := Std.HashSet.ofList (bootstrap ++ nodes)
  for (i, j) in lines do
    names := (← ((decodeGroup collect j).run names).mapError (s!"line {i}: " ++ ·)).2
  let declared := names.toList.mergeSort
  if declared.any (·.isEmpty) then throw "blank node name in groups"
  let header : Header := { bootstrap := ∅, declared }
  let resolve : Resolve := fun name => StateT.lift (header.nodeId name)
  let groups ←
    lines.mapM
      fun (i, j) => ((decodeGroup resolve j).run' {}).mapError (s!"line {i}: " ++ ·)
  let bootstrap ← bootstrap.mapM header.nodeId
  return ({ header with bootstrap := CCF.Finset.ofList bootstrap }, groups)

end Consensus.MidTrace
