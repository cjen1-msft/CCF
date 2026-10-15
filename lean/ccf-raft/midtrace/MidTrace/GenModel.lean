module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model.Node
public import MidTrace.GenLib

@[expose] public section

/-!
# The node model over `GenLib`

A function-by-function transliteration of `Model/NodeState.lean`,
`Model/ClusterConfig.lean` and `Model/Node.lean`: each definition has the same
name and structure as the one it encodes, with list, set, option and effect
operations replaced by their `GenLib` counterparts. Nothing here is specific
to mid-trace validation or to any lowering.

Representation (the only restriction is at most one effect per log entry):

* Entry: `term, sig, tx, effHas, effRet, nodes_0 .. nodes_{n-1}`; a
  transaction's effects are `[]` unless `effHas`, else one effect that is
  `retiredCommitted nodes` if `effRet` and `reconfiguration nodes` otherwise.
* Configuration: `index, nodes_0 .. nodes_{n-1}`.
* Message: `tag, term, prevLogIndex, prevLogTerm, leaderCommit, success,
  lastLogIndex, lastCommittableTerm, lastCommittableIndex, voteGranted`,
  then AppendEntries entries as an `SList` (offset, length, one array per
  entry field). Fields another variant does not have are never read.
* Node identities are indices into the declared nodes; `votedFor` is `-1` for
  `none`, and optional naturals are `-1` for `none`.
-/

namespace CCFRaft.MidTrace.Gen

open CCFRaft.MidTrace.Smt (Tm INF)
open CCFRaft.Model.Node (EntryContent TransactionEffect Input TimeoutKind)

def ROLE_NONE : Int := 0
def ROLE_FOLLOWER : Int := 1
def ROLE_PRE_VOTE_CANDIDATE : Int := 2
def ROLE_CANDIDATE : Int := 3
def ROLE_LEADER : Int := 4

def PHASE_ACTIVE : Int := 0
def PHASE_ORDERED : Int := 1
def PHASE_SIGNED : Int := 2
def PHASE_COMPLETED : Int := 3
def PHASE_RETIRED_COMMITTED : Int := 4

def TAG_AE : Int := 0
def TAG_AER : Int := 1
def TAG_RV : Int := 2
def TAG_RVR : Int := 3
def TAG_RPV : Int := 4
def TAG_RPVR : Int := 5
def TAG_PROPOSE : Int := 6

def E_TERM : Nat := 0
def E_SIG : Nat := 1
def E_TX : Nat := 2
def E_HAS : Nat := 3
def E_RET : Nat := 4
def E_NODES : Nat := 5

def C_INDEX : Nat := 0
def C_NODES : Nat := 1

def M_TAG : Nat := 0
def M_TERM : Nat := 1
def M_PREV : Nat := 2
def M_PREV_TERM : Nat := 3
def M_LEADER_COMMIT : Nat := 4
def M_SUCCESS : Nat := 5
def M_LAST_LOG : Nat := 6
def M_LC_TERM : Nat := 7
def M_LC_INDEX : Nat := 8
def M_GRANTED : Nat := 9
def M_ENT_OFF : Nat := 10
def M_ENT_LEN : Nat := 11
def M_ENTS : Nat := 12

/-- The fixed parameters: `InitialConfig` and the node universe. -/
structure Ctx where
  names : Array String
  /-- Node indices ordered by name. -/
  sorted : Array Nat
  /-- Each node's position in `sorted`. -/
  rank : Array Nat
  cfg0 : Array Bool
  preVote : Array Bool
  /-- Transaction identifiers; code `txNames.size` is any other identifier. -/
  txNames : Array String

namespace Ctx

def n (c : Ctx) : Nat := c.names.size

def ntx (c : Ctx) : Nat := c.txNames.size

def nodes (c : Ctx) : List Nat := List.range c.n

def bitsOf (c : Ctx) (nodes : Finset String) : Array Bool :=
  c.names.map fun name => decide (name ∈ nodes)

def txCode (c : Ctx) (id : String) : Nat :=
  (c.txNames.idxOf? id).getD c.ntx

def entrySrts (c : Ctx) : Array Srt :=
  #[.int, .bool, .int, .bool, .bool] ++ Array.replicate c.n .bool

def msgSrts (c : Ctx) : Array Srt :=
  #[.int, .int, .int, .int, .int, .bool, .int, .int, .int, .bool, .int, .int]
  ++ c.entrySrts.map .arr

def cfg0Record (c : Ctx) : Array Tm :=
  #[.int 0] ++ c.cfg0.map .bool

end Ctx

/-! ## State -/

structure SNode where
  role : Tm
  ct : Tm
  log : SList
  ci : Tm
  sent : Array Tm
  mi : Array Tm
  nf : Tm
  vf : Tm
  lk : Tm
  votes : SSet
  pv : SSet
  rci : Tm
deriving Inhabited

instance : Merge SNode :=
  ⟨fun c a b => do
    return {
      role := ← iteT c a.role b.role
      ct := ← iteT c a.ct b.ct
      log := ← Merge.merge c a.log b.log
      ci := ← iteT c a.ci b.ci
      sent := ← Merge.merge c a.sent b.sent
      mi := ← Merge.merge c a.mi b.mi
      nf := ← iteT c a.nf b.nf
      vf := ← iteT c a.vf b.vf
      lk := ← iteT c a.lk b.lk
      votes := ← Merge.merge c a.votes b.votes
      pv := ← Merge.merge c a.pv b.pv
      rci := ← iteT c a.rci b.rci
    }⟩

abbrev SMsg := Array Tm

def isReconf (e : Array Tm) : GM Tm := do
  andL [← notT e[E_SIG]!, e[E_HAS]!, ← notT e[E_RET]!]

def isRetCom (e : Array Tm) : GM Tm := do
  andL [← notT e[E_SIG]!, e[E_HAS]!, e[E_RET]!]

def msgEntries (m : SMsg) : SList :=
  { arrs := m.extract M_ENTS m.size, off := m[M_ENT_OFF]!, len := m[M_ENT_LEN]! }

def zeroEntries (c : Ctx) : GM (Array Tm) :=
  c.entrySrts.mapM fun s => zeroArr (.arr s)

def mkMsg (c : Ctx) (tag : Int) (term : Tm) (fields : List (Nat × Tm))
    (entries : Option SList := none)
    : GM SMsg := do
  let mut m : Array Tm :=
    #[
      .int tag,
      term,
      .int 0,
      .int 0,
      .int 0,
      .bool false,
      .int 0,
      .int 0,
      .int 0,
      .bool false,
      .int 0,
      .int 0
    ]
  for (f, v) in fields do
    m := m.set! f v
  match entries with
  | some ents =>
      m := (m.set! M_ENT_OFF ents.off).set! M_ENT_LEN ents.len
      return m ++ ents.arrs
  | none => return m ++ (← zeroEntries c)

/-! ## NodeState.lean -/

def entryAt? (log : SList) (index : Tm) : GM (SOpt (Array Tm)) := do
  return ⟨← andL [← le (.int 1) index, ← le index log.len], ← log.get (← addK index (-1))⟩

def termAt (log : SList) (index : Tm) : GM Tm := do
  let present ← andL [← le (.int 1) index, ← le index log.len]
  iteT present (← log.getF (← addK index (-1)) E_TERM) (.int 0)

def isSignatureAt (log : SList) (index : Tm) : GM Tm := do
  andL [← le (.int 1) index, ← le index log.len, ← log.getF (← addK index (-1)) E_SIG]

def maxCommittableIndex (log : SList) : GM Tm :=
  foldMax (.int 0) log.len (isSignatureAt log) pure (.int 0)

def maxCommittableTerm (log : SList) : GM Tm := do
  termAt log (← maxCommittableIndex log)

def maxCommittableIndexUpTo (log : SList) (frontier : Tm) : GM Tm := do
  maxCommittableIndex (← log.take frontier)

def messageEntries (log : SList) (previousIndex batchEnd : Tm) : GM SList := do
  (← log.drop previousIndex).take (← natSub batchEnd previousIndex)

def findHighestPossibleMatch (log : SList) (index term : Tm) : GM Tm := do
  foldMax (.int 0) (← minT index log.len)
    (fun candidate => do
      andL [← lt (.int 0) candidate, ← le (← termAt log candidate) term])
    pure (.int 0)

def firstLogIndexAfter (log : SList) (afterIndex : Tm) (predicate : Array Tm → GM Tm)
    : GM (SOpt Tm) :=
  log.findIdx? 1 fun entry index => do andL [← lt afterIndex index, ← predicate entry]

def lastCommittableIndex (st : SNode) : GM Tm := do
  maxT st.ci (← maxCommittableIndex st.log)

def lastCommittableTerm (st : SNode) : GM Tm := do
  termAt st.log (← lastCommittableIndex st)

/-! ## ClusterConfig.lean -/

/-- Position 0 is the initial configuration and position `p` is entry `p`. -/
def configurationHistory (c : Ctx) (log : SList) : MList where
  hi := log.len
  mask p := do
    let e ← log.get (← addK p (-1))
    orL [← eqK p 0, ← isReconf e]
  elem p := do
    let e ← log.get (← addK p (-1))
    let initial ← eqK p 0
    let bits ← c.cfg0.mapIdxM fun j bit => iteT initial (.bool bit) e[E_NODES + j]!
    return #[p] ++ bits
  dflt := #[.int 0] ++ Array.replicate c.n (.bool false)

def activeConfigurations (c : Ctx) (log : SList) (commitIndex : Tm) : GM MList := do
  let history := configurationHistory c log
  let committed :=
    history.filter fun configuration => le configuration[C_INDEX]! commitIndex
  return history.drop (← natSub (← committed.length) (.int 1))

def configurationMembers (c : Ctx) (configurations : MList) : GM SSet :=
  configurations.unionAt C_NODES c.n

def retirementIndexInLog (c : Ctx) (node : Nat) (log : SList) : GM (SOpt Tm) := do
  let history := configurationHistory c log
  let width := history.dflt.size
  let pairs ← history.zipTail
  pairs.findF?
    (fun pair => do andL [pair[C_NODES + node]!, ← notT pair[width + C_NODES + node]!])
    (width + C_INDEX)

def retiredCommittedNode (log : SList) (node : Nat) : GM Tm :=
  log.any fun entry => do andL [← isRetCom entry, entry[E_NODES + node]!]

def retiredCommittedNodes (c : Ctx) (log : SList) : GM SSet :=
  c.nodes.toArray.mapM (retiredCommittedNode log)

def hasConfigurationMajority (c : Ctx) (support : SSet) (configuration : Array Tm)
    : GM Tm := do
  let nodes := configuration.extract C_NODES (C_NODES + c.n)
  lt (← countT nodes) (← doubleT (← countT (← SSet.inter support nodes)))

def SNode.activeConfigurations (c : Ctx) (st : SNode) : GM MList :=
  Gen.activeConfigurations c st.log st.ci

def SNode.activeMembers (c : Ctx) (st : SNode) : GM SSet := do
  configurationMembers c (← st.activeConfigurations c)

def SNode.retirementCompletedNodes (c : Ctx) (st : SNode) : GM SSet := do
  let committedLog ← st.log.take st.ci
  let committed :=
    (configurationHistory c st.log).filter
      fun configuration => le configuration[C_INDEX]! st.ci
  let current ← committed.lastD c.cfg0Record
  let currentNodes := current.extract C_NODES (C_NODES + c.n)
  let removed ← SSet.diff (← configurationMembers c committed) currentNodes
  let pending ← SSet.diff removed (← retiredCommittedNodes c committedLog)
  SSet.filter pending
    fun node => do
      return (← retirementIndexInLog c node committedLog).isSome

structure SRetirement where
  index : SOpt Tm
  committableIndex : SOpt Tm
  phase : Tm

def SNode.retirement (c : Ctx) (node : Nat) (st : SNode) : GM SRetirement := do
  let index ← retirementIndexInLog c node st.log
  let after ← firstLogIndexAfter st.log index.val fun entry => pure entry[E_SIG]!
  let committableIndex : SOpt Tm := ⟨← andL [index.isSome, after.isSome], after.val⟩
  let phase ←
    iteT index.isSome
      (← iteT (← le (.int 0) st.rci) (.int PHASE_RETIRED_COMMITTED)
          (← iteT (← le index.val st.ci) (.int PHASE_COMPLETED)
              (← iteT committableIndex.isSome (.int PHASE_SIGNED) (.int PHASE_ORDERED))))
      (.int PHASE_ACTIVE)
  return { index, committableIndex, phase }

def SNode.retiredCommitted (c : Ctx) (node : Nat) (st : SNode) : GM Tm := do
  eqK (← st.retirement c node).phase PHASE_RETIRED_COMMITTED

def SNode.commitThrough (node : Nat) (st : SNode) (commitIndex : Tm) : GM SNode := do
  let retired ← retiredCommittedNode (← st.log.take commitIndex) node
  let rci ← iteT (← le (.int 0) st.rci) st.rci (← iteT retired commitIndex (.int (-1)))
  return { st with ci := commitIndex, rci }

def campaignEligible (c : Ctx) (node : Nat) (st : SNode) : GM Tm := do
  let signed ← maxCommittableIndex st.log
  (← st.activeConfigurations c).any
    fun configuration => do
      andL [configuration[C_NODES + node]!, ← le configuration[C_INDEX]! signed]

/-! ## Node.lean: leader state -/

def hasQuorum (c : Ctx) (configurations : MList) (voters : SSet) : GM Tm :=
  configurations.all (hasConfigurationMajority c voters)

def eligiblePeers (c : Ctx) (st : SNode) (self : Nat) : GM SSet := do
  return (← SSet.union (← st.activeMembers c) (← st.retirementCompletedNodes c)).erase
    self

def latestMembershipIndex (configurations : MList) (node : Nat) : GM Tm :=
  configurations.maxD (fun configuration => pure configuration[C_NODES + node]!)
    (fun configuration => pure configuration[C_INDEX]!) (.int 0)

def findSuccessor (c : Ctx) (st : SNode) (self : Nat) : GM (SOpt Tm) := do
  let configurations ← st.activeConfigurations c
  let eligible ← eligiblePeers c st self
  let latest ← c.nodes.toArray.mapM (latestMembershipIndex configurations)
  let ranks : Array Tm := c.rank.map fun (r : Nat) => Tm.int (Int.ofNat r)
  let mut best : SOpt Tm := ⟨.bool false, .int 0⟩
  for candidate in c.sorted do
    let selectedMatch ← pick st.mi best.val
    let selectedLatest ← pick latest best.val
    let selectedRank ← pick ranks best.val
    let better ←
      orL
        [
          ← lt selectedMatch st.mi[candidate]!,
          ← andL
              [
                ← eqT selectedMatch st.mi[candidate]!,
                ← orL
                    [
                      ← lt selectedLatest latest[candidate]!,
                      ← andL
                          [
                            ← eqT selectedLatest latest[candidate]!,
                            ← lt selectedRank (.int c.rank[candidate]!)
                          ]
                    ]
              ]
        ]
    let replace ← andL [eligible[candidate]!, ← orL [← notT best.isSome, better]]
    best ← Merge.merge replace (⟨.bool true, .int candidate⟩ : SOpt Tm) best
  return best

def nominateSuccessor (c : Ctx) (st : SNode) (self : Nat) : EM Unit := do
  let successor ← findSuccessor c st self
  swhen successor.isSome do sendAtE (← mkMsg c TAG_PROPOSE st.ct []) successor.val c.n

def canStartElection (c : Ctx) (st : SNode) (self : Nat) : GM Tm := do
  andL
    [
      ← orL
          [
            ← eqK st.role ROLE_FOLLOWER,
            ← eqK st.role ROLE_PRE_VOTE_CANDIDATE,
            ← eqK st.role ROLE_CANDIDATE
          ],
      ← orL
          [
            ← andL [(← st.activeMembers c)[self]!, ← campaignEligible c self st],
            (← st.retirementCompletedNodes c)[self]!
          ],
      ← notT (← st.retiredCommitted c self)
    ]

def highestCommittableIndex (c : Ctx) (st : SNode) (self : Nat) : GM Tm := do
  let members ← st.activeMembers c
  let configurations ← st.activeConfigurations c
  foldMax (.int 0) st.log.len
    (fun index => do
      let replicatedBy ←
        SSet.filter members
          fun node => do
            orL [.bool (node == self), ← le index st.mi[node]!]
      andL
        [
          ← lt st.ci index,
          ← isSignatureAt st.log index,
          ← eqT (← termAt st.log index) st.ct,
          ← hasQuorum c configurations replicatedBy
        ])
    pure (.int 0)

def advanceCommit (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  let commitIndex ← highestCommittableIndex c st self
  sif (← le commitIndex st.ci) (pure st) do
    let committed ← st.commitThrough self commitIndex
    sif (← committed.retiredCommitted c self)
      (do
        swhen (← eqK st.role ROLE_LEADER) (nominateSuccessor c st self)
        return { committed with role := .int ROLE_NONE, lk := .bool false })
      (pure committed)

/-! ## Node.lean: outgoing messages -/

def makeAppendEntriesRequest (c : Ctx) (st : SNode) (destination : Nat) (endIndex : Tm)
    : GM SMsg := do
  let previousIndex := st.sent[destination]!
  mkMsg c TAG_AE st.ct
    [
      (M_PREV, previousIndex),
      (M_PREV_TERM, ← termAt st.log previousIndex),
      (M_LEADER_COMMIT, st.ci)
    ]
    (some (← messageEntries st.log previousIndex endIndex))

def makeRequestVoteRequest (c : Ctx) (tag : Int) (st : SNode) : GM SMsg := do
  mkMsg c tag st.ct
    [(M_LC_TERM, ← lastCommittableTerm st), (M_LC_INDEX, ← lastCommittableIndex st)]

/-! ## Node.lean: appending entries -/

/-- `applyTransactionEffect` for the first effect, when `appliedEffects = []`. -/
def applyTransactionEffect (c : Ctx) (self : Nat) (st : SNode)
    (effect : TransactionEffect String)
    : EM SNode := do
  match effect with
  | .reconfiguration nodes =>
      let bits := c.bitsOf nodes
      let previous ← (configurationHistory c st.log).lastD c.cfg0Record
      let previousConfiguration := previous.extract C_NODES (C_NODES + c.n)
      guardE
        (← andL
            [
              .bool (bits.any id),
              ← notT (← SSet.eqS (SSet.ofBools bits) previousConfiguration)
            ])
      let addedPeers :=
        (← SSet.diff (SSet.ofBools bits) (← eligiblePeers c st self)).erase self
      let configured : SNode :=
        {
          st with
            sent :=
              ← c.nodes.toArray.mapM
                  fun peer =>
                    iteT addedPeers[peer]! st.log.len st.sent[peer]!
        }
      for peer in c.sorted do
        swhen addedPeers[peer]! do
          sendE (← makeAppendEntriesRequest c configured peer st.log.len) peer
      return configured
  | .retiredCommitted nodes =>
      let bits := c.bitsOf nodes
      let awaiting ←
        SSet.diff (← st.retirementCompletedNodes c) (← retiredCommittedNodes c st.log)
      guardE (← andL [.bool (bits.any id), ← SSet.subset (SSet.ofBools bits) awaiting])
      return st

def appendEntry (c : Ctx) (self : Nat) (st : SNode) (content : EntryContent String String)
    : EM SNode := do
  match content with
  | .transaction txId effects =>
      let tx : Tm := .int (c.txCode txId)
      match effects with
      | [] =>
          let record :=
            #[st.ct, .bool false, tx, .bool false, .bool false]
            ++ Array.replicate c.n (.bool false)
          return { st with log := ← st.log.push record }
      | [effect] =>
          let st ← applyTransactionEffect c self st effect
          let (retired, nodes) :=
            match effect with
            | .reconfiguration nodes => (false, nodes)
            | .retiredCommitted nodes => (true, nodes)
          let record :=
            #[st.ct, .bool false, tx, .bool true, .bool retired]
            ++ (c.bitsOf nodes).map .bool
          return { st with log := ← st.log.push record }
      | _ =>
          unsupported "an appended transaction with several effects"
          return st
  | .signature =>
      guardE (← notT (← eqK st.log.len 0))
      let record :=
        #[st.ct, .bool true, .int 0, .bool false, .bool false]
        ++ Array.replicate c.n (.bool false)
      return { st with log := ← st.log.push record }

def appendBatch (c : Ctx) (self : Nat) (st : SNode)
    (entries : List (EntryContent String String))
    : EM SNode := do
  guardE
    (← andL
        [
          ← eqK st.role ROLE_LEADER,
          ← notT (← st.retiredCommitted c self),
          .bool !entries.isEmpty
        ])
  let mut appended := st
  for entry in entries do
    appended ← appendEntry c self appended entry
  advanceCommit c appended self

def sendEntries (c : Ctx) (self : Nat) (st : SNode) (destination : Nat) (endIndex : Tm)
    : EM SNode := do
  let previousIndex := st.sent[destination]!
  let endTerm ← termAt st.log endIndex
  guardE
    (← andL
        [
          ← eqK st.role ROLE_LEADER,
          (← eligiblePeers c st self)[destination]!,
          ← le previousIndex endIndex,
          ← le endIndex st.log.len,
          ← (← messageEntries st.log previousIndex endIndex).all
              fun entry => eqT entry[E_TERM]! endTerm,
          ← orL [← notT (← st.retiredCommitted c self), ← lt previousIndex endIndex]
        ])
  sendE (← makeAppendEntriesRequest c st destination endIndex) destination
  return { st with sent := st.sent.set! destination endIndex }

/-! ## Node.lean: handling AppendEntries -/

def appendEntryMatchesLog (st : SNode) (request : SMsg) : GM Tm := do
  orL
    [
      ← eqK request[M_PREV]! 0,
      ← andL
          [
            ← le request[M_PREV]! st.log.len,
            ← eqT (← termAt st.log request[M_PREV]!) request[M_PREV_TERM]!
          ]
    ]

def hasTermConflict (st : SNode) (request : SMsg) : GM Tm := do
  (← st.log.drop request[M_PREV]!).zipAny (msgEntries request)
    fun existing incoming => do notT (← eqT existing[E_TERM]! incoming[E_TERM]!)

def handleAppendEntiresFromLeader (c : Ctx) (self : Nat) (st : SNode) (request : SMsg)
    : GM (SNode × SMsg) := do
  let entries := msgEntries request
  let previousIndex := request[M_PREV]!
  let newLog ← st.log.append (← entries.drop (← natSub st.log.len previousIndex))
  let commitIndex ←
    maxT st.ci
      (← maxCommittableIndexUpTo newLog
          (← minT request[M_LEADER_COMMIT]! (← addT previousIndex entries.len)))
  let marker ←
    firstLogIndexAfter newLog (.int 0)
      fun entry => do
        andL [← isRetCom entry, entry[E_NODES + self]!]
  let firstNewSignature ←
    firstLogIndexAfter newLog (← maxT st.log.len marker.val)
      fun entry => pure entry[E_SIG]!
  let retirementCommitIndex ←
    iteT marker.isSome
      (← iteT firstNewSignature.isSome (← minT commitIndex firstNewSignature.val)
          commitIndex)
      commitIndex
  let committed ←
    ({ st with log := newLog } : SNode).commitThrough self retirementCommitIndex
  let response ←
    mkMsg c TAG_AER committed.ct
      [(M_SUCCESS, .bool true), (M_LAST_LOG, ← addT previousIndex entries.len)]
  return (← committed.commitThrough self commitIndex, response)

def handleAppendEntriesRequest (c : Ctx) (self source : Nat) (st : SNode) (request : SMsg)
    : EM SNode := do
  let term := request[M_TERM]!
  let st ←
    Merge.merge
      (← andL
          [
            ← eqT term st.ct,
            ← orL [← eqK st.role ROLE_CANDIDATE, ← eqK st.role ROLE_PRE_VOTE_CANDIDATE]
          ])
      { st with role := .int ROLE_FOLLOWER, nf := .bool true } st
  let previousIndex := request[M_PREV]!
  sif (← orL [← lt term st.ct, ← notT (← appendEntryMatchesLog st request)])
    (do
      sif (← orL [← lt term st.ct, ← eqK (← termAt st.log previousIndex) 0])
        (sendE
          (← mkMsg c TAG_AER st.ct [(M_SUCCESS, .bool false), (M_LAST_LOG, st.log.len)])
          source)
        (do
          let lastLogIndex ←
            findHighestPossibleMatch st.log previousIndex request[M_PREV_TERM]!
          sendE
            (← mkMsg c TAG_AER (← termAt st.log lastLogIndex)
                [(M_SUCCESS, .bool false), (M_LAST_LOG, lastLogIndex)])
            source)
      return st)
    (do
      let st := { st with lk := .bool true }
      let conflict ← hasTermConflict st request
      sif (← orL [← lt previousIndex st.ci, ← andL [conflict, ← notT st.nf]]) (pure st) do
        let st ←
          Merge.merge conflict
            { st with log := ← st.log.take previousIndex, nf := .bool false } st
        let (next, response) ← handleAppendEntiresFromLeader c self st request
        sendE response source
        return next)

def handleAppendEntriesResponse (c : Ctx) (self : Nat) (st : SNode) (source : Nat)
    (response : SMsg)
    : EM SNode := do
  sif (← notT (← eqK st.role ROLE_LEADER)) (pure st) do
    sif response[M_SUCCESS]!
      (do
        sif (← eqT response[M_TERM]! st.ct)
          (advanceCommit c
            {
              st with
                mi := st.mi.set! source (← maxT st.mi[source]! response[M_LAST_LOG]!)
            }
            self)
          (pure st))
      (do
        let retryIndex ←
          findHighestPossibleMatch st.log response[M_LAST_LOG]! response[M_TERM]!
        return {
          st with
            sent :=
              st.sent.set! source
                (← maxT (← minT retryIndex st.sent[source]!) st.mi[source]!)
        })

/-! ## Node.lean: handling elections -/

def voteLogUpToDate (st : SNode) (request : SMsg) : GM Tm := do
  let term ← maxCommittableTerm st.log
  orL
    [
      ← lt term request[M_LC_TERM]!,
      ← andL
          [
            ← eqT request[M_LC_TERM]! term,
            ← le (← maxCommittableIndex st.log) request[M_LC_INDEX]!
          ]
    ]

def handleRequestVoteRequest (c : Ctx) (st : SNode) (source : Nat) (request : SMsg)
    : EM SNode := do
  let voteGranted ←
    andL
      [
        ← eqT request[M_TERM]! st.ct,
        ← voteLogUpToDate st request,
        ← notT st.lk,
        ← orL [← eqK st.vf (-1), ← eqK st.vf source]
      ]
  sendE (← mkMsg c TAG_RVR st.ct [(M_GRANTED, voteGranted)]) source
  return { st with vf := ← iteT voteGranted (.int source) st.vf }

def handleRequestPreVote (c : Ctx) (st : SNode) (source : Nat) (request : SMsg)
    : EM SNode := do
  let voteGranted ← andL [← eqT request[M_TERM]! st.ct, ← voteLogUpToDate st request]
  sendE (← mkMsg c TAG_RPVR st.ct [(M_GRANTED, voteGranted)]) source
  return st

def leaderState (c : Ctx) (st : SNode) : GM SNode := do
  let log ←
    Merge.merge (← lt (.int 0) st.ci) (← st.log.take (← lastCommittableIndex st)) st.log
  return {
    st with
      role := .int ROLE_LEADER
      log
      lk := .bool true
      sent := Array.replicate c.n log.len
      mi := Array.replicate c.n (.int 0)
  }

def becomeLeader (c : Ctx) (self : Nat) (st : SNode) : EM SNode := do
  let leader ← advanceCommit c (← leaderState c st) self
  let peers ← eligiblePeers c leader self
  for peer in c.sorted do
    swhen peers[peer]! do
      sendE (← makeAppendEntriesRequest c leader peer leader.log.len) peer
  return leader

def electIfQuorum (c : Ctx) (self : Nat) (st : SNode) : EM SNode := do
  let ready ←
    andL
      [
        ← eqK st.role ROLE_CANDIDATE,
        ← hasQuorum c (← st.activeConfigurations c) st.votes,
        ← notT (← st.retiredCommitted c self)
      ]
  sif ready (becomeLeader c self st) (pure st)

def broadcastToOthers (c : Ctx) (self : Nat) (st : SNode) (message : SMsg) : EM Unit := do
  let others := (← st.activeMembers c).erase self
  for destination in c.sorted do
    swhen others[destination]! (sendE message destination)

def becomeCandidate (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  let candidate : SNode :=
    {
      st with
        role := .int ROLE_CANDIDATE
        ct := ← addK st.ct 1
        vf := .int self
        lk := .bool false
        votes := SSet.single c.n self
        pv := SSet.empty c.n
    }
  let next ← electIfQuorum c self candidate
  broadcastToOthers c self candidate (← makeRequestVoteRequest c TAG_RV candidate)
  return next

def becomePreVoteCandidate (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  let preVoteCandidate : SNode :=
    {
      st with
        role := .int ROLE_PRE_VOTE_CANDIDATE
        lk := .bool false
        pv := SSet.single c.n self
    }
  sif (← hasQuorum c (← preVoteCandidate.activeConfigurations c) preVoteCandidate.pv)
    (becomeCandidate c preVoteCandidate self)
    (do
      broadcastToOthers c self preVoteCandidate
        (← makeRequestVoteRequest c TAG_RPV preVoteCandidate)
      return preVoteCandidate)

def startElection (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  guardE (← canStartElection c st self)
  if c.preVote[self]! then becomePreVoteCandidate c st self else becomeCandidate c st self

def handleRequestVoteResponse (c : Ctx) (self : Nat) (st : SNode) (source : Nat)
    (response : SMsg)
    : EM SNode := do
  let accepted ←
    andL
      [← eqK st.role ROLE_CANDIDATE, ← eqT response[M_TERM]! st.ct, response[M_GRANTED]!]
  sif accepted (electIfQuorum c self { st with votes := st.votes.insert source })
    (pure st)

def handleRequestPreVoteResponse (c : Ctx) (self : Nat) (st : SNode) (source : Nat)
    (response : SMsg)
    : EM SNode := do
  let accepted ←
    andL
      [
        ← eqK st.role ROLE_PRE_VOTE_CANDIDATE,
        ← eqT response[M_TERM]! st.ct,
        response[M_GRANTED]!
      ]
  sif accepted
    (do
      let st := { st with pv := st.pv.insert source }
      sif (← hasQuorum c (← st.activeConfigurations c) st.pv) (becomeCandidate c st self)
        (pure st))
    (pure st)

def checkQuorum (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  guardE
    (← andL
        [← eqK st.role ROLE_LEADER, ← SSet.nonempty ((← st.activeMembers c).erase self)])
  return { st with role := .int ROLE_FOLLOWER, lk := .bool false }

def handleProposeVoteRequest (c : Ctx) (st : SNode) (self : Nat) (term : Tm)
    : EM SNode := do
  sif (← andL [← eqT term st.ct, ← canStartElection c st self])
    (becomeCandidate c st self) (pure st)

def updateTerm (st : SNode) (term : Tm) : GM SNode := do
  Merge.merge (← lt st.ct term)
    {
      st with
        role := .int ROLE_FOLLOWER
        ct := term
        vf := .int (-1)
        lk := .bool false
        nf := .bool true
        pv := st.pv.map fun _ => .bool false
    }
    st

def observeTerm (st : SNode) (message : SMsg) : GM SNode := do
  let tag := message[M_TAG]!
  let updated ← updateTerm st message[M_TERM]!
  let response ← Merge.merge (← eqK st.role ROLE_LEADER) updated st
  Merge.merge (← eqK tag TAG_PROPOSE) st
    (← Merge.merge (← eqK tag TAG_AER) response updated)

/-! ## Node.lean: the step -/

def receive (c : Ctx) (self source : Nat) (st : SNode) (message : SMsg) : EM SNode := do
  let st ← observeTerm st message
  let tag := message[M_TAG]!
  sif (← eqK tag TAG_AE) (handleAppendEntriesRequest c self source st message)
  <| sif (← eqK tag TAG_AER) (handleAppendEntriesResponse c self st source message)
  <| sif (← eqK tag TAG_RV) (handleRequestVoteRequest c st source message)
  <| sif (← eqK tag TAG_RVR) (handleRequestVoteResponse c self st source message)
  <| sif (← eqK tag TAG_RPV) (handleRequestPreVote c st source message)
  <| sif (← eqK tag TAG_RPVR) (handleRequestPreVoteResponse c self st source message)
  <| handleProposeVoteRequest c st self message[M_TERM]!

def act (c : Ctx) (self : Nat) (st : SNode) : Input String String → EM SNode
  | .append entries => appendBatch c self st entries
  | .sendEntries destination endIndex =>
      match c.names.idxOf? destination with
      | some destination => sendEntries c self st destination (.int endIndex)
      | none => do
          guardE (.bool false)
          return st
  | .timeout .election => startElection c st self
  | .timeout .checkQuorum => checkQuorum c st self
  | .nominateSuccessor => do
      guardE (← eqK st.role ROLE_LEADER)
      nominateSuccessor c st self
      return st

end CCFRaft.MidTrace.Gen
