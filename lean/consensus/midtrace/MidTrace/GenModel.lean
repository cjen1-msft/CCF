module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Model
public import MidTrace.GenLib

@[expose] public section

/-!
# The node model over `GenLib`

A function-by-function transliteration of `Model/NodeState.lean`,
`Model/ClusterConfig.lean` and `Model/Node.lean`: each definition has the same
name and structure as the one it encodes, with list, set, option and effect
operations replaced by their `GenLib` counterparts. Nothing here is specific
to mid-trace validation or to any lowering.

Representation over the replay header's finite universe:

* Entry: term, signature flag, request ID, configuration-present flag, then
  independent configuration and retirement-confirmation bitsets.
* Configuration: `index, nodes_0 .. nodes_{n-1}`.
* Message: `tag, term, prevLogIndex, prevLogTerm, primaryCommit, success,
  lastLogIndex, lastCommittableTerm, lastCommittableIndex, voteGranted`,
  then AppendEntries entries as an `SList` (offset, length, one array per
  entry field). Fields another variant does not have are never read.
* Node identities are indices into the declared nodes; `votedFor` is `-1` for
  `none`, and optional naturals are `-1` for `none`.
-/

namespace Consensus.MidTrace.Gen

open Model.Node (Entry EntryContent AppendEntryInput Input)

abbrev Tm := Smt.Tm

def ROLE_NONE : Int := 0
def ROLE_FOLLOWER : Int := 1
def ROLE_PREVOTE : Int := 2
def ROLE_CANDIDATE : Int := 3
def ROLE_PRIMARY : Int := 4

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
def E_REQ : Nat := 2
def E_HAS_CFG : Nat := 3
def E_CFG_START : Nat := 4
def E_RC_START (n : Nat) : Nat := E_CFG_START + n

def C_INDEX : Nat := 0
def C_NODES : Nat := 1

def M_TAG : Nat := 0
def M_TERM : Nat := 1
def M_PREV : Nat := 2
def M_PREV_TERM : Nat := 3
def M_PRIMARY_COMMIT : Nat := 4
def M_SUCCESS : Nat := 5
def M_LAST_LOG : Nat := 6
def M_LC_TERM : Nat := 7
def M_LC_INDEX : Nat := 8
def M_GRANTED : Nat := 9
def M_ENT_OFF : Nat := 10
def M_ENT_LEN : Nat := 11
def M_ENTS : Nat := 12

/-- Node IDs are indices in the lexically ordered replay header. -/
structure Ctx where
  n : Nat

namespace Ctx

def nodes (c : Ctx) : List Nat := List.range c.n

def bitsOf (c : Ctx) (nodes : CCF.Finset Nat) : SSet :=
  c.nodes.toArray.map fun i => .bool (decide (i ∈ nodes))

def entrySrts (c : Ctx) : Array Srt :=
  #[.int, .bool, .int, .bool] ++ Array.replicate (2 * c.n) .bool

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
  pk : Tm
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
      pk := ← iteT c a.pk b.pk
      votes := ← Merge.merge c a.votes b.votes
      pv := ← Merge.merge c a.pv b.pv
      rci := ← iteT c a.rci b.rci
    }⟩

abbrev SMsg := Array Tm

def entryRecord (c : Ctx) (term : Tm) (content : EntryContent) : Array Tm :=
  let m := content.metadata
  let req :=
    match content with
    | .transaction id _ => id
    | .signature => 0
  #[term, .bool content.isSignature, .int req, .bool m.configuration.isSome]
  ++ c.bitsOf (m.configuration.getD ∅)
  ++ c.bitsOf m.retirementConfirmations

/-- Keep the base arrays for witness decoding. Mask unused variant fields in the
symbolic log so equality of records is precisely equality of entries. -/
def declareLogWithBases (c : Ctx) (len : Tm) : GM (SList × Array Tm) := do
  let fields ←
    c.entrySrts.mapIdxM
      fun i s =>
        declareArr (.arr s) (some 0) (gapUniform := i == E_TERM)
  let sig := fields[E_SIG]!
  let has := fields[E_HAS_CFG]!
  let arrs ←
    fields.mapIdxM
      fun i a => do
        if i == E_TERM || i == E_SIG then return a
        lam c.entrySrts[i]!
          fun k => do
            let tx ← notT (← select sig k)
            let present ←
              if E_CFG_START <= i && i < E_RC_START c.n then
                andL [tx, ← select has k]
              else
                pure tx
            iteT present (← select a k) (if i == E_REQ then .int 0 else .bool false)
  return ({ off := .int 0, len, arrs }, fields)

def declareLog (c : Ctx) (len : Tm) : GM SList := Prod.fst <$> declareLogWithBases c len

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

/-- Position `p` denotes entry `p + 1`; an empty log has no configurations. -/
def configurationHistory (c : Ctx) (log : SList) : SFiltered where
  hi := log.len
  mask p := do
    andL [← lt p log.len, ← log.getF p E_HAS_CFG]
  elem p := do
    let e ← log.get p
    return #[← addK p 1] ++ e.extract E_CFG_START (E_RC_START c.n)
  dflt := #[.int 0] ++ Array.replicate c.n (.bool false)

def activeConfigurations (c : Ctx) (log : SList) (commitIndex : Tm) : GM SFiltered := do
  let history := configurationHistory c log
  let committed :=
    history.filter fun configuration => le configuration[C_INDEX]! commitIndex
  return history.drop (← natSub (← committed.length) (.int 1))

def configurationMembers (c : Ctx) (configurations : SFiltered) : GM SSet :=
  configurations.unionAt C_NODES c.n

def latestConfigurationMembers (c : Ctx) (history : SFiltered) : GM SSet := do
  return (← history.lastD history.dflt).extract C_NODES (C_NODES + c.n)

def removedNodes (c : Ctx) (log : SList) : GM SSet := do
  let history := configurationHistory c log
  SSet.diff (← configurationMembers c history) (← latestConfigurationMembers c history)

def retirementIndexInLog (c : Ctx) (node : Nat) (log : SList) : GM (SOpt Tm) := do
  let history := configurationHistory c log
  let width := history.dflt.size
  let pairs ← history.zipTail
  pairs.findF?
    (fun pair => do andL [pair[C_NODES + node]!, ← notT pair[width + C_NODES + node]!])
    (width + C_INDEX)

def retiredCommittedNodes (c : Ctx) (log : SList) : GM SSet :=
  c.nodes.toArray.mapM fun node => log.any fun e => pure e[E_RC_START c.n + node]!

def hasConfigurationMajority (c : Ctx) (support : SSet) (configuration : Array Tm)
    : GM Tm := do
  let nodes := configuration.extract C_NODES (C_NODES + c.n)
  lt (← countT nodes) (← doubleT (← countT (← SSet.inter support nodes)))

def SNode.activeConfigurations (c : Ctx) (st : SNode) : GM SFiltered :=
  Gen.activeConfigurations c st.log st.ci

def SNode.signedActiveConfigurations (c : Ctx) (st : SNode) : GM SFiltered := do
  let signed ← maxCommittableIndex st.log
  return (← st.activeConfigurations c).filter fun cfg => le cfg[C_INDEX]! signed

def SNode.activeMembers (c : Ctx) (st : SNode) : GM SSet := do
  configurationMembers c (← st.activeConfigurations c)

def SNode.retirementCompletedNodes (c : Ctx) (st : SNode) : GM SSet := do
  let committedLog ← st.log.take st.ci
  SSet.diff (← removedNodes c committedLog) (← retiredCommittedNodes c committedLog)

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

def SNode.isRetiredCommitted (c : Ctx) (node : Nat) (st : SNode) : GM Tm := do
  eqK (← st.retirement c node).phase PHASE_RETIRED_COMMITTED

def SNode.recordCommit (c : Ctx) (node : Nat) (st : SNode) (ci : Tm) : GM SNode := do
  let marker ←
    firstLogIndexAfter (← st.log.take ci) (.int 0) fun e => pure e[E_RC_START c.n + node]!
  let previouslyConfirmed ← le (.int 0) st.rci
  let next := { st with ci, rci := ← iteT previouslyConfirmed st.rci (← marker.code) }
  let clear ← andL [← notT previouslyConfirmed, ← next.isRetiredCommitted c node]
  return {
    next with
      role := ← iteT clear (.int ROLE_NONE) st.role,
      pk := ← iteT clear (.bool false) st.pk
  }

/-! ## Node.lean: primary state -/

def hasQuorum (c : Ctx) (configurations : SFiltered) (voters : SSet) : GM Tm := do
  andL
    [
      ← configurations.any (fun _ => pure (.bool true)),
      ← configurations.all (hasConfigurationMajority c voters)
    ]

def eligiblePeers (c : Ctx) (st : SNode) (self : Nat) : GM SSet := do
  return (← SSet.union (← st.activeMembers c) (← st.retirementCompletedNodes c)).erase
    self

def latestMembershipIndex (configurations : SFiltered) (node : Nat) : GM Tm :=
  configurations.maxD (fun configuration => pure configuration[C_NODES + node]!)
    (fun configuration => pure configuration[C_INDEX]!) (.int 0)

def findSuccessor (c : Ctx) (st : SNode) (self : Nat) (excluded := SSet.empty c.n)
    : GM (SOpt Tm) := do
  let configurations ← st.activeConfigurations c
  let eligible ← SSet.diff (← eligiblePeers c st self) excluded
  let latest ← c.nodes.toArray.mapM (latestMembershipIndex configurations)
  let mut best : SOpt Tm := ⟨.bool false, .int 0⟩
  for candidate in c.nodes do
    let selectedMatch ← pick st.mi best.val
    let selectedLatest ← pick latest best.val
    -- Candidates are visited in increasing ID order, so a tie favors this candidate.
    let better ←
      orL
        [
          ← lt selectedMatch st.mi[candidate]!,
          ← andL
              [
                ← eqT selectedMatch st.mi[candidate]!,
                ← le selectedLatest latest[candidate]!
              ]
        ]
    let replace ← andL [eligible[candidate]!, ← orL [← notT best.isSome, better]]
    best ← Merge.merge replace (⟨.bool true, .int candidate⟩ : SOpt Tm) best
  return best

def nominateSuccessor (c : Ctx) (st : SNode) (self : Nat) (excluded := SSet.empty c.n)
    : EM SNode := do
  guardE (← eqK st.role ROLE_PRIMARY)
  let successor ← findSuccessor c st self excluded
  swhen successor.isSome do sendAtE (← mkMsg c TAG_PROPOSE st.ct []) successor.val c.n
  return st

def canStartElection (c : Ctx) (st : SNode) (self : Nat) : GM Tm := do
  andL
    [
      ← orL
          [
            ← eqK st.role ROLE_FOLLOWER,
            ← eqK st.role ROLE_PREVOTE,
            ← eqK st.role ROLE_CANDIDATE
          ],
      ← orL
          [
            (← configurationMembers c (← st.signedActiveConfigurations c))[self]!,
            (← st.retirementCompletedNodes c)[self]!
          ],
      ← notT (← st.isRetiredCommitted c self)
    ]

def highestCommittableIndex (c : Ctx) (st : SNode) (self : Nat) : GM Tm := do
  let members ← st.activeMembers c
  let commits ←
    scan .int st.ci
      fun index ci => do
        let configs :=
          (← activeConfigurations c st.log ci).filter (fun cfg => le cfg[C_INDEX]! index)
        let replicatedBy ←
          SSet.filter members
            fun node => do
              orL [.bool (node == self), ← le index st.mi[node]!]
        let commit ←
          andL
            [
              ← lt ci index,
              ← isSignatureAt st.log index,
              ← eqT (← termAt st.log index) st.ct,
              ← hasQuorum c configs replicatedBy
            ]
        iteT commit index ci
  select commits st.log.len

def advanceCommit (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  let commitIndex ← highestCommittableIndex c st self
  sif (← le commitIndex st.ci) (pure st) do
    let committed ← st.recordCommit c self commitIndex
    swhen (← andL [← committed.isRetiredCommitted c self, ← eqK st.role ROLE_PRIMARY]) do
      let frontier ← (← SOpt.ofCode committed.rci).getD commitIndex
      discard
      <| nominateSuccessor c st self (← retiredCommittedNodes c (← st.log.take frontier))
    return committed

/-! ## Node.lean: outgoing messages -/

def makeAppendEntriesRequest (c : Ctx) (st : SNode) (destination : Nat) (endIndex : Tm)
    : GM SMsg := do
  let previousIndex := st.sent[destination]!
  mkMsg c TAG_AE st.ct
    [
      (M_PREV, previousIndex),
      (M_PREV_TERM, ← termAt st.log previousIndex),
      (M_PRIMARY_COMMIT, st.ci)
    ]
    (some (← messageEntries st.log previousIndex endIndex))

def makeRequestVoteRequest (c : Ctx) (tag : Int) (st : SNode) : GM SMsg := do
  mkMsg c tag st.ct
    [(M_LC_TERM, ← lastCommittableTerm st), (M_LC_INDEX, ← lastCommittableIndex st)]

def sendEntries (c : Ctx) (self : Nat) (st : SNode) (destination : Nat) (endIndex : Tm)
    : EM SNode := do
  if destination >= c.n then
    guardE (.bool false)
    return st
  let previousIndex := st.sent[destination]!
  let endTerm ← termAt st.log endIndex
  guardE
    (← andL
        [
          ← eqK st.role ROLE_PRIMARY,
          (← eligiblePeers c st self)[destination]!,
          ← le previousIndex endIndex,
          ← le endIndex st.log.len,
          ← (← messageEntries st.log previousIndex endIndex).all
              fun entry => eqT entry[E_TERM]! endTerm,
          ← orL
              [
                ← notT (← st.isRetiredCommitted c self),
                ← lt (← addK previousIndex 1) endIndex
              ]
        ])
  sendE (← makeAppendEntriesRequest c st destination endIndex) destination
  return { st with sent := st.sent.set! destination endIndex }

/-! ## Node.lean: appending entries -/

def appendEntry (c : Ctx) (self : Nat) (st : SNode) (content : EntryContent)
    : EM SNode := do
  if content.isSignature then guardE (← lt (.int 0) st.log.len)
  let metadata := content.metadata
  if metadata.retirementConfirmations.Nonempty then
    let awaiting ←
      SSet.diff (← st.retirementCompletedNodes c) (← retiredCommittedNodes c st.log)
    guardE (← SSet.subset (c.bitsOf metadata.retirementConfirmations) awaiting)
  let mut st := st
  if let some nodes := metadata.configuration then
    let bits := c.bitsOf nodes
    let previous ← latestConfigurationMembers c (configurationHistory c st.log)
    guardE
      (← andL
          [
            .bool (decide nodes.Nonempty),
            ← notT (← SSet.eqS bits previous),
            ← notT (← SSet.nonempty (← SSet.inter bits (← removedNodes c st.log)))
          ])
    let added := (← SSet.diff bits (← eligiblePeers c st self)).erase self
    st :=
      {
        st with
          sent := ← c.nodes.toArray.mapM fun j => iteT added[j]! st.log.len st.sent[j]!
      }
    for peer in c.nodes do
      swhen added[peer]! do sendE (← makeAppendEntriesRequest c st peer st.log.len) peer
  return { st with log := ← st.log.push (entryRecord c st.ct content) }

def appendBatch (c : Ctx) (self : Nat) (st : SNode) (entries : List AppendEntryInput)
    : EM SNode := do
  guardE
    (← andL
        [
          ← eqK st.role ROLE_PRIMARY,
          ← notT (← st.isRetiredCommitted c self),
          .bool !entries.isEmpty
        ])
  let mut appended := st
  for entry in entries do
    appended ← appendEntry c self appended entry.content
    for (peer, batchEnd) in entry.flushes do
      appended ← sendEntries c self appended peer (.int batchEnd)
  advanceCommit c appended self

/-! ## Node.lean: handling AppendEntries -/

def appendEntryMatchesLog (st : SNode) (request : SMsg) : GM Tm := do
  andL
    [
      ← le request[M_PREV]! st.log.len,
      ← eqT (← termAt st.log request[M_PREV]!) request[M_PREV_TERM]!
    ]

def firstTermConflictIndex (st : SNode) (request : SMsg) : GM (SOpt Tm) := do
  let prev := request[M_PREV]!
  let localTail ← st.log.drop prev
  let incoming := msgEntries request
  let hi ← addK (← minT localTail.len incoming.len) (-1)
  let differs i := do
    neT (← localTail.getF i E_TERM) (← incoming.getF i E_TERM)
  let index ← foldFirst (.int 0) hi differs (fun i => do addK (← addT prev i) 1) (.int 0)
  return ⟨← lt (.int 0) index, index⟩

def handleAppendEntiresFromPrimary (c : Ctx) (self : Nat) (st : SNode) (request : SMsg)
    : GM (SNode × SMsg) := do
  let entries := msgEntries request
  let previousIndex := request[M_PREV]!
  let newLog ← st.log.append (← entries.drop (← natSub st.log.len previousIndex))
  let last ← addT previousIndex entries.len
  let limit ← minT request[M_PRIMARY_COMMIT]! last
  let commitAt (k : Tm) := do
    maxT st.ci (← maxCommittableIndexUpTo newLog (← minT k limit))
  -- At each new signature commitAt is monotone. Only the first commit that
  -- includes a confirmation can change rci, role or pk. Run recordCommit on
  -- that exact prefix (not the final log), then do the unconditional final commit.
  let marker ← firstLogIndexAfter newLog (.int 0) fun e => pure e[E_RC_START c.n + self]!
  let first ←
    foldFirst (← addK st.log.len 1) newLog.len
      (fun k => do
        andL [← isSignatureAt newLog k, marker.isSome, ← le marker.val (← commitAt k)])
      pure newLog.len
  let mid := { st with log := ← newLog.take first }
  let mid ← mid.recordCommit c self (← commitAt first)
  let next ←
    ({ mid with log := newLog } : SNode).recordCommit c self (← commitAt newLog.len)
  return (next, ← mkMsg c TAG_AER next.ct [(M_SUCCESS, .bool true), (M_LAST_LOG, last)])

def becomeAwareOfNewTerm (st : SNode) (term : Tm) : GM SNode := do
  return {
    st with
      role := .int ROLE_FOLLOWER,
      ct := term,
      nf := .bool true,
      vf := ← iteT (← eqT st.ct term) st.vf (.int (-1)),
      pk := .bool false,
      votes := SSet.empty st.votes.size,
      pv := SSet.empty st.pv.size
  }

def handleAppendEntriesRequest (c : Ctx) (self source : Nat) (st : SNode) (request : SMsg)
    : EM SNode := do
  let term := request[M_TERM]!
  let st ←
    Merge.merge
      (← andL
          [
            ← eqT term st.ct,
            ← orL [← eqK st.role ROLE_CANDIDATE, ← eqK st.role ROLE_PREVOTE]
          ])
      (← becomeAwareOfNewTerm st term) st
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
      let st := { st with pk := .bool true }
      let conflict ← firstTermConflictIndex st request
      sif (← orL [← lt previousIndex st.ci, ← andL [conflict.isSome, ← notT st.nf]])
        (pure st) do
        let st ←
          Merge.merge conflict.isSome
            {
              st with
                log := ← st.log.take (← natSub conflict.val (.int 1)), nf := .bool false
            } st
        let (next, response) ← handleAppendEntiresFromPrimary c self st request
        sendE response source
        return next)

def handleAppendEntriesResponse (c : Ctx) (self : Nat) (st : SNode) (source : Nat)
    (response : SMsg)
    : EM SNode := do
  sif (← notT (← eqK st.role ROLE_PRIMARY)) (pure st) do
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
        ← notT st.pk,
        ← orL [← eqK st.vf (-1), ← eqK st.vf source]
      ]
  sendE (← mkMsg c TAG_RVR st.ct [(M_GRANTED, voteGranted)]) source
  return { st with vf := ← iteT voteGranted (.int source) st.vf }

def handleRequestPreVoteRequest (c : Ctx) (st : SNode) (source : Nat) (request : SMsg)
    : EM SNode := do
  let voteGranted ← andL [← eqT request[M_TERM]! st.ct, ← voteLogUpToDate st request]
  sendE (← mkMsg c TAG_RPVR st.ct [(M_GRANTED, voteGranted)]) source
  return st

def primaryState (c : Ctx) (st : SNode) : GM SNode := do
  let log ←
    Merge.merge (← lt (.int 0) st.ci) (← st.log.take (← lastCommittableIndex st)) st.log
  return {
    st with
      role := .int ROLE_PRIMARY
      log
      pk := .bool true
      sent := Array.replicate c.n log.len
      mi := Array.replicate c.n (.int 0)
  }

def becomePrimary (c : Ctx) (self : Nat) (st : SNode) : EM SNode := do
  let st ← advanceCommit c (← primaryState c st) self
  let peers ← eligiblePeers c st self
  for peer in c.nodes do
    swhen peers[peer]! do sendE (← makeAppendEntriesRequest c st peer st.log.len) peer
  return st

def electIfQuorum (c : Ctx) (self : Nat) (st : SNode) : EM SNode := do
  let ready ←
    andL
      [
        ← eqK st.role ROLE_CANDIDATE,
        ← hasQuorum c (← st.activeConfigurations c) st.votes,
        ← notT (← st.isRetiredCommitted c self)
      ]
  sif ready (becomePrimary c self st) (pure st)

def broadcastToOthers (c : Ctx) (self : Nat) (st : SNode) (message : SMsg) : EM Unit := do
  let others := (← st.activeMembers c).erase self
  for destination in c.nodes do
    swhen others[destination]! (sendE message destination)

def becomeCandidate (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  let candidate : SNode :=
    {
      st with
        role := .int ROLE_CANDIDATE
        ct := ← addK st.ct 1
        vf := .int self
        pk := .bool false
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
        role := .int ROLE_PREVOTE
        pk := .bool false
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
  becomePreVoteCandidate c st self

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
    andL [← eqK st.role ROLE_PREVOTE, ← eqT response[M_TERM]! st.ct, response[M_GRANTED]!]
  sif accepted
    (do
      let st := { st with pv := st.pv.insert source }
      sif (← hasQuorum c (← st.activeConfigurations c) st.pv) (becomeCandidate c st self)
        (pure st))
    (pure st)

def checkQuorum (c : Ctx) (st : SNode) (self : Nat) : EM SNode := do
  guardE
    (← andL
        [← eqK st.role ROLE_PRIMARY, ← SSet.nonempty ((← st.activeMembers c).erase self)])
  return { st with role := .int ROLE_FOLLOWER, pk := .bool false }

def handleProposeRequestVoteRequest (c : Ctx) (st : SNode) (self : Nat) (term : Tm)
    : EM SNode := do
  sif (← andL [← eqT term st.ct, ← canStartElection c st self])
    (becomeCandidate c st self) (pure st)

def updateTerm (st : SNode) (term : Tm) : GM SNode := do
  Merge.merge (← lt st.ct term) (← becomeAwareOfNewTerm st term) st

def observeTerm (st : SNode) (message : SMsg) : GM SNode := do
  let tag := message[M_TAG]!
  let updated ← updateTerm st message[M_TERM]!
  let response ← Merge.merge (← eqK st.role ROLE_PRIMARY) updated st
  Merge.merge (← eqK tag TAG_PROPOSE) st
    (← Merge.merge (← eqK tag TAG_AER) response updated)

/-! ## Node.lean: the step -/

def initAsBackup (st : SNode) (entries : SList) : EM SNode := do
  guardE
    (← andL
        [
          ← eqK st.role ROLE_NONE,
          ← eqK st.ct 0,
          ← eqK st.log.len 0,
          ← eqK st.ci 0,
          ← orL [← eqK entries.len 0, ← isSignatureAt entries entries.len]
        ])
  becomeAwareOfNewTerm { st with log := entries, ci := entries.len }
    (← termAt entries entries.len)

def receive (c : Ctx) (self source : Nat) (st : SNode) (message : SMsg) : EM SNode := do
  let tag := message[M_TAG]!
  let needsPeer ← orL [← eqK tag TAG_AER, ← eqK tag TAG_RVR, ← eqK tag TAG_RPVR]
  sif (← andL [needsPeer, ← notT (← eligiblePeers c st self)[source]!]) (pure st) do
    let st ← observeTerm st message
    sif (← eqK tag TAG_AE) (handleAppendEntriesRequest c self source st message)
    <| sif (← eqK tag TAG_AER) (handleAppendEntriesResponse c self st source message)
    <| sif (← eqK tag TAG_RV) (handleRequestVoteRequest c st source message)
    <| sif (← eqK tag TAG_RVR) (handleRequestVoteResponse c self st source message)
    <| sif (← eqK tag TAG_RPV) (handleRequestPreVoteRequest c st source message)
    <| sif (← eqK tag TAG_RPVR) (handleRequestPreVoteResponse c self st source message)
    <| handleProposeRequestVoteRequest c st self message[M_TERM]!

def literalLog (c : Ctx) (entries : List Entry) : GM SList := do
  entries.foldlM (fun l e => l.push (entryRecord c (.int e.term) e.content))
    (⟨← zeroEntries c, .int 0, .int 0⟩ : SList)

def act (c : Ctx) (self : Nat) (st : SNode) : Input → EM SNode
  | .append entries => appendBatch c self st entries
  | .sendEntries destination endIndex => sendEntries c self st destination (.int endIndex)
  | .timeout .election => startElection c st self
  | .timeout .checkQuorum => checkQuorum c st self
  | .nominateSuccessor => nominateSuccessor c st self
  | .initAsBackup entries => do initAsBackup st (← literalLog c entries)

end Consensus.MidTrace.Gen
