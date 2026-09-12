-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeRetirementCompletedConstraints
import Sparse.NativeRetirementCompletedEncoding
import Sparse.NativeCompilerEncoding
import Sparse.NativeAssignmentEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

def retirementCompletedFirstId (base : Nat) (peer : Nat) : Nat := base + 1 + 3 * peer
def retirementCompletedRetirementId (base : Nat) (peer : Nat) : Nat :=
  retirementCompletedFirstId base peer + 1
def retirementCompletedRetiredId (base : Nat) (peer : Nat) : Nat :=
  retirementCompletedFirstId base peer + 2

def retirementCompletedWitnessAssignment {width : PNat}
    (assignment : Assignment) (base : Nat) (peers : List (Fin width))
    (first retirement retired : Fin width -> Int) : Assignment :=
  match peers with
  | [] => assignment
  | peer :: rest =>
    retirementCompletedWitnessAssignment
      (((assignment.set .int base (first peer)).set .int (base + 1) (retirement peer)).set
        .int (base + 2) (retired peer))
      (base + 3) rest first retirement retired

theorem retirement_completed_witness_assignment_agrees {width : PNat}
    (assignment : Assignment) (limit base : Nat) (peers : List (Fin width))
    (first retirement retired : Fin width -> Int) (within : limit <= base) :
    assignment.AgreesBelow limit
      (retirementCompletedWitnessAssignment assignment base peers first retirement retired) := by
  induction peers generalizing assignment base with
  | nil => exact fun _ _ _ => rfl
  | cons peer rest ih =>
    apply (assignment.agrees_below_set limit .int base _ within).trans
    apply (Assignment.agrees_below_set _ limit .int (base + 1) _ (by omega)).trans
    apply (Assignment.agrees_below_set _ limit .int (base + 2) _ (by omega)).trans
    exact ih _ _ (by omega)

theorem retirement_completed_witness_assignment_head {width : PNat}
    (assignment : Assignment) (base : Nat) (peer : Fin width) (rest : List (Fin width))
    (first retirement retired : Fin width -> Int) :
    let extended := retirementCompletedWitnessAssignment assignment base (peer :: rest)
      first retirement retired
    extended .int base = first peer /\
      extended .int (base + 1) = retirement peer /\
      extended .int (base + 2) = retired peer := by
  let seeded :=
    (((assignment.set .int base (first peer)).set .int (base + 1) (retirement peer)).set
      .int (base + 2) (retired peer))
  have agreement := retirement_completed_witness_assignment_agrees seeded (base + 3)
    (base + 3) rest first retirement retired (le_refl _)
  dsimp only [retirementCompletedWitnessAssignment]
  constructor
  · rw [<- agreement .int base (by omega)]
    simp [seeded, Assignment.set]
  · constructor
    · rw [<- agreement .int (base + 1) (by omega)]
      simp [seeded, Assignment.set]
    · rw [<- agreement .int (base + 2) (by omega)]
      simp [seeded, Assignment.set]

def retirementCompletedPeerClauses {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed first retirement retired : Nat)
    (peer : Fin width) : List (Expr .bool) :=
  [implies enabled
      (retirementIndexTerm width bootstrap committedLength entries peer
        (.free .int first) (.free .int retirement)),
    implies enabled
      (retiredRecordTerm width committedLength entries peer (.free .int retired)),
    implies enabled
      (.equal (.bit (.free (.bits width) completed) peer)
        (retirementCompletedMemberTerm peer current members
          (.free .int first) (.free .int retirement) (.free .int retired)))]

def retirementCompletedClausesFrom {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed : Nat) :
    Nat -> List (Fin width) -> List (Expr .bool)
  | _, [] => []
  | base, peer :: rest =>
    retirementCompletedPeerClauses bootstrap enabled entries committedLength current members
      completed base (base + 1) (base + 2) peer ++
    retirementCompletedClausesFrom bootstrap enabled entries committedLength current members
      completed (base + 3) rest

def retirementCompletedClauses {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed base : Nat) : List (Expr .bool) :=
  retirementCompletedClausesFrom bootstrap enabled entries committedLength current members
    completed (base + 1) (List.finRange width)

theorem retirement_completed_witness_clauses_holds {width : PNat}
    (seed : Assignment) (base completedId : Nat) (completedBits : BitVec width)
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (peers : List (Fin width))
    (first retirement retired : Fin width -> Int)
    (completedLookup :
      retirementCompletedWitnessAssignment seed base peers first retirement retired
        (.bits width) completedId = completedBits)
    (constraints : forall peer,
      (implies enabled
        (retirementIndexTerm width bootstrap committedLength entries peer
          (.integer (first peer)) (.integer (retirement peer)))).eval
          (retirementCompletedWitnessAssignment seed base peers first retirement retired)
          Locals.empty = true /\
      (implies enabled
        (retiredRecordTerm width committedLength entries peer
          (.integer (retired peer)))).eval
          (retirementCompletedWitnessAssignment seed base peers first retirement retired)
          Locals.empty = true /\
      (implies enabled
        (.equal (.bit (.bits completedBits) peer)
          (retirementCompletedMemberTerm peer current members
            (.integer (first peer)) (.integer (retirement peer))
            (.integer (retired peer))))).eval
          (retirementCompletedWitnessAssignment seed base peers first retirement retired)
          Locals.empty = true) :
    Holds (retirementCompletedClausesFrom bootstrap enabled entries committedLength current
      members completedId base peers)
      (retirementCompletedWitnessAssignment seed base peers first retirement retired) := by
  induction peers generalizing seed base with
  | nil => simp [retirementCompletedClausesFrom, Holds]
  | cons peer rest ih =>
    let final := retirementCompletedWitnessAssignment seed base (peer :: rest)
      first retirement retired
    have lookup := retirement_completed_witness_assignment_head seed base peer rest
      first retirement retired
    dsimp only at lookup
    have lookupFinal :
        final .int base = first peer /\
          final .int (base + 1) = retirement peer /\
          final .int (base + 2) = retired peer := by
      simpa [final] using lookup
    have completedFinal : final (.bits width) completedId = completedBits := by
      simpa [final] using completedLookup
    intro formula member
    simp only [retirementCompletedClausesFrom, List.mem_append] at member
    rcases member with head | tail
    · simp [retirementCompletedPeerClauses] at head
      rcases head with same | same | same
      · subst formula
        change (implies enabled
          (retirementIndexTerm width bootstrap committedLength entries peer
            (.integer (final .int base)) (.integer (final .int (base + 1))))).eval
              final Locals.empty = true
        rw [lookupFinal.1, lookupFinal.2.1]
        exact (constraints peer).1
      · subst formula
        change (implies enabled
          (retiredRecordTerm width committedLength entries peer
            (.integer (final .int (base + 2))))).eval final Locals.empty = true
        rw [lookupFinal.2.2]
        exact (constraints peer).2.1
      · subst formula
        change (implies enabled
          (.equal (.bit (.bits (final (.bits width) completedId)) peer)
            (retirementCompletedMemberTerm peer current members
              (.integer (final .int base)) (.integer (final .int (base + 1)))
              (.integer (final .int (base + 2)))))).eval final Locals.empty = true
        rw [completedFinal, lookupFinal.1, lookupFinal.2.1, lookupFinal.2.2]
        exact (constraints peer).2.2
    ·
      apply ih
        (((seed.set .int base (first peer)).set .int (base + 1) (retirement peer)).set
          .int (base + 2) (retired peer)) (base + 3)
      · simpa [retirementCompletedWitnessAssignment] using completedLookup
      · simpa [retirementCompletedWitnessAssignment] using constraints
      · exact tail

structure RetirementCompletedConstraintsResult {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat) : Prop where
  inputsBounded :
    enabled.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    length.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    entries.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    commit.symbols.all (fun symbol => symbol.2 < before.next) = true /\
    current.symbols.all (fun symbol => symbol.2 < before.next) = true
  completedId : completed = before.next
  next : after.next = before.next + 1 + 3 * width
  sameBootstrap : after.bootstrap = before.bootstrap
  sameColumns : after.toColumns = before.toColumns
  clauses : after.assertions.toList = before.assertions.toList ++
    retirementCompletedClauses bootstrap enabled entries (logRangeMinTerm commit length)
      current (currentConfigurationMembersTerm width bootstrap entries current)
      before.next before.next

structure PeerConstraintsResult {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed : Nat) (peers : List (Fin width))
    (before after : Encoding width) : Prop where
  next : after.next = before.next + 3 * peers.length
  sameBootstrap : after.bootstrap = before.bootstrap
  sameColumns : after.toColumns = before.toColumns
  clauses : after.assertions.toList = before.assertions.toList ++
    retirementCompletedClausesFrom bootstrap enabled entries committedLength current members
      completed before.next peers

theorem retirement_completed_peer_constraints_success {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed : Nat) (peers : List (Fin width))
    (before after : Encoding width)
    (run : (retirementCompletedPeerConstraints bootstrap enabled entries committedLength
      current members completed peers).run before = .ok ((), after)) :
    PeerConstraintsResult bootstrap enabled entries committedLength current members completed
      peers before after := by
  induction peers generalizing before with
  | nil =>
    simp only [retirementCompletedPeerConstraints, StateT.run, pure] at run
    have same := congrArg Prod.snd (Except.ok.inj run)
    dsimp only at same
    subst after
    constructor <;> simp [retirementCompletedClausesFrom]
  | cons peer rest ih =>
    simp only [retirementCompletedPeerConstraints] at run
    obtain ⟨first, firstState, firstRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨retirement, retirementState, retirementRun, run⟩ :=
      (bind_run _ _ _ _ _).mp run
    obtain ⟨retired, retiredState, retiredRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, firstAsserted, firstAssertion, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, retirementAsserted, retirementAssertion, run⟩ :=
      (bind_run _ _ _ _ _).mp run
    obtain ⟨_, retiredAsserted, retiredAssertion, run⟩ :=
      (bind_run _ _ _ _ _).mp run
    have result := ih retiredAsserted run
    obtain ⟨firstId, firstNext, firstBootstrap, firstColumns, firstClauses⟩ :=
      fresh_success before firstState first firstRun
    obtain ⟨retirementId, retirementNext, retirementBootstrap, retirementColumns,
      retirementClauses⟩ :=
      fresh_success firstState retirementState retirement retirementRun
    obtain ⟨retiredId, retiredNext, retiredBootstrap, retiredColumns, retiredClauses⟩ :=
      fresh_success retirementState retiredState retired retiredRun
    obtain ⟨firstFrame, firstPushed⟩ :=
      assertion_success _ retiredState firstAsserted firstAssertion
    obtain ⟨retirementFrame, retirementPushed⟩ :=
      assertion_success _ firstAsserted retirementAsserted retirementAssertion
    obtain ⟨retiredFrame, retiredPushed⟩ :=
      assertion_success _ retirementAsserted retiredAsserted retiredAssertion
    constructor
    · rw [result.next, retiredFrame.next, retirementFrame.next, firstFrame.next,
        retiredNext, retirementNext, firstNext]
      simp
      omega
    · exact result.sameBootstrap.trans (retiredFrame.bootstrap.trans
        (retirementFrame.bootstrap.trans (firstFrame.bootstrap.trans
          (retiredBootstrap.trans (retirementBootstrap.trans firstBootstrap)))))
    · exact result.sameColumns.trans (retiredFrame.columns.trans
        (retirementFrame.columns.trans (firstFrame.columns.trans
          (retiredColumns.trans (retirementColumns.trans firstColumns)))))
    · rw [result.clauses, retiredPushed, Array.toList_push, retirementPushed,
        Array.toList_push, firstPushed, Array.toList_push, retiredClauses,
        retirementClauses, firstClauses, firstId, retirementId, retiredId,
        retirementNext, firstNext]
      simp [retirementCompletedClausesFrom, retirementCompletedPeerClauses,
        List.append_assoc]
      have retiredStateNext : retiredAsserted.next = before.next + 3 := by
        rw [retiredFrame.next, retirementFrame.next, firstFrame.next,
          retiredNext, retirementNext, firstNext]
      rw [retiredStateNext]

theorem retirement_completed_constraints_success {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) :
    RetirementCompletedConstraintsResult bootstrap enabled length entries commit current
      before after completed := by
  simp only [retirementCompletedConstraints, get_bind_run] at run
  split at run
  · rename_i bounded
    obtain ⟨completedId, allocated, completedRun, run⟩ := (bind_run _ _ _ _ _).mp run
    obtain ⟨_, final, peerRun, run⟩ := (bind_run _ _ _ _ _).mp run
    have returned : (completedId, final) = (completed, after) := Except.ok.inj run
    have sameCompleted := congrArg Prod.fst returned
    have sameAfter := congrArg Prod.snd returned
    dsimp only at sameCompleted sameAfter
    subst completed
    subst after
    obtain ⟨completedEq, allocatedNext, allocatedBootstrap, allocatedColumns,
      allocatedClauses⟩ := fresh_success before allocated completedId completedRun
    have peers := retirement_completed_peer_constraints_success bootstrap enabled entries
      (logRangeMinTerm commit length) current
      (currentConfigurationMembersTerm width bootstrap entries current)
      completedId (List.finRange width) allocated final peerRun
    constructor
    · simp only [Bool.and_eq_true] at bounded
      exact ⟨bounded.1.1.1.1, bounded.1.1.1.2, bounded.1.1.2, bounded.1.2, bounded.2⟩
    · exact completedEq
    · rw [peers.next, allocatedNext]
      simp
    · exact peers.sameBootstrap.trans allocatedBootstrap
    · exact peers.sameColumns.trans allocatedColumns
    · rw [peers.clauses, allocatedClauses, completedEq, allocatedNext]
      simp [retirementCompletedClauses]
  · cases run

theorem retirement_completed_constraints_holds {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
      Holds (retirementCompletedClauses bootstrap enabled entries
        (logRangeMinTerm commit length) current
        (currentConfigurationMembersTerm width bootstrap entries current)
        before.next before.next) assignment := by
  rw [(retirement_completed_constraints_success bootstrap enabled length entries commit current
    before after completed run).clauses]
  simp [Holds, or_imp, forall_and]

theorem retirement_completed_constraints_holds_before {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment) :
    Holds before.assertions.toList assignment :=
  ((retirement_completed_constraints_holds bootstrap enabled length entries commit current
    before after completed run assignment).mp holds).1

theorem retirement_completed_constraints_references {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (valid : ReferencesValid before) :
    ReferencesValid after := by
  have shape := retirement_completed_constraints_success bootstrap enabled length entries
    commit current before after completed run
  cases valid
  constructor <;> simp_all only [shape.sameColumns, shape.next] <;> omega

theorem retirement_completed_peer_constraints_sound {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed base : Nat) (peers : List (Fin width))
    (assignment : Assignment)
    (holds : Holds (retirementCompletedClausesFrom bootstrap enabled entries committedLength
      current members completed base peers) assignment)
    (enabledTrue : enabled.eval assignment Locals.empty = true) :
    forall peer, peer ∈ peers ->
      exists first retirement retired : Int,
        (retirementIndexTerm width bootstrap committedLength entries peer
          (.integer first) (.integer retirement)).eval assignment Locals.empty = true /\
        (retiredRecordTerm width committedLength entries peer
          (.integer retired)).eval assignment Locals.empty = true /\
        (Term.bit (.free (.bits width) completed) peer).eval assignment Locals.empty =
          (retirementCompletedMemberTerm peer current members
            (.integer first) (.integer retirement) (.integer retired)).eval
              assignment Locals.empty := by
  induction peers generalizing base with
  | nil => simp
  | cons head rest ih =>
    intro peer member
    have firstAccepted := holds
      (implies enabled
        (retirementIndexTerm width bootstrap committedLength entries head
          (.free .int base) (.free .int (base + 1))))
      (by simp [retirementCompletedClausesFrom, retirementCompletedPeerClauses])
    have retiredAccepted := holds
      (implies enabled
        (retiredRecordTerm width committedLength entries head (.free .int (base + 2))))
      (by simp [retirementCompletedClausesFrom, retirementCompletedPeerClauses])
    have bitAccepted := holds
      (implies enabled
        (.equal (.bit (.free (.bits width) completed) head)
          (retirementCompletedMemberTerm head current members
            (.free .int base) (.free .int (base + 1)) (.free .int (base + 2)))))
      (by simp [retirementCompletedClausesFrom, retirementCompletedPeerClauses])
    have tailHolds : Holds
        (retirementCompletedClausesFrom bootstrap enabled entries committedLength
          current members completed (base + 3) rest) assignment := by
      intro formula tailMember
      exact holds formula (by
        simp only [retirementCompletedClausesFrom, List.mem_append]
        exact Or.inr tailMember)
    simp only [List.mem_cons] at member
    rcases member with same | member
    · subst peer
      refine ⟨assignment .int base, assignment .int (base + 1),
        assignment .int (base + 2), ?_, ?_, ?_⟩
      · simpa [implies, Term.eval, enabledTrue] using firstAccepted
      · simpa [implies, Term.eval, enabledTrue] using retiredAccepted
      · simpa [implies, Term.eval, enabledTrue] using bitAccepted
    · exact ih (base + 3) tailHolds peer member

theorem retirement_completed_constraints_sound {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (enabledTrue : enabled.eval assignment Locals.empty = true) :
    completed = before.next /\
    forall peer : Fin width, exists first retirement retired : Int,
      (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries peer
        (.integer first) (.integer retirement)).eval assignment Locals.empty = true /\
      (retiredRecordTerm width (logRangeMinTerm commit length) entries peer
        (.integer retired)).eval assignment Locals.empty = true /\
      (Term.bit (.free (.bits width) completed) peer).eval assignment Locals.empty =
        (retirementCompletedMemberTerm peer current
          (currentConfigurationMembersTerm width bootstrap entries current)
          (.integer first) (.integer retirement) (.integer retired)).eval
            assignment Locals.empty := by
  have shape := retirement_completed_constraints_success bootstrap enabled length entries
    commit current before after completed run
  have completedEq := shape.completedId
  subst completed
  refine ⟨rfl, ?_⟩
  intro peer
  have constraints :=
    ((retirement_completed_constraints_holds bootstrap enabled length entries commit current
      before after before.next run assignment).mp holds).2
  exact retirement_completed_peer_constraints_sound bootstrap enabled entries
    (logRangeMinTerm commit length) current
    (currentConfigurationMembersTerm width bootstrap entries current)
    before.next (before.next + 1) (List.finRange width) assignment constraints enabledTrue
    peer (List.mem_finRange peer)

theorem retirement_completed_constraints_bits_correct {width : PNat}
    [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment)
    (holds : Holds after.assertions.toList assignment)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) = log.entries position)
    (enabledTrue : enabled.eval assignment Locals.empty = true)
    (currentAccepted :
      (currentConfigurationIndexTerm width length entries commit current).eval
        assignment Locals.empty = true) :
    assignment (.bits width) completed =
      encodeBits (retirementCompletedNodes log.decode commitNat) := by
  obtain ⟨completedEq, witnesses⟩ :=
    retirement_completed_constraints_sound bootstrap enabled length entries commit current
      before after completed run assignment holds enabledTrue
  choose first retirement retired accepted using witnesses
  subst completed
  apply retirement_completed_bits_constraints_correct assignment Locals.empty bootstrap length
    entries commit current (fun node => .integer (first node))
    (fun node => .integer (retirement node)) (fun node => .integer (retired node))
    (.free (.bits width) before.next) log commitNat sameLength sameCommit sameBootstrap
    sameEntries currentAccepted
  · intro node
    exact (accepted node).1
  · intro node
    exact (accepted node).2.1
  · intro node
    exact (accepted node).2.2

theorem retirement_completed_clauses_disabled {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool)
    (entries : Expr (.array .int (entryTy width))) (committedLength current : Expr .int)
    (members : Expr (.bits width)) (completed base : Nat) (peers : List (Fin width))
    (assignment : Assignment) (disabled : enabled.eval assignment Locals.empty = false) :
    Holds (retirementCompletedClausesFrom bootstrap enabled entries committedLength current
      members completed base peers) assignment := by
  induction peers generalizing base with
  | nil => simp [retirementCompletedClausesFrom, Holds]
  | cons peer rest ih =>
    intro formula member
    simp only [retirementCompletedClausesFrom, List.mem_append] at member
    rcases member with head | tail
    · simp [retirementCompletedPeerClauses] at head
      rcases head with same | same | same
      · subst formula
        simp [implies, Term.eval, disabled]
      · subst formula
        simp [implies, Term.eval, disabled]
      · subst formula
        simp [implies, Term.eval, disabled]
    · exact ih (base + 3) formula tail

theorem retirement_completed_constraints_complete_disabled {width : PNat}
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (disabled : enabled.eval assignment Locals.empty = false) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended := by
  refine ⟨assignment, fun _ _ _ => rfl, ?_⟩
  apply (retirement_completed_constraints_holds bootstrap enabled length entries commit current
    before after completed run assignment).mpr
  exact ⟨holds, retirement_completed_clauses_disabled bootstrap enabled entries
    (logRangeMinTerm commit length) current
    (currentConfigurationMembersTerm width bootstrap entries current)
    before.next (before.next + 1) (List.finRange width) assignment disabled⟩

theorem retirement_completed_constraints_complete_enabled {width : PNat}
    [Bootstrap (Fin width)]
    (bootstrap : BitVec width) (enabled : Expr .bool) (length : Expr .int)
    (entries : Expr (.array .int (entryTy width))) (commit current : Expr .int)
    (before after : Encoding width) (completed : Nat)
    (run : (retirementCompletedConstraints bootstrap enabled length entries commit current).run
      before = .ok (completed, after)) (assignment : Assignment)
    (holds : Holds before.assertions.toList assignment)
    (log : NativeArrayCheckQuorum.Log (Fin width) Nat) (commitNat : Nat)
    (sameLength : length.eval assignment Locals.empty = (log.length : Int))
    (sameCommit : commit.eval assignment Locals.empty = (commitNat : Int))
    (sameBootstrap : decodeBits bootstrap = INITIAL_CONFIGURATION)
    (sameEntries : forall position, position < log.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) = log.entries position)
    (enabledTrue : enabled.eval assignment Locals.empty = true)
    (currentAccepted :
      (currentConfigurationIndexTerm width length entries commit current).eval
        assignment Locals.empty = true) :
    exists extended : Assignment, assignment.AgreesBelow before.next extended /\
      Holds after.assertions.toList extended /\
      extended (.bits width) completed =
        encodeBits (retirementCompletedNodes log.decode commitNat) := by
  classical
  have shape := retirement_completed_constraints_success bootstrap enabled length entries
    commit current before after completed run
  obtain ⟨firstChoice, retirementChoice, retiredChoice, _, canonical⟩ :=
    NativeEncode.retirement_completed_constraints_complete assignment Locals.empty bootstrap
      length entries commit log commitNat sameLength sameCommit sameBootstrap sameEntries
  let completedBits := encodeBits (retirementCompletedNodes log.decode commitNat)
  let first : Fin width -> Int := fun peer => firstMatchValue (firstChoice peer)
  let retirement : Fin width -> Int := fun peer => firstMatchValue (retirementChoice peer)
  let retired : Fin width -> Int := fun peer => firstMatchValue (retiredChoice peer)
  let seed := assignment.set (.bits width) before.next completedBits
  let extended := retirementCompletedWitnessAssignment seed (before.next + 1)
    (List.finRange width) first retirement retired
  have seedAgreement : assignment.AgreesBelow before.next seed :=
    assignment.agrees_below_set before.next (.bits width) before.next completedBits (le_refl _)
  have witnessAgreement : seed.AgreesBelow (before.next + 1) extended :=
    retirement_completed_witness_assignment_agrees seed (before.next + 1) (before.next + 1)
      (List.finRange width) first retirement retired (le_refl _)
  have agreement : assignment.AgreesBelow before.next extended :=
    seedAgreement.trans (witnessAgreement.restrict (by omega))
  have completedLookup : extended (.bits width) before.next = completedBits := by
    rw [<- witnessAgreement (.bits width) before.next (by omega)]
    simp [seed, Assignment.set]
  have enabledSame : enabled.eval extended Locals.empty = enabled.eval assignment Locals.empty :=
    (enabled.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp shape.inputsBounded.1 symbol member)
      agreement).symm
  have lengthSameAssignment :
      length.eval extended Locals.empty = length.eval assignment Locals.empty :=
    (length.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp shape.inputsBounded.2.1 symbol member)
      agreement).symm
  have entriesSameAssignment :
      entries.eval extended Locals.empty = entries.eval assignment Locals.empty :=
    (entries.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp shape.inputsBounded.2.2.1 symbol member)
      agreement).symm
  have commitSameAssignment :
      commit.eval extended Locals.empty = commit.eval assignment Locals.empty :=
    (commit.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp shape.inputsBounded.2.2.2.1 symbol member)
      agreement).symm
  have currentSameAssignment :
      current.eval extended Locals.empty = current.eval assignment Locals.empty :=
    (current.eval_agrees_below assignment extended Locals.empty before.next
      (fun symbol member => by
        simpa using List.all_eq_true.mp shape.inputsBounded.2.2.2.2 symbol member)
      agreement).symm
  have sameLengthExtended : length.eval extended Locals.empty = (log.length : Int) :=
    lengthSameAssignment.trans sameLength
  have sameCommitExtended : commit.eval extended Locals.empty = (commitNat : Int) :=
    commitSameAssignment.trans sameCommit
  have sameEntriesExtended : forall position, position < log.length ->
      modelEntry (entries.eval extended Locals.empty (position : Int)) =
        log.entries position := by
    intro position live
    rw [entriesSameAssignment]
    exact sameEntries position live
  have enabledExtended : enabled.eval extended Locals.empty = true :=
    enabledSame.trans enabledTrue
  obtain ⟨currentNat, sameCurrent, _, _⟩ :=
    current_configuration_terms_sound assignment Locals.empty bootstrap length entries commit
      current log commitNat sameBootstrap sameLength sameCommit sameEntries currentAccepted
  have currentIndex :=
    (current_configuration_index_term_native_correct assignment Locals.empty length entries
      commit current log commitNat currentNat sameLength sameCommit sameCurrent
      sameEntries).mp currentAccepted
  have sameCurrentExtended : current.eval extended Locals.empty = (currentNat : Int) :=
    currentSameAssignment.trans sameCurrent
  have currentAcceptedExtended :
      (currentConfigurationIndexTerm width length entries commit current).eval
        extended Locals.empty = true :=
    (current_configuration_index_term_native_correct extended Locals.empty length entries
      commit current log commitNat currentNat sameLengthExtended sameCommitExtended
      sameCurrentExtended sameEntriesExtended).mpr currentIndex
  let committedLog := NativeArrayLogWrite.take log commitNat
  have sameCommittedLength :
      (logRangeMinTerm commit length).eval assignment Locals.empty =
        (committedLog.length : Int) := by
    simp [committedLog, log_range_min_term_eval, NativeArrayLogWrite.take,
      sameCommit, sameLength]
  have sameCommittedLengthExtended :
      (logRangeMinTerm commit length).eval extended Locals.empty =
        (committedLog.length : Int) := by
    simp [committedLog, log_range_min_term_eval, NativeArrayLogWrite.take,
      sameCommitExtended, sameLengthExtended]
  have sameCommittedEntries : forall position, position < committedLog.length ->
      modelEntry (entries.eval assignment Locals.empty (position : Int)) =
        committedLog.entries position := by
    intro position live
    simpa [committedLog, NativeArrayLogWrite.take] using
      sameEntries position (by
        simp [committedLog, NativeArrayLogWrite.take] at live
        omega)
  have sameCommittedEntriesExtended : forall position, position < committedLog.length ->
      modelEntry (entries.eval extended Locals.empty (position : Int)) =
        committedLog.entries position := by
    intro position live
    simpa [committedLog, NativeArrayLogWrite.take] using
      sameEntriesExtended position (by
        simp [committedLog, NativeArrayLogWrite.take] at live
        omega)
  have constraints : forall peer,
      (implies enabled
        (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries peer
          (.integer (first peer)) (.integer (retirement peer)))).eval extended Locals.empty =
          true /\
      (implies enabled
        (retiredRecordTerm width (logRangeMinTerm commit length) entries peer
          (.integer (retired peer)))).eval extended Locals.empty = true /\
      (implies enabled
        (.equal (.bit (.bits completedBits) peer)
          (retirementCompletedMemberTerm peer current
            (currentConfigurationMembersTerm width bootstrap entries current)
            (.integer (first peer)) (.integer (retirement peer))
            (.integer (retired peer))))).eval extended Locals.empty = true := by
    intro peer
    have retirementNative :=
      (retirement_index_term_correct assignment Locals.empty bootstrap
        (logRangeMinTerm commit length) entries peer
        (.integer (firstMatchValue (firstChoice peer)))
        (.integer (firstMatchValue (retirementChoice peer))) committedLog
        (firstChoice peer) (retirementChoice peer) sameCommittedLength
        (by simp [Term.eval]) (by simp [Term.eval]) sameBootstrap
        sameCommittedEntries).mp (canonical peer).1
    have retirementAcceptedExtended :
        (retirementIndexTerm width bootstrap (logRangeMinTerm commit length) entries peer
          (.integer (first peer)) (.integer (retirement peer))).eval
            extended Locals.empty = true := by
      apply (retirement_index_term_correct extended Locals.empty bootstrap
        (logRangeMinTerm commit length) entries peer (.integer (first peer))
        (.integer (retirement peer)) committedLog (firstChoice peer)
        (retirementChoice peer) sameCommittedLengthExtended
        (by simp [Term.eval, first]) (by simp [Term.eval, retirement]) sameBootstrap
        sameCommittedEntriesExtended).mpr
      exact retirementNative
    have retiredNative :
        NativeArrayFirstMatch.FirstMatch committedLog
          (fun _ entry => Sparse.RetirementScan.namesRetiredNode peer entry)
          (retiredChoice peer) := by
      apply (first_match_term_correct assignment Locals.empty
        (logRangeMinTerm commit length)
        (.integer (firstMatchValue (retiredChoice peer)))
        (retiredRecordPredicate entries peer) committedLog
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode peer entry)
        (retiredChoice peer) sameCommittedLength (by simp [Term.eval]) _).mp
      · simpa [retiredRecordTerm] using (canonical peer).2.1
      · intro position live
        rw [retired_record_predicate_eval, sameCommittedEntries position live]
    have retiredAcceptedExtended :
        (retiredRecordTerm width (logRangeMinTerm commit length) entries peer
          (.integer (retired peer))).eval extended Locals.empty = true := by
      rw [retiredRecordTerm]
      apply (first_match_term_correct extended Locals.empty
        (logRangeMinTerm commit length) (.integer (retired peer))
        (retiredRecordPredicate entries peer) committedLog
        (fun _ entry => Sparse.RetirementScan.namesRetiredNode peer entry)
        (retiredChoice peer) sameCommittedLengthExtended
        (by simp [Term.eval, retired]) _).mpr
      · exact retiredNative
      · intro position live
        rw [retired_record_predicate_eval, sameCommittedEntriesExtended position live]
    have memberCorrect :=
      retirement_completed_member_constraints_correct extended Locals.empty bootstrap length
        entries commit current (.integer (first peer)) (.integer (retirement peer))
        (.integer (retired peer)) peer log commitNat sameLengthExtended sameCommitExtended
        sameBootstrap sameEntriesExtended currentAcceptedExtended retirementAcceptedExtended
        retiredAcceptedExtended
    have bitAccepted :
        (Term.equal (.bit (.bits completedBits) peer)
          (retirementCompletedMemberTerm peer current
            (currentConfigurationMembersTerm width bootstrap entries current)
            (.integer (first peer)) (.integer (retirement peer))
            (.integer (retired peer)))).eval extended Locals.empty = true := by
      have bitValue : completedBits.getLsbD peer.val =
        (retirementCompletedMemberTerm peer current
          (currentConfigurationMembersTerm width bootstrap entries current)
          (.integer (first peer)) (.integer (retirement peer))
          (.integer (retired peer))).eval extended Locals.empty := by
        apply Bool.eq_iff_iff.mpr
        simpa only [completedBits, encode_bits_bit, decide_eq_true_eq] using memberCorrect.symm
      simpa only [Term.eval, decide_eq_true_eq] using bitValue
    constructor
    · simpa [implies, Term.eval, enabledExtended] using retirementAcceptedExtended
    · constructor
      · simpa [implies, Term.eval, enabledExtended] using retiredAcceptedExtended
      · simpa [implies, Term.eval, enabledExtended] using bitAccepted
  have generatedHolds : Holds
      (retirementCompletedClauses bootstrap enabled entries (logRangeMinTerm commit length)
        current (currentConfigurationMembersTerm width bootstrap entries current)
        before.next before.next) extended := by
    apply retirement_completed_witness_clauses_holds seed (before.next + 1) before.next
      completedBits bootstrap enabled entries (logRangeMinTerm commit length) current
      (currentConfigurationMembersTerm width bootstrap entries current)
      (List.finRange width) first retirement retired completedLookup constraints
  refine ⟨extended, agreement, ?_, ?_⟩
  · apply (retirement_completed_constraints_holds bootstrap enabled length entries commit current
      before after completed run extended).mpr
    exact ⟨before.holds_agrees_below assignment extended holds agreement, generatedHolds⟩
  · rw [shape.completedId]
    exact completedLookup

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
