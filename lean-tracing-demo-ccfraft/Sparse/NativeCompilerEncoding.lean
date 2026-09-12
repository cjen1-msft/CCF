-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Sparse.NativeObservationEncoding

set_option autoImplicit false

namespace CCFRaft.NativeEncode

open NativeSmt

structure SameReferences {width : PNat} (before after : Encoding width) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns = before.toColumns
  next : after.next = before.next

theorem SameReferences.role {width : PNat} {before after : Encoding width} (same : SameReferences before after) :
    after.role = before.role :=
  congrArg Columns.role same.columns

theorem SameReferences.newFollower {width : PNat} {before after : Encoding width}
    (same : SameReferences before after) : after.newFollower = before.newFollower :=
  congrArg Columns.newFollower same.columns

theorem SameReferences.trans {width : PNat} {first middle last : Encoding width}
    (left : SameReferences first middle) (right : SameReferences middle last) :
    SameReferences first last :=
  ⟨right.bootstrap.trans left.bootstrap, right.columns.trans left.columns, right.next.trans left.next⟩

theorem bind_run {width : PNat} {firstValue lastValue : Type}
    (first : EncodeM width firstValue) (second : firstValue -> EncodeM width lastValue)
    (before after : Encoding width) (value : lastValue) :
    (first >>= second).run before = .ok (value, after) <->
      exists (intermediate : firstValue) (middle : Encoding width),
        first.run before = .ok (intermediate, middle) /\
          (second intermediate).run middle = .ok (value, after) := by
  simp only [StateT.run, Bind.bind, StateT.bind, Except.bind]
  cases step : first before with
  | error error => simp
  | ok pair =>
    rcases pair with ⟨intermediate, middle⟩
    simp

theorem get_bind_run {width : PNat} {value : Type}
    (body : Encoding width -> EncodeM width value) (before : Encoding width) :
    (get >>= body).run before = (body before).run before := rfl

theorem assertion_success {width : PNat} (formula : Expr .bool) (before after : Encoding width)
    (run : (assertion formula).run before = .ok ((), after)) :
    SameReferences before after /\ after.assertions = before.assertions.push formula := by
  simp only [assertion, StateT.run] at run
  split at run
  · cases run
    exact ⟨⟨rfl, rfl, rfl⟩, rfl⟩
  · contradiction

theorem fresh_success {width : PNat} (before after : Encoding width) (id : Nat)
    (run : fresh.run before = .ok (id, after)) :
    id = before.next /\ after.next = before.next + 1 /\ after.bootstrap = before.bootstrap /\
      after.toColumns = before.toColumns /\
      after.assertions = before.assertions := by
  simp only [fresh, StateT.run, Except.ok.injEq, Prod.mk.injEq] at run
  rcases run with ⟨rfl, rfl⟩
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem define_success {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after)) :
    id = before.next /\ after.next = before.next + 1 /\ after.bootstrap = before.bootstrap /\
      after.toColumns = before.toColumns /\
      after.assertions = before.assertions.push (.equal (.free sort id) value) := by
  simp only [define, StateT.run] at run
  split at run
  · obtain ⟨allocatedId, middle, allocated, continued⟩ :=
      (bind_run fresh (fun allocatedId => do
        assertion (.equal (.free sort allocatedId) value)
        return allocatedId) before after id).mp run
    obtain ⟨result, final, asserted, returned⟩ :=
      (bind_run (assertion (.equal (.free sort allocatedId) value)) (fun _ => pure allocatedId)
        middle after id).mp continued
    cases result
    have same : (allocatedId, final) = (id, after) := Except.ok.inj returned
    have sameId := congrArg Prod.fst same
    have sameFinal := congrArg Prod.snd same
    dsimp only at sameId sameFinal
    subst allocatedId
    subst final
    obtain ⟨sameId, next, bootstrap, columns, previous⟩ := fresh_success before middle id allocated
    obtain ⟨frame, appended⟩ := assertion_success _ middle after asserted
    exact ⟨sameId, frame.next.trans next, frame.bootstrap.trans bootstrap,
      frame.columns.trans columns, by rw [appended, previous]⟩
  · contradiction

theorem define_known {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after)) :
    value.symbols.all (fun symbol => symbol.2 < before.next) = true := by
  simp only [define, StateT.run] at run
  split at run
  · assumption
  · contradiction

theorem define_satisfiability {width : PNat} {sort : Ty} (value : Expr sort)
    (before after : Encoding width) (id : Nat)
    (run : (define value).run before = .ok (id, after)) :
    (exists assignment, Holds after.assertions.toList assignment) <->
      (exists assignment, Holds before.assertions.toList assignment) := by
  obtain ⟨sameId, _, _, _, appended⟩ := define_success value before after id run
  rw [appended, sameId]
  simpa [Holds, or_imp, forall_and] using
    (definition_preserves_satisfiability before value (define_known value before after id run)).symm

theorem assert_all_success {width : PNat} (formulas : List (Expr .bool))
    (before after : Encoding width) (run : (assertAll formulas).run before = .ok ((), after)) :
    SameReferences before after /\ after.assertions.toList = before.assertions.toList ++ formulas := by
  induction formulas generalizing before with
  | nil =>
    have same : before = after := congrArg Prod.snd (Except.ok.inj run)
    subst after
    exact ⟨⟨rfl, rfl, rfl⟩, by simp⟩
  | cons formula rest ih =>
    obtain ⟨value, middle, first, second⟩ :=
      (bind_run (assertion formula) (fun _ => assertAll rest) before after ()).mp run
    cases value
    obtain ⟨firstFrame, firstClauses⟩ := assertion_success formula before middle first
    obtain ⟨lastFrame, lastClauses⟩ := ih middle second
    refine ⟨firstFrame.trans lastFrame, ?_⟩
    simp [lastClauses, firstClauses, List.append_assoc]

theorem assert_all_holds {width : PNat} (formulas : List (Expr .bool))
    (before after : Encoding width) (run : (assertAll formulas).run before = .ok ((), after))
    (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\ Holds formulas assignment := by
  rw [(assert_all_success formulas before after run).2]
  simp [Holds, or_imp, forall_and]

theorem observation_instruction_run {width : PNat}
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before : Encoding width)
    (clauses : List (Expr .bool))
    (emitted : observationClauses before.toColumns item = .ok clauses) :
    (instruction item).run before = (assertAll clauses).run before := by
  cases item <;> simp [observationClauses] at emitted
  all_goals subst clauses; rfl

theorem observation_instruction_success {width : PNat} [Bootstrap (Fin width)]
    (item : NativeArrayCheckQuorum.Instruction (Fin width) Nat) (before after : Encoding width)
    (clauses : List (Expr .bool))
    (emitted : observationClauses before.toColumns item = .ok clauses)
    (run : (instruction item).run before = .ok ((), after))
    (assignment : Assignment) (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (model : State (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toColumns arrays)
    (represented : NativeArrayCheckQuorum.Rep arrays model) :
    SameReferences before after /\
      (Holds after.assertions.toList assignment <->
        Holds before.assertions.toList assignment /\ NativeArrayCheckQuorum.modelFollows model [item]) := by
  rw [observation_instruction_run item before clauses emitted] at run
  refine ⟨(assert_all_success clauses before after run).1, ?_⟩
  rw [assert_all_holds clauses before after run assignment,
    observation_model_correct assignment before.toColumns arrays model columns
      represented item clauses emitted]

theorem initial_domains_success {width : PNat} (before after : Encoding width)
    (run : (initialDomains width).run before = .ok ((), after)) (assignment : Assignment) :
    SameReferences before after /\
      (Holds after.assertions.toList assignment <-> Holds before.assertions.toList assignment /\
        (forall node : Fin width, NodeDomain width assignment node.val)) := by
  refine ⟨(assert_all_success (initialAssertions width) before after run).1, ?_⟩
  rw [assert_all_holds (initialAssertions width) before after run assignment,
    initial_assertions_domains]

def quorumClauses {width : PNat} (before : Encoding width) (node : Nat) : List (Expr .bool) :=
  leadingGuards before.role node ++
    configurationGuards width before.bootstrap node before.next (before.next + 1) ++
    [.equal (.free (.array .int .int) (before.next + 2)) (stepDownRole before.role node),
      .equal (.free (.array .int .bool) (before.next + 3)) (stepDownFollower before.newFollower node)]

structure QuorumResult {width : PNat} (before after : Encoding width) (node : Nat) : Prop where
  bootstrap : after.bootstrap = before.bootstrap
  columns : after.toColumns =
    { before.toColumns with role := before.next + 2, newFollower := before.next + 3 }
  next : after.next = before.next + 4
  clauses : after.assertions.toList = before.assertions.toList ++ quorumClauses before node
  guardSymbols : forall formula, formula ∈ (leadingGuards before.role node ++
      configurationGuards width before.bootstrap node before.next (before.next + 1)) ->
    forall symbol, symbol ∈ formula.symbols -> symbol.2 < before.next + 2

theorem QuorumResult.role {width : PNat} {before after : Encoding width} {node : Nat}
    (result : QuorumResult before after node) : after.role = before.next + 2 :=
  congrArg Columns.role result.columns

theorem QuorumResult.newFollower {width : PNat} {before after : Encoding width} {node : Nat}
    (result : QuorumResult before after node) : after.newFollower = before.next + 3 :=
  congrArg Columns.newFollower result.columns

theorem quorum_success {width : PNat} (node : Nat) (before after : Encoding width)
    (run : (checkQuorum node).run before = .ok ((), after)) :
    QuorumResult before after node := by
  simp only [checkQuorum, get_bind_run] at run
  obtain ⟨firstResult, first, leading, run⟩ := (bind_run _ _ _ _ _).mp run
  cases firstResult
  obtain ⟨currentId, second, current, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨witnessId, third, witness, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨guardResult, fourth, configuration, run⟩ := (bind_run _ _ _ _ _).mp run
  cases guardResult
  obtain ⟨roleId, fifth, role, run⟩ := (bind_run _ _ _ _ _).mp run
  obtain ⟨followerId, sixth, follower, run⟩ := (bind_run _ _ _ _ _).mp run
  change Except.ok ((), { sixth with role := roleId, newFollower := followerId }) = .ok ((), after) at run
  have final := congrArg Prod.snd (Except.ok.inj run)
  dsimp only at final
  rw [<- final]
  obtain ⟨firstFrame, firstClauses⟩ := assert_all_success _ before first leading
  obtain ⟨currentIdEq, secondNext, secondBootstrap, secondColumns, secondClauses⟩ :=
    fresh_success first second currentId current
  obtain ⟨witnessIdEq, thirdNext, thirdBootstrap, thirdColumns, thirdClauses⟩ :=
    fresh_success second third witnessId witness
  obtain ⟨fourthFrame, fourthClauses⟩ := assert_all_success _ third fourth configuration
  obtain ⟨roleIdEq, fifthNext, fifthBootstrap, fifthColumns, fifthClauses⟩ :=
    define_success _ fourth fifth roleId role
  obtain ⟨followerIdEq, sixthNext, sixthBootstrap, sixthColumns, sixthClauses⟩ :=
    define_success _ fifth sixth followerId follower
  have currentIndex : currentId = before.next := currentIdEq.trans firstFrame.next
  have witnessIndex : witnessId = before.next + 1 := by
    rw [witnessIdEq, secondNext, firstFrame.next]
  have roleIndex : roleId = before.next + 2 := by
    rw [roleIdEq, fourthFrame.next, thirdNext, secondNext, firstFrame.next]
  have followerIndex : followerId = before.next + 3 := by
    rw [followerIdEq, fifthNext, fourthFrame.next, thirdNext, secondNext, firstFrame.next]
  constructor
  · exact sixthBootstrap.trans (fifthBootstrap.trans (fourthFrame.bootstrap.trans
      (thirdBootstrap.trans (secondBootstrap.trans firstFrame.bootstrap))))
  · simpa only [sixthColumns, fifthColumns, fourthFrame.columns, thirdColumns,
      secondColumns, firstFrame.columns, roleIndex, followerIndex]
  · dsimp only
    rw [sixthNext, fifthNext, fourthFrame.next, thirdNext, secondNext, firstFrame.next]
  · dsimp only
    rw [sixthClauses, Array.toList_push, fifthClauses, Array.toList_push, fourthClauses,
      thirdClauses, secondClauses, firstClauses, currentIndex, witnessIndex, roleIndex, followerIndex]
    simp [quorumClauses, List.append_assoc]
  · intro formula member symbol occurs
    have physical : formula ∈ fourth.assertions.toList := by
      rw [fourthClauses, thirdClauses, secondClauses, firstClauses, currentIndex, witnessIndex,
        List.append_assoc]
      exact List.mem_append_right _ member
    have bounded := fourth.symbolsBounded formula (by simpa using physical) symbol occurs
    rw [fourthFrame.next, thirdNext, secondNext, firstFrame.next] at bounded
    exact bounded

theorem quorum_holds {width : PNat} (node : Nat) (before after : Encoding width)
    (run : (checkQuorum node).run before = .ok ((), after)) (assignment : Assignment) :
    Holds after.assertions.toList assignment <->
      Holds before.assertions.toList assignment /\
      Holds (leadingGuards before.role node ++
        configurationGuards width before.bootstrap node before.next (before.next + 1)) assignment /\
      (Term.equal (.free (.array .int .int) (before.next + 2))
        (stepDownRole before.role node)).eval assignment Locals.empty = true /\
      (Term.equal (.free (.array .int .bool) (before.next + 3))
        (stepDownFollower before.newFollower node)).eval assignment Locals.empty = true := by
  rw [(quorum_success node before after run).clauses]
  simp [quorumClauses, Holds, or_imp, forall_and, and_assoc]

theorem quorum_native_success {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (before after : Encoding width)
    (run : (checkQuorum node.val).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toColumns arrays)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    Holds before.assertions.toList assignment /\ NativeArrayCheckQuorum.enabled arrays node /\
      NodeColumnsRep assignment after.toColumns (NativeArrayCheckQuorum.step arrays node) := by
  obtain ⟨previous, guards, roleBinding, followerBinding⟩ :=
    (quorum_holds node.val before after run assignment).mp holds
  have enabled := (node_columns_enabled assignment before.bootstrap before.toColumns
    arrays node before.next (before.next + 1) (by omega) columns sameBootstrap).mp
      ⟨assignment .int before.next, assignment .int (before.next + 1), by
        simpa [Assignment.set] using guards⟩
  have present : (arrays node).isSome = true :=
    (columns.allocated node).symm.trans (guards (allocated node.val) (by simp [leadingGuards]))
  have effect := node_columns_step assignment before.toColumns
    (before.next + 2) (before.next + 3) arrays node columns present roleBinding followerBinding
  have shape := quorum_success node.val before after run
  exact ⟨previous, enabled, by simpa only [shape.columns] using effect⟩

theorem quorum_model_success {width : PNat} [Bootstrap (Fin width)]
    (node : Fin width) (before after : Encoding width)
    (run : (checkQuorum node.val).run before = .ok ((), after))
    (assignment : Assignment) (holds : Holds after.assertions.toList assignment)
    (arrays : NativeArrayCheckQuorum.Arrays (Fin width) Nat) (model : State (Fin width) Nat)
    (columns : NodeColumnsRep assignment before.toColumns arrays)
    (represented : NativeArrayCheckQuorum.Rep arrays model)
    (sameBootstrap : decodeBits before.bootstrap = INITIAL_CONFIGURATION) :
    Holds before.assertions.toList assignment /\ CCFRaft.Enabled model (.checkQuorum node) /\
      NodeColumnsRep assignment after.toColumns (NativeArrayCheckQuorum.step arrays node) /\
      NativeArrayCheckQuorum.Rep (NativeArrayCheckQuorum.step arrays node)
        (CCFRaft.next model (.checkQuorum node)) := by
  obtain ⟨previous, enabled, afterColumns⟩ :=
    quorum_native_success node before after run assignment holds arrays columns sameBootstrap
  exact ⟨previous, (NativeArrayCheckQuorum.enabled_correct arrays model represented node).mp enabled,
    afterColumns, NativeArrayCheckQuorum.step_correct arrays model represented node⟩

end CCFRaft.NativeEncode

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.NativeEncode).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
