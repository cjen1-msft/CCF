import Sparse.ConditionalQueueTraceEncoding
import Sparse.QueueSummaryEncoding

set_option autoImplicit false

namespace CCFRaft.Sparse.ConditionalQueueSpecialization

open Smt (Assignment Term)
open QueueEncoding (InputInt)
open QueueStream (Event concreteFollows)
open ConditionalQueueEncoding (evaluate)
open ConditionalQueueAccounting (select)
open QueueScalarEncoding (evalTrace)

abbrev Entry := ConditionalQueueEncoding.Entry

def fact (id : Nat) : Term .bool -> Option Bool
  | .unknown .bool key => if key == id then some true else none
  | .not (.unknown .bool key) => if key == id then some false else none
  | .equal (.unknown .bool key) (.boolean value) => if key == id then some value else none
  | .equal (.boolean value) (.unknown .bool key) => if key == id then some value else none
  | _ => none

theorem fact_sound (assignment : Assignment) (id : Nat) (term : Term .bool) (value : Bool)
    (found : fact id term = some value) (holds : term.eval assignment = true) :
    assignment.constant .bool id = value := by
  unfold fact at found
  split at found <;> (try split at found) <;> simp_all [Term.eval]

def lookup (input : SmtScript.Formula) (id : Nat) : Option Bool :=
  match input with
  | [] => none
  | term :: rest =>
    match fact id term with
    | some value => some value
    | none => lookup rest id

theorem lookup_sound (assignment : Assignment) (input : SmtScript.Formula)
    (holds : SmtScript.Holds assignment input) (id : Nat) (value : Bool)
    (found : lookup input id = some value) :
    assignment.constant .bool id = value := by
  induction input with
  | nil => simp [lookup] at found
  | cons term rest ih =>
    cases first : fact id term with
    | none =>
      exact ih (fun t member => holds t (List.mem_cons_of_mem _ member))
        (by simpa [lookup, first] using found)
    | some result =>
      have same : result = value := by simpa [lookup, first] using found
      simpa only [same] using fact_sound assignment id term result first (holds term (by simp))

def resolveGuard (input : SmtScript.Formula) : Term .bool -> Option Bool
  | .boolean value => some value
  | .unknown .bool id => lookup input id
  | .not guard => (resolveGuard input guard).map Bool.not
  | _ => none

theorem resolve_guard_sound (assignment : Assignment) (input : SmtScript.Formula)
    (holds : SmtScript.Holds assignment input) (guard : Term .bool) (value : Bool)
    (resolved : resolveGuard input guard = some value) :
    guard.eval assignment = value := by
  induction guard using resolveGuard.induct generalizing value with
  | case1 result => simpa [resolveGuard, Term.eval] using resolved
  | case2 id =>
    exact lookup_sound assignment input holds id value
      (by simpa only [resolveGuard] using resolved)
  | case3 guard ih =>
    cases child : resolveGuard input guard with
    | none => simp [resolveGuard, child] at resolved
    | some result =>
      have same := ih result child
      simpa [resolveGuard, child, Term.eval, same] using resolved
  | case4 guard _ _ _ => simp [resolveGuard, *] at resolved

theorem resolve_guard_no_unary (input : SmtScript.Formula) (guard : Term .bool) (value : Bool)
    (resolved : resolveGuard input guard = some value) (domain result : Smt.Ty) (id : Nat) :
    Not (Membership.mem (SmtScript.termSymbols guard) (.unary domain result id)) := by
  induction guard using resolveGuard.induct generalizing value with
  | case1 _ => simp [SmtScript.termSymbols]
  | case2 _ => simp [SmtScript.termSymbols]
  | case3 guard ih =>
    cases child : resolveGuard input guard with
    | none => simp [resolveGuard, child] at resolved
    | some value => exact ih value child
  | case4 guard _ _ _ => simp [resolveGuard, *] at resolved

def selectKnown (input : SmtScript.Formula) : List Entry -> Option (List (Event InputInt))
  | [] => some []
  | (guard, event) :: rest => do
    let active <- resolveGuard input guard
    let tail <- selectKnown input rest
    pure (if active then event :: tail else tail)

theorem select_known_sound (assignment : Assignment) (input : SmtScript.Formula)
    (holds : SmtScript.Holds assignment input) (entries : List Entry) (trace : List (Event InputInt))
    (resolved : selectKnown input entries = some trace) :
    evalTrace assignment trace = select (evaluate assignment entries) := by
  induction entries generalizing trace with
  | nil => simpa [selectKnown, evalTrace, evaluate, select] using resolved.symm
  | cons entry rest ih =>
    cases entry with
    | mk guard event =>
      cases active : resolveGuard input guard with
      | none => simp [selectKnown, active] at resolved
      | some value =>
        cases tail : selectKnown input rest with
        | none => simp [selectKnown, active, tail] at resolved
        | some events =>
          have guard_value := resolve_guard_sound assignment input holds guard value active
          have rest_value := ih events tail
          cases value <;> simp_all [selectKnown, evalTrace, evaluate, select]
          subst trace
          simp_all

theorem select_known_guards (input : SmtScript.Formula) (entries : List Entry)
    (trace : List (Event InputInt)) (resolved : selectKnown input entries = some trace) :
    forall entry, Membership.mem entries entry -> exists value, resolveGuard input entry.1 = some value := by
  induction entries generalizing trace with
  | nil => simp
  | cons entry rest ih =>
    cases active : resolveGuard input entry.1 with
    | none => simp [selectKnown, active] at resolved
    | some value =>
      cases tail : selectKnown input rest with
      | none => simp [selectKnown, active, tail] at resolved
      | some events =>
        intro item member
        rcases List.mem_cons.mp member with same | member
        next => simpa only [same] using Exists.intro value active
        next => exact ih events tail item member

theorem selected_source_uf (input : SmtScript.Formula) (entries : List Entry)
    (trace : List (Event InputInt)) (resolved : selectKnown input entries = some trace)
    (domain result : Smt.Ty) (id : Nat)
    (member : Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id)) :
    Membership.mem (SmtScript.symbols input) (.unary domain result id) := by
  cases List.mem_flatMap.mp (List.mem_dedup.mp member) with
  | intro term spec =>
    rcases List.mem_append.mp spec.1 with original | guard
    next =>
      exact List.mem_dedup.mpr
        (List.mem_flatMap.mpr (Exists.intro term (And.intro original spec.2)))
    next =>
      cases List.mem_map.mp guard with
      | intro entry present =>
        cases select_known_guards input entries trace resolved entry present.1 with
        | intro value found =>
          exact False.elim (resolve_guard_no_unary input entry.1 value found domain result id
            (by simpa only [present.2] using spec.2))

def encode (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) : SmtScript.Formula :=
  match selectKnown input entries with
  | some trace => QueueSummaryEncoding.encode input trace length
  | none => ConditionalQueueTraceEncoding.encode input entries length

def render (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) : String :=
  SmtScript.render (encode input entries length)

theorem unresolved_encode (input : SmtScript.Formula) (entries : List Entry) (length : InputInt)
    (unresolved : selectKnown input entries = none) :
    encode input entries length = ConditionalQueueTraceEncoding.encode input entries length := by
  simp [encode, unresolved]

theorem encode_exists_iff (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input entries length)) <->
      (exists original : Assignment, exists queue : List Int,
        SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
          concreteFollows queue (select (evaluate original entries))) := by
  unfold encode
  cases resolved : selectKnown input entries with
  | none => exact ConditionalQueueTraceEncoding.encode_exists_iff input entries length
  | some trace =>
    rw [QueueSummaryEncoding.encode_exists_iff]
    constructor <;> intro witness
    next =>
      cases witness with
      | intro original witness =>
        cases witness with
        | intro queue spec =>
          refine Exists.intro original (Exists.intro queue (And.intro spec.1 (And.intro spec.2.1 ?_)))
          simpa only [select_known_sound original input spec.1 entries trace resolved] using spec.2.2
    next =>
      cases witness with
      | intro original witness =>
        cases witness with
        | intro queue spec =>
          refine Exists.intro original (Exists.intro queue (And.intro spec.1 (And.intro spec.2.1 ?_)))
          rw [select_known_sound original input spec.1 entries trace resolved]
          exact spec.2.2

theorem rendered_exists_iff (input : SmtScript.Formula) (entries : List Entry) (length : InputInt) :
    (exists assignment : Assignment,
      SmtScriptText.runText assignment (render input entries length) = some true) <->
      (exists original : Assignment, exists queue : List Int,
        SmtScript.Holds original input /\ (queue.length : Int) = length.eval original /\
          concreteFollows queue (select (evaluate original entries))) := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  exact encode_exists_iff input entries length

theorem summary_complete (original : Assignment) (input : SmtScript.Formula)
    (trace : List (Event InputInt)) (length : InputInt) (queue : List Int)
    (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (evalTrace original trace)) :
    exists assignment : Assignment,
      SmtScript.Holds assignment (QueueSummaryEncoding.encode input trace length) /\
      assignment.constant = original.constant /\ assignment.selectors = original.selectors /\
      forall domain result id, Membership.mem (SmtScript.symbols input) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  let normalized := QueueSummaryEncoding.normalize trace
  have replay : concreteFollows queue (evalTrace original normalized) :=
    (QueueSummaryEncoding.normalize_correct original queue trace).mpr follows
  have nonnegative : 0 <= length.eval original := by
    rw [<- queue_length]
    exact Int.natCast_nonneg _
  cases (QueueClause.compiled_exists_iff (QueueTraceEncoding.trackedKeys original normalized)
    (length.eval original) nonnegative (evalTrace original normalized)
    (QueueInitialEncoding.tracked_uses original normalized)
    (QueueTraceEncoding.freshFiller _) (QueueTraceEncoding.filler_fresh _)).mpr
      (Exists.intro queue (And.intro queue_length replay)) with
  | intro order witness =>
    cases witness with
    | intro state spec =>
      refine Exists.intro (QueueTraceEncoding.installWitness original input normalized length state order)
        (And.intro ?_ (And.intro rfl (And.intro rfl ?_)))
      next =>
        exact QueueTraceEncoding.encode_from_heap original input normalized length state order
          input_holds nonnegative spec.1 spec.2.1 spec.2.2
      next =>
        intro domain result id member
        exact QueueTraceEncoding.witness_external original input normalized length state order
          domain result id member

theorem fallback_complete (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (queue : List Int) (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (select (evaluate original entries))) :
    exists assignment : Assignment,
      SmtScript.Holds assignment (ConditionalQueueTraceEncoding.encode input entries length) /\
      assignment.constant = original.constant /\ assignment.selectors = original.selectors /\
      forall domain result id,
        Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  have nonnegative : 0 <= length.eval original := by
    rw [<- queue_length]
    exact Int.natCast_nonneg _
  cases (SignedQueue.signed_exists_iff
    ((ConditionalQueueEncoding.keysOf entries).map (InputInt.eval original)).toFinset
    (length.eval original) nonnegative (select (evaluate original entries))
    (ConditionalQueueTraceEncoding.selected_uses original entries)
    (QueueTraceEncoding.freshFiller _) (QueueTraceEncoding.filler_fresh _)).mpr
      (Exists.intro queue (And.intro queue_length follows)) with
  | intro order witness =>
    cases witness with
    | intro counts spec =>
      let initial : QueueClause.Cursor Int :=
        { counts, window := { head := 0, tail := length.eval original } }
      have replay : ConditionalQueueAccounting.replay order initial (evaluate original entries) :=
        (ConditionalQueueAccounting.replay_iff _ _ _).mpr
          ((QueueClause.cursor_iff_signed _ _ _).mpr spec.2)
      cases ConditionalQueueTraceEncoding.replay_complete original order entries 0 0
        (fun _ => initial) replay with
      | intro heap proof =>
        have root := proof.1 0 (Nat.le_refl _)
        refine Exists.intro
          (ConditionalQueueTraceEncoding.installWitness original input entries length heap order)
          (And.intro ?_ (And.intro rfl (And.intro rfl ?_)))
        next =>
          apply ConditionalQueueTraceEncoding.witness_satisfies original input entries length heap order
            input_holds nonnegative
          next => rw [root]
          next => simpa only [root] using spec.1
          next => exact proof.2
        next =>
          intro domain result id member
          exact ConditionalQueueTraceEncoding.witness_external original input entries length heap order
            domain result id member

theorem encode_complete (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (queue : List Int) (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (select (evaluate original entries))) :
    exists assignment : Assignment, SmtScript.Holds assignment (encode input entries length) /\
      assignment.constant = original.constant /\ assignment.selectors = original.selectors /\
      forall domain result id,
        Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  unfold encode
  cases resolved : selectKnown input entries with
  | none => exact fallback_complete original input entries length queue input_holds queue_length follows
  | some trace =>
    have selected : concreteFollows queue (evalTrace original trace) := by
      rwa [select_known_sound original input input_holds entries trace resolved]
    cases summary_complete original input trace length queue input_holds queue_length selected with
    | intro assignment spec =>
      refine Exists.intro assignment (And.intro spec.1 (And.intro spec.2.1 (And.intro spec.2.2.1 ?_)))
      intro domain result id member
      exact spec.2.2.2 domain result id
        (selected_source_uf input entries trace resolved domain result id member)

theorem rendered_complete (original : Assignment) (input : SmtScript.Formula) (entries : List Entry)
    (length : InputInt) (queue : List Int) (input_holds : SmtScript.Holds original input)
    (queue_length : (queue.length : Int) = length.eval original)
    (follows : concreteFollows queue (select (evaluate original entries))) :
    exists assignment : Assignment,
      SmtScriptText.runText assignment (render input entries length) = some true /\
      assignment.constant = original.constant /\ assignment.selectors = original.selectors /\
      forall domain result id,
        Membership.mem (SmtScript.symbols (input ++ entries.map Prod.fst)) (.unary domain result id) ->
        assignment.unary domain result id = original.unary domain result id := by
  simp only [render, <- SmtScriptText.formula_text_iff]
  exact encode_complete original input entries length queue input_holds queue_length follows

namespace Regression

def facts : SmtScript.Formula :=
  [.unknown .bool 0, .not (.unknown .bool 1),
    .equal (.unknown .bool 2) (.boolean false),
    .equal (.boolean true) (.unknown .bool 3)]

theorem flat_facts :
    lookup facts 0 = some true /\ lookup facts 1 = some false /\
      lookup facts 2 = some false /\ lookup facts 3 = some true /\
      lookup facts 4 = none /\
      resolveGuard facts (.not (.not (.unknown .bool 3))) = some true := by
  simp [lookup, facts, fact, resolveGuard]

theorem selection_keeps_observations :
    selectKnown facts
      [(.unknown .bool 0, .peek (.symbolic 7)), (.unknown .bool 1, .pop (.symbolic 8)),
        (.unknown .bool 2, .length 99), (.not (.unknown .bool 3), .send (.literal 8)),
        (.boolean true, .length 2)] =
      some [.peek (.symbolic 7), .length 2] := by
  simp [selectKnown, resolveGuard, lookup, facts, fact]

theorem unknown_fallback (length : InputInt) :
    encode [] [(.boolean true, .send (.symbolic 0)), (.unknown .bool 1, .length 1)] length =
      ConditionalQueueTraceEncoding.encode []
        [(.boolean true, .send (.symbolic 0)), (.unknown .bool 1, .length 1)] length := by
  apply unresolved_encode
  simp [selectKnown, resolveGuard, lookup]

theorem inactive_uf_fallback (length : InputInt) :
    encode []
      [(.ite (.boolean true) (.boolean true) (.app .nodes .bool 999 (.nodes 0)), .length 0)] length =
      ConditionalQueueTraceEncoding.encode []
        [(.ite (.boolean true) (.boolean true) (.app .nodes .bool 999 (.nodes 0)), .length 0)] length := by
  apply unresolved_encode
  simp [selectKnown, resolveGuard]

theorem empty_path (input : SmtScript.Formula) (length : InputInt) :
    encode input [] length = QueueSummaryEncoding.encode input [] length := rfl

theorem contradictory_first_match :
    lookup [.unknown .bool 0, .not (.unknown .bool 0)] 0 = some true := rfl

theorem contradictory_input (length : InputInt) :
    Not (exists assignment : Assignment, SmtScript.Holds assignment
      (encode [.unknown .bool 0, .not (.unknown .bool 0)]
        [(.unknown .bool 0, .send (.literal 0))] length)) := by
  rw [encode_exists_iff]
  intro witness
  cases witness with
  | intro original witness =>
    cases witness with
    | intro queue spec =>
      have positive := spec.1 (.unknown .bool 0) (by simp)
      have negative := spec.1 (.not (.unknown .bool 0)) (by simp)
      simp_all [Term.eval]

theorem negative_length (input : SmtScript.Formula) (entries : List Entry) (length : Int)
    (negative : length < 0) :
    Not (exists assignment : Assignment, SmtScript.Holds assignment (encode input entries (.literal length))) := by
  rw [encode_exists_iff]
  intro witness
  cases witness with
  | intro original witness =>
    cases witness with
    | intro queue spec =>
      have same : (queue.length : Int) = length := spec.2.1
      have nonnegative := Int.natCast_nonneg queue.length
      omega

theorem arbitrary_initial (queue : List Int) :
    exists assignment : Assignment, SmtScript.Holds assignment
      (encode [] [(.boolean false, .pop (.literal 42)), (.boolean true, .length queue.length)]
        (.literal (queue.length : Int))) := by
  apply (encode_exists_iff _ _ _).mpr
  refine Exists.intro QueueEncoding.regressionInput (Exists.intro queue (And.intro ?_ (And.intro rfl ?_)))
  next => simp [SmtScript.Holds]
  next =>
    simp [evaluate, select, QueueScalarEncoding.evalEvent, Term.eval, concreteFollows]

def nativeInput : Assignment :=
  { QueueEncoding.regressionInput with
    selectors := { txWrong := fun _ => 17, cfgWrong := fun _ => 1, retiredWrong := fun _ => 2 } }

def nativeFacts : SmtScript.Formula :=
  [.not (.unknown .bool 7), .equal (.transactionId .signature) (.integer 17),
    .ite (.boolean true) (.boolean true) (.app .entry .bool 900 (.unknown .entry 42))]

def duplicateTrace : List Entry :=
  [(.unknown .bool 7, .pop (.literal 42)), (.boolean true, .pop (.symbolic 0)),
    (.boolean true, .peek (.symbolic 1)), (.boolean true, .send (.symbolic 1)),
    (.boolean true, .length 1)]

theorem alias_duplicates_native_preservation :
    exists assignment : Assignment,
      SmtScriptText.runText assignment (render nativeFacts duplicateTrace (.literal 2)) = some true /\
      assignment.constant = nativeInput.constant /\ assignment.selectors = nativeInput.selectors /\
      forall domain result id,
        Membership.mem (SmtScript.symbols (nativeFacts ++ duplicateTrace.map Prod.fst)) (.unary domain result id) ->
        assignment.unary domain result id = nativeInput.unary domain result id := by
  apply rendered_complete nativeInput nativeFacts duplicateTrace (.literal 2) [0, 0]
  next =>
    simp [SmtScript.Holds, nativeFacts, Term.eval, nativeInput, QueueEncoding.regressionInput,
      EntrySelectorSemantics.rawTx]
  next => rfl
  next =>
    simp [duplicateTrace, evaluate, select, QueueScalarEncoding.evalEvent, Term.eval,
      InputInt.eval, InputInt.term, nativeInput, QueueEncoding.regressionInput, concreteFollows]

def sizedInput (size : Nat) : Assignment :=
  { QueueEncoding.regressionInput with
    constant ty id := match ty with
      | .int => (size : Int)
      | ty => QueueEncoding.regressionInput.constant ty id }

theorem symbolic_initial_size (size : Nat) :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] [(.boolean true, .length size)] (.symbolic 19)) = some true := by
  apply (rendered_exists_iff _ _ _).mpr
  refine Exists.intro (sizedInput size) (Exists.intro (List.replicate size (7 : Int))
    (And.intro ?_ (And.intro ?_ ?_)))
  next => simp [SmtScript.Holds]
  next => simp [InputInt.eval, InputInt.term, Term.eval, sizedInput]
  next => simp [evaluate, select, QueueScalarEncoding.evalEvent, Term.eval, concreteFollows]

theorem symbolic_million_initial :
    exists assignment : Assignment, SmtScriptText.runText assignment
      (render [] [(.boolean true, .length 1000000)] (.symbolic 19)) = some true :=
  symbolic_initial_size 1000000

end Regression

end CCFRaft.Sparse.ConditionalQueueSpecialization

run_cmd do
  let mut count := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ConditionalQueueSpecialization).isPrefixOf name then
      count := count + 1
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ConditionalQueueSpecialization: {count} declarations passed the transitive axiom gate"
