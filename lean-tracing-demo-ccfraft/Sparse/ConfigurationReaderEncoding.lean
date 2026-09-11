import Sparse.Configuration
import Sparse.TypedJointPredicateEncoding
import MachineGenerated.HandlerProofs

set_option autoImplicit false

namespace CCFRaft.Sparse.ConfigurationReaderEncoding

open Smt (Assignment Term Symbol)
open IntervalEncoding (natTerm natValue)
open EntryPredicate (Predicate Operand Query)
open TypedIntervalEncoding (SymbolicGraph interpret)
open VersionedIntervals (RootArrays)

variable {size roots : Nat}

structure Request (size : Nat) where
  version : Fin size
  -- These three fields name Int symbols, not their values.
  length : Nat
  frontier : Nat
  index : Nat
  nodes : Term .nodes

def Request.symbols (request : Request size) : List Symbol :=
  [.constant .int request.length, .constant .int request.frontier, .constant .int request.index] ++
    SmtScript.termSymbols request.nodes

def Request.maximum (request : Request size) : Nat :=
  max request.length (max request.frontier (max request.index (SymbolBounds.termMax request.nodes)))

theorem Request.maximum_correct (request : Request size) :
    request.maximum = request.symbols.toFinset.sup SymbolBounds.symbolId := by
  simp [Request.maximum, Request.symbols, SymbolBounds.termMax_correct, SymbolBounds.symbolId]

def freshBase (request : Request size) (reserved : Nat) : Nat :=
  max request.maximum reserved + 1

theorem fresh_bounds (request : Request size) (reserved : Nat) :
    request.length < freshBase request reserved /\
    request.frontier < freshBase request reserved /\
    request.index < freshBase request reserved /\
    SymbolBounds.termMax request.nodes < freshBase request reserved /\
    reserved < freshBase request reserved := by
  simp only [freshBase, Request.maximum]
  omega

theorem fresh_symbols (request : Request size) (reserved : Nat) (symbol : Symbol)
    (member : Membership.mem request.symbols symbol) :
    SymbolBounds.symbolId symbol < freshBase request reserved := by
  have bound : SymbolBounds.symbolId symbol <= request.maximum := by
    rw [request.maximum_correct]
    exact Finset.le_sup (List.mem_toFinset.mpr member)
  unfold freshBase
  omega

def clipTerm (request : Request size) : Term .int :=
  .ite (.le (natTerm request.frontier) (natTerm request.length))
    (natTerm request.frontier) (natTerm request.length)

def anchorTerm (request : Request size) : Term .int :=
  .ite (.le (natTerm request.index) (.integer 0)) (.integer 0)
    (.sub (natTerm request.index) (.integer 1))

variable [bootstrap : Bootstrap Node]

-- first stores min(frontier, length); first + 1 stores the truncated index predecessor.
def constraints (request : Request size) (first : Nat) : SmtScript.Formula :=
  TypedIntervalReadBlock.domainFormula [request.length, request.frontier, request.index] ++
    [.equal (natTerm first) (clipTerm request),
     .equal (natTerm (first + 1)) (anchorTerm request),
     .le (natTerm request.index) (natTerm first),
     .implies (.equal (natTerm request.index) (.integer 0))
       (.equal request.nodes (.nodes (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION)))]

structure Scalars (assignment : Assignment) (request : Request size) (first : Nat) : Prop where
  length_nonnegative : 0 <= assignment.constant .int request.length
  frontier_nonnegative : 0 <= assignment.constant .int request.frontier
  index_nonnegative : 0 <= assignment.constant .int request.index
  clip : assignment.constant .int first =
    ((min (natValue assignment request.frontier) (natValue assignment request.length) : Nat) : Int)
  anchor : assignment.constant .int (first + 1) = ((natValue assignment request.index - 1 : Nat) : Int)

theorem constraints_correct (assignment : Assignment) (request : Request size) (first : Nat) :
    SmtScript.Holds assignment (constraints request first) <->
      Scalars assignment request first /\
      natValue assignment request.index <=
        min (natValue assignment request.frontier) (natValue assignment request.length) /\
      (natValue assignment request.index = 0 ->
        request.nodes.eval assignment = NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) := by
  have raw :
      SmtScript.Holds assignment (constraints request first) <->
        0 <= assignment.constant .int request.length /\
        0 <= assignment.constant .int request.frontier /\
        0 <= assignment.constant .int request.index /\
        assignment.constant .int first = (clipTerm request).eval assignment /\
        assignment.constant .int (first + 1) = (anchorTerm request).eval assignment /\
        assignment.constant .int request.index <= assignment.constant .int first /\
        (assignment.constant .int request.index = 0 ->
          request.nodes.eval assignment = NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) := by
    have domains : SmtScript.Holds assignment
        (TypedIntervalReadBlock.domainFormula [request.length, request.frontier, request.index]) <->
        0 <= assignment.constant .int request.length /\
        0 <= assignment.constant .int request.frontier /\
        0 <= assignment.constant .int request.index := by
      simp only [TypedIntervalReadBlock.domainFormula, SmtScript.Holds,
        List.forall_mem_map, List.mem_dedup, natTerm, Term.eval, decide_eq_true_eq]
      simp
    rw [constraints, QueueEncoding.holds_append, domains]
    simp [SmtScript.Holds, natTerm, Term.eval, and_assoc]
    tauto
  have clip (frontier length : Int) (hf : 0 <= frontier) (hl : 0 <= length) :
      (if frontier <= length then frontier else length) =
        ((min frontier.toNat length.toNat : Nat) : Int) := by split <;> omega
  have anchor (index : Int) (hi : 0 <= index) :
      (if index <= 0 then 0 else index - 1) = ((index.toNat - 1 : Nat) : Int) := by split <;> omega
  rw [raw]
  simp only [clipTerm, anchorTerm, Term.eval, natTerm, decide_eq_true_eq]
  constructor
  next =>
    intro h
    have hc : assignment.constant .int first =
        ((min (natValue assignment request.frontier) (natValue assignment request.length) : Nat) : Int) :=
      h.2.2.2.1.trans (clip _ _ h.2.1 h.1)
    have ha := h.2.2.2.2.1.trans (anchor _ h.2.2.1)
    refine And.intro (Scalars.mk h.1 h.2.1 h.2.2.1 hc ha) (And.intro ?_ ?_)
    next =>
      apply Int.ofNat_le.mp
      rw [show (natValue assignment request.index : Int) = assignment.constant .int request.index from
        Int.toNat_of_nonneg h.2.2.1, <- hc]
      exact h.2.2.2.2.2.1
    next =>
      intro zero
      apply h.2.2.2.2.2.2
      have cast := congrArg (fun value : Nat => (value : Int)) zero
      simpa only [natValue, Int.toNat_of_nonneg h.2.2.1, Int.natCast_zero] using cast
  next =>
    intro h
    refine And.intro h.1.length_nonnegative (And.intro h.1.frontier_nonnegative
      (And.intro h.1.index_nonnegative (And.intro ?_ (And.intro ?_ (And.intro ?_ ?_)))))
    next => exact h.1.clip.trans (clip _ _ h.1.frontier_nonnegative h.1.length_nonnegative).symm
    next => exact h.1.anchor.trans (anchor _ h.1.index_nonnegative).symm
    next =>
      rw [h.1.clip]
      simpa only [natValue, Int.toNat_of_nonneg h.1.index_nonnegative] using
        Int.ofNat_le.mpr h.2.1
    next => intro zero; apply h.2.2; simp [natValue, zero]

def anchorQuery (request : Request size) (first : Nat) : Query size :=
  { lower := first + 1, upper := request.index,
    predicate := .eq (.entryContent (.cell request.version)) (.input (.reconfiguration request.nodes)) }

def suffixQuery (request : Request size) (first : Nat) : Query size :=
  { lower := request.index, upper := first,
    predicate := .not (.isContent .reconfiguration (.entryContent (.cell request.version))) }

def queries (request : Request size) (first : Nat) : List (Query size) :=
  [anchorQuery request first, suffixQuery request first]

theorem constraints_symbols (request : Request size) (first : Nat) (symbol : Symbol) :
    Membership.mem (SmtScript.symbols (constraints request first)) symbol <->
      Membership.mem request.symbols symbol \/
        symbol = .constant .int first \/ symbol = .constant .int (first + 1) := by
  simp [constraints, SmtScript.symbols, TypedIntervalReadBlock.domainFormula,
    SmtScript.termSymbols, natTerm, clipTerm, anchorTerm, Request.symbols, or_and_right, exists_or]
  tauto

theorem constraints_maximum (request : Request size) (first : Nat) :
    SymbolBounds.formulaMax (constraints request first) = max request.maximum (first + 1) := by
  have symbols :
      (SmtScript.symbols (constraints request first)).toFinset =
        insert (.constant .int first) (insert (.constant .int (first + 1)) request.symbols.toFinset) := by
    ext symbol
    simp only [List.mem_toFinset, constraints_symbols, Finset.mem_insert]
    tauto
  rw [SymbolBounds.formulaMax_correct, symbols]
  simp only [Finset.sup_insert, <- request.maximum_correct, SymbolBounds.symbolId]
  omega

omit bootstrap in
theorem query_metadata (request : Request size) (first : Nat) :
    (queries request first).length = 2 /\
    (anchorQuery request first).predicate.references = [request.version] /\
    (suffixQuery request first).predicate.references = [request.version] /\
    (anchorQuery request first).predicate.externalSymbols = SmtScript.termSymbols request.nodes /\
    (suffixQuery request first).predicate.externalSymbols = [] := by
  simp [queries, anchorQuery, suffixQuery, Predicate.references, Predicate.referenceOccurrences,
    Operand.referenceOccurrences, Predicate.externalSymbols, Operand.externalSymbols, SmtScript.termSymbols]

omit bootstrap in
theorem query_maximum (request : Request size) (first : Nat) :
    max (anchorQuery request first).externalMax (suffixQuery request first).externalMax =
      max (first + 1) (max request.index (SymbolBounds.termMax request.nodes)) := by
  simp only [anchorQuery, suffixQuery, Query.externalMax, Predicate.externalMax,
    Operand.externalMax, SymbolBounds.termMax]
  omega

-- Decoding a finite prefix is confined to the semantic proposition.
def logView (values : Nat -> EntryValue.Entry) (length : Nat) : ArrayLog.ArrayLog :=
  { length, entries := fun position => EntryValue.decodeEntry (values position) }

omit bootstrap in
theorem reconfig_at (values : Nat -> EntryValue.Entry) (length index : Nat)
    (nodes : Finset Node) (positive : 0 < index) (within : index <= length) :
    Configuration.Reconfig (logView values length).decode index nodes <->
      EntryValue.decodeContent (values (index - 1)).content = .reconfiguration nodes := by
  have live : index - 1 < length := by omega
  simp [Configuration.Reconfig, ArrayLog.model_entryAt, logView, ArrayLog.ArrayLog.read,
    Nat.ne_of_gt positive, live, EntryValue.decode_entry_content]

omit bootstrap in
theorem no_reconfiguration (content : EntryValue.Content) :
    (forall nodes : Finset Node, Not (EntryValue.decodeContent content = .reconfiguration nodes)) <->
      Smt.ContentTag.test .reconfiguration content = false := by
  cases content <;>
    simp [Smt.ContentTag.test, EntryValue.Content.isReconfiguration, EntryValue.Content.reconfiguration?]

theorem current_storage_iff (values : Nat -> EntryValue.Entry) (length frontier index : Nat)
    (mask : BitVec NODE_COUNT) :
    currentConfigurationAt (logView values length).decode frontier =
      { index, nodes := NodeSetCodec.decodeNodes mask } <->
      index <= min frontier length /\
      (index = 0 -> mask = NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) /\
      (0 < index -> (values (index - 1)).content = .reconfiguration mask) /\
      (forall position, index <= position -> position < min frontier length ->
        Smt.ContentTag.test .reconfiguration (values position).content = false) := by
  rw [Configuration.currentConfigurationAt_exclusion_iff]
  simp only [ArrayLog.decode_length, logView]
  constructor
  next =>
    intro h
    refine And.intro h.1 (And.intro ?_ (And.intro ?_ ?_))
    next =>
      intro zero
      rcases h.2.1 with implicit | physical
      next =>
        have same := congrArg NodeSetCodec.encodeNodes implicit.2
        simpa using same
      next => have bound := Configuration.reconfig_bounds physical; simp [zero] at bound
    next =>
      intro positive
      rcases h.2.1 with implicit | physical
      next => omega
      next =>
        have content := (reconfig_at values length index _ positive (by omega)).mp physical
        rw [<- EntryValue.decode_reconfiguration mask, EntryValue.decode_content_eq_iff] at content
        exact content
    next =>
      intro position lower upper
      apply (no_reconfiguration _).mp
      intro nodes content
      apply h.2.2 (position + 1) nodes (by omega) (by omega)
      apply (reconfig_at values length (position + 1) nodes (by omega) (by omega)).mpr
      simpa using content
  next =>
    intro h
    refine And.intro h.1 (And.intro ?_ ?_)
    next =>
      by_cases zero : index = 0
      next => exact Or.inl (And.intro zero (by rw [h.2.1 zero]; simp))
      next =>
        apply Or.inr
        apply (reconfig_at values length index _ (by omega) (by omega)).mpr
        rw [h.2.2.1 (by omega)]
        exact EntryValue.decode_reconfiguration mask
    next =>
      intro candidate nodes lower upper physical
      have content := (reconfig_at values length candidate nodes (by omega) (by omega)).mp physical
      exact (no_reconfiguration _).mpr (h.2.2.2 (candidate - 1) (by omega) (by omega)) nodes content

def cells (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (position : Nat) : EntryValue.Entry :=
  VersionedIntervals.evaluate (interpret assignment graph) arrays position request.version

def Result (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) : Prop :=
  currentConfigurationAt (logView (cells assignment graph arrays request)
    (natValue assignment request.length)).decode (natValue assignment request.frontier) =
      { index := natValue assignment request.index, nodes := NodeSetCodec.decodeNodes (request.nodes.eval assignment) }

def Meaning (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (first : Nat) : Prop :=
  SmtScript.Holds assignment (constraints request first) /\
    VersionedIntervals.Realizes (interpret assignment graph)
      (IntervalQueries.schemas (TypedJointPredicateEncoding.localQueries assignment (queries request first))) arrays

theorem meaning_correct (assignment : Assignment) (graph : SymbolicGraph roots .entry size)
    (arrays : RootArrays roots EntryValue.Entry) (request : Request size) (first : Nat) :
    Meaning assignment graph arrays request first <->
      Scalars assignment request first /\ Result assignment graph arrays request := by
  rw [Meaning, constraints_correct]
  have singleton (index : Nat) (predicate : Nat -> Prop) :
      (forall position, index <= position + 1 -> position < index -> predicate position) <->
        (0 < index -> predicate (index - 1)) := by
    constructor
    next => intro all positive; exact all _ (by omega) (by omega)
    next =>
      intro hit position lower upper
      have same : position = index - 1 := by omega
      rw [same]
      exact hit (by omega)
  have query_meaning (scalars : Scalars assignment request first) :
      VersionedIntervals.Realizes (interpret assignment graph)
        (IntervalQueries.schemas (TypedJointPredicateEncoding.localQueries assignment (queries request first))) arrays <->
        (0 < natValue assignment request.index ->
          (cells assignment graph arrays request (natValue assignment request.index - 1)).content =
            .reconfiguration (request.nodes.eval assignment)) /\
        (forall position, natValue assignment request.index <= position ->
          position < min (natValue assignment request.frontier) (natValue assignment request.length) ->
          Smt.ContentTag.test .reconfiguration (cells assignment graph arrays request position).content = false) := by
    have clip : natValue assignment first =
        min (natValue assignment request.frontier) (natValue assignment request.length) := by
      simp only [natValue, scalars.clip, Int.toNat_natCast]
    have anchor : natValue assignment (first + 1) = natValue assignment request.index - 1 := by
      simp only [natValue, scalars.anchor, Int.toNat_natCast]
    simp [VersionedIntervals.Realizes, IntervalQueries.schemas, TypedJointPredicateEncoding.localQueries,
      queries, anchorQuery, suffixQuery, Query.toLocalQuery, VersionedIntervals.Query.Inside,
      Predicate.eval, Operand.eval, Term.eval, cells, clip, anchor, singleton]
  constructor
  next =>
    intro h
    refine And.intro h.1.1 ?_
    rw [Result, current_storage_iff]
    exact And.intro h.1.2.1 (And.intro h.1.2.2 ((query_meaning h.1.1).mp h.2))
  next =>
    intro h
    have result := (current_storage_iff _ _ _ _ _).mp h.2
    exact And.intro (And.intro h.1 (And.intro result.1 result.2.1))
      ((query_meaning h.1).mpr result.2.2)

theorem latest_at_length (state : NodeState Node Nat) :
    latestConfiguration state = currentConfigurationAt state.log state.log.length := by
  unfold latestConfiguration currentConfigurationAt
  have same (configurations : List (Configuration Node))
      (bounds : forall configuration, Membership.mem configurations configuration ->
        configuration.index <= state.log.length) (initial : Configuration Node) :
      configurations.foldl (fun _ configuration => configuration) initial =
        configurations.foldl (fun current configuration =>
          if configuration.index <= state.log.length then configuration else current) initial := by
    induction configurations generalizing initial with
    | nil => rfl
    | cons configuration rest ih =>
      simp only [List.foldl_cons, if_pos (bounds configuration (by simp))]
      exact ih (fun item member => bounds item (List.mem_cons_of_mem _ member)) configuration
  exact same _ (fun configuration member => (configurationsInLog_index_bounds state.log member).2) _

theorem current_content_congr (left right : Nat -> EntryValue.Entry)
    (same : forall position, (left position).content = (right position).content)
    (length frontier index : Nat) (mask : BitVec NODE_COUNT) :
    (currentConfigurationAt (logView left length).decode frontier =
      { index, nodes := NodeSetCodec.decodeNodes mask }) <->
    (currentConfigurationAt (logView right length).decode frontier =
      { index, nodes := NodeSetCodec.decodeNodes mask }) := by
  simp only [current_storage_iff, same]

namespace Regression

theorem empty (values : Nat -> EntryValue.Entry) (frontier : Nat) :
    currentConfigurationAt (logView values 0).decode frontier =
      { index := 0, nodes := NodeSetCodec.decodeNodes (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) } := by
  rw [current_storage_iff]
  simp

theorem zero_frontier (values : Nat -> EntryValue.Entry) (length : Nat) :
    currentConfigurationAt (logView values length).decode 0 =
      { index := 0, nodes := NodeSetCodec.decodeNodes (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) } := by
  rw [current_storage_iff]
  simp

theorem physical_singleton (term : Int) (mask : BitVec NODE_COUNT) (frontier : Nat)
    (positive : 0 < frontier) :
    currentConfigurationAt
      (logView (fun _ => { term, content := .reconfiguration mask }) 1).decode frontier =
        { index := 1, nodes := NodeSetCodec.decodeNodes mask } := by
  have clip : min frontier 1 = 1 := Nat.min_eq_right (by omega)
  simp [current_storage_iff, clip]
  intro position lower zero
  omega

theorem physical_empty (term : Int) :
    currentConfigurationAt
      (logView (fun _ => { term, content := .reconfiguration (NodeSetCodec.encodeNodes {}) }) 1).decode 1000000 =
        { index := 1, nodes := {} } := by
  simpa using physical_singleton term (NodeSetCodec.encodeNodes {}) 1000000 (by decide)

theorem physical_bootstrap (term : Int) :
    currentConfigurationAt
      (logView (fun _ => { term, content := .reconfiguration (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) }) 1).decode 1 =
        { index := 1, nodes := INITIAL_CONFIGURATION } := by
  simpa using physical_singleton term (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) 1 (by decide)

theorem later_configuration_rejected (values : Nat -> EntryValue.Entry)
    (length frontier index candidate : Nat) (mask laterMask : BitVec NODE_COUNT)
    (later : index < candidate) (within : candidate <= min frontier length)
    (entry : (values (candidate - 1)).content = .reconfiguration laterMask) :
    Not (currentConfigurationAt (logView values length).decode frontier =
      { index, nodes := NodeSetCodec.decodeNodes mask }) := by
  intro result
  have excluded := ((current_storage_iff _ _ _ _ _).mp result).2.2.2
    (candidate - 1) (by omega) (by omega)
  rw [entry] at excluded
  contradiction

theorem negative_rejected (assignment : Assignment) (request : Request size) (first : Nat)
    (negative : assignment.constant .int request.length < 0 \/
      assignment.constant .int request.frontier < 0 \/ assignment.constant .int request.index < 0) :
    Not (SmtScript.Holds assignment (constraints request first)) := by
  intro held
  have scalars := ((constraints_correct _ _ _).mp held).1
  rcases negative with hn | hf | hp
  next => exact not_lt_of_ge scalars.length_nonnegative hn
  next => exact not_lt_of_ge scalars.frontier_nonnegative hf
  next => exact not_lt_of_ge scalars.index_nonnegative hp

theorem aliased_ids (assignment : Assignment)
    (source : assignment.constant .int 0 = 1)
    (clip : assignment.constant .int 10 = 1) (anchor : assignment.constant .int 11 = 0) :
    SmtScript.Holds assignment (constraints
      ({ version := 0, length := 0, frontier := 0, index := 0,
         nodes := .nodes (NodeSetCodec.encodeNodes INITIAL_CONFIGURATION) } : Request 1) 10) := by
  simp [constraints, TypedIntervalReadBlock.domainFormula, SmtScript.Holds, natTerm,
    clipTerm, anchorTerm, Term.eval, source, clip, anchor]

omit bootstrap in
theorem inactive_selector_metadata :
    ({ version := 0, length := 2, frontier := 3, index := 4,
       nodes := .ite (.boolean true) (.nodes 0)
         (.configurationNodes (.entryContent (.app .int .entry 900 (.integer (-7))))) } : Request 1).symbols =
      [.constant .int 2, .constant .int 3, .constant .int 4, .unary .int .entry 900] := rfl

omit bootstrap in
theorem inactive_selector_freshness :
    freshBase
      ({ version := 0, length := 2, frontier := 3, index := 4,
         nodes := .ite (.boolean true) (.nodes 0)
           (.configurationNodes (.entryContent (.app .int .entry 900 (.integer (-7))))) } : Request 1) 20 = 901 := rfl

end Regression

end CCFRaft.Sparse.ConfigurationReaderEncoding

run_cmd do
  let mut count := 0
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.ConfigurationReaderEncoding).isPrefixOf name then
      count := count + 1
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"ConfigurationReaderEncoding: {count} declarations passed the transitive axiom gate"
