import Sparse.QueuePlan
import Sparse.SmtScript
import Sparse.SymbolBounds

-- Count-read block only. Queue guards, windows, and initial accounting are not emitted.
set_option autoImplicit false

namespace CCFRaft.Sparse.QueueEncoding

open Smt (Assignment Term Symbol Ty)
open QueueStream (Event)
open QueueReadback (writeCount storeValue)

inductive InputInt where
  | literal (value : Int)
  | symbolic (id : Nat)
  deriving DecidableEq, Repr

def InputInt.term : InputInt -> Term .int
  | .literal value => .integer value
  | .symbolic id => .unknown .int id

def InputInt.eval (assignment : Assignment) (value : InputInt) : Int :=
  value.term.eval assignment

abbrev symbolId := SymbolBounds.symbolId

def freshBase (input : SmtScript.Formula) : Nat :=
  (SmtScript.symbols input).toFinset.sup symbolId + 1

@[csimp] theorem freshBase_eq_summary : freshBase = SymbolBounds.freshBase := by
  funext input
  simp only [freshBase, SymbolBounds.freshBase, SymbolBounds.formulaMax_correct, symbolId]

def installCounts {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) : Assignment where
  constant := original.constant
  unary domain result id :=
    match domain, result with
    | .int, .int =>
      if inside : base <= id /\ id < base + size + 1 then
        counts (Fin.mk (id - base) (by omega))
      else original.unary .int .int id
    | domain, result => original.unary domain result id
  selectors := original.selectors

@[simp] theorem install_selectors {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) :
    (installCounts original base counts).selectors = original.selectors := rfl

@[simp] theorem install_at {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) (version : Fin (size + 1)) :
    (installCounts original base counts).unary .int .int (base + version.val) = counts version := by
  have inside : base <= base + version.val /\ base + version.val < base + size + 1 := by
    have bound := version.isLt
    omega
  simp only [installCounts, dif_pos inside, Nat.add_sub_cancel_left]

theorem install_outside {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) (domain result : Ty) (id : Nat)
    (outside_range : id < base \/ base + size + 1 <= id) :
    (installCounts original base counts).unary domain result id =
      original.unary domain result id := by
  have outside : Not (base <= id /\ id < base + size + 1) := by omega
  cases domain <;> cases result <;> simp only [installCounts, dif_neg outside]

@[simp] theorem input_install {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) (value : InputInt) :
    value.eval (installCounts original base counts) = value.eval original := by
  cases value <;> rfl

theorem eval_install {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) {ty : Ty} (term : Term ty)
    (below : forall symbol, Membership.mem (SmtScript.termSymbols term) symbol ->
      symbolId symbol < base) :
    term.eval (installCounts original base counts) = term.eval original := by
  induction term with
  | boolean value => rfl
  | integer value => rfl
  | nodes value => rfl
  | signature => rfl
  | unknown ty id => rfl
  | app domain result id argument ih =>
    have id_bound := below (.unary domain result id) (by simp [SmtScript.termSymbols])
    have argument_eq := ih (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    simp only [Term.eval, argument_eq,
      install_outside original base counts domain result id (Or.inl id_bound)]
  | add left right ihl ihr
  | sub left right ihl ihr
  | le left right ihl ihr
  | equal left right ihl ihr
  | and left right ihl ihr
  | implies left right ihl ihr =>
    have left_eq := ihl (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    have right_eq := ihr (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    simp only [Term.eval, left_eq, right_eq]
  | entry left right ihl ihr =>
    have left_eq := ihl (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    have right_eq := ihr (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    simp only [Term.eval, left_eq, right_eq]
  | transaction value ih | reconfiguration value ih | retiredCommitted value ih
  | entryTerm value ih | entryContent value ih | isContent _ value ih =>
    simp only [Term.eval, ih below]
  | transactionId value ih | configurationNodes value ih | retiredNodes value ih =>
    simp only [Term.eval, ih below, install_selectors]
  | not value ih =>
    exact congrArg Bool.not (ih below)
  | ite condition yes no ihc ihy ihn =>
    have condition_eq := ihc (fun symbol member =>
      below symbol (by simp [SmtScript.termSymbols, member]))
    have yes_eq := ihy (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    have no_eq := ihn (fun symbol member => below symbol (by simp [SmtScript.termSymbols, member]))
    simp only [Term.eval, condition_eq, yes_eq, no_eq]

theorem input_symbol_bound (input : SmtScript.Formula) (symbol : Symbol)
    (member : Membership.mem (SmtScript.symbols input) symbol) :
    symbolId symbol < freshBase input := by
  have bound := Finset.le_sup (f := symbolId) (show Membership.mem
    (SmtScript.symbols input).toFinset symbol by simpa using member)
  exact Nat.lt_succ_of_le bound

theorem fresh_base_congr (left right : SmtScript.Formula)
    (same : forall term, Membership.mem left term <-> Membership.mem right term) :
    freshBase left = freshBase right := by
  have symbols : (SmtScript.symbols left).toFinset = (SmtScript.symbols right).toFinset := by
    ext symbol
    simp only [List.mem_toFinset, SmtScript.symbol_coverage, same]
  simp only [freshBase, symbols]

theorem fresh_symbol (input : SmtScript.Formula) (version : Nat) :
    Not (Membership.mem (SmtScript.symbols input) (.unary .int .int (freshBase input + version))) := by
  intro member
  have bound := input_symbol_bound input _ member
  change freshBase input + version < freshBase input at bound
  omega

theorem count_names_distinct (base left right : Nat) :
    (Symbol.unary .int .int (base + left)).name =
      (Symbol.unary .int .int (base + right)).name <-> left = right := by
  rw [Smt.function_signature_names]
  simp

theorem fresh_name (input : SmtScript.Formula) (version : Nat) (symbol : Symbol)
    (member : Membership.mem (SmtScript.symbols input) symbol) :
    Not ((Symbol.unary .int .int (freshBase input + version)).name = symbol.name) := by
  intro equal
  have same := Smt.symbol_name_injective equal
  apply fresh_symbol input version
  rw [same]
  exact member

theorem input_preserved {size : Nat} (input : SmtScript.Formula) (original : Assignment)
    (counts : Fin (size + 1) -> Int -> Int) :
    SmtScript.Holds (installCounts original (freshBase input) counts) input <->
      SmtScript.Holds original input := by
  have preserved (term : Term .bool) (present : Membership.mem input term) :
      term.eval (installCounts original (freshBase input) counts) = term.eval original := by
    apply eval_install
    intro symbol member
    apply input_symbol_bound input symbol
    apply (SmtScript.symbol_coverage input symbol).mpr
    exact Exists.intro term (And.intro present
      (by simpa only [SmtScript.lower_symbols] using member))
  constructor
  next =>
    intro holds term present
    rw [Eq.symm (preserved term present)]
    exact holds term present
  next =>
    intro holds term present
    rw [preserved term present]
    exact holds term present

structure Observation (trace : List (Event InputInt)) where
  version : Fin (writeCount trace + 1)
  key : InputInt
  expected : InputInt

def ancestorList {size : Nat} (limit : Fin (size + 1)) (key : InputInt) :
    List (Prod (Fin (size + 1)) InputInt) :=
  List.ofFn (fun prior : Fin (limit.val + 1) =>
    (Fin.mk prior.val (Nat.lt_of_lt_of_le prior.isLt
      (Nat.succ_le_succ (Nat.le_of_lt_succ limit.isLt))), key))

theorem ancestor_list_mem {size : Nat} (limit : Fin (size + 1)) (key : InputInt)
    (query : Prod (Fin (size + 1)) InputInt) :
    Membership.mem (ancestorList limit key) query <->
      Membership.mem (QueuePlan.ancestors limit key) query := by
  simp only [ancestorList, List.mem_ofFn, QueuePlan.ancestors,
    Finset.mem_image, Finset.mem_univ, true_and]

theorem ancestor_list_nodup {size : Nat} (limit : Fin (size + 1)) (key : InputInt) :
    (ancestorList limit key).Nodup := by
  apply List.nodup_ofFn.mpr
  intro left right equal
  apply Fin.ext
  exact congrArg (fun query => query.1.val) equal

def extendDemand {size : Nat} (seed : Prod (Fin (size + 1)) InputInt) :
    List (Prod (Fin (size + 1)) InputInt) -> List (Prod (Fin (size + 1)) InputInt)
  | [] => [seed]
  | entry :: rest =>
    if seed.2 = entry.2 then (max seed.1 entry.1, entry.2) :: rest
    else entry :: extendDemand seed rest

def summarizeDemands {size : Nat} :
    List (Prod (Fin (size + 1)) InputInt) -> List (Prod (Fin (size + 1)) InputInt)
  | [] => []
  | seed :: rest => extendDemand seed (summarizeDemands rest)

def Covers {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt))
    (query : Prod (Fin (size + 1)) InputInt) : Prop :=
  exists seed, Membership.mem seeds seed /\ query.2 = seed.2 /\ query.1 <= seed.1

theorem covers_cons {size : Nat} (seed query : Prod (Fin (size + 1)) InputInt)
    (rest : List (Prod (Fin (size + 1)) InputInt)) :
    Covers (seed :: rest) query <->
      (query.2 = seed.2 /\ query.1 <= seed.1) \/ Covers rest query := by
  simp [Covers]

theorem extend_covers {size : Nat} (seed query : Prod (Fin (size + 1)) InputInt)
    (rest : List (Prod (Fin (size + 1)) InputInt)) :
    Covers (extendDemand seed rest) query <->
      (query.2 = seed.2 /\ query.1 <= seed.1) \/ Covers rest query := by
  induction rest with
  | nil => simp [extendDemand, Covers]
  | cons entry rest ih =>
    by_cases same : seed.2 = entry.2
    next => simp [extendDemand, same, covers_cons, and_or_left, or_assoc]
    next => simp [extendDemand, same, covers_cons, ih, or_left_comm]

theorem summary_covers {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt))
    (query : Prod (Fin (size + 1)) InputInt) :
    Covers (summarizeDemands seeds) query <-> Covers seeds query := by
  induction seeds with
  | nil => rfl
  | cons seed rest ih => simp only [summarizeDemands, extend_covers, covers_cons, ih]

theorem extend_keys_mem {size : Nat} (seed : Prod (Fin (size + 1)) InputInt)
    (rest : List (Prod (Fin (size + 1)) InputInt)) (key : InputInt) :
    Membership.mem ((extendDemand seed rest).map Prod.snd) key <->
      key = seed.2 \/ Membership.mem (rest.map Prod.snd) key := by
  induction rest with
  | nil => simp [extendDemand]
  | cons entry rest ih =>
    by_cases same : seed.2 = entry.2 <;>
      simp [extendDemand, same, ih, or_left_comm]

theorem extend_keys_nodup {size : Nat} (seed : Prod (Fin (size + 1)) InputInt)
    (rest : List (Prod (Fin (size + 1)) InputInt)) (unique : (rest.map Prod.snd).Nodup) :
    ((extendDemand seed rest).map Prod.snd).Nodup := by
  induction rest with
  | nil => simp [extendDemand]
  | cons entry rest ih =>
    by_cases same : seed.2 = entry.2
    next => simpa [extendDemand, same] using unique
    next =>
      simp only [List.map_cons, List.nodup_cons] at unique
      simp only [extendDemand, if_neg same, List.map_cons, List.nodup_cons, extend_keys_mem]
      exact And.intro (not_or_intro (Ne.symm same) unique.1) (ih unique.2)

theorem summary_keys_nodup {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt)) :
    ((summarizeDemands seeds).map Prod.snd).Nodup := by
  induction seeds with
  | nil => simp [summarizeDemands]
  | cons seed rest ih => exact extend_keys_nodup seed _ ih

def prefixQueries {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt)) :
    List (Prod (Fin (size + 1)) InputInt) :=
  (summarizeDemands seeds).flatMap (fun seed => ancestorList seed.1 seed.2)

theorem prefix_queries_mem {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt))
    (query : Prod (Fin (size + 1)) InputInt) :
    Membership.mem (prefixQueries seeds) query <-> Covers seeds query := by
  rw [Iff.symm (summary_covers seeds query)]
  cases query with
  | mk version key =>
    simp [prefixQueries, Covers, ancestor_list_mem, QueuePlan.mem_ancestors, and_comm]

theorem prefix_queries_exact {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt)) :
    (prefixQueries seeds).toFinset =
      (seeds.flatMap (fun seed => ancestorList seed.1 seed.2)).toFinset := by
  ext query
  rw [List.mem_toFinset, prefix_queries_mem, List.mem_toFinset]
  cases query with
  | mk version key =>
    simp [Covers, ancestor_list_mem, QueuePlan.mem_ancestors, and_comm]

theorem prefix_queries_nodup {size : Nat} (seeds : List (Prod (Fin (size + 1)) InputInt)) :
    (prefixQueries seeds).Nodup := by
  apply List.nodup_flatMap.mpr
  refine And.intro (fun seed _ => ancestor_list_nodup seed.1 seed.2) ?_
  have separated : List.Pairwise (fun left right => Not (left.2 = right.2)) (summarizeDemands seeds) := by
    simpa only [List.Nodup, List.pairwise_map] using summary_keys_nodup seeds
  apply separated.imp
  intro left right different
  change List.Disjoint (ancestorList left.1 left.2) (ancestorList right.1 right.2)
  rw [List.disjoint_left]
  intro query left_member right_member
  have left_key := ((QueuePlan.mem_ancestors left.1 query.1 left.2 query.2).mp
    ((ancestor_list_mem left.1 left.2 query).mp left_member)).2
  have right_key := ((QueuePlan.mem_ancestors right.1 query.1 right.2 query.2).mp
    ((ancestor_list_mem right.1 right.2 query).mp right_member)).2
  exact different (left_key.symm.trans right_key)

def demandSeeds (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) :
    List (Prod (Fin (writeCount trace + 1)) InputInt) :=
  keys.map (fun key => (0, key)) ++
    (List.ofFn (fun index : Fin (writeCount trace) =>
      (index.castSucc, (QueuePlan.operation trace index).key))) ++
    observations.map (fun observation => (observation.version, observation.key))

def syntaxQueries (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) :
    List (Prod (Fin (writeCount trace + 1)) InputInt) :=
  prefixQueries (demandSeeds keys trace observations)

theorem syntax_queries_nodup (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) : (syntaxQueries keys trace observations).Nodup :=
  prefix_queries_nodup _

theorem syntax_queries_exact (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) :
    (syntaxQueries keys trace observations).toFinset =
      (keys.flatMap (ancestorList 0) ++
        (List.ofFn (fun index : Fin (writeCount trace) =>
          ancestorList index.castSucc (QueuePlan.operation trace index).key)).flatten ++
        observations.flatMap (fun observation : Observation trace =>
          ancestorList observation.version observation.key)).toFinset := by
  rw [syntaxQueries, prefix_queries_exact]
  simp [demandSeeds, List.flatMap, List.map_ofFn, Function.comp_def]

theorem syntax_members (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (query : Prod (Fin (writeCount trace + 1)) InputInt) :
    Membership.mem (syntaxQueries keys trace observations) query <->
      Membership.mem (QueuePlan.demands keys.toFinset trace) query \/
      exists observation, Membership.mem observations observation /\
        Membership.mem (QueuePlan.ancestors observation.version observation.key) query := by
  rw [syntaxQueries, prefix_queries_mem]
  cases query with
  | mk version key =>
    simp [Covers, demandSeeds, QueuePlan.demands, QueuePlan.mem_ancestors,
      and_or_left, exists_or, and_assoc, or_assoc, and_comm, eq_comm]
    simp only [Fin.le_def, Fin.val_castSucc, and_left_comm]

def syntaxDemands (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) :
    Finset (Prod (Fin (writeCount trace + 1)) InputInt) :=
  (syntaxQueries keys trace observations).toFinset

theorem syntax_downward (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace))
    (version prior : Fin (writeCount trace + 1)) (key : InputInt)
    (before : prior.val <= version.val)
    (member : Membership.mem (syntaxDemands keys trace observations) (version, key)) :
    Membership.mem (syntaxDemands keys trace observations) (prior, key) := by
  have selected := (syntax_members keys trace observations (version, key)).mp
    (by simpa [syntaxDemands] using member)
  suffices earlier : Membership.mem (syntaxQueries keys trace observations) (prior, key) by
    simpa [syntaxDemands] using earlier
  apply (syntax_members keys trace observations (prior, key)).mpr
  cases selected with
  | inl queue =>
    exact Or.inl (QueuePlan.demands_downward keys.toFinset trace version prior key before queue)
  | inr observed =>
    cases observed with
    | intro observation spec =>
      have earlier := QueuePlan.ancestors_downward observation.version version prior
        observation.key key before spec.2
      exact Or.inr (Exists.intro observation (And.intro spec.1 earlier))

def values {size : Nat} (assignment : Assignment) (base : Nat) :
    Fin (size + 1) -> Int -> Int :=
  fun version => assignment.unary .int .int (base + version.val)

def interpretedGraph (assignment : Assignment) (trace : List (Event InputInt))
    (counts : Fin (writeCount trace + 1) -> Int -> Int) :
    Readback.Graph Int Int (writeCount trace) where
  stores index :=
    { prior := index.castSucc
      key := (QueuePlan.operation trace index).key.eval assignment
      value := storeValue
        (counts index.castSucc ((QueuePlan.operation trace index).key.eval assignment))
        (QueuePlan.operation trace index).event }
  earlier index := Nat.lt_succ_self index.val

def semanticDemands (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) :
    Finset (Prod (Fin (writeCount trace + 1)) Int) :=
  (syntaxDemands keys trace observations).image
    (fun query => (query.1, query.2.eval assignment))

theorem observation_demand (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (observation : Observation trace) (member : Membership.mem observations observation) :
    Membership.mem (semanticDemands assignment keys trace observations)
      (observation.version, observation.key.eval assignment) := by
  apply Finset.mem_image.mpr
  refine Exists.intro (observation.version, observation.key) (And.intro ?_ rfl)
  apply List.mem_toFinset.mpr
  apply (syntax_members keys trace observations _).mpr
  exact Or.inr (Exists.intro observation (And.intro member
    ((QueuePlan.mem_ancestors _ _ _ _).mpr (And.intro (Nat.le_refl _) rfl))))

theorem old_value_demand (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (index : Fin (writeCount trace)) :
    Membership.mem (semanticDemands assignment keys trace observations)
      (index.castSucc, (QueuePlan.operation trace index).key.eval assignment) := by
  apply Finset.mem_image.mpr
  refine Exists.intro (index.castSucc, (QueuePlan.operation trace index).key) (And.intro ?_ rfl)
  apply List.mem_toFinset.mpr
  exact (syntax_members keys trace observations _).mpr
    (Or.inl (QueuePlan.old_count_demand keys.toFinset trace index))

theorem semantic_closed (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (counts : Fin (writeCount trace + 1) -> Int -> Int) :
    Readback.Closed (interpretedGraph assignment trace counts)
      (semanticDemands assignment keys trace observations) := by
  intro index key member _
  cases Finset.mem_image.mp member with
  | intro query spec =>
    have version := congrArg Prod.fst spec.2
    have key_eq := congrArg Prod.snd spec.2
    have before : index.castSucc.val <= query.1.val := by
      change query.1 = index.succ at version
      rw [version]
      exact Nat.le_succ _
    have predecessor := syntax_downward keys trace observations query.1 index.castSucc
      query.2 before spec.1
    exact Finset.mem_image.mpr (Exists.intro (index.castSucc, query.2)
      (And.intro predecessor (Prod.ext rfl key_eq)))

def readRef (base version : Nat) (key : InputInt) : Term .int :=
  .app .int .int (base + version) key.term

def writeValue (trace : List (Event InputInt)) (base : Nat)
    (index : Fin (writeCount trace)) : Term .int :=
  match QueuePlan.operation trace index with
  | .send key =>
    .ite (.equal (readRef base index.val key) (.integer 0)) (.integer 1)
      (readRef base index.val key)
  | .pop key => .sub (readRef base index.val key) (.integer 1)

def readEquation (trace : List (Event InputInt)) (base : Nat) :
    Prod (Fin (writeCount trace + 1)) InputInt -> Term .bool
  | (Fin.mk 0 _, _) => .boolean true
  | (Fin.mk (index + 1) bound, key) =>
    let prior : Fin (writeCount trace) := Fin.mk index (Nat.lt_of_succ_lt_succ bound)
    .equal (readRef base (index + 1) key)
      (.ite (.equal key.term (QueuePlan.operation trace prior).key.term)
        (writeValue trace base prior) (readRef base index key))

def observationEquation {trace : List (Event InputInt)} (base : Nat)
    (observation : Observation trace) : Term .bool :=
  .equal (readRef base observation.version.val observation.key) observation.expected.term

def countFormula (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (base : Nat) : SmtScript.Formula :=
  (syntaxQueries keys trace observations).map (readEquation trace base) ++
    observations.map (observationEquation base)

def operationArray (trace : List (Event InputInt)) : Array (QueuePlan.StoreOp InputInt) :=
  (QueuePlan.operations trace).toArray

theorem operation_array_size (trace : List (Event InputInt)) :
    (operationArray trace).size = writeCount trace := by
  simp [operationArray, QueuePlan.operations_length]

theorem operation_array_lookup (trace : List (Event InputInt)) (index : Fin (writeCount trace)) :
    (operationArray trace)[index.val]'(by rw [operation_array_size]; exact index.isLt) =
      QueuePlan.operation trace index := by
  simp [operationArray, QueuePlan.operation]

def writeValueFrom (base index : Nat) : QueuePlan.StoreOp InputInt -> Term .int
  | .send key =>
    .ite (.equal (readRef base index key) (.integer 0)) (.integer 1) (readRef base index key)
  | .pop key => .sub (readRef base index key) (.integer 1)

def readEquationFrom {size : Nat} (lookup : Fin size -> QueuePlan.StoreOp InputInt) (base : Nat) :
    Prod (Fin (size + 1)) InputInt -> Term .bool
  | (Fin.mk 0 _, _) => .boolean true
  | (Fin.mk (index + 1) bound, key) =>
    let operation := lookup (Fin.mk index (Nat.lt_of_succ_lt_succ bound))
    .equal (readRef base (index + 1) key)
      (.ite (.equal key.term operation.key.term)
        (writeValueFrom base index operation) (readRef base index key))

theorem read_equation_from_original (trace : List (Event InputInt)) (base : Nat) :
    readEquationFrom (QueuePlan.operation trace) base = readEquation trace base := by
  funext query
  cases query with
  | mk version key =>
    cases version with
    | mk index bound =>
      cases index with
      | zero => rfl
      | succ index =>
        simp only [readEquationFrom, readEquation]
        cases operation : QueuePlan.operation trace (Fin.mk index (Nat.lt_of_succ_lt_succ bound)) <;>
          simp [writeValueFrom, writeValue, operation]

def countFormulaCached (keys : List InputInt) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (base : Nat) : SmtScript.Formula :=
  let operations := operationArray trace
  let lookup := fun index : Fin (writeCount trace) =>
    operations[index.val]'(by simpa only [operations, operation_array_size] using index.isLt)
  let seeds := keys.map (fun key => (0, key)) ++
    List.ofFn (fun index : Fin (writeCount trace) => (index.castSucc, (lookup index).key)) ++
    observations.map (fun observation => (observation.version, observation.key))
  (prefixQueries seeds).map (readEquationFrom lookup base) ++
    observations.map (observationEquation base)

@[csimp] theorem countFormula_eq_cached : countFormula = countFormulaCached := by
  funext keys trace observations base
  simp only [countFormulaCached, operation_array_lookup, read_equation_from_original,
    countFormula, syntaxQueries, demandSeeds]

def encode (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) : SmtScript.Formula :=
  input ++ countFormula keys trace observations (freshBase input)

theorem encode_members_preserved (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) (term : Term .bool) :
    Membership.mem (encode input keys trace observations) term <->
      Membership.mem (input ++
        (((demandSeeds keys trace observations).flatMap (fun seed => ancestorList seed.1 seed.2)).map
          (readEquation trace (freshBase input)) ++ observations.map (observationEquation (freshBase input)))) term := by
  have members (query : Prod (Fin (writeCount trace + 1)) InputInt) :
      Membership.mem (syntaxQueries keys trace observations) query <->
        Membership.mem ((demandSeeds keys trace observations).flatMap (fun seed => ancestorList seed.1 seed.2)) query := by
    change Membership.mem (prefixQueries (demandSeeds keys trace observations)) query <-> _
    rw [Iff.symm List.mem_toFinset, prefix_queries_exact, List.mem_toFinset]
  simp only [encode, countFormula, List.mem_append, List.mem_map, members]

theorem allocation_bound_preserved (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) :
    freshBase (encode input keys trace observations) =
      freshBase (input ++
        (((demandSeeds keys trace observations).flatMap (fun seed => ancestorList seed.1 seed.2)).map
          (readEquation trace (freshBase input)) ++ observations.map (observationEquation (freshBase input)))) :=
  fresh_base_congr _ _ (encode_members_preserved input keys trace observations)

def render (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) : String :=
  SmtScript.render (encode input keys trace observations)

theorem write_value_eval (assignment : Assignment) (trace : List (Event InputInt))
    (base : Nat) (index : Fin (writeCount trace)) :
    (writeValue trace base index).eval assignment =
      storeValue (values assignment base index.castSucc
        ((QueuePlan.operation trace index).key.eval assignment))
        (QueuePlan.operation trace index).event := by
  cases op : QueuePlan.operation trace index <;>
    simp [writeValue, op, QueuePlan.StoreOp.key, QueuePlan.StoreOp.event, storeValue,
      Term.eval, readRef, values, InputInt.eval]

theorem read_successor (assignment : Assignment) (trace : List (Event InputInt))
    (base : Nat) (index : Fin (writeCount trace)) (key : InputInt) :
    (readEquation trace base (index.succ, key)).eval assignment = true <->
      values assignment base index.succ (key.eval assignment) =
        if key.eval assignment = (QueuePlan.operation trace index).key.eval assignment then
          storeValue (values assignment base index.castSucc
            ((QueuePlan.operation trace index).key.eval assignment))
            (QueuePlan.operation trace index).event
        else values assignment base index.castSucc (key.eval assignment) := by
  cases index
  simp [readEquation, Term.eval, write_value_eval, readRef, values, InputInt.eval]

theorem reads_correct (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) (base : Nat) :
    SmtScript.Holds assignment ((syntaxQueries keys trace observations).map (readEquation trace base)) <->
      Readback.Equations (interpretedGraph assignment trace (values assignment base)) none
        (semanticDemands assignment keys trace observations) (values assignment base) := by
  constructor
  next =>
    intro holds
    refine And.intro (by simp) ?_
    intro index actual member
    cases Finset.mem_image.mp member with
    | intro query spec =>
      cases query with
      | mk version key =>
        have version_eq : version = index.succ := congrArg Prod.fst spec.2
        have key_eq : key.eval assignment = actual := congrArg Prod.snd spec.2
        subst version
        subst actual
        apply (read_successor assignment trace base index key).mp
        apply holds
        apply List.mem_map.mpr
        exact Exists.intro (index.succ, key)
          (And.intro (by simpa [syntaxDemands] using spec.1) rfl)
  next =>
    intro equations term member
    cases List.mem_map.mp member with
    | intro query spec =>
      rw [Eq.symm spec.2]
      cases query with
      | mk version key =>
        cases version using Fin.cases with
        | zero => rfl
        | succ index =>
          apply (read_successor assignment trace base index key).mpr
          apply equations.2 index (key.eval assignment)
          exact Finset.mem_image.mpr (Exists.intro (index.succ, key)
            (And.intro (by simpa [syntaxDemands] using spec.1) rfl))

def ObservationsHold (assignment : Assignment) {trace : List (Event InputInt)}
    (counts : Fin (writeCount trace + 1) -> Int -> Int) (observations : List (Observation trace)) : Prop :=
  forall observation, Membership.mem observations observation ->
    counts observation.version (observation.key.eval assignment) = observation.expected.eval assignment

theorem observations_agree (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (left right : Fin (writeCount trace + 1) -> Int -> Int)
    (agree : forall version key, Membership.mem (semanticDemands assignment keys trace observations) (version, key) ->
      left version key = right version key) :
    ObservationsHold assignment left observations <-> ObservationsHold assignment right observations := by
  unfold ObservationsHold
  apply forall_congr'
  intro observation
  apply forall_congr'
  intro member
  rw [agree _ _ (observation_demand assignment keys trace observations observation member)]

theorem family_update (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (counts : Fin (writeCount trace + 1) -> Int -> Int) (root : Int -> Int)
    (agree : forall version key, Membership.mem (semanticDemands assignment keys trace observations) (version, key) ->
      Readback.array (interpretedGraph assignment trace counts) root version key = counts version key)
    (index : Fin (writeCount trace)) :
    Readback.array (interpretedGraph assignment trace counts) root index.succ =
      Function.update (Readback.array (interpretedGraph assignment trace counts) root index.castSucc)
        ((QueuePlan.operation trace index).key.eval assignment)
        (storeValue (Readback.array (interpretedGraph assignment trace counts) root index.castSucc
          ((QueuePlan.operation trace index).key.eval assignment)) (QueuePlan.operation trace index).event) := by
  rw [QueueReadback.array_update _ _ index rfl]
  rw [agree _ _ (old_value_demand assignment keys trace observations index)]
  rfl

theorem observations_correct (assignment : Assignment) (trace : List (Event InputInt))
    (observations : List (Observation trace)) (base : Nat) :
    SmtScript.Holds assignment (observations.map (observationEquation base)) <->
      ObservationsHold assignment (values assignment base) observations := by
  simp [SmtScript.Holds, ObservationsHold, observationEquation, Term.eval, readRef, values, InputInt.eval]

theorem holds_append (assignment : Assignment) (left right : SmtScript.Formula) :
    SmtScript.Holds assignment (left ++ right) <->
      SmtScript.Holds assignment left /\ SmtScript.Holds assignment right := by
  simp only [SmtScript.Holds, List.mem_append, or_imp, forall_and]

def CountSemantics (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (counts : Fin (writeCount trace + 1) -> Int -> Int) : Prop :=
  Readback.Equations (interpretedGraph assignment trace counts) none
      (semanticDemands assignment keys trace observations) counts /\
    ObservationsHold assignment counts observations

theorem count_formula_correct (assignment : Assignment) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) (base : Nat) :
    SmtScript.Holds assignment (countFormula keys trace observations base) <->
      CountSemantics assignment keys trace observations (values assignment base) := by
  rw [countFormula, holds_append, reads_correct, observations_correct]
  rfl

theorem encode_correct (assignment : Assignment) (input : SmtScript.Formula)
    (keys : List InputInt) (trace : List (Event InputInt)) (observations : List (Observation trace)) :
    SmtScript.Holds assignment (encode input keys trace observations) <->
      SmtScript.Holds assignment input /\
        CountSemantics assignment keys trace observations (values assignment (freshBase input)) := by
  rw [encode, holds_append, count_formula_correct]

@[simp] theorem values_install {size : Nat} (original : Assignment) (base : Nat)
    (counts : Fin (size + 1) -> Int -> Int) :
    values (installCounts original base counts) base = counts := by
  funext version
  exact install_at original base counts version

@[simp] theorem graph_install (original : Assignment) (base : Nat)
    (trace : List (Event InputInt))
    (installed counts : Fin (writeCount trace + 1) -> Int -> Int) :
    interpretedGraph (installCounts original base installed) trace counts =
      interpretedGraph original trace counts := by
  simp only [interpretedGraph, input_install]

@[simp] theorem demands_install (original : Assignment) (base : Nat)
    (keys : List InputInt) (trace : List (Event InputInt)) (observations : List (Observation trace))
    (counts : Fin (writeCount trace + 1) -> Int -> Int) :
    semanticDemands (installCounts original base counts) keys trace observations =
      semanticDemands original keys trace observations := by
  simp only [semanticDemands, input_install]

@[simp] theorem observations_install (original : Assignment) (base : Nat)
    (trace : List (Event InputInt)) (observations : List (Observation trace))
    (installed counts : Fin (writeCount trace + 1) -> Int -> Int) :
    ObservationsHold (installCounts original base installed) counts observations <->
      ObservationsHold original counts observations := by
  simp only [ObservationsHold, input_install]

theorem install_satisfies (original : Assignment) (input : SmtScript.Formula)
    (keys : List InputInt) (trace : List (Event InputInt)) (observations : List (Observation trace))
    (counts : Fin (writeCount trace + 1) -> Int -> Int)
    (input_holds : SmtScript.Holds original input)
    (semantics : CountSemantics original keys trace observations counts) :
    SmtScript.Holds (installCounts original (freshBase input) counts)
      (encode input keys trace observations) := by
  apply (encode_correct _ input keys trace observations).mpr
  refine And.intro ((input_preserved input original counts).mpr input_holds) ?_
  simpa only [CountSemantics, values_install, graph_install, demands_install,
    observations_install] using semantics

theorem encode_exists_iff (input : SmtScript.Formula) (keys : List InputInt)
    (trace : List (Event InputInt)) (observations : List (Observation trace)) :
    (exists assignment : Assignment, SmtScript.Holds assignment (encode input keys trace observations)) <->
    (exists original : Assignment, exists counts : Fin (writeCount trace + 1) -> Int -> Int,
      exists root : Int -> Int,
        SmtScript.Holds original input /\
        (forall version key, Membership.mem (semanticDemands original keys trace observations) (version, key) ->
          Readback.array (interpretedGraph original trace counts) root version key = counts version key) /\
        ObservationsHold original (Readback.array (interpretedGraph original trace counts) root) observations) := by
  constructor
  next =>
    intro witness
    cases witness with
    | intro assignment holds =>
      have valid := (encode_correct assignment input keys trace observations).mp holds
      cases (Readback.finite_readback_iff
          (interpretedGraph assignment trace (values assignment (freshBase input))) none
          (semanticDemands assignment keys trace observations) (values assignment (freshBase input))
          (semantic_closed assignment keys trace observations _)).mp valid.2.1 with
      | intro root spec =>
        exact Exists.intro assignment (Exists.intro (values assignment (freshBase input))
          (Exists.intro root (And.intro valid.1 (And.intro spec.2
            ((observations_agree assignment keys trace observations _ _ spec.2).mpr valid.2.2)))))
  next =>
    intro witness
    cases witness with
    | intro original witness =>
      cases witness with
      | intro counts witness =>
        cases witness with
        | intro root spec =>
          have equations := (Readback.finite_readback_iff (interpretedGraph original trace counts) none
            (semanticDemands original keys trace observations) counts
            (semantic_closed original keys trace observations counts)).mpr
              (Exists.intro root (And.intro (by simp) spec.2.1))
          exact Exists.intro (installCounts original (freshBase input) counts)
            (install_satisfies original input keys trace observations counts spec.1
              (And.intro equations
                ((observations_agree original keys trace observations _ _ spec.2.1).mp spec.2.2)))

theorem commands_correct (assignment : Assignment) (input : SmtScript.Formula)
    (keys : List InputInt) (trace : List (Event InputInt)) (observations : List (Observation trace)) :
    SmtScript.run assignment (SmtScript.compile (encode input keys trace observations)) = some true <->
      SmtScript.Holds assignment input /\
        CountSemantics assignment keys trace observations (values assignment (freshBase input)) :=
  (SmtScript.formula_holds_iff assignment (encode input keys trace observations)).symm.trans
    (encode_correct assignment input keys trace observations)

def regressionInput : Assignment where
  constant ty _ := match ty with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }
  unary _ result _ _ := match result with
    | .bool => false | .int => 0 | .nodes => 0
    | .content => .signature | .entry => { term := 0, content := .signature }

def regressionTrace : List (Event InputInt) :=
  [.send (.literal (-2)), .send (.literal (-2)), .pop (.literal (-2))]

def regressionObservations : List (Observation regressionTrace) :=
  [{ version := 0, key := .literal (-2), expected := .literal 0 },
   { version := 1, key := .literal (-2), expected := .literal 1 },
   { version := 2, key := .literal (-2), expected := .literal 1 },
   { version := 3, key := .literal (-2), expected := .literal 0 }]

def regressionCounts (version : Fin (writeCount regressionTrace + 1)) (key : Int) : Int :=
  if key = -2 then (if version.val = 1 \/ version.val = 2 then 1 else 0) else -7

theorem observed_prefix_regression :
    syntaxQueries [.literal (-2), .literal (-2)] regressionTrace regressionObservations =
      ancestorList (3 : Fin (writeCount regressionTrace + 1)) (.literal (-2)) := by
  decide +kernel

theorem unobserved_prefix_regression :
    syntaxQueries [.literal (-2), .literal (-2)] regressionTrace [] =
      ancestorList (2 : Fin (writeCount regressionTrace + 1)) (.literal (-2)) := by
  decide +kernel

theorem merged_prefixes {size : Nat} (left right : Fin (size + 1)) (key : InputInt) :
    prefixQueries [(left, key), (right, key)] = ancestorList (max left right) key := by
  simp [prefixQueries, summarizeDemands, extendDemand]

theorem distinct_prefixes {size : Nat} (left right : Fin (size + 1)) (first second : InputInt)
    (different : Not (first = second)) :
    prefixQueries [(left, first), (right, second)] =
      ancestorList right second ++ ancestorList left first := by
  simp [prefixQueries, summarizeDemands, extendDemand, different]

theorem duplicate_send_regression :
    SmtScript.run (installCounts regressionInput (freshBase []) regressionCounts)
      (SmtScript.compile (encode [] [.literal (-2)] regressionTrace regressionObservations)) =
        some true := by
  apply (SmtScript.formula_holds_iff _ _).mp
  apply install_satisfies
  next => simp [SmtScript.Holds]
  next =>
    constructor
    next =>
      constructor
      next => simp
      next =>
        intro index key _
        fin_cases index <;> by_cases same : key = -2 <;>
          simp [interpretedGraph, regressionCounts, regressionTrace, QueuePlan.operation,
            QueuePlan.operations, QueuePlan.StoreOp.key, QueuePlan.StoreOp.event, storeValue,
            InputInt.eval, InputInt.term, Term.eval, same, writeCount, QueueClause.writes]
    next =>
      simp [ObservationsHold, regressionObservations, regressionCounts, regressionTrace,
        InputInt.eval, InputInt.term, Term.eval, writeCount, QueueClause.writes]

def aliasInput : SmtScript.Formula :=
  [.equal (.unknown .int 0) (.unknown .int 1)]

def aliasObservations : List (Observation []) :=
  [{ version := 0, key := .symbolic 0, expected := .literal 0 },
   { version := 0, key := .symbolic 1, expected := .literal 1 }]

theorem inconsistent_alias_regression :
    Not (exists assignment : Assignment,
      SmtScript.Holds assignment (encode aliasInput [.symbolic 0, .symbolic 1] [] aliasObservations)) := by
  intro witness
  cases witness with
  | intro assignment holds =>
    have valid := (encode_correct assignment aliasInput _ [] aliasObservations).mp holds
    have same_key : (InputInt.symbolic 0).eval assignment = (InputInt.symbolic 1).eval assignment := by
      have input := valid.1 (.equal (.unknown .int 0) (.unknown .int 1)) (by simp [aliasInput])
      simpa [InputInt.eval, InputInt.term, Term.eval] using input
    have first := valid.2.2
      { version := 0, key := .symbolic 0, expected := .literal 0 } (by simp [aliasObservations])
    have second := valid.2.2
      { version := 0, key := .symbolic 1, expected := .literal 1 } (by simp [aliasObservations])
    change values assignment (freshBase aliasInput) 0 ((InputInt.symbolic 0).eval assignment) = 0 at first
    change values assignment (freshBase aliasInput) 0 ((InputInt.symbolic 1).eval assignment) = 1 at second
    rw [same_key] at first
    omega

end CCFRaft.Sparse.QueueEncoding

run_cmd do
  for (name, _) in (<- Lean.getEnv).constants.toList do
    if (`CCFRaft.Sparse.QueueEncoding).isPrefixOf name then
      for axiomName in (<- Lean.collectAxioms name) do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo "Sparse.QueueEncoding: allowed-axiom gate passed."
