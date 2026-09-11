import Sparse.EntryValue

set_option autoImplicit false

namespace CCFRaft.Sparse.EntrySelectorSemantics

open EntryValue

structure WrongSelectors where
  txWrong : Content -> Int
  cfgWrong : Content -> BitVec NODE_COUNT
  retiredWrong : Content -> BitVec NODE_COUNT

def rawTx (interpretation : WrongSelectors) : Content -> Int
  | .transaction tx => tx
  | content => interpretation.txWrong content

def rawCfg (interpretation : WrongSelectors) : Content -> BitVec NODE_COUNT
  | .reconfiguration nodes => nodes
  | content => interpretation.cfgWrong content

def rawRetired (interpretation : WrongSelectors) : Content -> BitVec NODE_COUNT
  | .retiredCommitted nodes => nodes
  | content => interpretation.retiredWrong content

@[simp] theorem rawTx_matching (interpretation : WrongSelectors) (tx : Int) :
    rawTx interpretation (.transaction tx) = tx := rfl

@[simp] theorem rawCfg_matching (interpretation : WrongSelectors)
    (nodes : BitVec NODE_COUNT) :
    rawCfg interpretation (.reconfiguration nodes) = nodes := rfl

@[simp] theorem rawRetired_matching (interpretation : WrongSelectors)
    (nodes : BitVec NODE_COUNT) :
    rawRetired interpretation (.retiredCommitted nodes) = nodes := rfl

theorem rawTx_wrong (interpretation : WrongSelectors) (content : Content)
    (absent : content.transaction? = none) :
    rawTx interpretation content = interpretation.txWrong content := by
  cases content <;> simp_all [Content.transaction?, rawTx]

theorem rawCfg_wrong (interpretation : WrongSelectors) (content : Content)
    (absent : content.reconfiguration? = none) :
    rawCfg interpretation content = interpretation.cfgWrong content := by
  cases content <;> simp_all [Content.reconfiguration?, rawCfg]

theorem rawRetired_wrong (interpretation : WrongSelectors) (content : Content)
    (absent : content.retiredCommitted? = none) :
    rawRetired interpretation content = interpretation.retiredWrong content := by
  cases content <;> simp_all [Content.retiredCommitted?, rawRetired]

theorem raw_selectors_complete
    (tx : Content -> Int) (cfg retired : Content -> BitVec NODE_COUNT)
    (tx_matching : forall value, tx (.transaction value) = value)
    (cfg_matching : forall nodes, cfg (.reconfiguration nodes) = nodes)
    (retired_matching : forall nodes, retired (.retiredCommitted nodes) = nodes) :
    exists interpretation : WrongSelectors,
      rawTx interpretation = tx /\ rawCfg interpretation = cfg /\
        rawRetired interpretation = retired := by
  refine Exists.intro { txWrong := tx, cfgWrong := cfg, retiredWrong := retired }
    (And.intro ?_ (And.intro ?_ ?_))
  all_goals
    funext content
    cases content <;>
      simp [rawTx, rawCfg, rawRetired, tx_matching, cfg_matching, retired_matching]

-- Sequence both branch results before choosing a value, even in a dead branch.
def eagerIte {A : Type} (test : Option Bool) (yes no : Option A) : Option A := do
  let condition <- test
  let yesValue <- yes
  let noValue <- no
  pure (if condition then yesValue else noValue)

@[simp] theorem eagerIte_some {A : Type} (condition : Bool) (yes no : A) :
    eagerIte (some condition) (some yes) (some no) =
      some (if condition then yes else no) := rfl

@[simp] theorem eagerIte_missing_test {A : Type} (yes no : Option A) :
    eagerIte none yes no = none := rfl

@[simp] theorem eagerIte_missing_yes {A : Type} (condition : Bool) (no : Option A) :
    eagerIte (some condition) none no = none := rfl

@[simp] theorem eagerIte_missing_no {A : Type} (condition : Bool) (yes : Option A) :
    eagerIte (some condition) yes none = none := by
  cases yes <;> rfl

theorem eagerIte_success_iff {A : Type} (test : Option Bool) (yes no : Option A) :
    (eagerIte test yes no).isSome = true <->
      test.isSome = true /\ yes.isSome = true /\ no.isSome = true := by
  cases test <;> cases yes <;> cases no <;> simp [eagerIte]

theorem guarded_tx_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : Int) :
    (if content.isTransaction then rawTx interpretation content else fallback) =
      content.transaction?.getD fallback := by
  cases content <;> rfl

theorem guarded_cfg_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : BitVec NODE_COUNT) :
    (if content.isReconfiguration then rawCfg interpretation content else fallback) =
      content.reconfiguration?.getD fallback := by
  cases content <;> rfl

theorem guarded_retired_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : BitVec NODE_COUNT) :
    (if content.isRetiredCommitted then rawRetired interpretation content else fallback) =
      content.retiredCommitted?.getD fallback := by
  cases content <;> rfl

def txOr (interpretation : WrongSelectors) (content : Content)
    (fallback : Int) : Option Int :=
  eagerIte (some content.isTransaction) (some (rawTx interpretation content)) (some fallback)

def cfgOr (interpretation : WrongSelectors) (content : Content)
    (fallback : BitVec NODE_COUNT) : Option (BitVec NODE_COUNT) :=
  eagerIte (some content.isReconfiguration) (some (rawCfg interpretation content)) (some fallback)

def retiredOr (interpretation : WrongSelectors) (content : Content)
    (fallback : BitVec NODE_COUNT) : Option (BitVec NODE_COUNT) :=
  eagerIte (some content.isRetiredCommitted) (some (rawRetired interpretation content))
    (some fallback)

@[simp] theorem txOr_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : Int) :
    txOr interpretation content fallback = some (content.transaction?.getD fallback) := by
  simp only [txOr, eagerIte_some, guarded_tx_eq_getD]

@[simp] theorem cfgOr_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : BitVec NODE_COUNT) :
    cfgOr interpretation content fallback = some (content.reconfiguration?.getD fallback) := by
  simp only [cfgOr, eagerIte_some, guarded_cfg_eq_getD]

@[simp] theorem retiredOr_eq_getD (interpretation : WrongSelectors)
    (content : Content) (fallback : BitVec NODE_COUNT) :
    retiredOr interpretation content fallback =
      some (content.retiredCommitted?.getD fallback) := by
  simp only [retiredOr, eagerIte_some, guarded_retired_eq_getD]

theorem txOr_independent (left right : WrongSelectors) (content : Content) (fallback : Int) :
    txOr left content fallback = txOr right content fallback := by simp

theorem cfgOr_independent (left right : WrongSelectors) (content : Content)
    (fallback : BitVec NODE_COUNT) :
    cfgOr left content fallback = cfgOr right content fallback := by simp

theorem retiredOr_independent (left right : WrongSelectors) (content : Content)
    (fallback : BitVec NODE_COUNT) :
    retiredOr left content fallback = retiredOr right content fallback := by simp

theorem configuration_retired_paths (interpretation : WrongSelectors)
    (nodes fallback : BitVec NODE_COUNT) :
    cfgOr interpretation (.reconfiguration nodes) fallback = some nodes /\
      retiredOr interpretation (.reconfiguration nodes) fallback = some fallback /\
      cfgOr interpretation (.retiredCommitted nodes) fallback = some fallback /\
      retiredOr interpretation (.retiredCommitted nodes) fallback = some nodes := by
  simp [Content.reconfiguration?, Content.retiredCommitted?]

theorem raw_configuration_retired_distinctions (interpretation : WrongSelectors)
    (nodes : BitVec NODE_COUNT) :
    rawCfg interpretation (.retiredCommitted nodes) =
        interpretation.cfgWrong (.retiredCommitted nodes) /\
      rawRetired interpretation (.reconfiguration nodes) =
        interpretation.retiredWrong (.reconfiguration nodes) := by
  exact And.intro rfl rfl

-- Counterexamples use two legal interpretations, not a distinguished default.
private def zeros : WrongSelectors :=
  { txWrong := fun _ => 0, cfgWrong := fun _ => 0, retiredWrong := fun _ => 0 }
private def ones : WrongSelectors :=
  { txWrong := fun _ => 1, cfgWrong := fun _ => 1, retiredWrong := fun _ => 1 }

theorem unguarded_signature_disagreement :
    exists left right : WrongSelectors,
      rawTx left .signature != rawTx right .signature /\
        rawCfg left .signature != rawCfg right .signature /\
        rawRetired left .signature != rawRetired right .signature := by
  exact Exists.intro zeros (Exists.intro ones (by decide))

theorem guarded_signature_equal (left right : WrongSelectors)
    (txFallback : Int) (maskFallback : BitVec NODE_COUNT) :
    txOr left .signature txFallback = some txFallback /\
      txOr right .signature txFallback = some txFallback /\
      cfgOr left .signature maskFallback = some maskFallback /\
      cfgOr right .signature maskFallback = some maskFallback /\
      retiredOr left .signature maskFallback = some maskFallback /\
      retiredOr right .signature maskFallback = some maskFallback := by
  simp [Content.transaction?, Content.reconfiguration?, Content.retiredCommitted?]

theorem mismatched_transaction_operand (fallback : Int) :
    exists left right : WrongSelectors,
      eagerIte (some (Content.transaction 7).isTransaction)
          (some (rawTx left .signature)) (some fallback) !=
        eagerIte (some (Content.transaction 7).isTransaction)
          (some (rawTx right .signature)) (some fallback) := by
  refine Exists.intro zeros (Exists.intro ones ?_)
  simp [Content.isTransaction, Content.transaction?, rawTx, zeros, ones]

theorem mismatched_mask_operands (nodes fallback : BitVec NODE_COUNT) :
    exists left right : WrongSelectors,
      eagerIte (some (Content.reconfiguration nodes).isReconfiguration)
          (some (rawCfg left (.retiredCommitted nodes))) (some fallback) !=
        eagerIte (some (Content.reconfiguration nodes).isReconfiguration)
          (some (rawCfg right (.retiredCommitted nodes))) (some fallback) /\
      eagerIte (some (Content.retiredCommitted nodes).isRetiredCommitted)
          (some (rawRetired left (.reconfiguration nodes))) (some fallback) !=
        eagerIte (some (Content.retiredCommitted nodes).isRetiredCommitted)
          (some (rawRetired right (.reconfiguration nodes))) (some fallback) := by
  refine Exists.intro zeros (Exists.intro ones ?_)
  simp [Content.isReconfiguration, Content.reconfiguration?,
    Content.isRetiredCommitted, Content.retiredCommitted?, rawCfg, rawRetired, zeros, ones]
  decide

theorem dead_branch_failure :
    eagerIte (some false) (none : Option Int) (some 9) = none /\
      eagerIte (some true) (some 9) (none : Option Int) = none := by
  simp

end CCFRaft.Sparse.EntrySelectorSemantics

run_cmd do
  let namespaceName := `CCFRaft.Sparse.EntrySelectorSemantics
  let environment <- Lean.getEnv
  let mut count := 0
  for (name, _) in environment.constants.toList do
    if namespaceName.isPrefixOf name then
      count := count + 1
      let axioms <- Lean.collectAxioms name
      for axiomName in axioms do
        unless axiomName == ``propext || axiomName == ``Classical.choice ||
            axiomName == ``Quot.sound do
          throwError "unexpected axiom in {name}: {axiomName}"
  Lean.logInfo m!"EntrySelectorSemantics: audited {count} declarations; only propext, Classical.choice, Quot.sound"
