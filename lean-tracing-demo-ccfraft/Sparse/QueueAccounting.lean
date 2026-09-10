import Sparse.QueueCounts

set_option autoImplicit false

namespace CCFRaft.Sparse.QueueAccounting

variable {A : Type} [DecidableEq A] [BEq A] [LawfulBEq A]

structure Accounting (A : Type) where
  seen : A -> Bool
  total : Int

def account (counts : A -> Int) (state : Accounting A) (message : A) : Accounting A :=
  { seen := Function.update state.seen message true
    total := state.total + if state.seen message then 0 else counts message }

def accounts (counts : A -> Int) : Accounting A -> List A -> Accounting A
  | state, [] => state
  | state, message :: rest => accounts counts (account counts state message) rest

def Accounting.Correct (state : Accounting A) (keys : Finset A) (counts : A -> Int) : Prop :=
  (forall message, state.seen message = decide (Membership.mem keys message)) /\
    state.total = keys.sum counts

omit [BEq A] [LawfulBEq A] in
theorem account_correct (counts : A -> Int) (state : Accounting A) (keys : Finset A)
    (correct : state.Correct keys counts) (message : A) :
    (account counts state message).Correct (insert message keys) counts := by
  constructor
  next =>
    intro key
    by_cases same : key = message <;>
      simp [account, Function.update, same, correct.1]
  next =>
    by_cases present : Membership.mem keys message
    next =>
      simp [account, correct.1, correct.2, present, Finset.insert_eq_of_mem present]
    next =>
      simp [account, correct.1, correct.2, present, Finset.sum_insert, Int.add_comm]

omit [BEq A] [LawfulBEq A] in
theorem accounts_correct (counts : A -> Int) (state : Accounting A) (keys : Finset A)
    (correct : state.Correct keys counts) (messages : List A) :
    (accounts counts state messages).Correct (Union.union keys messages.toFinset) counts := by
  induction messages generalizing state keys with
  | nil => simpa [accounts] using correct
  | cons message rest ih =>
    have next := ih (account counts state message) (insert message keys)
      (account_correct counts state keys correct message)
    simpa [accounts, Finset.union_comm, Finset.union_left_comm, Finset.union_assoc] using next

omit [BEq A] [LawfulBEq A] in
theorem initial_accounts_exact (counts : A -> Int) (messages : List A) :
    (accounts counts { seen := fun _ => false, total := 0 } messages).total =
      messages.toFinset.sum counts := by
  have initial : Accounting.Correct { seen := fun _ => false, total := 0 } {} counts := by
    simp [Accounting.Correct]
  simpa using (accounts_correct counts _ {} initial messages).2

def prefixCount (prefixValues : List A) : A -> Int :=
  prefixValues.foldl (fun counts message =>
    Function.update counts message (counts message + 1)) (fun _ => 0)

theorem count_fold_correct (counts : A -> Int) (prior rest : List A)
    (correct : forall message, counts message = (prior.count message : Int)) :
    forall message,
      (rest.foldl (fun current key => Function.update current key (current key + 1))
        counts) message = ((prior ++ rest).count message : Int) := by
  induction rest generalizing counts prior with
  | nil => simpa using correct
  | cons head tail ih =>
    let updated := Function.update counts head (counts head + 1)
    have next : forall message, updated message = ((prior ++ [head]).count message : Int) := by
      intro message
      by_cases same : message = head <;>
        simp [updated, same, List.count_append, correct, Ne.symm]
    have h := ih updated (prior ++ [head]) next
    simpa [updated, List.foldl_cons, List.append_assoc] using h

theorem prefix_count_exact (prefixValues : List A) (message : A) :
    prefixCount prefixValues message = (prefixValues.count message : Int) := by
  have h := count_fold_correct (fun _ => 0) [] prefixValues (by simp)
  simpa [prefixCount] using h message

def boundedPrefix (limit : Nat) : Nat -> (A -> Int) -> List A -> (A -> Int)
  | _, counts, [] => counts
  | index, counts, message :: rest =>
    boundedPrefix limit (index + 1)
      (if index < limit then Function.update counts message (counts message + 1) else counts) rest

omit [BEq A] [LawfulBEq A] in
theorem bounded_prefix_fold (limit index : Nat) (counts : A -> Int) (messages : List A) :
    boundedPrefix limit index counts messages =
      (messages.take (limit - index)).foldl
        (fun current message => Function.update current message (current message + 1)) counts := by
  induction messages generalizing index counts with
  | nil => simp [boundedPrefix]
  | cons message rest ih =>
    by_cases within : index < limit
    next =>
      have difference : limit - index = (limit - (index + 1)) + 1 := by omega
      simp only [boundedPrefix, within, if_true, difference, List.take_succ_cons, List.foldl_cons, ih]
    next =>
      have difference : limit - index = 0 := by omega
      have later : limit - (index + 1) = 0 := by omega
      simp only [boundedPrefix, within, if_false, difference, List.take_zero, List.foldl_nil, ih, later]

theorem bounded_prefix_exact (limit : Nat) (messages : List A) (message : A) :
    boundedPrefix limit 0 (fun _ => 0) messages message =
      ((messages.take limit).count message : Int) := by
  rw [bounded_prefix_fold]
  simpa only [Nat.sub_zero, prefixCount] using prefix_count_exact (messages.take limit) message

end CCFRaft.Sparse.QueueAccounting

run_cmd do
  for theoremName in [
      ``CCFRaft.Sparse.QueueAccounting.initial_accounts_exact,
      ``CCFRaft.Sparse.QueueAccounting.prefix_count_exact,
      ``CCFRaft.Sparse.QueueAccounting.bounded_prefix_exact] do
    let axioms <- Lean.collectAxioms theoremName
    for name in axioms do
      unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
        throwError "unexpected axiom: {name}"
