module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.HandReadersElectionBReflect
public import ConsensusCoverage.ReadersGenerated
public import ConsensusCoverage.HandReadersElectionBFrontier
import all ConsensusCoverage.HandReadersElectionBReflect
import all ConsensusCoverage.HandReadersElectionBCampaign
import all ConsensusCoverage.HandReadersElectionBFrontier
import all ConsensusCoverage.SolvedWitnesses
import all Consensus.Proofs.SafetyInvariant
public meta import ConsensusCoverage.HandReadersElectionBReflect

namespace ConsensusCoverage.HandReadersElectionB.Bounds

open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Safety Ledger SolvedWitnesses
set_option maxRecDepth 16384
set_option maxHeartbeats 0
set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option Elab.async false

private abbrev Within (log : List Entry) (xs : List Nat) := ∀ n ∈ xs, n ≤ log.length
private abbrev Fold (log : List Entry) (xs : List Nat) := ∀ best : Nat, Within log xs → best ≤ log.length →
  xs.foldl (fun best index => if isSignatureAt log index then max best index else best) best ≤ log.length

private theorem validRange (log : List Entry) : Within log (List.range (log.length + 1)) :=
  fun _ m => Nat.le_of_lt_succ (List.mem_range.mp m)

private theorem cons (l : List Entry) :
    (∃ tail, Fold l tail ∧ Within l (List.range (l.length+1))) ↔ True :=
  ⟨fun _ => trivial,fun _ => ⟨[],fun _ _ h => h,validRange l⟩⟩

private theorem unsigned (l : List Entry) :
    (∃ hd tl, Fold l tl ∧ ∃ best, Within l (hd :: tl) ∧ best ≤ l.length ∧
      ¬isSignatureAt l hd = true ∧ Within l (List.range (l.length+1)) ∧ hd ≤ l.length) ↔ True :=
  ⟨fun _ => trivial,fun _ => ⟨0,[],fun _ _ h => h,0,by simp [Within],Nat.zero_le _,by simp [isSignatureAt,entryAt?],
    validRange l,Nat.zero_le _⟩⟩

private theorem signed (l : List Entry) :
    (∃ hd tl, Fold l tl ∧ ∃ best, Within l (hd :: tl) ∧ best ≤ l.length ∧
      isSignatureAt l hd = true ∧ Within l (List.range (l.length+1)) ∧ hd ≤ l.length) ↔
      0 < maxCommittableIndex l := by
  constructor
  · rintro ⟨_,_,_,_,_,_,sig_,_,_⟩
    exact Nat.lt_of_lt_of_le (signature_pos sig_) (signatureIndex_le_maxCommittableIndex sig_)
  · intro pos
    have le := maxCommittableIndexBounded l
    exact ⟨maxCommittableIndex l,[],fun _ _ h => h,0,by simpa [Within] using le,Nat.zero_le _,
      maxCommittableIndexPositiveIsSignature pos,validRange l,le⟩

open Lean Elab Command in
run_cmd liftTermElabM do
  let mut rules := #[``cons,``signed,``unsigned,``Frontier.erased_iff,``Frontier.scan_iff,``Frontier.last_iff]
  for n in [`ConsensusCoverage.HandReadersElectionB.Campaign.erased,`ConsensusCoverage.HandReadersElectionB.Campaign.named] do
    for i in [1:10] do rules := rules.push (n.appendIndexAfter i)
  Reflect.compile `ConsensusCoverage.HandReadersElectionB.Bounds.Reflected
    #[``step_maxCommittableIndexBounded_values_nil,``step_maxCommittableIndexBounded_values_cons,
      ``step_maxCommittableIndexBounded_signature_pos,``step_maxCommittableIndexBounded_signature_neg]
    rules

end ConsensusCoverage.HandReadersElectionB.Bounds
