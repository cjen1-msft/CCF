module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ActionProfile
import all ConsensusCoverage.ActionProfile
import all ConsensusCoverage.FullProfile
import all ConsensusCoverage.PinnedClasses
import all Consensus.Proofs.SafetyInvariant

/-!
# Exact executable answers for the generated fresh-envelope family

The reach conditions ask whether a **value** is present after the step and was
absent before it. Re-sending an identical queued envelope does not count, even
when the step also consumes one occurrence. `LocalTransition` proves that every
fresh value came from the actual outgoing list; `Summary.sends` supplies the
generated send premises. Thus the executable code only needs the two raw queues.

The scope is `covered`; this module does not decide the other generated questions
or count the joint reachable edge labels. For example, `terms_now_after_inr` also
requires the fresh canonical-log witness in `reach_1`. An unchanged other node
alone does not supply that witness.
-/

set_option backward.privateInPublic true
set_option backward.privateInPublic.warn false
set_option autoImplicit false

namespace ConsensusCoverage.ReducedQuestions

open CCF CCF.MultiNodeTransitionSystem
open Consensus Consensus.Model Consensus.Model.Node Consensus.Proofs Consensus.Proofs.Safety

private def bumping : Message → Bool
  | .appendEntriesResponse _ | .proposeRequestVoteRequest _ => false
  | _ => true

private theorem bumping_iff (m : Message) : bumping m = true ↔ Bumping m := by
  cases m <;> simp [bumping, Bumping]

private def freshSend (s : Model.State) (sent : List Model.Envelope)
    (test : Message → Bool) : Bool :=
  sent.any fun e => !s.network.contains e && test e.payload

private theorem freshSend_iff (s : Model.State) (sent : List Model.Envelope)
    (test : Message → Bool) :
    freshSend s sent test = true ↔
      ∃ e ∈ sent, ¬ e ∈ s.network ∧ test e.payload = true := by
  simp [freshSend, List.any_eq_true]

private theorem pending_of_sent [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) {e : Model.Envelope} (h : e ∈ c.sent) : Pending (f.advance t) e := by
  change e ∈ t.network
  rw [c.tr.networkEq]
  exact List.mem_append_right _ h

private theorem reach43_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (e : Model.Envelope) :
    PinnedClasses.reach_43 f t c c e ↔
      Pending (f.advance t) e ∧ Bumping e.payload ∧ ¬ Pending f e := by
  constructor
  · rintro ⟨_, _, _, pending, bumps, fresh, _, rfl⟩
    exact ⟨pending, bumps, fun old => fresh ⟨old, bumps⟩⟩
  · rintro ⟨pending, bumps, fresh⟩
    exact ⟨c, rfl, e, pending, bumps, fun old => fresh old.1, rfl, rfl⟩

private def outgoing [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : List Model.Envelope := c.sent

/-- This generated path asks for a term-bearing outgoing envelope absent from the
entire pre-step queue, not merely absent from the retained queue after delivery. -/
public theorem message_terms_mem_network_inr_iff
    [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t) :
    PinnedClasses.sig c .message_terms_mem_network_inr ↔
      freshSend (FullProfile.current f) (outgoing c) bumping = true := by
  change PinnedClasses.step_message_terms_mem_network_inr f t c ↔ _
  rw [freshSend_iff]
  constructor
  · rintro ⟨w, pin, e, reach, sent, _, _⟩
    subst w
    obtain ⟨_, bumps, fresh⟩ := (reach43_iff c e).mp reach
    exact ⟨e, sent, fresh, (bumping_iff _).mpr bumps⟩
  · rintro ⟨e, sent, fresh, bumps⟩
    have pending := pending_of_sent c sent
    have bumps := (bumping_iff _).mp bumps
    exact ⟨c, rfl, e, (reach43_iff c e).mpr ⟨pending, bumps, fresh⟩, sent, pending, bumps⟩

private theorem reach25_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (e : Model.Envelope) :
    PinnedClasses.reach_25 f t c c e ↔ Pending (f.advance t) e ∧ ¬ Pending f e := by
  constructor
  · rintro ⟨_, _, _, pending, fresh, _, rfl⟩
    exact ⟨pending, fresh⟩
  · rintro ⟨pending, fresh⟩
    exact ⟨c, rfl, e, pending, fresh, rfl, rfl⟩

private theorem reach26_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (e : Model.Envelope) :
    PinnedClasses.reach_26 f t c c e ↔ e ∈ c.sent ∧ ¬ Pending f e := by
  constructor
  · rintro ⟨w, pin, _, reach, sent, _, _, rfl⟩
    subst w
    exact ⟨sent, ((reach25_iff c e).mp reach).2⟩
  · rintro ⟨sent, fresh⟩
    have pending := pending_of_sent c sent
    exact ⟨c, rfl, e, (reach25_iff c e).mpr ⟨pending, fresh⟩, sent, pending, rfl, rfl⟩

private theorem messages_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    PinnedClasses.sig c .messages_mem_network_inr ↔
      freshSend f.current c.sent (fun _ => true) = true := by
  change PinnedClasses.step_messages_mem_network_inr f t c ↔ _
  rw [freshSend_iff]
  constructor
  · rintro ⟨w, pin, e, reach, sent, _⟩
    subst w
    exact ⟨e, sent, ((reach25_iff c e).mp reach).2, rfl⟩
  · rintro ⟨e, sent, fresh, _⟩
    have pending := pending_of_sent c sent
    exact ⟨c, rfl, e, (reach25_iff c e).mpr ⟨pending, fresh⟩, sent, pending⟩

public inductive MessageKind where
  | appendEntriesRequest | appendEntriesResponse | requestVoteRequest | requestVoteResponse
  | requestPreVoteRequest | requestPreVoteResponse | proposeRequestVoteRequest
  deriving DecidableEq, BEq, Repr

private def messageKind : Message → MessageKind
  | .appendEntriesRequest _ => .appendEntriesRequest
  | .appendEntriesResponse _ => .appendEntriesResponse
  | .requestVoteRequest _ => .requestVoteRequest
  | .requestVoteResponse _ => .requestVoteResponse
  | .requestPreVoteRequest _ => .requestPreVoteRequest
  | .requestPreVoteResponse _ => .requestPreVoteResponse
  | .proposeRequestVoteRequest _ => .proposeRequestVoteRequest

private def MessageKind.Arg : MessageKind → Type
  | .appendEntriesRequest => AppendEntriesRequest
  | .appendEntriesResponse => AppendEntriesResponse
  | .requestVoteRequest | .requestPreVoteRequest => RequestVoteRequest
  | .requestVoteResponse | .requestPreVoteResponse => RequestVoteResponse
  | .proposeRequestVoteRequest => Nat

private def MessageKind.make (k : MessageKind) : k.Arg → Message :=
  match k with
  | .appendEntriesRequest => .appendEntriesRequest
  | .appendEntriesResponse => .appendEntriesResponse
  | .requestVoteRequest => .requestVoteRequest
  | .requestVoteResponse => .requestVoteResponse
  | .requestPreVoteRequest => .requestPreVoteRequest
  | .requestPreVoteResponse => .requestPreVoteResponse
  | .proposeRequestVoteRequest => .proposeRequestVoteRequest

private def hasKind (k : MessageKind) (m : Message) : Bool := decide (messageKind m = k)

private theorem hasKind_iff (k : MessageKind) (m : Message) :
    hasKind k m = true ↔ ∃ a : k.Arg, m = k.make a := by
  cases k <;> cases m <;> simp [hasKind, messageKind, MessageKind.make, MessageKind.Arg]

private theorem sent_kind_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : MessageKind) :
    (∃ w : Ctx f t, w = c ∧ ∃ e : Model.Envelope,
      PinnedClasses.reach_26 f t c w e ∧ SendOK w.actor w.pre w.event w.post e ∧
        ∃ a : k.Arg, e.payload = k.make a ∧ e.payload = k.make a ∧ e ∈ w.sent) ↔
    freshSend f.current c.sent (hasKind k) = true := by
  rw [freshSend_iff]
  constructor
  · rintro ⟨w, pin, e, reach, _, a, eq, _, sent⟩
    subst w
    exact ⟨e, sent, ((reach26_iff c e).mp reach).2, (hasKind_iff _ _).mpr ⟨a, eq⟩⟩
  · rintro ⟨e, sent, fresh, tag⟩
    obtain ⟨a, eq⟩ := (hasKind_iff _ _).mp tag
    exact ⟨c, rfl, e, (reach26_iff c e).mpr ⟨sent, fresh⟩, Summary.sends c.sum e sent,
      a, eq, eq, sent⟩

private theorem term_kind_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : MessageKind) (bumps : ∀ a : k.Arg, Bumping (k.make a)) :
    (∃ w : Ctx f t, w = c ∧ ∃ e : Model.Envelope,
      PinnedClasses.reach_43 f t c w e ∧ e ∈ w.sent ∧ SendOK w.actor w.pre w.event w.post e ∧
        ∃ a : k.Arg, e.payload = k.make a ∧ e.payload = k.make a ∧
          Pending (f.advance t) e ∧ Bumping e.payload ∧ 2 ≤ w.post.currentTerm) ↔
    freshSend f.current c.sent (hasKind k) = true := by
  rw [freshSend_iff]
  constructor
  · rintro ⟨w, pin, e, reach, sent, _, a, eq, _⟩
    subst w
    exact ⟨e, sent, ((reach43_iff c e).mp reach).2.2, (hasKind_iff _ _).mpr ⟨a, eq⟩⟩
  · rintro ⟨e, sent, fresh, tag⟩
    obtain ⟨a, eq⟩ := (hasKind_iff _ _).mp tag
    have pending := pending_of_sent c sent
    have bump : Bumping e.payload := eq ▸ bumps a
    exact ⟨c, rfl, e, (reach43_iff c e).mpr ⟨pending, bump, fresh⟩, sent, Summary.sends c.sum e sent,
      a, eq, eq, pending, bump, c.post_two (.inr ⟨e, sent, bump⟩)⟩

private def sentBranch : MessageKind → Classes.StepBranch
  | .appendEntriesRequest => .new_message_h_appendEntriesRequest
  | .appendEntriesResponse => .new_message_h_appendEntriesResponse
  | .requestVoteRequest => .new_message_h_requestVoteRequest
  | .requestVoteResponse => .new_message_h_requestVoteResponse
  | .requestPreVoteRequest => .new_message_h_requestPreVoteRequest
  | .requestPreVoteResponse => .new_message_h_requestPreVoteResponse
  | .proposeRequestVoteRequest => .new_message_h_proposeRequestVoteRequest

private theorem sent_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : MessageKind) :
    PinnedClasses.sig c (sentBranch k) ↔ freshSend f.current c.sent (hasKind k) = true := by
  have normalized (k : MessageKind) := sent_kind_iff c k
  simp only [SendOK, and_assoc] at normalized
  cases k with
  | appendEntriesRequest => exact normalized .appendEntriesRequest
  | appendEntriesResponse => exact normalized .appendEntriesResponse
  | requestVoteRequest => exact normalized .requestVoteRequest
  | requestVoteResponse => exact normalized .requestVoteResponse
  | requestPreVoteRequest => exact normalized .requestPreVoteRequest
  | requestPreVoteResponse => exact normalized .requestPreVoteResponse
  | proposeRequestVoteRequest => exact normalized .proposeRequestVoteRequest

public inductive TermKind where
  | appendEntriesRequest | requestVoteRequest | requestVoteResponse
  | requestPreVoteRequest | requestPreVoteResponse
  deriving DecidableEq, Repr

private def TermKind.message : TermKind → MessageKind
  | .appendEntriesRequest => .appendEntriesRequest
  | .requestVoteRequest => .requestVoteRequest
  | .requestVoteResponse => .requestVoteResponse
  | .requestPreVoteRequest => .requestPreVoteRequest
  | .requestPreVoteResponse => .requestPreVoteResponse

private def termBranch : TermKind → Classes.StepBranch
  | .appendEntriesRequest => .message_terms_h_appendEntriesRequest
  | .requestVoteRequest => .message_terms_h_requestVoteRequest
  | .requestVoteResponse => .message_terms_h_requestVoteResponse
  | .requestPreVoteRequest => .message_terms_h_requestPreVoteRequest
  | .requestPreVoteResponse => .message_terms_h_requestPreVoteResponse

private theorem term_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : TermKind) :
    PinnedClasses.sig c (termBranch k) ↔
      freshSend f.current c.sent (hasKind k.message) = true := by
  have bumps (k : TermKind) (a : k.message.Arg) : Bumping (k.message.make a) := by
    cases k <;> exact trivial
  have normalized (k : TermKind) := term_kind_iff c k.message (bumps k)
  simp only [SendOK, and_assoc] at normalized
  cases k with
  | appendEntriesRequest => exact normalized .appendEntriesRequest
  | requestVoteRequest => exact normalized .requestVoteRequest
  | requestVoteResponse => exact normalized .requestVoteResponse
  | requestPreVoteRequest => exact normalized .requestPreVoteRequest
  | requestPreVoteResponse => exact normalized .requestPreVoteResponse

private theorem reach1002_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (e : Model.Envelope) :
    PinnedClasses.reach_1002 f t c c.tr e ↔ Pending (f.advance t) e ∧ ¬ Pending f e := by
  constructor
  · rintro ⟨w, pin, e', reach, _, _, rfl⟩
    subst w
    exact (reach25_iff c e).mp reach
  · intro h
    exact ⟨c, rfl, e, (reach25_iff c e).mpr h, h.1, rfl, rfl⟩

private theorem reach1003_imp [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (e : Model.Envelope) :
    PinnedClasses.reach_1003 f t c c.tr e → Pending (f.advance t) e ∧ ¬ Pending f e := by
  rintro ⟨w, pin, e', reach, _, _, _, rfl⟩
  subst w
  obtain ⟨pending, _, fresh⟩ := (reach43_iff c e).mp reach
  exact ⟨pending, fresh⟩

private theorem old_append_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) : PinnedClasses.sig c .mem_network_mem_append_inl ↔ False := by
  change PinnedClasses.step_mem_network_mem_append_inl f t c ↔ False
  refine ⟨?_, False.elim⟩
  rintro (⟨w, pin, e, reach, retained, _⟩ | ⟨w, pin, e, reach, retained, _⟩) <;> subst w
  · exact ((reach1002_iff c e).mp reach).2 (c.tr.pendingSub e retained)
  · exact (reach1003_imp c e reach).2 (c.tr.pendingSub e retained)

private theorem new_append_iff [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) :
    PinnedClasses.sig c .mem_network_mem_append_inr ↔
      freshSend f.current c.sent (fun _ => true) = true := by
  change PinnedClasses.step_mem_network_mem_append_inr f t c ↔ _
  rw [freshSend_iff]
  constructor
  · rintro (⟨w, pin, e, reach, sent, _⟩ | ⟨w, pin, e, reach, sent, _⟩) <;> subst w
    · exact ⟨e, sent, ((reach1002_iff c e).mp reach).2, rfl⟩
    · exact ⟨e, sent, (reach1003_imp c e reach).2, rfl⟩
  · rintro ⟨e, sent, fresh, _⟩
    have pending := pending_of_sent c sent
    exact .inl ⟨c.tr, rfl, e, (reach1002_iff c e).mpr ⟨pending, fresh⟩, sent, pending⟩

private theorem freshSend_eq [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (test : Message → Bool) :
    freshSend f.current c.sent test = freshSend f.current t.network test := by
  apply Bool.eq_iff_iff.mpr
  simp only [freshSend_iff]
  constructor
  · rintro ⟨e, sent, fresh, yes⟩
    exact ⟨e, pending_of_sent c sent, fresh, yes⟩
  · rintro ⟨e, pending, fresh, yes⟩
    rcases c.tr.mem_network pending with old | sent
    · exact (fresh old).elim
    · exact ⟨e, sent, fresh, yes⟩

public inductive Column where
  | message | bumping | sentKind (k : MessageKind) | termKind (k : TermKind)
  | retained | outgoing
  deriving DecidableEq, Repr

@[expose] public def Column.branch : Column → Classes.StepBranch
  | .message => .messages_mem_network_inr
  | .bumping => .message_terms_mem_network_inr
  | .sentKind k => sentBranch k
  | .termKind k => termBranch k
  | .retained => .mem_network_mem_append_inl
  | .outgoing => .mem_network_mem_append_inr

/-- On a successful reachable step, read the covered column using only the two
snapshots; neither the chosen context nor a replay of the action is needed. -/
@[expose] public def answer (before after : Model.State) : Column → Bool
  | .message | .outgoing => freshSend before after.network (fun _ => true)
  | .bumping => freshSend before after.network bumping
  | .sentKind k => freshSend before after.network (hasKind k)
  | .termKind k => freshSend before after.network (hasKind k.message)
  | .retained => false

public theorem context_correct [Config.InitialConfiguration] {f : Frame} {t : Model.State}
    (c : Ctx f t) (k : Column) :
    answer (FullProfile.current f) t k = true ↔ PinnedClasses.sig c k.branch := by
  cases k with
  | message => exact ((messages_iff c).trans (Bool.eq_iff_iff.mp (freshSend_eq c _))).symm
  | bumping =>
    exact ((message_terms_mem_network_inr_iff c).trans (Bool.eq_iff_iff.mp (freshSend_eq c _))).symm
  | sentKind k => exact ((sent_iff c k).trans (Bool.eq_iff_iff.mp (freshSend_eq c _))).symm
  | termKind k => exact ((term_iff c k).trans (Bool.eq_iff_iff.mp (freshSend_eq c _))).symm
  | retained => simpa [answer, Column.branch] using (old_append_iff c).symm
  | outgoing => exact ((new_append_iff c).trans (Bool.eq_iff_iff.mp (freshSend_eq c _))).symm

public theorem answer_iff (s : ActionProfile.Step) (k : Column) :
    answer s.before s.after k = true ↔ ActionProfile.holds s (.step k.branch) := by
  have h := @context_correct ⟨s.cfg⟩ s.frame s.after s.context k
  rw [s.current_eq] at h
  exact h

public theorem answer_eq (s : ActionProfile.Step) (k : Column) :
    answer s.before s.after k = ActionProfile.label s (.step k.branch) :=
  Bool.eq_iff_iff.mpr ((answer_iff s k).trans (ActionProfile.label_true s _).symm)

@[expose] public def columns : List Column :=
  [.message, .bumping, .retained, .outgoing] ++
  [.appendEntriesRequest, .appendEntriesResponse, .requestVoteRequest, .requestVoteResponse,
    .requestPreVoteRequest, .requestPreVoteResponse, .proposeRequestVoteRequest].map .sentKind ++
  [.appendEntriesRequest, .requestVoteRequest, .requestVoteResponse,
    .requestPreVoteRequest, .requestPreVoteResponse].map .termKind

/-- The literal generated `StepBranch` table, not a count of rows or outcomes. -/
@[expose] public def covered : List Classes.StepBranch := columns.map Column.branch

public theorem covered_count : covered.Nodup ∧ covered.length = 16 := by decide

public theorem mem_covered_iff (b : Classes.StepBranch) :
    b ∈ covered ↔ ∃ k : Column, k.branch = b := by
  have all (k : Column) : k ∈ columns := by
    cases k <;> first | decide | (rename_i k; cases k <;> decide)
  simp only [covered, List.mem_map]
  exact ⟨fun ⟨k, _, eq⟩ => ⟨k, eq⟩, fun ⟨k, eq⟩ => ⟨k, all k, eq⟩⟩

/-- Lookup by generated branch; `none` is unsupported, not a negative answer. -/
@[expose] public def read? (before after : Model.State) (b : Classes.StepBranch) : Option Bool :=
  (columns.find? fun k => decide (k.branch = b)).map (answer before after)

public theorem read?_correct (s : ActionProfile.Step) (b : Classes.StepBranch) (value : Bool) :
    read? s.before s.after b = some value ↔
      b ∈ covered ∧ value = ActionProfile.label s (.step b) := by
  unfold read?
  cases h : columns.find? (fun k => decide (k.branch = b)) with
  | none =>
    have notCovered : b ∉ covered := by
      intro coveredB
      obtain ⟨k, mem, eq⟩ := List.mem_map.mp (show b ∈ columns.map Column.branch from coveredB)
      have no := List.find?_eq_none.mp h k mem
      simp [eq] at no
    simp [notCovered]
  | some k =>
    have eq : k.branch = b :=
      of_decide_eq_true (List.find?_some (p := fun j : Column => decide (j.branch = b)) h)
    subst b
    have mem : k.branch ∈ covered := (mem_covered_iff _).mpr ⟨k, rfl⟩
    simp only [Option.map_some, answer_eq, Option.some.injEq, mem, true_and, eq_comm]

private def heartbeatReplay : Option (List (List Classes.StepBranch)) := do
  let cfg : CCF.Finset NodeID := {0, 1}
  let nodes := [0, 1]
  let first : Model.State := { nodes := nodes.map fun n => (n, initialNodeState cfg n) }
  let send : Model.Action := .local 0 (.sendEntries 1 0)
  let once ← (transitionSystem cfg nodes).step first send
  let e ← once.network.head?
  let twice ← (transitionSystem cfg nodes).step once send
  guard (twice.network == [e, e])
  let reply ← (transitionSystem cfg nodes).step twice (.deliver e)
  return [(first, once), (once, twice), (twice, reply)].map fun (s, t) =>
    covered.filter fun b => read? s t b == some true

-- Evaluate the actual model steps: fresh request, equal duplicate, fresh (non-bumping) reply.
private theorem heartbeatReplay_check : heartbeatReplay = some [
    [.messages_mem_network_inr, .message_terms_mem_network_inr, .mem_network_mem_append_inr,
      .new_message_h_appendEntriesRequest, .message_terms_h_appendEntriesRequest],
    [],
    [.messages_mem_network_inr, .mem_network_mem_append_inr, .new_message_h_appendEntriesResponse]] := by
  decide +kernel

end ConsensusCoverage.ReducedQuestions
