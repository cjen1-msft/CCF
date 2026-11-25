module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
public import ConsensusCoverage.ClauseSmallBMessageSend
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseSmallBMessageSend
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
import all ConsensusCoverage.StateCoverage
import all Consensus.Proofs.SafetyInvariant
meta import ConsensusCoverage.ReachPath

namespace ConsensusCoverage.ClauseSmallB.MessageTerms

open Consensus Consensus.Proofs Safety SolvedWitnesses
open ClauseQuestions ClauseExactTables ActionProfile

set_option maxHeartbeats 0
set_option maxRecDepth 8192
set_option Elab.async false

public theorem columns : nonTrunk .message_terms =
    [.message_terms_mem_network_inr, .message_terms_h_appendEntriesRequest,
      .message_terms_h_requestVoteRequest, .message_terms_h_requestVoteResponse,
      .message_terms_h_requestPreVoteRequest, .message_terms_h_requestPreVoteResponse,
      .post_two_active_inl, .post_two_active_inr_inl, .post_two_active_inr_inr_inl,
      .post_two_active_inr_inr_inr, .leader_floor_led_inl, .leader_floor_led_inr,
      .mem_network_mem_append_inl, .mem_network_mem_append_inr] := by
  decide +kernel

private noncomputable abbrev bit (s : Step) (tag : Classes.StepBranch) := label s (.step tag)

private def kinds : List ReducedQuestions.TermKind :=
  [.appendEntriesRequest, .requestVoteRequest, .requestVoteResponse,
    .requestPreVoteRequest, .requestPreVoteResponse]

private noncomputable def termAnswers (s : Step) : List Bool :=
  kinds.map fun k => bit s (ReducedQuestions.Column.termKind k).branch

private theorem queue (s : Step) :
    bit s .message_terms_mem_network_inr = (termAnswers s).any id ∧
      (bit s .message_terms_mem_network_inr = true → bit s .mem_network_mem_append_inr = true) ∧
      bit s .mem_network_mem_append_inl = false := by
  open ReducedQuestions in
  have a := answer_eq s .bumping
  open ReducedQuestions in
  have out := answer_eq s .outgoing
  open ReducedQuestions in
  have old := answer_eq s .retained
  change _ = bit s .message_terms_mem_network_inr at a
  change _ = bit s .mem_network_mem_append_inr at out
  change _ = bit s .mem_network_mem_append_inl at old
  constructor
  · rw [← a, termAnswers]
    simp only [List.any_map, Function.comp_def, id_eq, ← ReducedQuestions.answer_eq]
    apply Bool.eq_iff_iff.mpr
    simp only [ReducedQuestions.answer, ReducedQuestions.answerFrom, List.any_eq_true]
    constructor
    · rintro ⟨m, hm, yes⟩
      cases m
      case appendEntriesRequest => exact ⟨.appendEntriesRequest, by decide, _, hm, rfl⟩
      case appendEntriesResponse => cases yes
      case requestVoteRequest => exact ⟨.requestVoteRequest, by decide, _, hm, rfl⟩
      case requestVoteResponse => exact ⟨.requestVoteResponse, by decide, _, hm, rfl⟩
      case requestPreVoteRequest => exact ⟨.requestPreVoteRequest, by decide, _, hm, rfl⟩
      case requestPreVoteResponse => exact ⟨.requestPreVoteResponse, by decide, _, hm, rfl⟩
      case proposeRequestVoteRequest => cases yes
    · rintro ⟨k, _, m, hm, yes⟩
      exact ⟨m, hm, by
        cases k <;> cases m <;>
          simp_all [ReducedQuestions.bumping, ReducedQuestions.hasKind,
            ReducedQuestions.messageKind, ReducedQuestions.TermKind.message]⟩
  · rw [← a, ← out, ← old]
    simp only [ReducedQuestions.answer, ReducedQuestions.answerFrom]
    rw [List.any_eq_true, List.any_eq_true]
    exact ⟨fun ⟨m, hm, _⟩ => ⟨m, hm, rfl⟩, trivial⟩

private theorem engaged_implies_term (s : Step)
    (pre : bit s .post_two_active_inl = true) : bit s .post_two_active_inr_inl = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  apply (test _).mpr
  obtain ⟨gate, engaged, post, le⟩ | ⟨gate, engaged, post, le⟩ := (test _).mp pre
  · exact .inl ⟨gate, .inl (s.context.pre_two engaged), s.context.pre_two engaged, post, le⟩
  · exact .inr ⟨gate, .inl (s.context.pre_two engaged), s.context.pre_two engaged, post, le⟩

private theorem send_reason [Config.InitialConfiguration] {f t} (c : Ctx f t)
    (h : sig c .message_terms_h_appendEntriesRequest ∨ sig c .message_terms_h_requestVoteRequest ∨
      sig c .message_terms_h_requestVoteResponse ∨ sig c .message_terms_h_requestPreVoteRequest ∨
      sig c .message_terms_h_requestPreVoteResponse) :
    sig c .post_two_active_inr_inl ∨ sig c .post_two_active_inr_inr_inl ∨
      sig c .post_two_active_inr_inr_inr := by
  have source : (reach% step_post_two_active_inl[1]) f t c c ∧
      ∃ e, e ∈ c.sent ∧ Bumping e.payload := by
    rcases h with h | h | h | h | h
    all_goals
      obtain ⟨e, root, out, src, ok, payload, h, h', after_, bump, _⟩ := h
      refine ⟨?_, e, out, bump⟩
      repeat' first | exact ⟨e, root, out, src, ok, payload, h, h', after_, bump, rfl⟩ |
        exact Or.inl ⟨e, root, out, src, ok, payload, h, h', after_, bump, rfl⟩ | apply Or.inr
  obtain ⟨root, sent⟩ := source
  have active : Engaged c.post ∨ ∃ e, e ∈ c.sent ∧ Bumping e.payload := .inr sent
  obtain engaged | high | recv | install := Summary.active c.sum active
  · exact .inl (.inr ⟨root, .inl (c.pre_two engaged), c.pre_two engaged, active, c.term_le⟩)
  · exact .inl (.inr ⟨root, .inl high, high, active, c.term_le⟩)
  · obtain ⟨n, msg, ev, bump, bound⟩ := recv
    have recv := And.intro ev (And.intro bump bound)
    exact .inr (.inl (.inr ⟨root, .inr (.inl ⟨n, msg, recv⟩), .inl ⟨n, msg, recv⟩,
      ⟨n, msg, recv⟩, n, ⟨msg, recv⟩, msg, recv, ev, ⟨bump, bound⟩, bump, bound, active, c.term_le⟩))
  · obtain ⟨entries, ev, pos, signed, term⟩ := install
    have why := And.intro ev (And.intro pos (And.intro signed term))
    exact .inr (.inr (.inr ⟨root, .inr (.inr ⟨entries, why⟩), .inr ⟨entries, why⟩,
      ⟨entries, why⟩, entries, why, ev, why.2, pos, why.2.2, signed, term, active, c.term_le⟩))

private theorem term_has_reason (s : Step) (h : (termAnswers s).any id = true) :
    (bit s .post_two_active_inr_inl || bit s .post_two_active_inr_inr_inl ||
      bit s .post_two_active_inr_inr_inr) = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  simp only [termAnswers, kinds, List.map_cons, List.map_nil, List.any_cons, List.any_nil,
    id_eq, Bool.or_false, Bool.or_eq_true, ReducedQuestions.Column.branch, ReducedQuestions.termBranch, test] at h
  simp only [Bool.or_eq_true, test]
  grind only [send_reason]

private def pack (terms : List Bool) (active high recv install bootstrap elected outgoing : Bool) :
    List Bool :=
  [terms.any id] ++ terms ++ [active, high, recv, install, bootstrap, elected, false, outgoing]

private theorem shape (s : Step) : (nonTrunkLabel .message_terms s).bits =
    pack (termAnswers s) (bit s .post_two_active_inl) (bit s .post_two_active_inr_inl)
      (bit s .post_two_active_inr_inr_inl) (bit s .post_two_active_inr_inr_inr)
      (bit s .leader_floor_led_inl) (bit s .leader_floor_led_inr) (bit s .mem_network_mem_append_inr) := by
  rw [nonTrunkLabel, restrictedLabel, columns, pack, ← (queue s).1]
  simp only [termAnswers, kinds, List.map_cons, List.map_nil, List.cons_append, List.nil_append,
    (queue s).2.2, ReducedQuestions.Column.branch, ReducedQuestions.termBranch]

private def termChoices : List (List Bool) :=
  booleans.flatMap fun a => booleans.flatMap fun b => booleans.flatMap fun c =>
    booleans.flatMap fun d => booleans.map fun e => [a, b, c, d, e]

private theorem terms_mem (s : Step) : termAnswers s ∈ termChoices := by
  unfold termAnswers kinds termChoices
  simp only [List.map_cons, List.map_nil]
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .message_terms_h_appendEntriesRequest), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .message_terms_h_requestVoteRequest), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .message_terms_h_requestVoteResponse), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .message_terms_h_requestPreVoteRequest), ?_⟩
  exact List.mem_map.mpr ⟨_, bool_mem _, rfl⟩

private def termTag : ReducedQuestions.TermKind → EventSupport.Tag
  | .appendEntriesRequest => .appendEntriesRequest
  | .requestVoteRequest => .requestVoteRequest
  | .requestVoteResponse => .requestVoteResponse
  | .requestPreVoteRequest => .requestPreVoteRequest
  | .requestPreVoteResponse => .requestPreVoteResponse

private theorem term_payload (s : Step) (k : ReducedQuestions.TermKind)
    (yes : bit s (ReducedQuestions.Column.termKind k).branch = true) :
    ∃ m ∈ ReducedQuestions.freshPayloads s.before s.after.network,
      MessageSend.payloadTag m = termTag k := by
  have hit := (ReducedQuestions.answer_eq s (.termKind k)).trans yes
  simp only [ReducedQuestions.answer, ReducedQuestions.answerFrom, List.any_eq_true] at hit
  obtain ⟨m, mem, kind⟩ := hit
  refine ⟨m, mem, ?_⟩
  cases k <;> cases m <;>
    simp_all [ReducedQuestions.hasKind, ReducedQuestions.messageKind, ReducedQuestions.TermKind.message,
      MessageSend.payloadTag, EventSupport.actionTag, EventSupport.messageTag, termTag]

private theorem term_kind (s : Step) (k : ReducedQuestions.TermKind)
    (yes : bit s (ReducedQuestions.Column.termKind k).branch = true) :
    termTag k ∈ MessageSend.allowedOutput (EventSupport.actionTag s.act) := by
  obtain ⟨m, mem, key⟩ := term_payload s k yes
  rw [← key]
  exact MessageSend.fresh_kind s m mem

private def termsAllowed (tag : EventSupport.Tag) (answers : List Bool) : Bool :=
  (kinds.zip answers).all fun (k, hit) =>
    !hit || decide (termTag k ∈ MessageSend.allowedOutput tag)

private theorem terms_allowed (s : Step) :
    termsAllowed (EventSupport.actionTag s.act) (termAnswers s) = true := by
  apply List.all_eq_true.mpr
  rintro ⟨k, hit⟩ mem
  rw [termAnswers, List.zip_map_right, List.mem_map] at mem
  obtain ⟨⟨l, k'⟩, pair, eq⟩ := mem
  have same : l = k' := by
    simp [kinds, List.zip] at pair
    grind only
  subst k'
  cases eq
  change (!bit s (ReducedQuestions.Column.termKind l).branch || _) = true
  cases h : bit s (ReducedQuestions.Column.termKind l).branch
  · rfl
  · simp [term_kind s l h]

private theorem outgoing_without_terms (s : Step) (out : bit s .mem_network_mem_append_inr = true)
    (no : (termAnswers s).any id = false) :
    EventSupport.Tag.appendEntriesResponse ∈ MessageSend.allowedOutput (EventSupport.actionTag s.act) ∨
      EventSupport.Tag.proposeRequestVoteRequest ∈ MessageSend.allowedOutput (EventSupport.actionTag s.act) := by
  have send := ReducedQuestions.answer_eq s .outgoing
  change _ = bit s .mem_network_mem_append_inr at send
  rw [← send] at out
  simp only [ReducedQuestions.answer, ReducedQuestions.answerFrom, List.any_eq_true] at out
  obtain ⟨m, mem, _⟩ := out
  have allowed := MessageSend.fresh_kind s m mem
  have bump := ReducedQuestions.answer_eq s .bumping
  change _ = bit s .message_terms_mem_network_inr at bump
  rw [(queue s).1, no] at bump
  have neg : ¬ ReducedQuestions.bumping m = true := fun yes => by
    have hit : ReducedQuestions.answer s.before s.after .bumping = true :=
      List.any_eq_true.mpr ⟨m, mem, yes⟩
    exact Bool.noConfusion (bump.symm.trans hit)
  cases m <;> simp [ReducedQuestions.bumping] at neg
  · exact .inl allowed
  · exact .inr allowed

private theorem event_gate (s : Step) (q : Classes.StepBranch) (yes : bit s q = true) :
    EventSupport.actionTag s.act ∈ EventSupport.allowed q := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  rw [← (s.context_eq s.context).mpr rfl]
  exact EventSupport.sig_support s.context q ((label_true s (.step q)).mp yes)

private def bumpingInput : List EventSupport.Tag :=
  [.appendEntriesRequest, .requestVoteRequest, .requestVoteResponse, .requestPreVoteRequest,
    .requestPreVoteResponse]

private theorem receive_gate (s : Step) (h : bit s .post_two_active_inr_inr_inl = true) :
    EventSupport.actionTag s.act ∈ bumpingInput := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test := (label_true s (.step .post_two_active_inr_inr_inl)).trans (sig_iff s.context _)
  obtain ⟨_, _, _, ⟨n, m, ev, bump, _⟩, _⟩ | ⟨_, _, _, ⟨n, m, ev, bump, _⟩, _⟩ := test.mp h
  all_goals
    rw [← (s.context_eq s.context).mpr rfl, EventSupport.actionTag_eq]
    change EventSupport.eventTag s.context.event ∈ _
    rw [ev]
    cases m <;> simp_all [Bumping, EventSupport.eventTag, EventSupport.messageTag, bumpingInput]

private theorem high_no_install (s : Step) (h : bit s .post_two_active_inr_inl = true) :
    EventSupport.actionTag s.act ≠ .initAsBackup := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test := (label_true s (.step .post_two_active_inr_inl)).trans (sig_iff s.context _)
  intro tag
  have fresh := MessageSend.install_fresh s tag
  obtain ⟨_, _, high, _⟩ | ⟨_, _, high, _⟩ := test.mp h
  all_goals omega

private theorem timeout_not_mixed (s : Step) (tag : EventSupport.actionTag s.act = .timeout)
    (pre : bit s .message_terms_h_requestPreVoteRequest = true) :
    ¬ (bit s .message_terms_h_appendEntriesRequest = true ∨
      bit s .message_terms_h_requestVoteRequest = true) := by
  obtain first | second := MessageSend.timeout_mode s tag
  · obtain ⟨m, mem, hit⟩ := term_payload s .requestPreVoteRequest pre
    have pure_ := first m mem
    rw [hit] at pure_
    exact False.elim ((by decide +kernel :
      termTag .requestPreVoteRequest ∉ [EventSupport.Tag.appendEntriesRequest,
        .proposeRequestVoteRequest, .requestVoteRequest]) pure_)
  · rintro (ae | vote)
    · obtain ⟨m, mem, hit⟩ := term_payload s .appendEntriesRequest ae
      exact (by decide +kernel : termTag .appendEntriesRequest ≠ .requestPreVoteRequest)
        (hit.symm.trans (second m mem))
    · obtain ⟨m, mem, hit⟩ := term_payload s .requestVoteRequest vote
      exact (by decide +kernel : termTag .requestVoteRequest ≠ .requestPreVoteRequest)
        (hit.symm.trans (second m mem))

private def valid (tag : EventSupport.Tag) (terms : List Bool)
    (active high recv install outgoing : Bool) : Bool :=
  termsAllowed tag terms &&
    (!decide (tag = .timeout) || !terms[3]?.getD false ||
      !(terms[0]?.getD false || terms[1]?.getD false)) &&
    (!active || high) &&
    (!high || decide (tag ≠ .initAsBackup)) &&
    (!recv || decide (tag ∈ bumpingInput)) &&
    (!install || decide (tag ∈ EventSupport.allowed .post_two_active_inr_inr_inr)) &&
    (if terms.any id then outgoing && (high || recv || install) else
      !outgoing || decide (EventSupport.Tag.appendEntriesResponse ∈ MessageSend.allowedOutput tag ∨
        EventSupport.Tag.proposeRequestVoteRequest ∈ MessageSend.allowedOutput tag))

private def fiber (tag : EventSupport.Tag) : List (List Bool) :=
  termChoices.flatMap fun terms =>
  booleans.flatMap fun active =>
  booleans.flatMap fun high =>
  booleans.flatMap fun recv =>
  booleans.flatMap fun install =>
  booleans.flatMap fun bootstrap =>
  booleans.flatMap fun elected =>
  booleans.flatMap fun outgoing =>
    if valid tag terms active high recv install outgoing then
      [pack terms active high recv install bootstrap elected outgoing]
    else []

private def tags : List EventSupport.Tag := EventSupport.inputs ++ EventSupport.messages

private theorem tags_mem (t : EventSupport.Tag) : t ∈ tags := by cases t <;> decide +kernel

public def upperPatterns : List (List Bool) := (tags.flatMap fiber).eraseDups

public theorem patterns_complete (s : Step) : (nonTrunkLabel .message_terms s).bits ∈ upperPatterns := by
  rw [shape]
  unfold upperPatterns
  apply List.mem_eraseDups.mpr
  apply List.mem_flatMap.mpr
  refine ⟨_, tags_mem (EventSupport.actionTag s.act), ?_⟩
  unfold fiber
  apply List.mem_flatMap.mpr
  refine ⟨_, terms_mem s, ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .post_two_active_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .post_two_active_inr_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .post_two_active_inr_inr_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .post_two_active_inr_inr_inr), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .leader_floor_led_inl), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .leader_floor_led_inr), ?_⟩
  refine List.mem_flatMap.mpr ⟨_, bool_mem (bit s .mem_network_mem_append_inr), ?_⟩
  have active := engaged_implies_term s
  have outgoing := (queue s).2.1
  rw [(queue s).1] at outgoing
  have reason := term_has_reason s
  have good : valid (EventSupport.actionTag s.act) (termAnswers s)
      (bit s .post_two_active_inl) (bit s .post_two_active_inr_inl)
      (bit s .post_two_active_inr_inr_inl) (bit s .post_two_active_inr_inr_inr)
      (bit s .mem_network_mem_append_inr) = true := by
    have recv := receive_gate s
    have install := event_gate s .post_two_active_inr_inr_inr
    have high := high_no_install s
    have nobump := outgoing_without_terms s
    have mixed := timeout_not_mixed s
    have one : (!decide (EventSupport.actionTag s.act = .timeout) ||
        !(termAnswers s)[3]?.getD false ||
        !((termAnswers s)[0]?.getD false || (termAnswers s)[1]?.getD false)) = true := by
      change (!decide (EventSupport.actionTag s.act = .timeout) ||
        !bit s .message_terms_h_requestPreVoteRequest ||
        !(bit s .message_terms_h_appendEntriesRequest || bit s .message_terms_h_requestVoteRequest)) = true
      simp only [Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true, decide_eq_true_eq]
      grind only
    simp only [valid, terms_allowed, one, Bool.true_and, Bool.and_eq_true, Bool.or_eq_true,
      Bool.not_eq_true', ← Bool.not_eq_true, decide_eq_true_eq]
    split
    all_goals
      simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true] at *
      grind only
  rw [ite_eq_left good]
  exact List.mem_cons_self

section
variable [Config.InitialConfiguration] {f : Frame} {t : Model.State} (c : Ctx f t)

private abbrev HasBacking := ∃ k p, Committed (f.advance t) k p

private theorem install_backing {es} (ev : c.event = .internal (.initAsBackup es))
    (positive : 0 < es.length) (signed : Model.Node.isSignatureAt es es.length = true) :
    HasBacking (f := f) (t := t) := by
  obtain ⟨_, _, _, k, p, key, _⟩ := c.snap_available ev positive signed
  exact ⟨k, p, key.mono t⟩

private theorem floor_backing {n k}
    (root : (reach% step_leader_floor_led_inl[0]) f t c n k ∨
      (reach% step_leader_floor_led_inl[1]) f t c n k ∨
      (reach% step_leader_floor_led_inl[2]) f t c n k ∨
      (reach% step_leader_floor_led_inl[3]) f t c n k ∨
      (reach% step_leader_floor_led_inl[4]) f t c n k ∨
      (reach% step_leader_floor_led_inl[5]) f t c n k ∨
      (reach% step_leader_floor_led_inl[6]) f t c n k ∨
      (reach% step_leader_floor_led_inl[7]) f t c n k ∨
      (reach% step_leader_floor_led_inl[8]) f t c n k) :
    HasBacking (f := f) (t := t) := by
  rcases root with h | h | h | h | h | h | h | h | h
  all_goals repeat' (change _ ∨ _ at h; rcases h with h | h)
  all_goals
    first
    | obtain ⟨_, _, _, es, ev, positive, signed, _, _, _, _, _, _⟩ := h
      exact install_backing c (es := es) ev positive signed
    | obtain ⟨es, ev, positive, signed, _⟩ := h.2.2.2.1
      exact install_backing c (es := es) ev positive signed
    | obtain ⟨_, es, ev, positive, signed, _, _, _, _, _, _⟩ := h
      exact install_backing c (es := es) ev positive signed
    | obtain ⟨_, _, _, ⟨part, _, _, _, _, key, _⟩, _⟩ := h
      exact ⟨k, part, key.1⟩

private theorem floor_answer_backing
    (hit : sig c .leader_floor_led_inl ∨ sig c .leader_floor_led_inr) :
    HasBacking (f := f) (t := t) := by
  rcases hit with h | h
  · repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      apply floor_backing c (n := Config.INITIAL_PRIMARY) (k := Model.BOOTSTRAP_TERM)
      repeat' first | exact h.1 | exact Or.inl h.1 | apply Or.inr
  · repeat' (change _ ∨ _ at h; rcases h with h | h)
    all_goals
      obtain ⟨n, k, root, _⟩ := h
      apply floor_backing c (n := n) (k := k)
      repeat' first | exact root | exact Or.inl root | apply Or.inr

end

private theorem floor_after_backed (s : Step)
    (h : bit s .leader_floor_led_inl = true ∨ bit s .leader_floor_led_inr = true) :
    (endpoints s).2.2 = true := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have test (tag : Classes.StepBranch) := (label_true s (.step tag)).trans (sig_iff s.context tag)
  have backed := floor_answer_backing s.context (h.imp (test _).mp (test _).mp)
  apply (StateCoverage.read_iff s.after (s.before :: s.past) s.context.inv_step).2.mpr
  exact (StateCoverage.backed_iff _ s.context.inv_step).mpr
    ⟨List.ne_nil_of_mem s.context.post_now, backed⟩

public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e =>
    (upperPatterns.filter fun bs =>
      (!(bs[10]?.getD false || bs[11]?.getD false) || e.2.2)).map (row e)

public theorem complete (s : Step) : nonTrunkLabel .message_terms s ∈ upperRows := by
  change row (endpoints s) (nonTrunkLabel .message_terms s).bits ∈ upperRows
  refine List.mem_flatMap.mpr ⟨_, endpoints_mem s, List.mem_map_of_mem (List.mem_filter.mpr
    ⟨patterns_complete s, ?_⟩)⟩
  rw [shape]
  change (!(bit s .leader_floor_led_inl || bit s .leader_floor_led_inr) ||
    (endpoints s).2.2) = true
  have need := floor_after_backed s
  simp only [Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true]
  grind only

public theorem upper_counts : upperPatterns.Nodup ∧ upperPatterns.length = 160 ∧
    upperRows.length = 840 := by decide +kernel

private def picks : List Pick :=
  [(row (z, p) (bits "00000011000000"), 0, 0),
    (row (p, p) (bits "00000011000000"), 0, 1),
    (row (z, b) (bits "00000011000000"), 1, 0),
    (row (z, z) (bits "00000011000000"), 2, 0),
    (row (z, z) (bits "11000011000001"), 2, 1),
    (row (z, b) (bits "00000011100001"), 2, 2),
    (row (b, b) (bits "00000011000000"), 2, 3),
    (row (b, b) (bits "11000011000001"), 2, 4),
    (row (b, p) (bits "00000011100001"), 2, 5),
    (row (z, z) (bits "10001011000001"), 3, 2),
    (row (z, z) (bits "10000111100001"), 3, 3),
    (row (z, z) (bits "10100011100001"), 3, 4),
    (row (z, z) (bits "10010011100001"), 3, 5),
    (row (z, z) (bits "11000011100001"), 3, 6),
    (row (p, p) (bits "00000000000000"), 4, 6),
    (row (p, p) (bits "10001011000001"), 4, 8),
    (row (p, p) (bits "10000111100001"), 4, 9),
    (row (p, p) (bits "10100011100001"), 4, 10),
    (row (p, p) (bits "10010011100001"), 4, 11),
    (row (p, p) (bits "11000011100001"), 4, 12),
    (row (b, b) (bits "00000011100001"), 5, 5),
    (row (b, b) (bits "00000000000000"), 5, 6),
    (row (b, b) (bits "10001011000001"), 5, 8),
    (row (b, b) (bits "10000111100001"), 5, 9),
    (row (b, b) (bits "10100011100001"), 5, 10),
    (row (b, b) (bits "10010011100001"), 5, 11),
    (row (b, b) (bits "11000011100001"), 5, 12),
    (row (b, p) (bits "00000011000000"), 6, 15),
    (row (z, z) (bits "00000000000001"), 15, 0),
    (row (b, b) (bits "00000000000001"), 16, 3),
    (row (p, p) (bits "00000000000001"), 17, 6),
    (row (z, z) (bits "00000000000000"), 18, 1),
    (row (z, z) (bits "00000000100001"), 21, 1),
    (row (z, z) (bits "00000011100001"), 21, 4),
    (row (z, z) (bits "10100011000001"), 23, 15),
    (row (b, b) (bits "00000000100001"), 24, 3),
    (row (b, b) (bits "00000011100000"), 24, 10),
    (row (b, p) (bits "00000000011000"), 25, 2),
    (row (p, p) (bits "11000011000001"), 25, 5),
    (row (p, p) (bits "00000011100001"), 34, 6),
    (row (z, z) (bits "10010000100001"), 35, 7),
    (row (z, z) (bits "00000011100000"), 35, 9),
    (row (z, z) (bits "10000100100001"), 61, 7),
    (row (b, b) (bits "10000100100001"), 63, 15),
    (row (b, b) (bits "10100011000001"), 64, 14),
    (row (p, p) (bits "00000011100000"), 69, 9),
    (row (p, p) (bits "10100011000001"), 75, 7),
    (row (b, p) (bits "00000011100000"), 79, 11),
    (row (b, b) (bits "00000000011000"), 83, 8),
    (row (b, p) (bits "00000000000001"), 86, 15),
    (row (b, p) (bits "00000000010100"), 177, 12)]

public def rows : List RestrictedProfile := picks.map Prod.fst

public def patterns : List (List Bool) := patternsOf rows

public def unresolvedRows : List RestrictedProfile := unresolved upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .message_terms s ∈ rows ∨ nonTrunkLabel .message_terms s ∈ unresolvedRows :=
  witnessed_or_unresolved (complete s)

public theorem counts : rows.Nodup ∧ rows.length = 51 ∧ patterns.Nodup ∧ patterns.length = 17 := by
  decide +kernel

private theorem picked : picks.all (checkPick .message_terms) = true :=
  all_split 14 (by decide +kernel) (all_split 14 (by decide +kernel)
    (all_split 14 (by decide +kernel) (by decide +kernel)))

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .message_terms s = r :=
  replay_picks (covered_of_check (by decide +kernel)) picked mem

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .message_terms s).bits = bs :=
  pattern_witness lower mem

end ConsensusCoverage.ClauseSmallB.MessageTerms
