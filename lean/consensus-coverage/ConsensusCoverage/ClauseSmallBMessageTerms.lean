module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseSmallB
import all ConsensusCoverage.ClauseMatchAck
import all ConsensusCoverage.ClauseQuestions
import all ConsensusCoverage.EventSupport
import all ConsensusCoverage.ReducedQuestions
import all ConsensusCoverage.ReadersTotal
import all ConsensusCoverage.SolvedWitnesses
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

private theorem receive_install_exclusive (s : Step)
    (receive : bit s .post_two_active_inr_inr_inl = true) :
    bit s .post_two_active_inr_inr_inr = false := by
  letI : Config.InitialConfiguration := ⟨s.cfg⟩
  have yes := EventSupport.sig_support s.context _ ((label_true s _).mp receive)
  apply EventSupport.label_false
  have disjoint (tag : EventSupport.Tag) :
      tag ∈ EventSupport.allowed .post_two_active_inr_inr_inl →
      tag ∉ EventSupport.allowed .post_two_active_inr_inr_inr := by
    cases tag <;> decide +kernel
  rw [← (s.context_eq s.context).mpr rfl]
  exact disjoint _ yes

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

public def upperPatterns : List (List Bool) :=
  termChoices.flatMap fun terms =>
  booleans.flatMap fun active =>
  booleans.flatMap fun high =>
  booleans.flatMap fun recv =>
  booleans.flatMap fun install =>
  booleans.flatMap fun bootstrap =>
  booleans.flatMap fun elected =>
  booleans.flatMap fun outgoing =>
    if (!active || high) && (!recv || !install) &&
      (!(terms.any id) || (outgoing && (high || recv || install))) then
      [pack terms active high recv install bootstrap elected outgoing]
    else []

public theorem patterns_complete (s : Step) : (nonTrunkLabel .message_terms s).bits ∈ upperPatterns := by
  rw [shape]
  unfold upperPatterns
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
  have disjoint := receive_install_exclusive s
  have outgoing := (queue s).2.1
  rw [(queue s).1] at outgoing
  have reason := term_has_reason s
  have valid :
      ((!bit s .post_two_active_inl || bit s .post_two_active_inr_inl) &&
      (!bit s .post_two_active_inr_inr_inl || !bit s .post_two_active_inr_inr_inr) &&
      (!((termAnswers s).any id) || (bit s .mem_network_mem_append_inr &&
        (bit s .post_two_active_inr_inl || bit s .post_two_active_inr_inr_inl ||
          bit s .post_two_active_inr_inr_inr)))) = true := by
    simp only [Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true', ← Bool.not_eq_true] at *
    grind only
  rw [ite_eq_left valid]
  exact List.mem_cons_self

public def upperRows : List RestrictedProfile :=
  endpointRows.flatMap fun e => upperPatterns.map (row e)

public theorem complete (s : Step) : nonTrunkLabel .message_terms s ∈ upperRows :=
  List.mem_flatMap.mpr ⟨_, endpoints_mem s, List.mem_map_of_mem (patterns_complete s)⟩

public theorem upper_counts : upperPatterns.length = 1064 ∧ upperRows.length = 6384 := by
  decide +kernel

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
    (row (z, z) (bits "00000011100000"), 35, 9)]

public def rows : List RestrictedProfile := picks.map Prod.fst

public def patterns : List (List Bool) := patternsOf rows

public def unresolvedRows : List RestrictedProfile := unresolved upperRows rows

public theorem covered_or_unresolved (s : Step) :
    nonTrunkLabel .message_terms s ∈ rows ∨ nonTrunkLabel .message_terms s ∈ unresolvedRows :=
  witnessed_or_unresolved (complete s)

public theorem counts : rows.Nodup ∧ rows.length = 42 ∧ patterns.Nodup ∧ patterns.length = 15 := by
  decide +kernel

private theorem picked : picks.all (checkPick .message_terms) = true :=
  all_split 14 (by decide +kernel) (all_split 14 (by decide +kernel) (by decide +kernel))

public theorem lower (r : RestrictedProfile) (mem : r ∈ rows) :
    ∃ s, nonTrunkLabel .message_terms s = r :=
  replay_picks (covered_of_check (by decide +kernel)) picked mem

public theorem patterns_lower (bs : List Bool) (mem : bs ∈ patterns) :
    ∃ s, (nonTrunkLabel .message_terms s).bits = bs :=
  pattern_witness lower mem

end ConsensusCoverage.ClauseSmallB.MessageTerms
