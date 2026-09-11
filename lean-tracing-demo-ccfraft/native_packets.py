# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Full packet sorts for arbitrary initial queues in the native-array prototype."""

PACKET_FIELDS = {
    "appendEntriesRequest": (
        ("term", "Int"),
        ("prevLogIndex", "Int"),
        ("prevLogTerm", "Int"),
        ("entries", "(Array Int Entry)"),
        ("entriesLength", "Int"),
        ("leaderCommit", "Int"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "appendEntriesResponse": (
        ("term", "Int"),
        ("success", "Bool"),
        ("lastLogIndex", "Int"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "requestVoteRequest": (
        ("term", "Int"),
        ("lastCommittableTerm", "Int"),
        ("lastCommittableIndex", "Int"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "requestVoteResponse": (
        ("term", "Int"),
        ("voteGranted", "Bool"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "requestPreVote": (
        ("term", "Int"),
        ("lastCommittableTerm", "Int"),
        ("lastCommittableIndex", "Int"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "requestPreVoteResponse": (
        ("term", "Int"),
        ("voteGranted", "Bool"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
    "proposeVoteRequest": (
        ("term", "Int"),
        ("source", "Node"),
        ("destination", "Node"),
    ),
}


def packet_declarations() -> list[str]:
    """Keep unknown initial packets unrestricted in kind, with natural live fields."""
    constructors, sources, terms, needs_source, domains = [], [], [], [], []
    for kind, fields in PACKET_FIELDS.items():
        constructors.append(
            f"(msg_{kind} "
            + " ".join(f"({kind}_{name} {sort})" for name, sort in fields)
            + ")"
        )
        pattern = f"(msg_{kind} {' '.join(name for name, _ in fields)})"
        sources.append(f"({pattern} source)")
        terms.append(f"({pattern} term)")
        needs_source.append(
            f"({pattern} {'true' if kind.endswith('Response') else 'false'})"
        )
        natural_fields = [f"(<= 0 {name})" for name, sort in fields if sort == "Int"]
        if kind == "appendEntriesRequest":
            natural_fields.append(
                "(forall ((i Int)) (=> (and (<= 0 i) (< i entriesLength)) "
                "(entryDomain (select entries i))))"
            )
        domains.append(f"({pattern} (and {' '.join(natural_fields)}))")
    return [
        f"(declare-datatype Packet ({' '.join(constructors)}))",
        f"(define-fun messageSource ((m Packet)) Node (match m ({' '.join(sources)})))",
        f"(define-fun messageTerm ((m Packet)) Int (match m ({' '.join(terms)})))",
        f"(define-fun messageNeedsSource ((m Packet)) Bool (match m ({' '.join(needs_source)})))",
        f"(define-fun messageDomain ((m Packet)) Bool (match m ({' '.join(domains)})))",
    ]
