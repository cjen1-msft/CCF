from abc import ABC, abstractmethod
from log_serialisation import LogEntry, LogSource


class PropertyViolation(Exception):
    pass


class StateMachine(ABC):
    def __init__(self, tag):
        self.tag = tag

    @abstractmethod
    def filter(self, entry: LogEntry) -> bool:
        pass

    @abstractmethod
    def init(self) -> None:
        pass

    @abstractmethod
    def try_advance(self, entry: LogEntry) -> None:
        pass

    @abstractmethod
    def finalise(self) -> None:
        pass

    def __eq__(self, other):
        return isinstance(other, StateMachine) and self.tag == other.tag

    def __hash__(self):
        return hash(self.tag)


class Generator(ABC):
    """Stateful spawner: consumes entries, emits StateMachine instances mid-stream.
    Must be deterministic and resettable via ``init()``
    """

    def __init__(self, tag: str):
        self.tag = tag

    @abstractmethod
    def try_spawn(self, entry: LogEntry) -> list[StateMachine]:
        pass

    @abstractmethod
    def init(self) -> None:
        pass


def evaluate_source(
    source: LogSource,
    sms: list[StateMachine],
    gens: list[Generator],
    accumulate=False,
    tag_filter: set[str] | None = None,
) -> tuple[
    set[StateMachine],
    set[StateMachine],
    dict[str, tuple[list[LogEntry], PropertyViolation | None]],
]:
    source.init()
    for p in sms:
        p.init()
    for g in gens:
        g.init()

    current: set[StateMachine] = set(sms)
    if tag_filter is not None:
        current = {sm for sm in current if sm.tag in tag_filter}
    failures: set[StateMachine] = set()
    accumulators: dict[str, tuple[list[LogEntry], PropertyViolation | None]] = {}
    for entry in source:
        for generator in gens:
            spawn = generator.try_spawn(entry)
            for sm in spawn:
                if tag_filter is None or sm.tag in tag_filter:
                    current.add(sm)

        for sm in list(current):
            if sm.filter(entry):
                if accumulate:
                    if sm.tag not in accumulators:
                        accumulators[sm.tag] = ([], None)
                    accumulators[sm.tag][0].append(entry)
                try:
                    sm.try_advance(entry)
                except PropertyViolation as e:
                    current.discard(sm)
                    failures.add(sm)
                    if accumulate:
                        accumulators[sm.tag] = (accumulators[sm.tag][0], e)

    for sm in list(current):
        try:
            sm.finalise()
        except PropertyViolation as e:
            current.discard(sm)
            failures.add(sm)
            if accumulate:
                if sm.tag not in accumulators:
                    accumulators[sm.tag] = ([], e)
                else:
                    accumulators[sm.tag] = (accumulators[sm.tag][0], e)

    return current, failures, accumulators


def evaluate(
    properties: list[StateMachine],
    source: LogSource,
    generators: list[Generator] | None = None,
) -> tuple[
    set[StateMachine],
    dict[StateMachine, tuple[list[LogEntry], PropertyViolation | None]],
    dict[StateMachine, list[LogEntry]],
]:
    generators = generators if generators is not None else []

    successes, failures, _ = evaluate_source(source, properties, generators)

    if len(failures) == 0:
        return successes, {}, {}

    _, repro_failures_set, accumulators = evaluate_source(
        source,
        properties,
        generators,
        accumulate=True,
        tag_filter={f.tag for f in failures},
    )

    repro_failures = {f: accumulators[f.tag] for f in repro_failures_set}
    non_repro_failures = {
        f: accumulators[f.tag][0]
        for f in failures
        if f not in repro_failures_set and f.tag in accumulators
    }

    return successes, repro_failures, non_repro_failures
