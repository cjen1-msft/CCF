from abc import abstractmethod, ABC
from dataclasses import dataclass
import datetime
import heapq
import json
import re
import sys


@dataclass
class LogEntry:
    timestamp: int
    message: str
    node_id: str | None
    metadata: dict


_EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)


def _iso_to_ns(ts_str: str) -> int:
    dt = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc
    )
    delta = dt - _EPOCH
    return (
        (delta.days * 86_400 + delta.seconds) * 1_000_000_000
        + delta.microseconds * 1000
    )


class LogSource(ABC):
    @abstractmethod
    def peek(self):
        pass

    @abstractmethod
    def pop(self):
        pass

    @abstractmethod
    def init(self):
        pass

    def __iter__(self):
        return self

    def __next__(self):
        entry = self.pop()
        if entry is None:
            raise StopIteration
        return entry

# CCF log lines start with a timestamp, followed by the thread id, then the log level (and optional tag) and the source file:line, then `|` and the message.
# 2026-04-22T13:29:42.194497Z 0   [info ] CCF/src/node/node_state.h:993        | Created new node n[6341e43002bc2e3fcaa9ff5f314ed0dc14ba5db2a618e5eb2135aa77b766b619]
CcfTtyRegex = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z)"
    r"\s+(?P<thread_id>\d+)"
    r"\s+\[(?P<level>[a-z]+)\s*\]"
    r"(?:\[(?P<tag>[^\]]*)\])?"
    r"\s*(?P<file>[^\s:]+):(?P<line>\d+)\s*"
    r"\|\s?(?P<message>.*)$"
)
# The node id is encoded in the body of the "Created (new|join|recovery) node"
# log line emitted at startup by src/node/node_state.h.
CcfTtyRegexNodeId = re.compile(
    r"Created (?:new|join|recovery) node n\[(?P<node_id>[0-9a-f]{64})\]"
)

class ParsingError(Exception):
    def __init__(self, msg, lineno, filepath):
        self.msg = msg
        self.lineno = lineno
        self.filepath = filepath
        super().__init__(f"{filepath}:{lineno}: {msg}")

class CCFTTYLogSource(LogSource):
    def __init__(self, log_file):
        self.log_file = log_file
        self.node_id = self._node_id(log_file)
        self._file = None
        self.init()

    def init(self):
        if self._file is not None:
            self._file.close()
        self._file = open(self.log_file, "r")
        self.lineno = 0
        self._unparsed_but_read = []
        self._next_entry = None
        self.eof = False

    @staticmethod
    def _node_id(log_file):
        with open(log_file, "r") as f:
            for line in f:
                m = CcfTtyRegexNodeId.search(line)
                if m:
                    return m['node_id']

    def _read_one_entry(self):
        entry = LogEntry(0, [], self.node_id, {})
        read_at_least_one = False
        while True:
            if len(self._unparsed_but_read) > 0:
                line = self._unparsed_but_read.pop(0)
            else:
                if self.eof:
                    return None
                line = self._file.readline()
                self.lineno += 1

            if not line:
                self.eof = True
                return entry

            m = CcfTtyRegex.match(line)

            # won't match if multiline entry
            if m is None:
                entry.message.append(line)
            else:
              if read_at_least_one:
                  # This header line belongs to the *next* entry; push it back
                  # without consuming it into the current entry's message.
                  self._unparsed_but_read.append(line)
                  return entry

              entry.message.append(m["message"])
              entry.timestamp = _iso_to_ns(m["timestamp"])

            read_at_least_one = True

    def peek(self):
        if self._next_entry is None:
            self._next_entry = self._read_one_entry()
        return self._next_entry

    def pop(self):
        entry = self.peek()
        self._next_entry = None
        return entry


class MergeTimeSource(LogSource):
    def __init__(self, tagged_log_sources: dict[str, LogSource], tag_key: str):
        self.sources: dict[str, LogSource] = tagged_log_sources
        self.tag_key = tag_key

        self.ordered_sources = None

    def init(self):
        for source in self.sources.values():
            source.init()
        self.ordered_sources = None

    def _init_ordered_sources(self):
        self.ordered_sources = [
            (source.peek().timestamp, tag, source)
            for tag, source in self.sources.items()
            if source.peek() is not None
        ]
        heapq.heapify(self.ordered_sources)

    def peek(self):
        if self.ordered_sources is None:
            self._init_ordered_sources()

        if not self.ordered_sources:
            return None

        _, tag, source = self.ordered_sources[0]
        entry = source.peek()
        entry.metadata[self.tag_key] = tag
        return entry

    def pop(self):
        if self.ordered_sources is None:
            self._init_ordered_sources()

        if not self.ordered_sources:
            return None

        timestamp, tag, source = heapq.heappop(self.ordered_sources)
        entry = source.pop()
        entry.metadata[self.tag_key] = tag

        if source.peek() is not None:
            heapq.heappush(self.ordered_sources, (source.peek().timestamp, tag, source))

        return entry

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <log_file> [<log_file> ...]", file=sys.stderr)
        sys.exit(1)

    log_sources = {path: CCFTTYLogSource(path) for path in sys.argv[1:]}
    merged = MergeTimeSource(log_sources, "path")
    for entry in merged:
        message = "\n".join(entry.message)
        print(
            f"{entry.timestamp}:{None if entry.node_id is None else entry.node_id[0:8]}:{json.dumps(entry.metadata)} "
            f"{json.dumps(message)}"
        )