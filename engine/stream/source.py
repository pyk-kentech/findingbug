from __future__ import annotations

from abc import ABC, abstractmethod
import gzip
import json
from pathlib import Path
import queue as queue_mod
import time
from typing import Any, Iterator

from engine.io.events import Event, normalize_event
from engine.noise.profile import BenignProfile
from engine.rules.schema import RuleSet


RawRecord = tuple[int, str]


class EventSource(ABC):
    @abstractmethod
    def __iter__(self) -> Iterator[Event]:
        raise NotImplementedError


class RawEventSource(ABC):
    @abstractmethod
    def __iter__(self) -> Iterator[RawRecord]:
        raise NotImplementedError


class RawStringPreFilter:
    """Cheap raw-line filter that runs before json.loads/CDR normalization."""

    GENERIC_LITERALS = {
        "read",
        "write",
        "execute",
        "connect",
        "spawn",
        "file",
        "proc",
        "process",
        "ip",
        "mem",
        "event",
        "subject",
        "object",
        "relation",
        "semantic_relations",
        "commandline",
        "image",
        "cdr",
        "true",
        "false",
    }

    def __init__(
        self,
        *,
        benign_markers: set[str] | None = None,
        threat_keywords: set[str] | None = None,
    ) -> None:
        self.benign_markers = {item.lower() for item in (benign_markers or set()) if isinstance(item, str) and item.strip()}
        self.threat_keywords = {item.lower() for item in (threat_keywords or set()) if isinstance(item, str) and item.strip()}

    @staticmethod
    def _collect_literals(value: Any) -> set[str]:
        out: set[str] = set()
        if isinstance(value, dict):
            for item in value.values():
                out |= RawStringPreFilter._collect_literals(item)
        elif isinstance(value, list):
            for item in value:
                out |= RawStringPreFilter._collect_literals(item)
        elif isinstance(value, str):
            text = value.strip().lower()
            if len(text) >= 3 and text not in RawStringPreFilter.GENERIC_LITERALS:
                out.add(text)
                if "/" in text:
                    parts = [part for part in text.replace("\\", "/").split("/") if part]
                    if parts:
                        out.add(parts[-1])
                if ":" in text:
                    rhs = text.split(":", 1)[1].strip()
                    if len(rhs) >= 3:
                        out.add(rhs)
        return out

    @staticmethod
    def _decode_profile_key(profile_key: str) -> dict[str, str] | None:
        try:
            payload = json.loads(profile_key)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        subject = payload.get("subject")
        relation = payload.get("relation")
        object_ = payload.get("object")
        if not all(isinstance(v, str) for v in (subject, relation, object_)):
            return None
        return {"subject": subject, "relation": relation, "object": object_}

    @staticmethod
    def _markers_from_profile(profile: BenignProfile | None) -> set[str]:
        if profile is None:
            return set()
        markers: set[str] = set()
        for key, metadata in profile.patterns.items():
            if not isinstance(metadata, dict):
                continue
            decoded = RawStringPreFilter._decode_profile_key(key)
            if not decoded:
                continue
            for field_name in ("subject", "object"):
                value = decoded[field_name]
                rhs = value.split(":", 1)[1] if ":" in value else value
                rhs = rhs.strip().lower()
                if len(rhs) >= 4:
                    markers.add(rhs)
                    if "/" in rhs:
                        parts = [part for part in rhs.replace("\\", "/").split("/") if part]
                        if parts:
                            markers.add(parts[-1])
        return markers

    @classmethod
    def from_ruleset(
        cls,
        ruleset: RuleSet,
        *,
        benign_profile: BenignProfile | None = None,
        extra_threat_keywords: set[str] | None = None,
    ) -> RawStringPreFilter:
        threat_keywords: set[str] = set(extra_threat_keywords or set())
        for rule in ruleset.rules:
            threat_keywords |= cls._collect_literals(rule.match_logic)
            threat_keywords |= cls._collect_literals(rule.event_predicate)
            threat_keywords |= cls._collect_literals(rule.entity_bindings)
            threat_keywords |= cls._collect_literals(rule.rule_id)
            threat_keywords |= cls._collect_literals(rule.name)
        return cls(
            benign_markers=cls._markers_from_profile(benign_profile),
            threat_keywords=threat_keywords,
        )

    def should_skip(self, line: str) -> bool:
        text = str(line or "").lower()
        if not text or not self.benign_markers:
            return False
        # DARPA TC / relational CDM records reference UUID-linked entities across records.
        # Raw substring filtering here can drop required causal context and cause false negatives.
        if "com.bbn.tc.schema.avro" in text or "\"datum\"" in text:
            return False
        if any(keyword in text for keyword in self.threat_keywords):
            return False
        return any(marker in text for marker in self.benign_markers)


def _normalize_raw_line(index: int, line: str) -> Event | None:
    raw = json.loads(line)
    if not isinstance(raw, dict):
        return None
    return normalize_event(raw, index)


class FileRawLineSource(RawEventSource):
    def __init__(
        self,
        path: str | Path,
        follow: bool = False,
        poll_interval_sec: float = 0.2,
        prefilter: RawStringPreFilter | None = None,
    ) -> None:
        self.path = Path(path)
        self.follow = bool(follow)
        self.poll_interval_sec = float(poll_interval_sec)
        self.prefilter = prefilter

    def __iter__(self) -> Iterator[RawRecord]:
        if self.follow and self.path.suffix.lower() == ".gz":
            raise ValueError("follow mode is not supported for .gz event sources")
        opener = gzip.open if self.path.suffix.lower() == ".gz" else Path.open
        with opener(self.path, "rt", encoding="utf-8") as f:
            index = 0
            while True:
                line = f.readline()
                if not line:
                    if self.follow:
                        time.sleep(self.poll_interval_sec)
                        continue
                    break
                line = line.strip()
                if not line:
                    continue
                if self.prefilter is not None and self.prefilter.should_skip(line):
                    continue
                index += 1
                yield index, line


class FileJsonlSource(EventSource):
    def __init__(
        self,
        path: str | Path,
        follow: bool = False,
        poll_interval_sec: float = 0.2,
        prefilter: RawStringPreFilter | None = None,
    ) -> None:
        self.raw_source = FileRawLineSource(
            path=path,
            follow=follow,
            poll_interval_sec=poll_interval_sec,
            prefilter=prefilter,
        )

    def __iter__(self) -> Iterator[Event]:
        for index, line in self.raw_source:
            event = _normalize_raw_line(index, line)
            if event is not None:
                yield event


class InMemoryQueueSource(EventSource):
    """
    In-memory streaming source for tests/local producers.

    The queue is expected to contain `Event` objects and optional `None` as a stop token.
    """

    def __init__(self, q: queue_mod.Queue[Event | None], timeout_sec: float = 0.5, stop_token: Event | None = None) -> None:
        self.q = q
        self.timeout_sec = float(timeout_sec)
        self.stop_token = stop_token

    def __iter__(self) -> Iterator[Event]:
        while True:
            try:
                item = self.q.get(timeout=self.timeout_sec)
            except queue_mod.Empty:
                break
            if item is self.stop_token:
                break
            if isinstance(item, Event):
                yield item


class DirectoryWatcherRawLineSource(RawEventSource):
    def __init__(
        self,
        directory: str | Path,
        pattern: str = "*.jsonl",
        poll_interval_sec: float = 0.5,
        start_at_end: bool = False,
        prefilter: RawStringPreFilter | None = None,
    ) -> None:
        self.directory = Path(directory)
        self.pattern = pattern
        self.poll_interval_sec = float(poll_interval_sec)
        self.start_at_end = bool(start_at_end)
        self.prefilter = prefilter

    def __iter__(self) -> Iterator[RawRecord]:
        file_offsets: dict[Path, int] = {}
        global_index = 0
        while True:
            files = sorted(self.directory.glob(self.pattern))
            for path in files:
                if not path.is_file():
                    continue
                size = path.stat().st_size
                if path not in file_offsets:
                    file_offsets[path] = size if self.start_at_end else 0
                if size < file_offsets[path]:
                    file_offsets[path] = 0
                with path.open("r", encoding="utf-8") as fh:
                    fh.seek(file_offsets[path])
                    while True:
                        line = fh.readline()
                        if not line:
                            break
                        file_offsets[path] = fh.tell()
                        line = line.strip()
                        if not line:
                            continue
                        if self.prefilter is not None and self.prefilter.should_skip(line):
                            continue
                        global_index += 1
                        yield global_index, line
            time.sleep(self.poll_interval_sec)


class DirectoryWatcherSource(EventSource):
    def __init__(
        self,
        directory: str | Path,
        pattern: str = "*.jsonl",
        poll_interval_sec: float = 0.5,
        start_at_end: bool = False,
        prefilter: RawStringPreFilter | None = None,
    ) -> None:
        self.raw_source = DirectoryWatcherRawLineSource(
            directory=directory,
            pattern=pattern,
            poll_interval_sec=poll_interval_sec,
            start_at_end=start_at_end,
            prefilter=prefilter,
        )

    def __iter__(self) -> Iterator[Event]:
        for index, line in self.raw_source:
            event = _normalize_raw_line(index, line)
            if event is not None:
                yield event


class KafkaSource(EventSource):
    def __init__(
        self,
        *,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        auto_offset_reset: str = "latest",
        poll_timeout_sec: float = 1.0,
        prefilter: RawStringPreFilter | None = None,
    ) -> None:
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self.poll_timeout_sec = float(poll_timeout_sec)
        self.prefilter = prefilter

    def __iter__(self) -> Iterator[Event]:
        try:
            from confluent_kafka import Consumer
        except ImportError as exc:
            raise RuntimeError("KafkaSource requires confluent-kafka (`pip install confluent-kafka`)") from exc

        consumer = Consumer(
            {
                "bootstrap.servers": self.bootstrap_servers,
                "group.id": self.group_id,
                "auto.offset.reset": self.auto_offset_reset,
                "enable.auto.commit": True,
            }
        )
        consumer.subscribe([self.topic])
        index = 0
        try:
            while True:
                message = consumer.poll(timeout=self.poll_timeout_sec)
                if message is None:
                    continue
                if message.error():
                    continue
                value = message.value()
                if value is None:
                    continue
                line = value.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                if self.prefilter is not None and self.prefilter.should_skip(line):
                    continue
                index += 1
                event = _normalize_raw_line(index, line)
                if event is not None:
                    yield event
        finally:
            consumer.close()
