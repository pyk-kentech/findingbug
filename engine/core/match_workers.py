from __future__ import annotations

from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
import math
import time
from typing import Any

from engine.core.matcher import Matcher, TTPMatch
from engine.io.events import Event
from engine.noise.profile import BenignProfile
from engine.rules.schema import Rule

_WORKER_RULES: list[Rule] = []
_WORKER_BENIGN_PROFILE: BenignProfile | None = None


@dataclass(slots=True)
class MatchBatchResult:
    matches_by_event_id: dict[str, list[TTPMatch]]
    drop_telemetry_by_event_id: dict[str, list[dict[str, Any]]]
    benign_profile_drop_count_by_event_id: dict[str, int]
    elapsed_seconds: float


def _split_event_shards(events_batch: list[Event], worker_count: int) -> list[list[Event]]:
    if worker_count <= 1 or len(events_batch) <= 1:
        return [list(events_batch)]
    shard_size = max(1, math.ceil(len(events_batch) / worker_count))
    return [list(events_batch[idx:idx + shard_size]) for idx in range(0, len(events_batch), shard_size)]


def _init_worker(rules: list[Rule], benign_profile: BenignProfile | None) -> None:
    global _WORKER_RULES, _WORKER_BENIGN_PROFILE
    _WORKER_RULES = list(rules)
    _WORKER_BENIGN_PROFILE = benign_profile


def _match_worker_task(events_shard: list[Event]) -> tuple[list[TTPMatch], list[dict[str, Any]]]:
    matcher = Matcher()
    matcher.benign_profile = _WORKER_BENIGN_PROFILE
    matches = matcher.match_batch(graph=None, rules_subset=_WORKER_RULES, events_batch=events_shard)
    return matches, list(matcher.last_drop_telemetry)


class ParallelMatcherExecutor:
    def __init__(
        self,
        rules: list[Rule],
        worker_count: int,
        benign_profile: BenignProfile | None = None,
    ) -> None:
        self.rules = list(rules)
        self.worker_count = max(1, int(worker_count))
        self.benign_profile = benign_profile
        self._executor = (
            ProcessPoolExecutor(
                max_workers=self.worker_count,
                initializer=_init_worker,
                initargs=(self.rules, self.benign_profile),
            )
            if self.worker_count > 1 and len(self.rules) > 1
            else None
        )

    def close(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=True, cancel_futures=False)
            self._executor = None

    def match_events(self, events_batch: list[Event]) -> MatchBatchResult:
        started = time.perf_counter()
        matches_by_event_id: dict[str, list[TTPMatch]] = defaultdict(list)
        drop_telemetry_by_event_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
        benign_profile_drop_count_by_event_id: dict[str, int] = defaultdict(int)

        if not events_batch:
            return MatchBatchResult({}, {}, {}, 0.0)

        if self._executor is None:
            task_results = [_match_worker_task(events_batch)]
        else:
            event_shards = _split_event_shards(events_batch, self.worker_count)
            futures = [self._executor.submit(_match_worker_task, shard) for shard in event_shards]
            task_results = [future.result() for future in futures]

        for matches, telemetry_rows in task_results:
            for match in matches:
                if match.event_ids:
                    matches_by_event_id[match.event_ids[0]].append(match)
            for row in telemetry_rows:
                event_id = row.get("event_id")
                if isinstance(event_id, str) and event_id:
                    drop_telemetry_by_event_id[event_id].append(row)
                    if row.get("reason") == "benign_profile_drop":
                        benign_profile_drop_count_by_event_id[event_id] += 1

        return MatchBatchResult(
            matches_by_event_id=dict(matches_by_event_id),
            drop_telemetry_by_event_id=dict(drop_telemetry_by_event_id),
            benign_profile_drop_count_by_event_id=dict(benign_profile_drop_count_by_event_id),
            elapsed_seconds=time.perf_counter() - started,
        )
