from __future__ import annotations

import json
import multiprocessing as mp
import queue
import time
from typing import Iterable, Iterator

from engine.io.events import normalize_event


RawRecord = tuple[int, str]
ParsedRecord = tuple[int, object | None, str | None]
_STOP = "__HOLMES_STOP__"


def _parser_worker(in_q: mp.Queue, out_q: mp.Queue) -> None:
    while True:
        try:
            item = in_q.get()
        except (EOFError, OSError):
            break
        if item == _STOP:
            break
        if not isinstance(item, tuple) or len(item) != 2:
            continue
        index, line = item
        try:
            raw = json.loads(line)
            if not isinstance(raw, dict):
                out_q.put((int(index), None, None))
                continue
            event = normalize_event(raw, int(index))
            out_q.put((int(index), event, None))
        except Exception as exc:  # noqa: BLE001
            out_q.put((int(index), None, f"{type(exc).__name__}: {exc}"))


def iter_parsed_events_parallel(
    raw_records: Iterable[RawRecord],
    *,
    worker_count: int,
    queue_size: int = 1024,
    max_reorder_buffer: int | None = None,
    telemetry: dict | None = None,
) -> Iterator[object]:
    if telemetry is not None:
        telemetry.setdefault("reorder_buffer_saturation_count", 0)
        telemetry.setdefault("max_observed_out_of_order_distance", 0)
        telemetry.setdefault("stall_duration_seconds", 0.0)
        telemetry.setdefault("current_reorder_buffer_depth", 0)
        telemetry.setdefault("max_observed_reorder_buffer_depth", 0)
    if int(worker_count) <= 1:
        for index, line in raw_records:
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    continue
                event = normalize_event(raw, int(index))
            except Exception:  # noqa: BLE001
                continue
            yield event
        return

    ctx = mp.get_context("spawn")
    in_q: mp.Queue = ctx.Queue(max(1, int(queue_size)))
    out_q: mp.Queue = ctx.Queue(max(1, int(queue_size)))
    workers = [ctx.Process(target=_parser_worker, args=(in_q, out_q), daemon=True) for _ in range(int(worker_count))]
    for proc in workers:
        proc.start()

    next_index = 1
    pending: dict[int, object | None] = {}
    enqueued = 0
    received = 0
    feeder_done = False
    raw_iter = iter(raw_records)
    reorder_cap = max(1, int(max_reorder_buffer if max_reorder_buffer is not None else queue_size))

    try:
        while True:
            while (
                not feeder_done
                and (enqueued - received) < max(1, int(queue_size))
                and len(pending) < reorder_cap
            ):
                try:
                    record = next(raw_iter)
                except StopIteration:
                    feeder_done = True
                    for _ in workers:
                        in_q.put(_STOP)
                    break
                in_q.put(record)
                enqueued += 1

            if received >= enqueued and feeder_done:
                break

            block_for_progress = len(pending) >= reorder_cap and next_index not in pending
            if block_for_progress and telemetry is not None:
                telemetry["reorder_buffer_saturation_count"] = int(telemetry.get("reorder_buffer_saturation_count", 0)) + 1
                block_started = time.monotonic()
            else:
                block_started = None
            try:
                index, event, _error = out_q.get(timeout=None if block_for_progress else 1.0)
            except queue.Empty:
                continue
            if block_started is not None and telemetry is not None:
                telemetry["stall_duration_seconds"] = float(telemetry.get("stall_duration_seconds", 0.0)) + max(0.0, time.monotonic() - block_started)
            received += 1
            pending[int(index)] = event
            if telemetry is not None:
                telemetry["current_reorder_buffer_depth"] = len(pending)
                telemetry["max_observed_reorder_buffer_depth"] = max(
                    int(telemetry.get("max_observed_reorder_buffer_depth", 0)),
                    len(pending),
                )
            if telemetry is not None:
                out_of_order_distance = max(0, int(index) - int(next_index))
                if out_of_order_distance > int(telemetry.get("max_observed_out_of_order_distance", 0)):
                    telemetry["max_observed_out_of_order_distance"] = out_of_order_distance
            while next_index in pending:
                ready = pending.pop(next_index)
                next_index += 1
                if telemetry is not None:
                    telemetry["current_reorder_buffer_depth"] = len(pending)
                if ready is not None:
                    yield ready
    finally:
        for proc in workers:
            if proc.is_alive():
                proc.join(timeout=2.0)
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=1.0)
