from __future__ import annotations

from dataclasses import dataclass, field
import math

from engine.rules.schema import APT_STAGES


def _to_paper_stage_severity(value: float | str | None) -> float:
    if value is None:
        return 2.0
    if isinstance(value, str):
        mapping = {
            "low": 2.0,
            "medium": 6.0,
            "high": 8.0,
            "critical": 10.0,
        }
        return float(mapping.get(value.lower(), 2.0))
    x = float(value)
    if x < 4.0:
        return 2.0
    if x < 7.0:
        return 6.0
    if x < 9.0:
        return 8.0
    return 10.0


@dataclass(slots=True)
class PaperExactState:
    stage_severity: list[float] = field(default_factory=lambda: [1.0] * len(APT_STAGES))
    stage_earliest_detection_time: list[str | None] = field(default_factory=lambda: [None] * len(APT_STAGES))
    stage_earliest_detection_sequence: list[int | None] = field(default_factory=lambda: [None] * len(APT_STAGES))
    log_score: float = 0.0
    score: float = 1.0
    detected: bool = False
    first_detection_time: str | None = None
    first_detection_sequence: int | None = None
    first_detection_log_score: float | None = None
    first_detection_score: float | None = None
    first_detection_tuple_snapshot: list[float] | None = None
    first_detection_contributing_stages: list[int] = field(default_factory=list)


class IncrementalPaperExactScorer:
    def __init__(self, weights: list[float] | None = None, tau: float | None = None) -> None:
        self.weights = list(weights) if weights is not None else [1.0] * len(APT_STAGES)
        if len(self.weights) != len(APT_STAGES):
            raise ValueError("paper_weights must contain exactly 7 values")
        self.tau = float(tau) if tau is not None else None
        if self.tau is not None and self.tau <= 0.0:
            raise ValueError("tau must be > 0")
        self.log_tau = math.log(self.tau) if self.tau is not None else None
        self.state = PaperExactState()

    def update(
        self,
        *,
        stage: int,
        raw_severity: float | str | None,
        event_time: str | None,
        sequence: int | None,
    ) -> bool:
        idx = max(1, min(int(stage), len(APT_STAGES))) - 1
        new_s = _to_paper_stage_severity(raw_severity)
        cur_s = float(self.state.stage_severity[idx])
        if new_s <= cur_s:
            return False

        self.state.log_score += float(self.weights[idx]) * (math.log(new_s) - math.log(cur_s))
        self.state.score = float(math.exp(self.state.log_score))
        self.state.stage_severity[idx] = float(new_s)

        if self.state.stage_earliest_detection_time[idx] is None:
            self.state.stage_earliest_detection_time[idx] = event_time
        if self.state.stage_earliest_detection_sequence[idx] is None:
            self.state.stage_earliest_detection_sequence[idx] = sequence

        if (not self.state.detected) and self.log_tau is not None and self.state.log_score >= self.log_tau:
            self.state.detected = True
            self.state.first_detection_time = event_time
            self.state.first_detection_sequence = sequence
            self.state.first_detection_log_score = float(self.state.log_score)
            self.state.first_detection_score = float(self.state.score)
            self.state.first_detection_tuple_snapshot = list(self.state.stage_severity)
            self.state.first_detection_contributing_stages = [
                i + 1 for i, s in enumerate(self.state.stage_severity) if float(s) > 1.0
            ]
        return True
