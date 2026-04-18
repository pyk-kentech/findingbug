# CPU TODO

`cpu계획.md`의 실행용 체크리스트 버전.
설명/회고보다 "지금 뭘 할지"에 집중한다.

## 1. 바로 할 일

- [ ] `graph_native_record_graph_event_time_seconds` 세부 계측 더 쪼개기
- [ ] `graph_add_residual`이 다시 커지는 구간 세부 계측 추가
- [ ] `trace_attack_full.jsonl` long-run 재측정
- [ ] `27%` 이후 구간에서 어떤 metric이 다시 치솟는지 정리

## 2. 성능 판단 기준

- [ ] `rolling_events_per_second_60s` 확인
- [ ] `rolling_events_per_second_300s` 확인
- [ ] `graph_add_time_seconds / hsg_update_time_seconds` 비율 확인
- [ ] full trace 후반부에서도 처리량 유지되는지 확인
- [ ] micro-metric 개선만 있고 end-to-end EPS가 나빠지면 폐기

## 3. 유지할 것

- [x] `prev_version` fast path 유지
- [x] `hsg_update` / `graph.add_event(...)` 계측 유지
- [x] grouped `graph_add_*` 지표 유지
- [x] detailed `graph_*_time_seconds` split 유지

## 4. 다시 하지 말 것

- [x] Rust native graph shadow batch record 경로 재도입 금지
- [x] `flow -> DATA_FLOW` direct merge fast path 재도입 금지

재시도 조건:
- shadow consistency 보장 방식이 생길 것
- 또는 full trace 기준 end-to-end EPS 개선이 먼저 확인될 것

## 5. Rust 메인 엔진 교체 TODO

- [x] 첫 authoritative handoff 단위를 `online propagation / pending edge flush`로 정하기
- [x] Python/Rust online mapper 동등성 체크 케이스 만들기
- [x] `flush_pending_edges()` Rust authoritative path 설계
- [ ] mismatch 시 Python fallback 전략 정의
- [ ] 1단계 완료 후 `online match add/remove` handoff 범위 정하기
- [ ] 그다음 `graph append / current_version / prune` handoff 범위 정하기

## 6. 이번 주 우선순위

1. Python/Rust online mapper 동등성 체크 케이스 만들기
2. `flush_pending_edges()` Rust authoritative path 활성화 범위 확대 및 smoke 정리
3. mismatch 시 fallback 기준 고정
4. [x] `100k` A/B 자동화로 `flush` 감소 확인, `seed_merge`를 실제로 타는 입력 조합 확정
4. 그다음 `graph append` handoff는 보류하고 online path부터 단계화

## 7. 완료 조건

- [x] `graph add` 내부 남은 큰 덩어리가 숫자로 식별될 것
- [x] 한 개 이상 최적화 후보가 "측정 가능한 목표"와 함께 정리될 것
- [x] Rust handoff 1단계의 범위가 문서로 고정될 것
- [x] Python/Rust online propagation 동등성 체크가 자동화될 것
- [ ] Rust authoritative flush path를 켜도 fallback 없이 smoke가 통과할 것
