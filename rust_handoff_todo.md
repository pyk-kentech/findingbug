# Rust Handoff TODO

`cpu계획.md`의 Rust ownership 전환 부분만 따로 뽑은 실행판.

## 1. 1단계 목표

- [x] 첫 authoritative handoff를 `online propagation / pending edge flush`로 정하기
- [x] Python path와 Rust path의 책임 경계 문장으로 고정
- [ ] mismatch 시 즉시 Python fallback하는 조건 정의

## 2. 왜 이 경로부터 하는가

- [x] Rust 쪽에 `online index` 기본 동작이 이미 있음
- [x] 현재 실측 병목 중 하나가 `online_graph_edge_flush -> seed merge`
- [x] `graph append`보다 회귀 위험이 낮음

## 3. 구현 순서

1. [x] Python/Rust online mapper 동등성 체크 도구 만들기
2. [x] `flush_pending_edges()` Rust authoritative 진입점 추가
3. [ ] smoke 입력에서 Python/Rust 결과 비교
4. [x] `100k`에서 `flush`/`seed_merge` 지표 비교
   - A/B 자동화 스크립트: `scripts/compare_native_online_authoritative.py`
   - 기준 입력/룰: `HOLMES/tmp/trace_attack_100k.jsonl` + `rules/darpa_tc_e3_rules.yaml`
   - 결과:
     - `EPS`: `2412.0 -> 2559.1` (`+6.1%`)
     - `online_graph_edge_flush_time_seconds`: `6.035 -> 4.146` (`-31.3%`)
     - `online_graph_edge_flush_flush_call_time_seconds`: `3.693 -> 1.834` (`-50.3%`)
     - `seed_merge_time`: `0.838 -> 0.0`
     - `matches/hsg_edges`: `71/12 -> 71/12`
     - `native_online_read_fallback_total = 0`
5. [ ] 안정화 후 `online match add/remove` ownership 확대
6. [ ] `trace_attack_full.jsonl` (`4,999,999` lines)에서 동일 A/B 재측정

## 4. 동등성 체크 항목

- [x] `mapper_contains_rule`
- [x] `mapper_earliest_seq`
- [x] `mapper_contains_match`
- [x] `mapper_min_hops`
- [x] `mapper_match_ids`

## 5. 성공 기준

- [ ] 동등성 체크가 자동화 테스트로 존재
- [ ] mismatch 없이 smoke 통과
- [ ] `100k`에서 `online_graph_edge_flush_time_seconds` 감소
- [ ] `100k`에서 `seed_merge_time` 감소
- [ ] fallback 없이 기본 실험이 재현 가능

## 6. 보류

- [ ] `graph append / current_version / prune` authoritative handoff
- [ ] `NativeBatchEngine.process_batch() -> True` 전체 takeover
