# HOLMES 코어 병목/메모리 해결 로드맵

## 0) 현재 결론
- `ac_min` 병목은 이미 완화됨
  - `set_diff` 고정
  - C 네이티브 `_acmin_native` 사용 가능
- 조상/거리 캐시 폭발도 1차 완화됨
  - `HOLMES_ANCESTOR_TOTAL_ENTRY_BUDGET`
  - on-demand ancestor 전환
- Rust `online prerequisite read path`는 샘플 기준 정합성 확보
- 그런데 full run을 막는 현재 핵심은 아래 3개다
  1. 단일 Python state machine으로 인한 1코어 병목
  2. eviction 이후 `online_full_resync`가 발생하는 구조
  3. 후반부 state growth (`graph`, `online_index`, `builder`, native mirror)

## 0-1) 2026-04-16 기준 실제 진행 상태

### 완료
- Python `online_index.on_match_removed()` 구현
- runner active match local eviction 경로 구현
- Rust native online read path 기본 정합성 확인
- Rust native graph seam 추가
  - `reset_graph()`
  - `record_graph_event(event)`
- Rust native online index decremental delete 추가
  - active eviction 이후 `HOLMES_NATIVE_ONLINE_READ_PRIMARY=1` 유지 가능
- builder -> runner edge eviction payload seam 추가
  - `last_evicted_hsg_edges`
- runner local HSG edge 제거 경로 추가
  - edge eviction만으로는 더 이상 `online_index` full rebuild를 강제하지 않음

### 진행 중
- builder pending state 축소 정책
  - stage 기반 capacity eviction은 이미 있음
  - 최근 다시 참조된 pending을 더 오래 보존하는 `last_activity` 기반 우선순위 강화 진행 중
- edge eviction의 완전한 local cascade delete
  - 현재는 local edge remove + cheap sync 수준
  - `online_index` 영향 범위까지 완전 국소화하는 단계는 아직 남음
- 실데이터(full trace) 운영 검증
  - `online_full_resync`는 거의 사라졌는지 확인 완료
  - 그러나 1코어 병목/graph_gc/hsg_update 비용으로 후반부 속도 급락이 여전히 남음

### 미완료
- Rust graph primary ownership 이전
- Rust online_index write/delete의 완전 primary화
- builder candidate/evaluation state의 Rust 이전
- Python/Rust state duplication 실질 축소

## 1) 지금 실제 병목 정의

### 1-1. CPU 병목
- 메인 실행 경로는 여전히 단일 `python -m engine.cli.run_pipeline`
- Rust는 일부 read path만 담당
- 실제 상태 변경은 아직 Python이 소유
  - `graph.add_event`
  - `online_index.on_match_added`
  - `hsg_builder.add_match`
  - runner orchestration
- 결과: CPU는 계속 1코어만 100%

### 1-1-a. 2026-04-16 full trace 관찰
- `/home/work/SIGMA/datasets/darpa_tc_e3/benchmark/trace_attack_full.jsonl`
- `HOLMES_NATIVE_BACKEND=rust`
- `HOLMES_NATIVE_ONLINE_READ_PRIMARY=1`
- `--use-online-prereq --matcher-workers 6 --ab-quality b`
- 관찰 결과:
  - parser worker를 6으로 줘도 전체 프로세스는 거의 1코어 사용에 머묾
  - `27%` 전후부터 속도 저하가 체감되고,
  - `24분` 시점 기준 CPU는 약 `99%`, RSS는 약 `7.6GB`
  - 즉 "멈춤"은 아니지만 사실상 단일 코어 병목 상태
- 의미:
  - 현재 6코어 활용은 parser 병렬화 수준에 머물고
  - HOLMES 핵심 state machine은 아직 Python 단일 루프 병목이다

### 1-2. 운영 병목
- `max_active_matches` / `max_hsg_edges` 같은 메모리 방어를 켜면
- eviction 이후 정합성을 맞추기 위해 `online_full_resync`가 발생
- 이게 전체 속도를 무너뜨림

### 1-2-a. 2026-04-16 검증 결과
- online prerequisite 경로 강제 검증에서
  - active eviction 발생
  - `online_full_resync_time_seconds = 0.0`
  - `native_online_read_fallback_total = 0`
- full trace에서도 metrics 기준
  - `online_full_resync_time_seconds = 0.0`
  - `native_online_read_fallback_total = 0`
- 의미:
  - 지금 시점의 주병목은 예전처럼 `full resync`가 아니라
  - `graph_gc_time_seconds`, `hsg_update_time_seconds`, Python state ownership이다

### 1-3. 메모리 병목
- 큰 ancestor/min_dist 캐시는 이미 껐지만
- 아래 상태는 계속 누적됨
  - raw graph state
  - Python `online_index`
  - Python `builder`
  - Rust native graph/index shadow
  - HSG edge/match state
- full trace 관찰:
  - RSS는 관찰 시점 기준 약 `7.6GB`로 아직 OOM 직전은 아니었음
  - 그러나 `retained_event_meta_count=500000`, `pruned_event_meta_count` 지속 증가,
  - `graph_version_node_count`, `graph_edge_count`가 계속 커지며
  - 후반부 `graph_gc`와 `hsg_update` 비용이 누적되어 속도 급락 유발

## 2) 목표 지표

### 2-1. 단기 목표
- full trace 100% 완주
- OOM / SIGKILL 137 제거
- `online_full_resync` 누적 시간을 현재 대비 90% 이상 감소
- 후반부 `events_per_second`를 최소 1k 이상 유지

### 2-2. 중기 목표
- CPU 6코어 환경에서 평균 400%+ 사용
- single Python baseline 대비 2.5x 이상 처리량
- 정합성 diff 0
  - `alerts`
  - `matches`
  - `hsg_edges`

## 3) 우선순위

### Priority 1. Full Resync 제거
- 이유: 지금 가장 직접적으로 속도를 망치는 운영 병목
- 현재 상태:
  - active match eviction은 일부 local delete 경로 추가 완료
  - edge eviction은 local edge remove + cheap sync까지 추가 완료
  - 다만 `online_index` 영향 범위의 완전 국소 삭제는 아직 미완료

### Priority 2. State growth 억제
- 이유: full run 후반부 SIGKILL 방지
- 대상:
  - `builder pending`
  - `active matches`
  - `HSG edges`
  - `events_by_id`
  - native shadow duplication

### Priority 3. Rust state ownership 이전
- 이유: 1코어 병목의 근본 해결
- 하지만 Priority 1, 2가 선행되어야 실제 운영 가치가 생김

## 4) 구현 로드맵

### Phase A. Python 경로의 삭제 가능 구조 완성

#### A-1. online_index decremental propagation
- 목표:
  - `on_match_removed()` 지원
  - local match 삭제 후 해당 노드와 downstream 노드 mapper 재계산
- 현재 상태:
  - Python `online_index`에 기본 local delete 경로 추가됨
  - active eviction 시 runner가 이 경로를 사용 가능
- 남은 문제:
  - edge eviction은 아직 지원 안 됨
  - Rust native online index에는 decremental delete가 없음

#### A-2. edge eviction의 국소화
- 필요 구조:
  - `edge -> affected match ids`
  - 또는 `match -> dependent edges`
  - 그리고 `online_index` 영향 범위 추적용 역방향 정보
- 목표:
  - edge cap 도달 시 전체 rebuild 없이 local cascade delete
- 현재 상태:
  - builder가 `last_evicted_hsg_edges` payload를 runner에 넘김
  - runner가 local HSG edge remove 가능
  - 그러나 `online_index` 영향 범위까지 국소 삭제하는 단계는 아직 남음

#### A-3. runner mirror/local online state 일관성
- 삭제 시 같이 정리되어야 하는 대상:
  - `matches`
  - `match_by_id`
  - `hsg_nodes`
  - `hsg_edges`
  - `seen_edges`
  - `match_to_entities`
  - `node_to_matches`
  - `entity_to_hsg_node`
  - Python `online_index`
- 원칙:
  - 삭제 payload 기반 O(K) 반영
  - full resync는 마지막 안전망으로만 남긴다
- 현재 상태:
  - `matches`, `match_by_id`, `hsg_edges`, `seen_edges`, entity index류의 local delete 경로 존재
  - active eviction에서는 Rust native delete까지 연동됨

### Phase B. 메모리 상한의 실제 운영화

#### B-1. 이미 들어간 방어선
- `HOLMES_ANCESTOR_TOTAL_ENTRY_BUDGET`
- `HOLMES_EVENT_META_SOFT_LIMIT`
- `max_pending_matches`
- `max_active_matches`
- `max_hsg_edges`

#### B-2. 현재 문제
- cap 자체보다 cap 이후 full resync가 더 비쌈
- 따라서 cap은 국소 삭제가 가능한 구조에서만 운영해야 함

#### B-3. 운영 원칙
- `max_hsg_edges`:
  - edge local delete가 되기 전까지는 기본 `0`
- `max_active_matches`:
  - local delete 경로 검증 후만 사용
- `HOLMES_NATIVE_SHADOW_CHECK=0`:
  - full run 기본값 유지
- `HOLMES_NATIVE_ONLINE_READ_PRIMARY=1`:
  - Python/Rust 정합성 검증 완료 범위에서만 유지

### Phase C. Rust state ownership 이전

#### C-1. 목표
- Python은 I/O + orchestration만 담당
- Rust가 실제 상태의 단일 진실 공급원(SSOT)

#### C-2. 이전 순서
1. `online_index` write/delete를 Rust primary로 이전
2. `graph add / edge append`를 Rust primary로 이전
3. `builder` candidate/evaluation state를 Rust로 이전
4. Python mirror를 제거

#### C-3. 중요한 조건
- Python loop 안에서 native 함수 남발 금지
- batch FFI 유지
- 읽기만 Rust가 아니라 쓰기/삭제 state ownership까지 넘어가야 멀티코어 효과가 난다

## 5) 구현 작업 목록

### Task 1. Python online_index delete 경로 안정화
- `on_match_removed()` 경로 검증
- multi-origin / multi-path 케이스 테스트
- downstream recompute correctness 확인
- 상태:
  - 기본 구현 완료
  - 추가 정합성 케이스 보강 필요

### Task 2. edge eviction 국소 삭제 설계
- `edge -> match` 또는 equivalent reverse dependency index 도입
- builder edge 삭제 시 영향 match 계산
- runner/online_index/local mirror 동기화
- 상태:
  - builder -> runner evicted edge payload seam 완료
  - runner local edge remove 완료
  - reverse dependency index / online_index cascade delete는 미완료

### Task 3. native online_index decremental delete
- Rust 쪽에도 `match remove` 지원 추가
- Python active eviction 이후 `read_primary`를 끄지 않도록 맞추기
- 상태:
  - 완료

### Task 4. builder state 축소 정책 재설계
- 오래된 pending TTL 강화
- stage/last_activity 기반 eviction 우선순위 명확화
- HSG edge eviction은 low-value edge 우선
- 상태:
  - low-value HSG edge eviction은 이미 있음 (`low_weight_lru`)
  - pending stage/last_activity 기반 eviction 우선순위 강화 진행 중
  - pending TTL 재설계는 미완료

### Task 5. graph/native state 중복 축소
- Python/Rust 양쪽 그래프를 동시에 들고 있는 구조 축소
- 가능하면 Rust SSOT, Python view-only로 축소
- 상태:
  - 미완료
  - full trace 기준 여전히 단일 Python state 소유 병목이 지배적

## 6) 현재 운영 가이드

### 6-1. 지금 기준 안전한 옵션
- `HOLMES_NATIVE_SHADOW_CHECK=0`
- `HOLMES_NATIVE_ONLINE_READ_PRIMARY=1`
- `HOLMES_ANCESTOR_TOTAL_ENTRY_BUDGET=20000000`
- `HOLMES_EVENT_META_SOFT_LIMIT=500000`
- `--ab-quality b`
- `--max-graph-path-candidates-per-match 12`
- `--max-graph-path-edges 1500`

### 6-2. 지금 기준 위험한 옵션
- `--max-hsg-edges`를 낮게 주는 것
  - 예전보다 훨씬 낫지만, `online_index` cascade delete가 아직 없어 aggressive cap은 여전히 리스크
- `--max-active-matches`를 낮게 주는 것
  - 기본 local delete는 들어갔지만, 매우 공격적인 cap에서는 추가 검증 필요

## 7) 성공 판정

### Go 조건
1. full trace 100% 완주
2. `online_full_resync_time_seconds` 거의 0 수준
3. SIGKILL 137 없음
4. Rust read/write/delete 정합성 diff 0
5. CPU 활용률 1코어 병목에서 다코어 병렬 단계로 진입

### No-Go 조건
- eviction만 켜도 속도가 급락
- full resync가 계속 누적
- Python/Rust 정합성 mismatch 발생
- state growth가 계속 선형 폭증

## 8) 냉정한 한 줄 결론
- 지금 HOLMES는 `path_factor` 문제를 넘어섰고,
- 남은 본질은 **삭제 불가능한 online state와 Python 소유 state machine**이다.
- 먼저 `full resync 제거`, 그다음 `Rust state ownership 이전` 순서로 가야 한다.

## 9) 구조 개선 v1

### 9-1. 목표
- `raw provenance graph`의 state ownership을 Rust primary로 옮기기 위한 첫 seam을 고정한다
- 이번 단계에서는 Python graph semantics를 유지하면서도, native graph write API를 병렬로 호출할 수 있게 만든다
- 아직 source of truth는 Python에 남기되, 다음 단계에서 `graph add/prune`를 native로 넘길 수 있게 인터페이스를 먼저 만든다

### 9-2. 구현 순서
1. `engine/native/backend.py`
   - graph write-primary용 backend API 추가
   - `reset_graph()`
   - `record_graph_event(event)`
2. `native-rust/src/lib.rs`
   - `NativeBatchEngine`에 graph state reset/add-event 메서드 추가
   - Python `Event` payload 1건을 바로 native graph에 반영할 수 있게 함
3. 테스트
   - backend wrapper가 새 graph seam을 정상 위임하는지 회귀 테스트 추가
4. 다음 단계
   - `engine/core/graph.py`에서 native graph seam을 실제로 호출
   - 그 뒤 `prune_stale_orphaned()`를 Rust로 이전

### 9-3. 이번 단계 성공 기준
- native backend 인터페이스가 graph write-primary seam을 포함한다
- Rust backend가 개별 event를 graph state에 반영할 수 있다
- Python 쪽에서 새 seam을 호출할 준비가 끝난다

### 9-4. API 설계 원칙
- 이번 seam은 "최소한의 쓰기 API"만 연다
  - `reset_graph()`
  - `record_graph_event(event)`
- 처음부터 범용 graph mutation API를 열지 않는다
  - 이유: Python graph의 현재 의미론을 그대로 복제하려 하면 인터페이스가 너무 빨리 커진다
- `record_graph_event(event)`는 Python `Event` 1건을 native graph에 반영하는 단방향 append 성격으로 제한한다
- 삭제/eviction/prune는 이번 단계에서 넣지 않는다
  - add path와 delete path를 한 번에 열면 정합성 디버깅 난이도가 급격히 올라간다

### 9-5. 호출 흐름
1. runner가 이벤트를 읽는다
2. Python `graph.add_event(...)`가 기존대로 state를 갱신한다
3. 같은 이벤트 payload를 backend seam으로 전달한다
4. Rust graph도 같은 이벤트를 반영한다
5. shadow check 또는 샘플 diff로 Python/Rust graph 정합성을 본다

### 9-6. 왜 이 순서가 맞는가
- 지금 당장 Python graph ownership을 바로 제거하면
  - 실패 시 롤백 범위가 너무 넓고
  - 어느 레이어에서 의미론이 깨졌는지 분리하기 어렵다
- 반대로 append seam만 먼저 고정하면
  - write path 스키마를 먼저 안정화할 수 있고
  - 이후 read path를 Rust로 붙이거나
  - prune/delete ownership을 넘길 때도 공통 payload를 재사용할 수 있다
- 즉, 이번 단계의 진짜 산출물은 "성능 향상" 그 자체보다
  - graph ownership 이전을 위한 안정적인 계약면(contract surface)이다

### 9-7. 이 단계에서 일부러 하지 않는 것
- `prune_stale_orphaned()` native 이전
- graph delete / orphan cleanup native 이전
- builder/online_index와 graph ownership 동시 이전
- 대규모 batch ingest 리라이트

### 9-8. 예상 리스크
- Python graph와 Rust graph의 event normalization 차이
  - 필드 누락
  - timestamp/type canonicalization 차이
  - entity id normalization 차이
- event 1건 단위 FFI 호출 비용
  - correctness seam으로는 괜찮지만 throughput 최적화는 아직 아님
- reset 시점 불일치
  - run 시작/재시작 시 Python/Rust graph가 다른 세션 state를 들고 갈 수 있음

### 9-9. 리스크 완화책
- `record_graph_event(event)`에 들어가는 payload를 Python graph 입력 직전 형태로 고정한다
- reset은 runner pipeline 시작 시 1회, full resync 직전/직후 규칙을 명시한다
- shadow diff는 전체 full diff보다
  - event count
  - node count
  - edge count
  - 특정 anchor entity의 adjacency 샘플
  순서로 점검한다
- 성능 경고는 허용하되 correctness mismatch는 즉시 실패로 본다

## 10) 구조 개선 v2

### 10-1. 목표
- `raw provenance graph`의 add path를 Rust primary로 전환한다
- Python graph는 write owner가 아니라 검증용 mirror 또는 view로 축소한다
- 이 시점부터는 "Python이 쓰고 Rust가 따라가는 구조"를 끝내고
  "Rust가 쓰고 Python은 필요 시 읽는 구조"로 넘긴다

### 10-2. 전환 조건
- v1에서 event append 정합성 mismatch가 사실상 0이어야 한다
- reset lifecycle이 안정화되어야 한다
- graph read path 일부가 native graph를 참조해도 결과 diff가 없어야 한다

### 10-3. 구현 방향
1. runner 또는 `graph.add_event` 상위 호출부에서 native add를 먼저 수행
2. Python graph write는 debug/shadow 모드에서만 유지
3. graph 조회 함수 중 hot path를 순서대로 native read로 전환
4. Python graph의 중복 state를 축소한다

### 10-4. 성공 기준
- full run에서 graph state의 primary owner가 Rust임이 명확하다
- Python graph mirror를 꺼도 주요 파이프라인이 동작한다
- 메모리 사용량이 Python-only 대비 유의미하게 감소한다

## 11) 삭제 경로와 ownership 이전의 연결

### 11-1. 왜 graph 이전만으로는 부족한가
- graph add path를 Rust로 옮겨도
  - `online_index`
  - `builder`
  - `HSG edge state`
  가 여전히 Python 소유면 1코어 병목은 크게 남는다
- 따라서 graph ownership 이전은 필요조건이지만 충분조건은 아니다

### 11-2. 그래도 graph를 먼저 옮기는 이유
- 모든 후속 state의 기반 입력이 event/edge 추가이기 때문
- graph seam이 안정화되면
  - online_index 입력도 같은 native state에서 뽑을 수 있고
  - builder candidate 계산도 Python 중간구조를 덜 거치게 만들 수 있다

### 11-3. 최종적으로 필요한 ownership 순서
1. graph add/reset
2. online_index write/delete
3. builder candidate/evaluation state
4. HSG edge/match lifecycle
5. Python mirror 제거

## 12) 당장 다음 액션

### 이번 주
- `engine/native/backend.py`에 graph seam 추가
- Rust `NativeBatchEngine`에 graph reset/add-event 연결
- backend wrapper 회귀 테스트 추가

### 그 다음 주
- Python graph 입력과 native graph 입력 payload를 완전히 동일하게 정리
- 샘플 trace에서 graph count/adjacency diff 검증
- reset/full resync lifecycle 문서화

### 그 다음 단계
- `engine/core/graph.py` 또는 runner 상위 경로에서 native seam 실제 호출
- `prune_stale_orphaned()` 이전 여부를 별도 실험 플래그로 검증

## 13) 실무적 판단
- 지금 필요한 것은 "거대한 Rust 이전 선언"이 아니라
  "작지만 되돌릴 수 있는 ownership seam"을 하나씩 박아 넣는 것이다.
- `online_full_resync` 제거와 state growth 억제가 먼저고,
- 그 위에서 graph -> online_index -> builder 순으로 Rust primary를 넓혀야 한다.
- 그래야 성능, 메모리, 정합성 셋을 동시에 잃지 않는다.

## 14) 2026-04-16 실행 결론
- active eviction local delete는 실데이터 전 단계에서 동작 확인
- native online decremental delete도 실동작 확인
- full trace 운영에서 `online_full_resync`는 더 이상 주병목이 아님
- 그러나 `27%` 전후부터 속도 급락이 재현되었고,
  핵심 원인은 `graph_gc` + `hsg_update` + 단일 Python state machine으로 보임
- 따라서 다음 우선순위는
  1. `graph add/write` ownership의 Rust 이전 준비
  2. builder state/GC 비용 축소
  3. parser 병렬화가 아니라 core state 업데이트의 다코어화

## 15) 2026-04-16 추가 실행 기록

### 15-1. `/tmp/darpa_full_rust6_tighter`
- 설정:
  - `HOLMES_EVENT_META_SOFT_LIMIT=300000`
  - `HOLMES_PROCESS_BATCH_SIZE=1000`
  - `--matcher-workers 6`
  - `--matcher-batch-size 10000`
  - `--max-pending-matches 10000`
  - `--max-active-matches 5000`
- 관찰:
  - 누적 평균 `events_per_second`는 약 `700~1200 ev/s`로 보였지만
  - 직전 로그 간 구간 속도로 계산한 실시간 처리량은 훨씬 낮았음
- 실시간 속도 예시:
  - `15:47:30 -> 15:48:50`: 약 `201 ev/s`
  - `15:48:50 -> 15:50:20`: 약 `178 ev/s`
  - `15:53:39 -> 15:54:43`: 약 `125 ev/s`
  - `15:54:43 -> 15:55:43`: 약 `133 ev/s`
  - `15:55:43 -> 15:56:45`: 약 `129 ev/s`
- 해석:
  - 누적 평균은 실제 체감 속도를 심하게 과대평가함
  - full trace 후반부 실시간 속도는 사실상 `130~200 ev/s` 수준으로 떨어짐
  - 이 상태라면 `25%` 전후에서도 이미 매우 느린 편으로 봐야 함

### 15-2. 병목 원인 재확인
- `online_full_resync_time_seconds = 0.0`
- `native_online_read_fallback_total = 0`
- `active_evicted_count = 0`
- `hsg_edges_evicted_count = 0`
- 의미:
  - 이번에 고친 local delete / native online delete는 병목의 주원인이 아님
  - 현재 느림의 핵심은 `graph_gc_time_seconds`, `hsg_update_time_seconds`, 단일 Python state ownership
  - cap이 충분히 발동하지 않아 state growth 자체는 여전히 크게 억제되지 못함

### 15-3. 적용한 코드 수정
- `engine/stream/runner.py`
  - retention 창에 아직 도달하지 않았고 cap pressure도 없으면
  - `taint_tracker.evict_stale()`와 `graph.prune_stale_orphaned()`를 건너뛰도록 수정
  - 이 경우에는 가벼운 `event meta` 정리만 수행
- 의도:
  - 삭제할 수 있는 데이터가 아직 없는 초반/중반 구간에서
  - deep GC가 전 그래프를 계속 스캔하는 비용을 제거
- 회귀 테스트:
  - `test_graph_gc_skips_deep_prune_before_retention_window` 추가
  - 관련 GC 테스트 3개 통과

### 15-4. `/tmp/darpa_full_rust6_tighter2`
- 위 GC 스킵 패치 반영 후 재실행
- 최신 로그 기준 누적 평균:
  - `events_per_second ≈ 1217.6`
- 그러나 실시간 구간 속도는 아래 기준으로 봐야 함:
  - `16:16:48 -> 16:17:48`: 약 `108 ev/s`
  - `16:17:48 -> 16:18:48`: 약 `191 ev/s`
  - `16:18:48 -> 16:19:48`: 약 `229 ev/s`
- 해석:
  - 이전 `tighter` 런의 후반부 `~130 ev/s`보다는 개선
  - 다만 여전히 실시간 처리량은 `~190~230 ev/s` 수준에 머물고
  - "6코어 활용"과는 거리가 멀다

### 15-5. 현재 판단
- 이번 GC 스킵 패치는 의미 있는 개선이다
  - 적어도 retention 창 전 deep GC의 낭비를 줄였다
- 하지만 근본 병목은 여전히 남아 있다
  - `hsg_update`
  - `graph add/write` 이후 Python 소유 state 갱신
  - 단일 Python 메인 루프
- 따라서 다음 작업 우선순위는 여전히 아래와 같다
  1. `graph_gc`에 이어 `hsg_update` hot path를 직접 줄이기
  2. `graph/online_index/builder` ownership을 더 Rust 쪽으로 이동
  3. 실시간 속도 기준 `1k ev/s` 유지가 가능한 구조로 바꾸기

## 16) 바로 다음 실험 계획

### 16-1. 실험 1: `hsg_update` 호출량 자체 줄이기
- 가설:
  - 현재는 매 이벤트 또는 과도하게 잦은 주기마다 HSG 관련 갱신 비용을 치르고 있을 가능성이 크다
  - match/edge 변화가 없는 구간에서는 update를 건너뛰거나 coalesce할 수 있다
- 할 일:
  - `hsg_update_time_seconds`가 어디에서 누적되는지 세부 계측 추가
  - 호출 횟수, 1회당 평균 비용, 실제 edge/match 변화량을 함께 로그에 남긴다
  - "상태 변화 없음" 구간에서는 HSG update skip 또는 batch flush 방식 실험
- 성공 기준:
  - full trace 중반 이후 실시간 처리량이 현재 대비 유의미하게 상승
  - alert/match diff 없이 `hsg_update_time_seconds` 비중 감소

### 16-2. 실험 2: graph add path의 Python 부가 작업 분리
- 가설:
  - graph에 event를 추가한 뒤 Python에서 수행하는 후속 bookkeeping이 hot path를 길게 만들고 있다
- 할 일:
  - `graph.add_event(...)` 주변의 세부 단계별 time split 계측
  - event normalization, adjacency 갱신, orphan/prune 관련 bookkeeping을 분리 기록
  - Rust seam 호출 전후 비용도 따로 측정
- 성공 기준:
  - add path 내부에서 실제 상위 1~2개 병목 함수가 드러난다
  - 이후 Rust ownership 이전 후보를 함수 단위로 자를 수 있다

### 16-3. 실험 3: builder pending 압력 조기 유도
- 가설:
  - 현재 cap이 충분히 빨리 작동하지 않아 후반부 state growth가 누적된다
  - 다만 무작정 cap을 낮추면 과거처럼 resync/정합성 리스크가 생길 수 있다
- 할 일:
  - `pending stage`, `last_activity`, `age`, `fanout` 기준 분포를 찍는다
  - low-value pending을 더 빨리 버리는 실험 플래그 추가
  - `max_pending_matches`를 낮추더라도 recall 손실이 어느 지점부터 커지는지 측정
- 성공 기준:
  - RSS 증가율 둔화
  - `builder` 관련 state count plateau 확인
  - alert/match 품질 저하가 허용 범위 내

## 17) 계측 전략 보강

### 17-1. 지금 로그의 문제
- 누적 평균 `events_per_second`만 보면 진행률이 좋아 보이는데
  실제 체감 속도와 심하게 어긋난다
- full trace 후반부 의사결정은 누적 평균이 아니라
  "최근 1분/5분 실시간 처리량" 기준으로 해야 한다

### 17-2. 추가할 지표
- `rolling_events_per_second_60s`
- `rolling_events_per_second_300s`
- `graph_add_time_seconds`
- `graph_gc_deep_prune_time_seconds`
- `hsg_update_call_count`
- `hsg_update_changed_match_count`
- `hsg_update_changed_edge_count`
- `builder_pending_count`
- `active_match_count`
- `online_index_entry_count`

### 17-3. 왜 필요한가
- 그래야 "무엇이 느린지"를 감이 아니라 수치로 자를 수 있다
- 특히 아래 구분이 가능해진다
  - update 호출이 너무 많은 문제인지
  - 호출은 적지만 1회 비용이 큰 문제인지
  - state growth 때문에 후반부 비용이 선형 이상으로 커지는 문제인지

## 18) 의사결정 기준 재정의

### 18-1. 좋은 개선의 기준
- 누적 평균만 오른 개선은 보류한다
- 아래 3개를 동시에 만족해야 실제 개선으로 본다
  1. 후반부 `rolling_events_per_second_60s` 상승
  2. RSS 또는 핵심 state count 증가율 둔화
  3. alerts/matches diff 없음

### 18-2. 버려야 할 개선의 기준
- 초기 5~10%만 빨라지고 후반부 속도 하락 곡선이 그대로인 경우
- cap을 세게 걸어서 메모리는 줄었지만 alert/match 품질이 흔들리는 경우
- shadow/offline 검증을 통과하지 못해 운영 옵션을 되돌려야 하는 경우

## 19) 작업 순서 재고정

### 19-1. 이제 당장 먼저 할 것
1. `hsg_update` 세부 계측 추가
2. `graph.add_event` 주변 time split 계측 추가
3. builder pending eviction 우선순위 강화
4. 그 다음에 graph write ownership seam 확장

### 19-2. 일부러 미루는 것
- parser worker 수 추가 확대
  - 이미 core bottleneck이 parser 밖에 있다는 증거가 충분하다
- 무작정 더 aggressive한 `max_hsg_edges`
  - cascade delete 완성 전에는 리스크가 더 크다
- 대규모 Rust 리라이트 일괄 진행
  - 지금은 seam과 계측 없이 크게 옮기면 원인 분리가 어려워진다

## 20) 최종 정리
- 2026-04-16 기준 HOLMES는 더 이상 `online_full_resync`가 main issue인 상태가 아니다
- 현재 본질은
  - 후반부 `graph_gc` / `hsg_update` 누적 비용
  - builder/pending 중심의 state growth
  - Python 단일 state ownership
- 그래서 다음 승부처는 두 가지다
  1. 후반부 실시간 처리량을 기준으로 병목을 다시 계측한다
  2. graph -> online_index -> builder 순서로 ownership 이전을 준비하되, 각 단계에서 state를 실제로 줄이는지 확인한다
- 한마디로,
  이제는 "resync를 없앴다"에서 멈추면 안 되고
  "후반부에도 안 느려지는 구조"까지 넘어가야 한다

## 21) 2026-04-16 추가 계측/최적화 회고

### 21-1. 이번에 실제로 추가한 계측
- `rolling_events_per_second_60s`
- `rolling_events_per_second_300s`
- `hsg_update_call_count`
- `hsg_update_changed_match_count`
- `hsg_update_changed_edge_count`
- `graph_add` grouped breakdown
  - `semantic`
  - `entity_identity`
  - `versioning`
  - `edge_bookkeeping`
  - `residual`
- graph 세부 split 추가
  - `native_record_graph_event`
  - `prev_by_entity_snapshot`
  - `changed_entities_sort`
  - `bump_entity_new_version`
  - `bump_entity_prev_version_link`
  - `ancestor_delta_propagation`
  - `add_event_return_payload`

### 21-2. 계측으로 확인한 사실
- `trace_attack_100k.jsonl` probe 기준
  - `graph_add_time_seconds`가 `hsg_update_time_seconds`보다 훨씬 컸다
  - 즉 이 시점 병목은 `hsg_update`보다 `graph.add_event(...)` 쪽이 더 지배적이었다
- 초반 grouped breakdown 기준
  - `versioning` 비중이 가장 컸고
  - 그 다음이 `edge_bookkeeping`
  - `semantic`과 `entity_identity`는 상대적으로 작았다
- 세부 split 이후에는
  - `bump_entity_prev_version_link`
  - `ancestor_delta_propagation`
  - `native_record_graph_event`
  가 눈에 띄는 hot path로 드러났다

### 21-3. 성공한 최적화
- `prev_version` edge에 대한 fast path 추가
  - 새 version node가 이전 version의 zero-cost ancestor state를 직접 계승
  - 매번 일반적인 ancestor delta propagation을 full로 돌리지 않게 변경
- 결과:
  - `graph_bump_entity_prev_version_link_time_seconds` 큰 폭 감소
  - `graph_ancestor_delta_propagation_time_seconds` 큰 폭 감소
  - `graph_add / hsg_update` 비율도 개선
- 판단:
  - 이 최적화는 유지 가치가 있다

### 21-4. 시도했지만 버린 최적화 1
- Rust native graph shadow 기록을 batch로 몰아서 호출하는 경로
- 의도:
  - Python -> Rust FFI 호출 횟수 감소
  - `native_record_graph_event` 비용 절감
- 결과:
  - 실제 probe에서 오히려 전체 처리량이 하락
  - native graph node/edge 수가 Python shadow와 어긋나는 구간도 관찰
- 판단:
  - 현재 구조에서는 No-Go
  - shadow consistency를 보장하는 전용 batch API 없이 재시도하지 않는다

### 21-5. 시도했지만 버린 최적화 2
- `flow_link -> DATA_FLOW edge`에 대한 direct ancestor merge fast path
- 의도:
  - `flow` edge에 대해 일반적인 delta BFS 대신
  - dst node 한정 direct merge로 `ancestor_delta_propagation` 비용 감소
- 결과:
  - `graph_flow_link_time_seconds`, `ancestor_delta_propagation_time_seconds` 자체는 줄었음
  - 그러나 전체 `events_per_second`는 오히려 악화
  - `graph_add_residual`도 커졌다
- 판단:
  - 표적 지표만 좋아지고 end-to-end 처리량이 나빠진 케이스
  - 현재 방식은 No-Go

### 21-6. 이번 실험에서 다시 확인한 운영 원칙
- local micro-metric 하나가 좋아졌다고 채택하면 안 된다
- 반드시 아래를 함께 본다
  1. `rolling_events_per_second_60s`
  2. `graph_add_time_seconds` / `hsg_update_time_seconds`
  3. native/python 정합성
  4. full trace 후반부 곡선 유지 여부
- 즉 "핫 함수 하나 빨라짐"보다
  "실제 end-to-end 처리량과 정합성이 함께 좋아졌는지"가 채택 기준이다

### 21-7. 지금 시점의 다음 우선순위
1. `graph_native_record_graph_event_time_seconds`를 줄이되 shadow consistency를 깨지 않는 방식 찾기
2. `graph_add_residual`이 다시 커지는 구간을 더 잘게 계측
3. `trace_attack_full.jsonl` 장시간 관찰에서 `27%` 이후 어떤 지표가 다시 치솟는지 확인

### 21-8. 냉정한 결론 업데이트
- 현재까지는 `hsg_update`보다 `graph.add_event(...)`가 더 큰 병목이다
- 그 안에서도 이미 `prev_version` 쪽은 한 번 의미 있게 줄였다
- 하지만 `native record`와 나머지 `graph_add residual`이 아직 남아 있다
- 따라서 다음 단계는
  - 무작정 새 fast path를 더 넣는 것이 아니라
  - "먹힌 최적화는 유지하고, 안 먹힌 최적화는 빨리 버리면서"
  - `graph add`의 남은 큰 덩어리를 더 정확히 자르는 쪽으로 가야 한다

## 22) Rust 메인 엔진 교체 진행도 점검

### 22-1. 한 줄 요약
- Rust 이관은 `메인 엔진 교체 직전`이 아니다
- 현재 상태는 `shadow/seam 단계가 꽤 진행된 상태`에 가깝다
- 체감상 진행도는 대략 `25~35%` 정도로 보는 것이 맞다

### 22-2. 이미 Rust 쪽으로 깔린 seam
- `NativeBatchEngine` 자체는 존재한다
- Python 쪽 backend seam도 이미 넓게 열려 있다
- 현재 Rust가 다루는 축은 크게 두 개다
  1. `graph shadow state`
  2. `online index shadow/read/prune seam`

### 22-3. Rust가 이미 할 수 있는 것
- event payload를 받아 native event로 변환
- native graph shadow state에 event 기록
- current version node 조회
- graph prune preview / apply
- online index edge 추가
- online match register / remove
- online mapper 계열 read 질의

즉, "Python 엔진이 돌고 있는 동안 Rust가 병렬 shadow state를 들고 있고",
일부 read/query/prune 계열은 이미 seam이 깔려 있는 상태다.

### 22-4. 아직 Rust가 메인 엔진이 아닌 이유
- `process_batch(...)`가 아직 authoritative path가 아니다
- 현재 Rust 구현은 batch를 받아 event payload를 읽고 카운트만 올린 뒤 `False`를 반환한다
- 그래서 Python runner는 Rust가 batch를 끝까지 소비했다고 판단하지 못하고
  결국 기존 Python `process_event(...)` 경로로 다시 내려간다

즉, "Rust batch 진입점은 있지만 실제 takeover는 아직 켜져 있지 않다"가 정확한 표현이다.

### 22-5. 아직 Python이 쥐고 있는 핵심 영역
- 실제 `process_event` 오케스트레이션
- matcher / rule semantics
- HSG builder / online state 업데이트의 본 처리
- score refresh / alerting
- batch 전체를 authoritative 하게 끝까지 처리하는 메인 loop

따라서 현재 Rust는 "보조 상태와 일부 조회 경로"는 맡고 있지만,
탐지 의미론과 최종 판정 흐름은 아직 Python이 소유하고 있다.

### 22-6. 지금 단계에서의 냉정한 판단
- Rust 이관은 `방향은 맞게 잡혔고 seam도 나쁘지 않게 깔린 상태`다
- 하지만 아직 가장 중요한 handoff, 즉
  `batch -> graph append -> online propagation -> candidate pruning -> score refresh`
  전체를 Rust가 authoritative 하게 소유하는 단계에는 도달하지 못했다
- 그래서 현 시점 표현은
  - "메인 엔진 교체가 많이 진행됐다" 보다는
  - "메인 엔진 교체를 위한 기반 seam이 꽤 쌓였다"가 더 정확하다

### 22-7. 다음 실제 마일스톤
1. `NativeBatchEngine.process_batch()`가 `True`를 반환할 수 있는 최소 의미 단위 정하기
2. 그 단위를 Python과 결과 동등성 비교로 고정하기
3. `graph append + online propagation`을 첫 authoritative ownership 후보로 올리기
4. 그 다음에 `candidate pruning / score refresh`를 Rust로 넘기기

### 22-8. CPU 최적화 관점에서의 의미
- 지금 성능 병목이 `graph.add_event(...)` 쪽에 더 가깝다는 점을 감안하면
  Rust 이관의 첫 실익도 `main engine 전체 교체`보다
  `graph append / online propagation hot path`를 authoritative 하게 넘기는 데서 먼저 나올 가능성이 크다
- 즉 Rust 이관도 "전부 한 번에 교체"보다
  `병목 hot path 우선 ownership 이전` 순서로 보는 것이 현실적이다

## 23) 2026-04-16 native_record split probe

### 23-1. 왜 다시 쪼갰는가
- `graph_native_record_graph_event_time_seconds`가 남은 병목 후보 중 하나였지만
  이 값만으로는
  - Python payload encode 비용인지
  - PyO3 / FFI 호출 비용인지
  - 그 외 wrapper overhead인지
  구분이 되지 않았다
- 그래서 계측을 아래처럼 추가 분해했다
  - `graph_native_record_payload_encode_time_seconds`
  - `graph_native_record_ffi_call_time_seconds`
  - `graph_native_record_overhead_time_seconds`
- 같이 residual 보정용으로
  - `graph_event_ts_parse_time_seconds`
  - `graph_entity_last_seen_update_time_seconds`
  - `graph_add_event_prep_time_seconds`
  도 노출했다

### 23-2. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 582.4`
  - `rolling_events_per_second_60s ≈ 583.1`
  - `graph_add_time_seconds ≈ 1.863`
  - `hsg_update_time_seconds ≈ 0.285`
  - `graph_add_residual_time_seconds ≈ 0.461`
  - `graph_native_record_graph_event_time_seconds ≈ 0.611`

### 23-3. split 해석
- `graph_native_record_graph_event_time_seconds ≈ 0.611` 내부 분해:
  - `payload_encode ≈ 0.015`
  - `ffi_call ≈ 0.579`
  - `overhead ≈ 0.018`
- 즉 native record 비용의 대부분은 `payload encode`가 아니라
  `실제 Python -> Rust FFI call` 쪽이다

### 23-4. residual 보정 해석
- 새로 분리한 `event prep`은
  - `event_ts_parse ≈ 0.0029`
  - `entity_last_seen_update ≈ 0.0055`
  - 합계 `graph_add_event_prep ≈ 0.0084`
- 비중상 매우 작다
- 즉 기존 residual의 주범이 `timestamp parse`나 `last_seen update`였던 것은 아니다

### 23-5. 지금 시점 결론
- `native_record`는 더 쪼개보니
  - `payload encode` 최적화 우선순위는 낮고
  - `FFI call` 감소 또는 ownership 이전이 더 본질적인 해법이다
- `event prep`은 residual 설명력이 작으므로
  다음 residual 분해 타겟은 다른 Python-side bookkeeping이어야 한다

### 23-6. 다음 액션 업데이트
1. `graph_native_record_graph_event_time_seconds`는 micro-encode 최적화보다 `FFI call 수/경계` 축소 관점으로 본다
2. `graph_add_residual`은 `path_factor_cache clear`, `current_version lookup`, return payload 주변 외 나머지 bookkeeping을 더 의심한다
3. Rust 이관도 "전체 메인 엔진 교체"보다 `graph append hot path ownership 이전`을 더 직접적인 성능 목표로 본다

## 24) 2026-04-16 lookup/meta residual 보정

### 24-1. 무엇을 추가했는가
- 기존에 이미 개별 지표로 있던 아래 시간을
  `graph_add` grouped breakdown에도 반영했다
  - `graph_current_version_lookup_time_seconds`
  - `graph_semantic_current_version_lookup_time_seconds`
  - `graph_node_meta_time_seconds`
- 새 grouped metric 이름:
  - `graph_add_lookup_meta_time_seconds`

### 24-2. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 581.1`
  - `graph_add_time_seconds ≈ 1.859`
  - `graph_add_lookup_meta_time_seconds ≈ 0.032`
  - `graph_add_lookup_meta_share ≈ 1.72%`
  - `graph_add_event_prep_time_seconds ≈ 0.0084`
  - `graph_add_residual_time_seconds ≈ 0.444`
  - `graph_add_residual_share ≈ 23.9%`

### 24-3. 해석
- `lookup/meta`는 분명 residual 일부를 설명하지만
  비중이 `~1.7%` 수준이라 핵심 덩어리라고 보기 어렵다
- 세부 분해:
  - `semantic_current_version_lookup ≈ 0.0164`
  - `node_meta ≈ 0.0082`
  - `current_version_lookup ≈ 0.0074`
- 즉 현재 residual의 큰 몫은
  `lookup/meta`를 추가로 집계한 뒤에도 여전히 남아 있다

### 24-4. 지금 시점 결론
- `native_record`는 여전히 `FFI call`이 지배적이다
- `event prep`도 작고
- `lookup/meta`도 작다
- 따라서 다음 residual 분해는
  단순 lookup류보다 `add_event` 본문 안의 나머지 Python bookkeeping 경로를 더 직접적으로 잘라야 한다

## 25) 2026-04-16 local bookkeeping residual 보정

### 25-1. 무엇을 추가했는가
- `add_event()` 안의 매우 로컬한 Python bookkeeping을 따로 분리했다
  - `graph_memory_semantic_rewrite_time_seconds`
  - `graph_changed_entities_finalize_time_seconds`
  - `graph_event_endpoint_resolve_time_seconds`
- grouped breakdown에는
  - `graph_add_local_bookkeeping_time_seconds`
  로 묶어 반영했다

### 25-2. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 571.7`
  - `graph_add_time_seconds ≈ 1.903`
  - `graph_add_local_bookkeeping_time_seconds ≈ 0.0202`
  - `graph_add_local_bookkeeping_share ≈ 1.06%`
  - `graph_add_lookup_meta_time_seconds ≈ 0.0321`
  - `graph_add_event_prep_time_seconds ≈ 0.0090`
  - `graph_add_residual_time_seconds ≈ 0.433`
  - `graph_add_residual_share ≈ 22.8%`

### 25-3. 세부 해석
- `memory_semantic_rewrite ≈ 0.0`
  - 이번 20k 입력에는 memory-object rewrite가 사실상 없었다
- `changed_entities_finalize ≈ 0.0138`
- `event_endpoint_resolve ≈ 0.0063`
- 즉 local bookkeeping은 분명 존재하지만
  residual의 큰 덩어리라고 보기에는 비중이 작다

### 25-4. 지금 시점 결론
- `native_record`는 여전히 `FFI call`이 지배적이다
- `event prep`, `lookup/meta`, `local bookkeeping`까지 묶어도 residual이 크게 남는다
- 따라서 다음 residual 분해는
  단순 dict/set 후처리보다
  `graph.add_event(...)` 바깥에서 함께 잡히는 상위 호출 구간이나
  `link/bump/native shadow` 경계 밖의 측정 누락 가능성까지 의심해야 한다

## 26) 2026-04-16 runner boundary 재분해

### 26-1. 왜 상위 경계를 다시 봤는가
- 지금까지 `graph_add_time_seconds`를 사실상 `graph.add_event(...)` 비용처럼 해석해 왔지만
  실제 runner 코드를 보면 이 시간 안에
  `self._flush_pending_online_graph_edges()`도 함께 들어가 있었다
- 즉 이 값은 순수 graph core만이 아니라
  `graph core + runner-side online edge flush` 합이었다

### 26-2. 추가한 grouped metric
- `graph_add_core_time_seconds`
- `graph_add_runner_overhead_time_seconds`

여기서 `runner_overhead`는 현재 `online_graph_edge_flush`와 동일하다.

### 26-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 581.9`
  - `graph_add_time_seconds ≈ 1.889`
  - `graph_add_core_time_seconds ≈ 1.462`
  - `graph_add_runner_overhead_time_seconds ≈ 0.428`
  - `graph_add_runner_overhead_share ≈ 22.6%`
  - `graph_add_residual_time_seconds ≈ 0.424`
  - `graph_native_record_ffi_call_time_seconds ≈ 0.592`

### 26-4. 해석
- 지금까지 residual처럼 보이던 것 중 큰 조각 하나는
  사실 `graph.add_event(...)` 내부가 아니라
  runner의 `online_graph_edge_flush`였다
- 즉 `graph_add_time_seconds`를 그대로 graph 내부 residual로 읽으면 과대해석이 된다
- 분리 후에도 남는 `core` residual은 여전히 존재하지만
  적어도 이제 "graph 내부"와 "runner flush"를 혼동하지 않게 되었다

### 26-5. 지금 시점 결론
- `native_record`는 `FFI call`이 크다
- `graph_add_time`의 약 `22~23%`는 runner-side flush다
- 따라서 다음 최적화 우선순위는 두 갈래다
  1. `native_record`의 호출 경계 축소 또는 ownership 이전
  2. `online_graph_edge_flush` 자체 최적화 또는 flush 빈도/경계 재설계

## 27) 2026-04-16 online_graph_edge_flush split

### 27-1. 왜 더 쪼갰는가
- `graph_add_runner_overhead_time_seconds`가 꽤 크게 나왔지만
  그 안에서도
  - Python `online_index.on_edge_added(...)`
  - native shadow `add_online_edge(...)`
  - 마지막 `flush_pending_edges()/native flush()`
  중 어디가 큰지는 아직 몰랐다

### 27-2. 추가한 지표
- `online_graph_edge_flush_python_apply_time_seconds`
- `online_graph_edge_flush_native_add_time_seconds`
- `online_graph_edge_flush_flush_call_time_seconds`

### 27-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 564.0`
  - `graph_add_runner_overhead_time_seconds ≈ 0.4455`
  - `graph_add_runner_overhead_share ≈ 23.7%`
  - `online_graph_edge_flush_python_apply_time_seconds ≈ 0.0609`
  - `online_graph_edge_flush_native_add_time_seconds ≈ 0.0`
  - `online_graph_edge_flush_flush_call_time_seconds ≈ 0.3665`

### 27-4. 해석
- runner-side flush 비용의 대부분은 `per-edge Python apply`보다
  `flush_pending_edges()` 쪽에 몰려 있다
- 이번 측정에서 `native_add_time`이 `0.0`인 것은
  online native shadow add 경로가 이 설정에서는 사실상 꺼져 있었기 때문이다
- 따라서 현재 hot spot은
  "edge를 하나씩 넣는 loop"보다
  "flush 시점의 propagation/정리" 쪽이라고 보는 편이 맞다

### 27-5. 지금 시점 결론
- `graph add` 계열에서 남은 큰 축은 두 개다
  1. `graph_native_record`의 `FFI call`
  2. `online_graph_edge_flush` 내부의 `flush_pending_edges()`
- 다음 최적화는
  `online_index.flush_pending_edges()` 자체를 더 자르거나
  flush cadence/batch 정책을 바꾸는 쪽이 우선이다

## 28) 2026-04-16 flush_pending_edges 내부 split

### 28-1. 왜 더 쪼갰는가
- `online_graph_edge_flush` 내부에서 큰 축이 `flush_pending_edges()`라는 것까지는 확인했다
- 하지만 그 안에서도
  - 배치 루프/호출 관리가 큰지
  - 실제 propagation 본체가 큰지
  는 아직 분리되지 않았다

### 28-2. 추가한 지표
- `online_index_flush_pending_edges_total_time_seconds`
- `online_index_flush_pending_edges_loop_time_seconds`
- `online_index_flush_pending_edges_propagate_time_seconds`
- `online_index_flush_pending_edges_batch_count`
- `online_index_flush_pending_edges_edge_count`

### 28-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 584.7`
  - `online_graph_edge_flush_time_seconds ≈ 0.4641`
  - `online_graph_edge_flush_flush_call_time_seconds ≈ 0.3833`
  - `online_index_flush_pending_edges_total_time_seconds ≈ 0.3713`
  - `online_index_flush_pending_edges_loop_time_seconds ≈ 0.3600`
  - `online_index_flush_pending_edges_propagate_time_seconds ≈ 0.3538`
  - `batch_count = 13,694`
  - `edge_count = 27,388`

### 28-4. 해석
- `flush_pending_edges()` 비용의 거의 전부는 실제 propagation 본체다
- loop/batch 관리 오버헤드는 상대적으로 매우 작다
- 즉 지금 병목은
  "flush를 호출하는 프레임" 자체보다
  "새 edge가 들어올 때 mapper delta를 downstream으로 전파하는 알고리즘" 쪽에 있다

### 28-5. 지금 시점 결론
- `graph add` hot path에서 남은 큰 축은 이제 더 명확하다
  1. `graph_native_record`의 `FFI call`
  2. `online_index.flush_pending_edges()` 내부의 propagation
- 따라서 다음 작업은
  `flush cadence`만 만지는 실험보다
  propagation 범위/빈도/trigger 자체를 줄일 수 있는지 보는 쪽이 더 직접적이다

## 29) 2026-04-16 propagation 내부 split

### 29-1. 왜 다시 쪼갰는가
- `flush_pending_edges()` 내부 비용이 propagation 본체라는 것은 확인했다
- 하지만 propagation 안에서도
  - 새 edge가 들어왔을 때 `dst`에 한 번 seed merge 하는 비용
  - 그 뒤 downstream으로 delta BFS를 퍼뜨리는 비용
  중 어디가 더 큰지는 아직 분리되지 않았다

### 29-2. 추가한 지표
- `online_index_propagate_across_new_edge_seed_merge_time_seconds`
- `online_index_propagate_across_new_edge_downstream_time_seconds`
- `online_index_propagate_across_new_edge_changed_match_total`
- `online_index_propagate_delta_time_seconds`
- `online_index_propagate_delta_queue_pop_count`
- `online_index_propagate_delta_edge_visit_count`
- `online_index_propagate_delta_changed_enqueue_count`

### 29-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 583.5`
  - `online_index_flush_pending_edges_propagate_time_seconds ≈ 0.3589`
  - `seed_merge ≈ 0.2492`
  - `downstream_time ≈ 0.0293`
  - `changed_match_total = 82,491`
  - `queue_pop_count = 60,495`
  - `edge_visit_count = 84,437`
  - `changed_enqueue_count = 49,991`
  - `depth_cutoff_total = 1,782`
  - `fanout_cutoff_total = 0`

### 29-4. 해석
- flush 경로 기준으로는 downstream BFS보다
  `new-edge seed merge` 쪽이 더 큰 축으로 보인다
- 즉 새 edge가 생길 때 `src_mapper.match_ids`를 전부 훑으며
  `dst_mapper`에 merge하는 단계가 현재 더 비싸다
- 주의:
  `online_index_propagate_delta_time_seconds`는 flush 경로뿐 아니라
  `on_match_added()`에서 쓰는 propagation도 함께 누적되므로
  flush 전용 해석은 `seed_merge`와 `downstream_time`을 우선 본다

### 29-5. 지금 시점 결론
- `online_index.flush_pending_edges()` 최적화의 1순위는
  BFS 후단보다 `new-edge seed merge` 부담을 줄이는 쪽이다
- 즉 다음 실험은
  - edge 추가 시 항상 full `src_mapper.match_ids`를 훑지 않게 만들 수 있는지
  - 또는 flush trigger/cadence를 조정해 seed merge 호출 횟수를 줄일 수 있는지
  를 보는 쪽이 맞다

## 30) 2026-04-16 seed merge scanned vs changed

### 30-1. 왜 이 비율을 봤는가
- `seed_merge`가 큰 축이라는 것은 확인했지만
  이게
  - "대부분 scan이 실제 변화로 이어지는 비싼 필수 작업"인지
  - "많이 훑지만 실제 변경은 적은 낭비성 작업"인지
  는 따로 봐야 했다

### 30-2. 추가한 지표
- `online_index_propagate_across_new_edge_scanned_match_total`
- `online_index_propagate_across_new_edge_changed_match_total`
- `online_index_propagate_across_new_edge_changed_match_ratio`
- `online_index_propagate_across_new_edge_empty_src_count`
- `online_index_propagate_across_new_edge_no_change_count`

### 30-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 결과:
  - `events_per_second ≈ 572.9`
  - `seed_merge_time ≈ 0.2534`
  - `scanned_match_total = 144,554`
  - `changed_match_total = 82,491`
  - `changed_match_ratio ≈ 0.571`
  - `empty_src_count = 9,331`
  - `no_change_count = 7,659`
  - `flush_edge_count = 27,388`

### 30-4. 해석
- seed merge는 "거의 다 헛수고" 타입은 아니다
  - 스캔한 match 중 약 `57%`는 실제 변경으로 이어졌다
- 하지만 동시에
  - `empty_src` edge도 많고
  - 스캔은 했지만 `no_change`로 끝나는 edge도 적지 않다
- 즉 최적화 방향은
  "merge 자체를 없앤다" 보다는
  "seed merge를 호출할 edge 수를 줄이거나, 의미 없는 호출을 더 빨리 걸러낸다" 쪽이 더 현실적이다

### 30-5. 지금 시점 결론
- 다음 실험 우선순위는
  1. `empty_src` / `no_change` 경로를 더 줄일 수 있는 trigger 조건 탐색
  2. `flush cadence`를 바꿔 seed merge 호출 횟수를 줄이는지 확인
  3. 그 다음에야 merge 내부 미세 최적화를 고민

## 31) 2026-04-16 flush cadence 정책 실험

### 31-1. 무엇을 넣었는가
- 실험용 env policy 추가:
  - `HOLMES_ONLINE_GRAPH_EDGE_FLUSH_POLICY=immediate|match_driven`
  - `HOLMES_ONLINE_GRAPH_EDGE_FLUSH_MAX_PENDING_EDGES`
- `match_driven` 모드에서는
  - 현재 이벤트에 `raw_match`가 있으면 flush
  - 또는 pending edge가 임계치 이상이면 flush
  - 아니면 flush를 미룬다
- snapshot/write 시점에는 강제 flush해서 상태 일관성을 유지한다

### 31-2. 비교 기준
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 비교:
  1. `immediate`
  2. `match_driven` with `HOLMES_ONLINE_GRAPH_EDGE_FLUSH_MAX_PENDING_EDGES=2048`

### 31-3. 결과
- `immediate`
  - `events_per_second ≈ 579.54`
  - `online_graph_edge_flush_call_count = 13,694`
  - `online_graph_edge_flush_time_seconds ≈ 0.4666`
  - `seed_merge_time ≈ 0.2493`
- `match_driven`
  - `events_per_second ≈ 582.18`
  - `online_graph_edge_flush_call_count = 7,007`
  - `online_graph_edge_flush_skipped_count = 13,602`
  - `online_graph_edge_flush_forced_count = 6,915`
  - `online_graph_edge_flush_match_driven_count = 92`
  - `online_graph_edge_flush_time_seconds ≈ 0.4716`
  - `seed_merge_time ≈ 0.2150`

### 31-4. 해석
- `match_driven`은 flush 호출 수를 거의 절반으로 줄였다
- `seed_merge_time`도 함께 감소했다
- `events_per_second`는 소폭이지만 개선됐다
- 다만 개선 폭은 크지 않았고
  강제 flush 비중이 아직 높아서
  "좋은 방향이긴 하지만 결정타는 아닌" 수준이다

### 31-5. 지금 시점 결론
- `flush cadence` 조정은 No-Go가 아니라 `소규모 Positive`다
- 즉 바로 폐기할 실험은 아니다
- 다음 단계는
  1. 왜 `forced_count`가 높은지 줄일 수 있는지 보기
  2. `max_pending_edges` 값을 더 키우거나 줄였을 때 EPS/정합성 곡선이 어떻게 바뀌는지 보기
  3. 여전히 더 큰 축인 `native_record FFI call`과 함께 우선순위 비교하기

## 32) 2026-04-16 match_driven threshold sweep

### 32-1. 무엇을 비교했는가
- `HOLMES_ONLINE_GRAPH_EDGE_FLUSH_POLICY=match_driven`
- `HOLMES_ONLINE_GRAPH_EDGE_FLUSH_MAX_PENDING_EDGES`
  - `256`
  - `512`
  - `2048`
  - `8192`

입력은 동일하게 `trace_attack_20k_probe.jsonl`, backend는 `HOLMES_NATIVE_BACKEND=rust`.

### 32-2. 결과 요약
- `256`
  - `EPS ≈ 570.36`
  - `flush_call_count = 7007`
  - `forced_count = 6915`
  - `threshold_count = 0`
- `512`
  - `EPS ≈ 580.47`
  - `flush_call_count = 7007`
  - `forced_count = 6915`
  - `threshold_count = 0`
- `2048`
  - `EPS ≈ 585.36`
  - `flush_call_count = 7007`
  - `forced_count = 6915`
  - `threshold_count = 0`
- `8192`
  - `EPS ≈ 586.85`
  - `flush_call_count = 7007`
  - `forced_count = 6915`
  - `threshold_count = 0`

### 32-3. 해석
- 이번 sweep에서 `max_pending_edges`는 사실상 거의 작동하지 않았다
- 근거:
  - 모든 값에서 `threshold_count = 0`
  - `flush_call_count`, `forced_count`, `match_driven_count`도 동일
- 즉 현재 `match_driven` 정책의 실제 flush trigger는
  `threshold`가 아니라 거의 전적으로 `forced flush` 경로다
- 따라서 threshold 값을 더 만지는 것은 지금 단계에서 우선순위가 낮다

### 32-4. 추가 관찰
- `256`은 오히려 느렸고
- `2048`와 `8192`는 비슷하며 `8192`가 가장 높게 나왔지만
  trigger 구성이 동일하므로 이 차이는 미세 노이즈에 가깝게 보는 편이 안전하다

### 32-5. 지금 시점 결론
- 다음으로 풀어야 할 것은 `max_pending_edges`가 아니라 `forced_count`의 원인이다
- 즉 다음 실험은
  - 어떤 조건에서 `force=True`가 자주 발생하는지 세분화
  - 그 강제 flush 중 일부를 더 미룰 수 있는지 검토
  - 아니면 강제 flush 경로 자체를 더 싸게 만들 수 있는지 보는 쪽이 맞다

## 33) 2026-04-16 native graph shadow deferred batch

### 33-1. 무엇을 바꿨는가
- `graph.add_event()`에서 native graph shadow를 매 이벤트마다 즉시 `record_graph_event(...)` 하지 않고
  payload를 pending queue에 쌓도록 변경했다
- 아래 시점에서만 batch flush 하도록 바꿨다
  - native `current_version` shadow check 직전
  - native prune preview/apply 직전
  - metrics / snapshot 작성 직전
- backend seam도 `record_graph_payloads(...)`를 추가해서
  payload snapshot을 그대로 batch FFI 호출할 수 있게 했다

### 33-2. 왜 이렇게 했는가
- 이전 계측에서 `native_record` 비용의 대부분이 payload encode가 아니라
  `Python -> Rust FFI call` 자체였다
- 그래서 "매 이벤트마다 한 번"보다
  "필요한 시점까지 모아두고 덜 자주 보낸다"가 더 직접적인 해법이었다

### 33-3. 짧은 Rust probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- flush policy: `immediate`
- 결과:
  - `events_per_second ≈ 589.5`
  - `graph_native_record_graph_event_time_seconds ≈ 0.4507`
  - `graph_native_record_ffi_call_time_seconds ≈ 0.4478`
  - `graph_native_record_event_count = 13,694`
  - `graph_native_record_ffi_call_count = 2,000`
  - `avg_events_per_ffi_call ≈ 6.85`

### 33-4. 비교 해석
- 이전 immediate 기준 probe에서는
  - `events_per_second ≈ 579.5`
  - `graph_native_record_ffi_call_time_seconds ≈ 0.5868`
  수준이었다
- 이번 deferred batch에서는
  - `FFI call time`이 줄었고
  - `EPS`도 함께 상승했다
- 즉 이번 변경은
  단순 metric 이동이 아니라 실제 처리량 개선까지 동반한 `Positive`로 볼 수 있다

### 33-5. 지금 시점 결론
- `native_record FFI call` 축은
  "호출 자체를 덜 자주 하게 만드는 것"이 실제로 먹힌다
- 따라서 이 방향은 유지 가치가 있다
- 다음은
  1. `match_driven flush`와 함께 썼을 때도 이득이 유지되는지 보기
  2. batch flush 경계가 너무 자주 열리는 지점을 더 줄일 수 있는지 보기

## 34) 2026-04-16 deferred native batch + match_driven 조합

### 34-1. 비교 대상
- `deferred native graph shadow batch`만 적용
- `match_driven flush`만 적용
- 두 개를 함께 적용

입력은 동일하게 `trace_attack_20k_probe.jsonl`, backend는 `HOLMES_NATIVE_BACKEND=rust`.

### 34-2. 조합 probe 결과
- `events_per_second ≈ 584.20`
- `graph_native_record_ffi_call_time_seconds ≈ 0.4512`
- `graph_native_record_ffi_call_count = 2000`
- `avg_events_per_ffi_call ≈ 6.85`
- `online_graph_edge_flush_time_seconds ≈ 0.6730`
- `online_graph_edge_flush_call_count = 7007`
- `online_graph_edge_flush_skipped_count = 13602`
- `online_graph_edge_flush_forced_count = 6915`
- `online_index_propagate_across_new_edge_seed_merge_time_seconds ≈ 0.4093`

### 34-3. 해석
- `deferred native batch` 쪽 이득은 유지된다
  - `FFI call count`는 낮게 유지됨
  - `FFI call time`도 낮은 편임
- 하지만 `match_driven flush`를 함께 켰을 때
  `online_graph_edge_flush`와 `seed_merge`가 다시 커졌다
- 결과적으로 조합 전체는
  - `deferred only`보다는 나쁘고
  - `match_driven only`보다는 비슷하거나 약간 낫지만
  - "둘의 이득이 예쁘게 합쳐진다" 수준은 아니다

### 34-4. 지금 시점 결론
- `deferred native graph shadow batch`는 유지 가치가 있다
- `match_driven flush`는 단독으로는 small positive였지만
  현재 조합 형태로는 우선 유지할 강한 근거가 부족하다
- 따라서 다음 운영 판단은
  1. `deferred native batch`는 유지
  2. `match_driven flush`는 실험 브랜치/옵션으로만 두고 기본값 채택은 보류

## 35) 2026-04-16 seed merge hotspot profiling

### 35-1. 무엇을 추가했는가
- `seed merge`를 아래 축으로 더 분해했다
  - edge type별
    - `data_flow`
    - `version_transition`
  - `src_mapper.match_ids` 크기 bucket별
    - `1`
    - `2~4`
    - `5~16`
    - `17~64`
    - `65+`

### 35-2. 기준 probe
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 운영 기준: `deferred native graph shadow batch + immediate flush`

### 35-3. 결과
- 전체 `seed_merge_time ≈ 0.2649`
- edge type별:
  - `data_flow_time ≈ 0.1316`
  - `data_flow_scanned = 80,881`
  - `data_flow_changed = 18,818`
  - `version_transition_time ≈ 0.1333`
  - `version_transition_scanned = 63,673`
  - `version_transition_changed = 63,673`
- bucket별:
  - `1`: `time ≈ 0.0016`, `scanned = 480`
  - `2~4`: `time ≈ 0.1153`, `scanned = 51,760`
  - `5~16`: `time ≈ 0.0140`, `scanned = 7,810`
  - `17~64`: `time ≈ 0.1339`, `scanned = 84,504`
  - `65+`: 사실상 `0`

### 35-4. 해석
- `version_transition`은 스캔한 만큼 거의 전부 changed로 이어진다
  - 즉 이쪽은 낭비성 호출보다는 "필수 비용"에 가깝다
- `data_flow`는 scanned 대비 changed 비율이 낮다
  - 즉 이쪽은 "많이 훑지만 실제 변화는 적은" 구간이 섞여 있다
- 크기 bucket 기준으로는
  - `17~64`가 가장 큰 시간 덩어리
  - 그 다음이 `2~4`
- 반대로 `65+`는 이번 입력에선 거의 없었다

### 35-5. 지금 시점 결론
- 다음 최적화 우선순위는
  1. `data_flow` seed merge에서 changed 비율이 낮은 경로를 더 줄이는 것
  2. 특히 `src match size 17~64` 구간을 먼저 타겟으로 보는 것
- 즉 지금은 "아주 큰 fan-out"보다
  "중간 크기 mapper가 자주 등장하는 구간"이 더 중요한 병목이다

## 36) 2026-04-16 empty-dst seed merge fast path

### 36-1. 무엇을 바꿨는가
- `dst mapper`가 완전히 비어 있는 경우
  기존처럼 match별 `_merge_match_from_src(...)`를 반복하지 않고
  `src mapper` 상태를 bulk copy로 채우는 fast path를 추가했다
- edge cost가
  - `0`이면 hops를 그대로 복사
  - `1`이면 hops만 `+1` 해서 복사

### 36-2. 왜 안전한가
- `dst`가 비어 있을 때는
  기존 merge가 결국 "src 상태를 dst에 처음 심는" 작업이므로
  bulk copy로도 의미를 보존할 수 있다
- 기존의 per-match merge와 같은 결과를 더 싼 방식으로 만드는 최적화다

### 36-3. 기준 probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 운영 기준: `deferred native graph shadow batch + immediate flush`
- 결과:
  - `events_per_second ≈ 582.54`
  - `seed_merge_time ≈ 0.1768`
  - `empty_dst_fast_path_count = 10,385`
  - `empty_dst_fast_path_time ≈ 0.0671`
  - `version_transition_seed_merge_time ≈ 0.0588`
  - `data_flow_seed_merge_time ≈ 0.1181`
  - `online_graph_edge_flush_time_seconds ≈ 0.4310`
  - `graph_native_record_ffi_call_time_seconds ≈ 0.4379`

### 36-4. 비교 해석
- 이전 hotspot probe 기준
  - `seed_merge_time ≈ 0.2649`
  - `version_transition_seed_merge_time ≈ 0.1333`
  - `data_flow_seed_merge_time ≈ 0.1316`
- 이번 fast path 이후
  - `seed_merge_time`가 큰 폭 감소
  - 특히 `version_transition`이 의미 있게 줄었다
  - `data_flow`도 소폭 감소했다
- 즉 이 최적화는
  "empty dst로 들어가는 seed merge"를 안전하게 싸게 만든 케이스로 볼 수 있다

### 36-5. 지금 시점 결론
- 이 fast path는 유지 가치가 있다
- 다음 타겟은 더 좁혀진다
  - `version_transition`은 한 번 크게 줄였고
  - 이제 남은 상대적 우선순위는 `data_flow seed merge`, 특히 `17~64 bucket`

## 37) 2026-04-16 match_id -> rule_id direct lookup

### 37-1. 무엇을 바꿨는가
- `NodeMapper`에 `rule_id_by_match`를 추가했다
- 기존 `_merge_match_from_src()`는
  match 하나를 처리할 때마다 `src.match_ids_by_rule` 전체를 훑으며
  어느 rule bucket에 속하는지 찾고 있었다
- 이를 `match_id -> rule_id` direct lookup으로 바꿔
  per-match rule scan을 제거했다

### 37-2. 왜 이게 타겟이었는가
- 앞선 profiling에서
  - `data_flow seed merge`
  - 특히 `17~64 bucket`
  이 남은 상대적 hot spot으로 보였다
- 이 구간은 per-match overhead 감소가 직접적으로 먹힐 가능성이 높았다

### 37-3. 기준 probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 운영 기준: `deferred native graph shadow batch + immediate flush`
- 결과:
  - `events_per_second ≈ 579.82`
  - `seed_merge_time ≈ 0.1695`
  - `data_flow_seed_merge_time ≈ 0.1077`
  - `version_transition_seed_merge_time ≈ 0.0618`
  - `bucket_17_64_time ≈ 0.0691`
  - `online_graph_edge_flush_time_seconds ≈ 0.4263`
  - `graph_native_record_ffi_call_time_seconds ≈ 0.4423`

### 37-4. 비교 해석
- 직전 `empty-dst fast path` 기준
  - `seed_merge_time ≈ 0.1768`
  - `data_flow_seed_merge_time ≈ 0.1181`
  - `bucket_17_64_time ≈ 0.1339`
- 이번 direct lookup 이후
  - `seed_merge_time` 추가 감소
  - `data_flow_seed_merge_time` 감소
  - `17~64 bucket` 시간이 크게 감소
- 즉 이번 최적화는
  우리가 노리고 있던 `data_flow / 17~64` 구간에 실제로 맞아 들어간다

### 37-5. 지금 시점 결론
- 이 최적화도 유지 가치가 있다
- 현재까지 online flush 쪽에서는
  1. `empty-dst fast path`
  2. `match_id -> rule_id direct lookup`
  두 개가 모두 의미 있게 먹혔다
- 다음 상대적 우선순위는
  `data_flow seed merge`의 남은 no-change / low-yield 경로를 더 줄이는 쪽이다

## 38) 2026-04-16 data_flow no-change precheck

### 38-1. 무엇을 바꿨는가
- `DATA_FLOW` edge에서만
  merge loop 전에 cheap precheck를 추가했다
- 조건:
  - `dst`가 이미 `src.match_ids`를 모두 가지고 있고
  - rule별 earliest sequence도 더 나쁘지 않고
  - origin별 hops도 이미 같거나 더 좋으면
  이번 edge는 merge해도 변할 것이 없다고 보고
  seed merge loop를 건너뛴다

### 38-2. 기준 probe 결과
- 입력: `trace_attack_20k_probe.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- 운영 기준: `deferred native graph shadow batch + immediate flush`
- 결과:
  - `events_per_second ≈ 578.35`
  - `seed_merge_time ≈ 0.1651`
  - `data_flow_seed_merge_time ≈ 0.1025`
  - `bucket_17_64_time ≈ 0.0628`
  - `data_flow_precheck_time ≈ 0.0671`
  - `data_flow_precheck_count = 7,672`
  - `data_flow_precheck_hit_count = 7,659`
  - `data_flow_precheck_hit_ratio ≈ 0.9983`

### 38-3. 해석
- precheck는 거의 완벽하게 no-change edge를 맞힌다
  - hit ratio가 `~99.8%`
- seed merge hot metric도 조금 더 줄었다
  - `data_flow`
  - `17~64 bucket`
  쪽 모두 추가 감소
- 다만 이번 20k 기준 `EPS`는 직전 direct-lookup probe와 비슷한 수준이라
  "큰 처리량 승리"라고 단정할 정도는 아니다

### 38-4. 지금 시점 결론
- 이 precheck는 구조적으로는 좋은 최적화다
  - no-change edge를 거의 정확히 거른다
  - hot metric도 추가로 줄인다
- 하지만 end-to-end 이득은 아직 소폭이라
  채택 여부는 `100k` 이상 재측정으로 보는 편이 안전하다

## 39) 현재 유지/보류 정리

### 39-1. 지금 유지할 최적화
- `prev_version` fast path
  - 새 version node가 이전 version의 zero-cost ancestor state를 직접 계승
  - `ancestor propagation`과 `prev_version link` 비용을 실제로 줄였다
- `deferred native graph shadow batch`
  - native graph shadow를 매 이벤트 즉시 기록하지 않고
    필요 시점 직전에 batch flush
  - `native_record FFI call` 감소와 end-to-end EPS 개선이 함께 확인됐다
- `empty-dst seed merge fast path`
  - `dst mapper`가 비어 있을 때 bulk copy로 채움
  - 특히 `version_transition` seed merge 시간을 크게 줄였다
- `match_id -> rule_id direct lookup`
  - per-match rule bucket scan 제거
  - `data_flow seed merge`, 특히 `17~64 bucket` 감소에 실제로 기여했다
- 세부 계측 전반
  - `graph_add` grouped breakdown
  - `native_record split`
  - `runner boundary split`
  - `flush_pending_edges split`
  - `seed merge hotspot profiling`
  - 이건 최적화 자체는 아니지만 지금 단계에선 유지 가치가 크다

### 39-2. 기본값 채택 보류
- `data_flow no-change precheck`
  - 구조적으로는 좋은 최적화이고 no-change edge를 거의 정확히 맞힌다
  - 다만 20k 기준 end-to-end EPS 개선폭은 아직 작다
  - 따라서 기본 채택 여부는 `100k` 이상에서 다시 판단
- `match_driven flush policy`
  - 단독으로는 small positive였음
  - 하지만 `deferred native batch`와 조합했을 때 이득이 예쁘게 합쳐지지 않았다
  - 기본값으로 켜기보다 실험 옵션으로만 유지하는 편이 안전

### 39-3. 보류/폐기한 실험
- Rust native graph shadow batch record의 초기 시도 버전
  - shadow consistency 이슈와 성능 악화로 No-Go
  - 지금 유지 중인 deferred batch는 이 실패 실험과 다르며, payload snapshot 기반의 안전한 형태다
- `flow -> DATA_FLOW` direct merge fast path
  - 표적 metric은 좋아졌지만 end-to-end 처리량이 나빠져 No-Go
- 단순 native record batch화 초기안
  - 구조 일관성 없이 FFI 호출만 줄이려던 접근은 폐기

### 39-4. 현재 우선순위
1. 유지할 최적화들로 `100k` 재측정
2. `data_flow no-change precheck`의 채택 여부를 장거리 실측으로 판단
3. 여전히 남는 병목이 있으면
   - `data_flow seed merge`
   - `forced flush` 경로
   - 그다음 Rust ownership 확대

### 39-5. 한 줄 결론
- 지금 당장은
  `deferred native batch + empty-dst fast path + direct lookup`
  조합은 유지
- `match_driven flush`와 `data_flow no-change precheck`는
  `100k` 재측정 전까지는 실험 상태로 둔다

## 40) 2026-04-16 keep set 기준 100k 재측정

### 40-1. 측정 조건
- 입력: `HOLMES/tmp/trace_attack_100k.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- flush policy: 기본값 `immediate`
- snapshot: 중간 snapshot 없이 최종 snapshot만 기록
- 이번 keep set 포함 항목:
  - `deferred native graph shadow batch`
  - `empty-dst seed merge fast path`
  - `match_id -> rule_id direct lookup`
  - `data_flow no-change precheck`

### 40-2. 결과
- `events_per_second ≈ 2715.52`
- `rolling_events_per_second_60s ≈ 2723.22`
- `graph_add_time_seconds ≈ 5.861`
- `hsg_update_time_seconds ≈ 0.550`
- `graph_add / hsg_update ≈ 10.66x`
- `graph_native_record_ffi_call_time_seconds ≈ 2.044`
- `graph_native_record_ffi_call_count = 100`
- `graph_native_record_avg_events_per_ffi_call ≈ 776.15`
- `online_graph_edge_flush_time_seconds ≈ 2.306`
- `online_graph_edge_flush_flush_call_time_seconds ≈ 1.822`
- `online_graph_edge_flush_call_count = 77,615`
- `seed_merge_time ≈ 0.815`
- `data_flow_seed_merge_time ≈ 0.417`
- `version_transition_seed_merge_time ≈ 0.398`
- `bucket_17_64_time ≈ 0.156`
- `data_flow_precheck_count = 55,085`
- `data_flow_precheck_hit_count = 55,066`
- `data_flow_precheck_hit_ratio ≈ 0.99966`
- `empty_dst_fast_path_count = 73,193`
- `empty_dst_fast_path_time ≈ 0.392`

### 40-3. 해석
- 20k에서 보던 병목 구조는 100k에서도 그대로 유지된다
  - 가장 큰 축은 여전히 `graph_add`
  - 그 안에서 큰 비중은 `native_record FFI`와 `online_graph_edge_flush`
- `deferred native batch`는 장거리에서도 의미가 있다
  - `FFI call_count = 100`
  - `avg_events_per_ffi_call ≈ 776`
  - 즉 per-event 호출로 되돌아가지 않고 batch 효과가 유지된다
- `data_flow no-change precheck`는 장거리에서도 정확도는 매우 높다
  - hit ratio가 `~99.97%`
  - no-change edge를 잘못 건너뛰는 문제는 현재 수치상 거의 보이지 않는다
- `empty-dst fast path`도 100k에서 충분히 많이 발동한다
  - `73k+` 호출
  - 즉 이 경로는 샘플 특화가 아니라 실제 장거리 입력에서도 자주 쓰인다

### 40-4. 운영 판단
- 유지:
  - `deferred native graph shadow batch`
  - `empty-dst seed merge fast path`
  - `match_id -> rule_id direct lookup`
- 유지하되 효과 해석은 보수적으로:
  - `data_flow no-change precheck`
  - 100k에서도 정확도는 매우 좋았지만, 동일 조건 A/B 100k 비교가 아직 없으므로
    "큰 처리량 개선"까지는 아직 단정하지 않는다
- 기본값 채택 보류:
  - `match_driven flush policy`

### 40-5. 지금 시점 다음 우선순위
1. `online_graph_edge_flush` 내부에서 여전히 큰 `seed merge`를 더 줄일 수 있는지 확인
2. `native_record FFI`를 더 줄이려면 Rust ownership을 어디까지 넘길지 경계 재설계
3. 필요하면 `data_flow no-change precheck on/off` 100k A/B를 한 번 더 찍어 채택 여부 확정

## 41) 2026-04-16 data_flow precheck 100k A/B

### 41-1. 측정 조건
- 입력: `HOLMES/tmp/trace_attack_100k.jsonl`
- backend: `HOLMES_NATIVE_BACKEND=rust`
- flush policy: 기본값 `immediate`
- 비교:
  - `HOLMES_ONLINE_INDEX_ENABLE_DATA_FLOW_PRECHECK=0`
  - `HOLMES_ONLINE_INDEX_ENABLE_DATA_FLOW_PRECHECK=1`

### 41-2. 결과
- precheck `off`
  - `events_per_second ≈ 2696.66`
  - `rolling_events_per_second_60s ≈ 2704.27`
  - `graph_add_time_seconds ≈ 5.856`
  - `online_graph_edge_flush_time_seconds ≈ 2.289`
  - `seed_merge_time ≈ 0.793`
  - `data_flow_seed_merge_time ≈ 0.397`
  - `bucket_17_64_time ≈ 0.172`
- precheck `on`
  - `events_per_second ≈ 2696.47`
  - `rolling_events_per_second_60s ≈ 2704.12`
  - `graph_add_time_seconds ≈ 5.886`
  - `online_graph_edge_flush_time_seconds ≈ 2.314`
  - `seed_merge_time ≈ 0.813`
  - `data_flow_seed_merge_time ≈ 0.414`
  - `bucket_17_64_time ≈ 0.156`
  - `data_flow_precheck_count = 55,085`
  - `data_flow_precheck_hit_count = 55,066`
  - `data_flow_precheck_hit_ratio ≈ 0.99966`

### 41-3. 해석
- 정확도만 보면 precheck는 매우 좋다
  - no-change edge를 거의 완벽하게 맞힌다
- 하지만 end-to-end 성능은 좋아지지 않았다
  - `EPS`는 사실상 동일하거나 아주 소폭 나빠졌다
  - `graph_add`
  - `online_graph_edge_flush`
  - `seed_merge`
  도 전체적으로는 `on`이 더 좋지 않았다
- 즉 이 precheck는
  "이론상 좋은 가드"이지만
  현재 구현과 현재 입력 분포에서는 검사 자체 비용을 상쇄하지 못한다

### 41-4. 운영 판단
- `data_flow no-change precheck`는 기본값으로 채택하지 않는다
- 기능은 실험 옵션으로만 남긴다
  - `HOLMES_ONLINE_INDEX_ENABLE_DATA_FLOW_PRECHECK=1`
- 기본 운영 경로는 `precheck off`가 맞다

## 42) 병목 분해 단계 종료 기준과 메인 ownership 전환 기준

### 42-1. 지금 하는 작업을 뭐라고 볼 것인가
- 현재 단계는 `가지치기`라기보다
  `계측 기반 병목 분해 + 핫패스 미세최적화`
  에 가깝다
- 목적은
  - 어디가 진짜 큰 병목인지 장거리 입력에서도 고정되는지 확인하고
  - 작은 수정으로 쉽게 줄일 수 있는 hot path를 먼저 걷어내고
  - 그다음 Rust ownership 확대 대상을 틀리지 않게 고르는 것이다

### 42-2. 병목 분해 단계 종료 조건
- 아래 조건이 충족되면
  추가 미세최적화보다 메인 구조 수정으로 넘어가는 편이 맞다
- 조건 1:
  `100k` 이상에서 큰 병목 2개가 반복해서 고정된다
  - 현재는 거의
    - `native_record FFI`
    - `online_graph_edge_flush -> seed merge`
    두 축으로 수렴했다
- 조건 2:
  새 미세최적화 1회당 end-to-end 개선폭이 작다
  - 실무 기준으로는
    `100k`에서 `EPS`가 `2~3%` 이상 잘 안 움직이면
    구조 변경 시점으로 본다
- 조건 3:
  unexplained residual이 충분히 줄었다
  - 지금은 예전처럼
    "어디서 먹는지 모르겠는 큰 덩어리"
    보다는
    병목 위치가 꽤 선명하다
- 조건 4:
  다음 ownership handoff 대상이 구체적으로 말해진다
  - 단순히 "Rust로 옮기자"가 아니라
    어느 함수/경계/책임을 넘길지 설명 가능해야 한다

### 42-3. 지금 시점 판정
- 현재는 이미 전환 경계에 거의 와 있다
- 이유:
  - `100k`에서도 병목 구조가 크게 흔들리지 않았다
  - 먹히는 미세최적화는 이미 몇 개 확보했다
  - 최근 실험들은
    정확도는 좋아도 end-to-end 이득이 작거나
    아예 기본값 채택으로 이어지지 않는 경우가 늘었다
- 따라서 앞으로는
  `잔미세튜닝 무한 반복`보다
  `메인 ownership 확대`
  쪽의 기대값이 더 크다

### 42-4. 메인 부분을 손본다는 뜻
- 여기서 말하는 "메인 부분"은
  단순 리팩터링이 아니라
  Python이 authoritative로 들고 있는 hot path 책임을 Rust 쪽으로 넘기는 것이다
- 우선 후보는 두 갈래다
  1. `graph append / native record` ownership 확대
  2. `online propagation / seed merge` ownership 확대

### 42-5. 실제 전환 트리거
- 아래 중 하나가 성립하면
  병목 분해 단계는 사실상 종료로 본다
1. `100k` 기준 새 미세최적화 2회 연속으로 `EPS +2%`를 못 넘김
2. 큰 병목이 계속 `native_record FFI`와 `seed merge`로 반복 확인됨
3. 새 실험이 대부분
   - metric은 좋아지지만
   - end-to-end는 그대로이거나
   - 운영 기본값 채택으로 이어지지 않음

### 42-6. 현재 권장 운영 판단
- 이제부터의 기본 방향은
  `미세최적화 계속`이 아니라
  `Rust authoritative ownership 확대 준비`
  로 잡는 편이 맞다
- 단, ownership 확대에 들어가기 전 마지막 확인으로
  남은 병목 축이 정말
  - `native_record FFI`
  - `online seed merge`
  인지만 가볍게 다시 확인하면 충분하다

### 42-7. 한 줄 결론
- 지금 단계는
  `메인 엔진 리라이트 직전의 병목 확정 단계`
  라고 보는 게 맞다
- 다음 큰 일은
  `어느 hot path를 Rust authoritative ownership으로 먼저 넘길지 결정하는 것`
  이다

## 43) 첫 Rust ownership handoff 후보 선정

### 43-1. 후보 비교
- 후보 A: `graph append / native record` ownership 확대
- 후보 B: `online propagation / seed merge` ownership 확대

### 43-2. 현재 판단
- 첫 authoritative handoff는
  `online propagation / seed merge`
  쪽이 더 현실적이다

### 43-3. 이유
- 이유 1:
  Rust 쪽에 이미 `online index`의 핵심 동작이 들어가 있다
  - `add_online_edge`
  - `register_online_match`
  - `remove_online_match`
  - `flush`
  - mapper 조회 계열
- 이유 2:
  지금 실제 큰 병목 중 하나가 정확히 이 경로다
  - `online_graph_edge_flush`
  - `seed merge`
- 이유 3:
  `graph append`는 아직 Python 의미론 의존이 더 크다
  - semantic relation 처리
  - version node/current_version 관리
  - prune hook 연동
  - runtime edge bookkeeping
  - 이쪽은 handoff 시 회귀 위험이 더 높다
- 이유 4:
  `native_record FFI`는 크지만
  이 비용을 근본적으로 없애려면 결국 graph append 전체를 넘겨야 한다
  - 즉 난이도가 더 크다
  - 반면 online propagation은 이미 shadow seam이 넓게 깔려 있어서
    authoritative 전환의 첫 단계로 더 적합하다

### 43-4. 권장 1단계 범위
- 1단계 handoff 범위는 크게 잡지 않는다
- 우선:
  `runtime graph edge가 추가된 뒤 pending edge flush를 Rust authoritative path로 처리`
  를 목표로 잡는 편이 좋다
- 즉 Python은 당분간
  - graph append
  - match 생성/삭제
  는 계속 담당하되
  `flush_pending_edges()`와 그 안의 propagation 책임만 Rust 쪽으로 옮기는 식이다

### 43-5. 1단계 성공 조건
- Python online index와 Rust online index를 같은 입력에 넣었을 때
  - mapper contains rule
  - earliest sequence
  - match membership
  - min hops
  가 일치할 것
- `100k` 기준으로
  - `online_graph_edge_flush_time_seconds`
  - `seed_merge_time`
  가 의미 있게 감소할 것
- fallback이 유지될 것
  - mismatch나 미구현 케이스에서 Python 경로로 즉시 되돌릴 수 있어야 함

### 43-6. 1단계 이후 순서
1. `online propagation authoritative`
2. `online match add/remove authoritative`
3. 그다음 `graph append / current_version / prune` ownership 확대

### 43-7. 한 줄 결론
- 첫 Rust handoff는
  `graph append`보다
  `online propagation / pending edge flush`
  쪽이 더 안전하고 ROI도 높다

## 44) Python/Rust online mapper 동등성 체크 추가

### 44-1. 무엇을 추가했는가
- 실제 `holmes_native_rs` backend를 사용하는 테스트를 추가했다
- 비교 대상:
  - Python `OnlineIndex`
  - `RustNativeBackend`의 online mapper 조회 seam
- 비교 항목:
  - `online_node_match_count`
  - `online_mapper_match_ids`
  - `online_mapper_contains_rule`
  - `online_mapper_earliest_seq`
  - `online_contains_match`
  - `online_mapper_min_hops`

### 44-2. 테스트 시나리오
- `DATA_FLOW` / `VERSION_TRANSITION` edge 추가
- pending edge 상태에서 `flush`
- match add
- edge 추가 후 재-`flush`
- match remove
- 각 단계마다 Python/Rust 결과를 비교

### 44-3. 현재 의미
- 이 테스트는
  `online propagation / pending edge flush`
  handoff의 최소 전제조건을 자동화한 것이다
- 즉 앞으로 Rust authoritative path를 붙일 때
  mapper 의미론이 Python과 같다는 걸 CI 레벨에서 바로 확인할 수 있다

### 44-4. 지금 시점 결론
- Rust handoff 1단계 전제조건 중
  `Python/Rust online mapper 동등성 체크 자동화`
  는 착수 완료로 본다
- 다음 단계는
  실제 `flush_pending_edges()` authoritative path를 Rust 쪽으로 여는 설계/구현이다
