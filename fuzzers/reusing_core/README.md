# reusing_core

테인트 스캔이 미리 찾아둔 값을 퍼징 중에 재사용하는 LibAFL 스테이지.

AFL++ 구현(`AFLplusplus_reusing/src/afl-fuzz-reusing.c`, 1,462줄)을 LibAFL로
옮긴 것. 실행 방식(forkserver / in-process)에 의존하지 않는 공유 크레이트라,
unibench용 퍼저와 FuzzBench용 퍼저가 같은 스테이지를 쓴다.

## 배경: reusing이 뭘 하는가

퍼징 **전에** 스캔을 한 번 돌린다 (`Reusing_scanner`의 `taint_scan`). 시드
코퍼스를 Angora의 DFSan 테인트 파이프라인으로 훑어서 세 가지를 남긴다.

| 파일 | 내용 |
|---|---|
| `value_pool.dict` | 스캔 중 새 브랜치를 열었던 값들. 읽힌 바이트 범위의 **모양**별로 묶임 |
| `unsolved_condition` | 한 번도 양쪽으로 가보지 못한 비교 사이트 `(cmpid, context, order)` |
| `<seed>.dtaint` | 시드 1개당 1개. 어떤 사이트가 입력의 어느 바이트 범위를 읽었는지 |

퍼징 중에는 이 캐시를 **읽기만** 한다. 어떤 입력의 테인트된 바이트 범위를,
같은 모양의 풀 값으로 덮어쓰고 실행하고 되돌린다. 그게 전부다.

## 왜 LibAFL 라이브러리를 안 건드리는가

StorFuzz는 같은 LibAFL(0.13.1) 위에 구현하면서 `libafl/src/feedbacks/map.rs`
등 라이브러리 코어를 고쳐야 했다. 피드백 판정 의미론(비트맵)을 바꿔야 했기
때문이다. reusing은 그럴 필요가 없다.

| | StorFuzz | reusing |
|---|---|---|
| 건드리는 축 | 피드백 (무엇을 흥미롭다 할까) | 스테이지 (어떻게 변이할까) |
| 타겟 계측 | 필요 (LLVM 패스 783줄) | **불필요** |
| 타겟 런타임 | 필요 (두 번째 공유메모리 맵) | **불필요** |
| 라이브러리 수정 | 필요 | **불필요** |
| 새 trait 구현 | 0개 | `Stage` 1개 |

특히 중요한 확인 하나: AFL++의 `unsolved_remove()`는 **선언만 있고 호출부가
없는 죽은 코드**다. unsolved 집합은 스캔이 만든 그대로 읽기 전용으로만
쓰이고, 퍼징 중에 "이제 풀렸으니 빼자"를 하지 않는다. 그래서 스테이지가
커버리지 피드백 결과를 들여다볼 일이 없고, StorFuzz가 라이브러리를 고쳐야
했던 종류의 문제가 생기지 않는다.

## 모듈 구성

```
src/
  lib.rs      튜너블 상수 (reusing_config.h 대응)
  dtaint.rs   .dtaint v3 파서
  pool.rs     value_pool.dict / unsolved_condition 파서
  meta.rs     State / Testcase metadata 타입
  stage.rs    ReusingStage 본체
  energy.rs   에너지 배분 래퍼
```

### 상태를 어디에 두는가

AFL++은 전부 `afl_state_t`와 `queue_entry`에 들고 있었다. LibAFL에서는
코퍼스 전역 데이터와 입력별 데이터를 나눠 둔다.

| AFL++ | 여기 | 비고 |
|---|---|---|
| `afl->value_pool`, `afl->unsolved` | `ReusingData` (State metadata) | 1회 로드, 불변. 직렬화 안 함 (재시작 시 파일에서 재구축) |
| `q->reusing_cur[]`, `reusing_done` | `ReusingCursors` (Testcase metadata) | 직렬화함 |
| `q->from_seed` | `FromSeed` (Testcase metadata) | 에너지 배분용 |
| `q->has_taint` | `CachedTaint` 존재 여부 | |

### 자료구조에서 줄어든 것

Rust 표준 라이브러리로 대체되어 사라진 AFL++ 코드:

- 풀 조회: 정렬 배열 + 이분탐색(비교 함수 5개 포함, ~150줄) → `HashMap<Vec<u32>, ValueBucket>`
- unsolved 집합: 손수 짠 open-addressing 해시셋(~120줄) → `HashSet<SiteKey>`
- `*_free()` 함수들 → `Drop`

1,462줄 → 600~800줄 예상.

## 동작 흐름 (`ReusingStage::perform`)

```
1. cursors.done 이면 즉시 반환
2. 이 테스트케이스의 .dtaint 로드 — 없으면 done = true
3. 스캔이 이미 푼 사이트 필터링
4. 커서 배열 크기를 "필터 전" 세트 수에 맞춤
5. 세트별로 풀 버킷 조회:
     live      = 버킷이 있고 커서가 안 끝난 세트 수
     remaining = 아직 안 써본 (세트, 값) 쌍의 총수
6. budget = clamp(live * 3, 256, 8192);  total = min(remaining, budget)
7. 라운드로빈: 세트당 3개씩 쓰고 다음 세트로, 예산 소진까지
     apply → evaluate_input → restore
8. 예산이 남은 걸 다 덮었으면 done = true
```

**왜 라운드로빈인가**: nm 시드 하나가 range set 1,000개에 풀 값 50만 개를
걸칠 수 있다. 한 세트를 다 비우고 다음으로 가면 첫 세트 안에서 방문 하나를
통째로 써버리고, 나머지 사이트는 캠페인 내내 손도 못 댄다. 세트당 3개씩만
쓰고 넘어간다. 각 세트의 커서가 테스트케이스에 남아서 다음 방문이 이어받는다.

**`RangeSet.idx`가 따로 있는 이유**: 커서 배열은 **필터 전** 위치로 인덱싱한다.
필터링 결과가 방문마다 달라져도 커서가 엉뚱한 세트를 가리키지 않게 하려는
것이다.

## 에너지 — 유일하게 그대로 못 옮긴 부분

AFL++:

```c
if (!afl->queue_cur->from_seed) perf_score *= 8;   // 신규 발견
else                            perf_score /= 2;   // 시드
```

근거는 측정값이다. objdump에서 24시간 커버리지 증가의 88%가 첫 8시간에
몰렸고, 시드 3,782개 대 신규 발견 131개라 시드에 예산을 그대로 주면 이전
캠페인이 이미 24시간 돌린 입력에 쓰게 된다.

그런데 **LibAFL 베이스라인에는 `perf_score` 개념이 없다**.
`StdMutationalStage::iterations()`가 입력과 무관하게 `1 + rand(128)`을 뽑는다.

선택지는 셋이었다.

| | 내용 | 판단 |
|---|---|---|
| 포기 | 스테이지만 추가 | AFL++ 결과와 비교 불가 |
| **자체 조절** | `iterations()` 뽑는 지점에서 같은 비율 적용 | **채택** |
| 스케줄러 교체 | `PowerQueueScheduler` 도입 | 베이스라인이 달라져 비교가 깨짐 |

`energy.rs`의 `ReusingEnergyStage`가 그 역할이다. 라이브러리도 베이스라인도
건드리지 않는다.

## 옮기지 않은 것

| AFL++ | 이유 |
|---|---|
| `reusing_skip_det` (시드의 deterministic 스테이지 스킵) | 베이스라인에 deterministic 스테이지가 없음 |
| 트리밍 끄기 (`1d118c86`) | 베이스라인이 트리밍을 안 함 |
| `unsolved_remove()` | AFL++에서도 죽은 코드 |

## 시드와 `.dtaint` 연결

AFL++은 `perform_dry_run()`의 pivot 지점에서 가로챘다. 시드 파일명과 큐
이름을 동시에 쥐는 유일한 순간이었기 때문이다.

LibAFL에는 그 훅이 없다. 대신 `load_initial_inputs()` **직후** 코퍼스를 한
바퀴 돌면서 처리한다 (`stage::attach_seed_taint`). `OnDiskCorpus`라
`Testcase::filename()`이 남아 있어서 스캔이 키로 쓴 이름을 그대로 찾을 수
있다. AFL++보다 오히려 단순하다.

## 현재 상태

**뼈대만 있음. 로직은 전부 `todo!()`.**

| 모듈 | 줄 | 상태 |
|---|---|---|
| `lib.rs` | 60 | 상수 확정 |
| `dtaint.rs` | 78 | 타입·시그니처 |
| `pool.rs` | 84 | 타입·시그니처 |
| `meta.rs` | 56 | 타입 확정 |
| `stage.rs` | 132 | `Stage` impl 골격 + 흐름 주석 |
| `energy.rs` | 81 | 래퍼 골격 |

아직 컴파일 확인을 안 했다. 호스트에 Rust가 없어서 개발 컨테이너가 필요하다.

### 미결 사항

- `energy.rs`: 내부 스테이지를 여러 번 돌릴지, `MutationalStage`를 직접
  구현해 `iterations()`를 오버라이드할지. 전자가 덜 침습적이고 후자가 AFL++
  의미에 더 가깝다.

### 구현 순서

1. `dtaint.rs` — 라이터가 Rust(`taint_scan.rs`의 `write_dtaint`)라 역함수로
   쓰면 된다. 기존 `.dtaint` 파일로 바로 검증 가능
2. `pool.rs` — 텍스트 파싱, 단위 테스트 가능
3. `meta.rs` 배선
4. `stage.rs` 본체
5. `energy.rs`

1~2는 타겟 없이 테스트할 수 있어서 먼저 하는 게 좋다.

## 쓰는 쪽

```
fuzzers/
├── reusing_core/                    이 크레이트
├── forkserver_reusing_cc/           unibench 팔 (예정)
└── reusing_fuzzbench_in_process/    FuzzBench 팔 (예정)
```

`fuzzers/` 안에 공유 크레이트를 두고 `path` 의존으로 끌어쓰는 구조는
StorFuzz가 `storfuzz_constants`로 쓰는 방식과 같다.

### FuzzBench 쪽에 미리 짚어둘 것

FuzzBench 타겟은 `LLVMFuzzerTestOneInput` 하네스다. reusing이 돌려면
`.dtaint`가 있어야 하고, 그건 Angora DFSan track 바이너리가 필요하다. Angora는
CLI 프로그램을 전제로 만들어져 있어서, 하네스를 감싸는 드라이버(`main()`에서
파일을 읽어 `LLVMFuzzerTestOneInput`을 호출)가 필요할 가능성이 크다. StorFuzz는
비슷한 문제를 `stub_rt.c`로 처리했다.

이 크레이트를 실행 방식 비의존으로 짜두면, 그때 퍼저 쪽은 배선만 하면 된다.

## 참고

- 이식 원본: `AFLplusplus_reusing/src/afl-fuzz-reusing.c`, `include/reusing_config.h`
- 캐시 생성: `Reusing_scanner/scanner/src/bin/taint_scan.rs`
- `.dtaint` 포맷: `AFLplusplus_reusing/include/dtaint.h`
- 베이스 커밋: LibAFL `bb579e62` (v0.13.1) — StorFuzz가 쓴 것과 동일
