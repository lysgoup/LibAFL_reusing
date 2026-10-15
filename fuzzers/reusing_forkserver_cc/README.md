# reusing_forkserver_cc

테인트 스캔 결과를 재사용하는 forkserver 퍼저. unibench 실험 팔이 쓴다.

LibAFL 예제 `fuzzers/forkserver_libafl_cc`의 복사본에, 베이스라인 팔
(`forkserver_libafl`)이 Docker 빌드 중에 적용하던 패치를 **미리 적용해둔**
것이다. 로직은 `fuzzers/reusing_core`에 있다.

## 왜 복사본인가

`forkserver_libafl_cc`를 직접 고치면 베이스라인 팔이 쓰는 패치가 깨진다
(`git apply`가 컨텍스트를 못 찾음). 별도 디렉터리로 두면 두 팔이 서로
간섭하지 않는다. StorFuzz도 같은 방식이다 — `fuzzers/fuzzbench`를 건드리지
않고 `fuzzers/storfuzz_fuzzbench_in_process`를 새로 만들었다.

FuzzBench 팔(`reusing_fuzzbench_in_process`, 예정)은 in-process 실행 모델이라
어차피 별도 디렉터리가 필요하다. 그래서 이름도 벤치마크가 아니라 실행 방식을
따른다.

## 출처

| 항목 | 값 |
|---|---|
| 베이스 | LibAFL `bb579e62` (v0.13.1), `fuzzers/forkserver_libafl_cc` |
| 패치 출처 | `Reusing-unibench_build` `42c47d6c6`, `forkserver_libafl/` |

## 적용한 패치

Docker 빌드 중 적용되던 순서 그대로, `git apply -p3 --directory=` 로 이
디렉터리에 적용했다.

| 패치 | sha256 (앞 12자) | 내용 |
|---|---|---|
| `forkserver_libafl_baseline.patch` | `1c892593bcd6` | `-o/--output-dir` 옵션, `queue/`·`crashes/`를 `OnDiskCorpus`로 저장, `LLVMPasses::AutoTokens`, `.need_libafl_arg(false)`, `.init_array` forkserver 주입 |
| `forkserver_toml_monitor.patch` | `bf69eb59131d` | `SimpleMonitor` → `OnDiskTOMLMonitor`, `<output>/stats.toml` 기록 |
| `forkserver_libafl_dryrun.patch` | `72a060365fc5` | 시드 임포트 완료 시 `queue/signal/dryrun_finish` 생성 |

순서가 중요하다. `toml_monitor`는 `baseline`이 `main.rs`를 고친 뒤를 전제하므로
순정 트리에 혼자 적용하면 실패한다.

## 적용하지 않은 패치

| 패치 | 이유 |
|---|---|
| `fuzzbench_stats.patch` (`d2f9a079a089`) | `fuzzers/fuzzbench/src/lib.rs`만 건드린다. 다른 패키지라 이 퍼저 빌드에 들어가지 않는다 |

## Cargo.toml 변경

소스 파일은 베이스라인과 **바이트 단위로 같고**, 차이는 `Cargo.toml` 하나뿐이다.

```diff
-name = "forkserver_libafl_cc"
+name = "reusing_forkserver_cc"

-libafl = { path = "../../libafl/" }
+libafl = { path = "../../libafl/", features = ["track_hit_feedbacks"] }

-libafl_targets = { ..., features = ["sancov_pcguard_hitcounts", "libfuzzer", "pointer_maps"] }
+libafl_targets = { ..., features = [..., "sancov_cmplog"] }

-env_logger = "0.11"
+mimalloc = { version = "*", default-features = false }
+env_logger = "*"
+log = "*"
+reusing_core = { path = "../reusing_core/" }
```

위 셋(`track_hit_feedbacks`, `sancov_cmplog`, `mimalloc`/`env_logger`/`log`)은
베이스라인 팔의 `Dockerfile`이 `sed`로 넣던 것과 같은 내용이다. 여기서는
소스에 못박았다.

`[lib] name`은 `libforkserver_libafl_cc` 그대로 두었다. 바꾸면
`src/bin/libafl_cc.rs`의 `link_staticlib(...)` 문자열도 고쳐야 해서 베이스라인
대비 diff가 늘어난다. 이미지가 분리돼 있어 이름이 겹쳐도 문제가 없다.

## 동등성 검증

두 팔의 차이가 reusing뿐임을 보이려면, 이 디렉터리가 "순정 + 패치 3개"와
같아야 한다. 베이스라인 이미지 안의 소스와 직접 대조한다.

```bash
cd fuzzers/reusing_forkserver_cc
for f in src/main.rs src/lib.rs src/bin/libafl_cc.rs; do
  l=$(sha256sum $f | cut -c1-16)
  i=$(docker run --rm --entrypoint sh unifuzz/unibench:forkserver_libafl \
        -c "sha256sum /root/StorFuzz-LibAFL/fuzzers/forkserver_libafl_cc/$f" | cut -c1-16)
  [ "$l" = "$i" ] && echo "$f 일치" || echo "$f 다름"
done
```

**현재 결과: 3개 전부 일치.**

`main.rs` 배선이 들어가면 이 검증은 깨진다. 그때는 "차이가 배선뿐"임을
`diff`로 확인하는 방식으로 바꿔야 한다.

**주의**: 베이스라인 팔은 여전히 패치를 빌드 중에 적용한다. 패치 파일을
고치면 두 팔이 조용히 어긋나므로, 고칠 때마다 위 검증을 다시 돌려야 한다.

## Dockerfile이 짧아지는 부분

패치를 미리 적용해둔 덕에, 이 퍼저용 Dockerfile은 베이스라인 것보다
`COPY`+`git apply` 8줄과 `sed` 블록 3줄이 빠진다.

```dockerfile
RUN git clone https://github.com/lysgoup/LibAFL_reusing.git /root/LibAFL-reusing && \
    cd /root/LibAFL-reusing && git checkout storfuzz-comparison
WORKDIR /root/LibAFL-reusing/fuzzers/reusing_forkserver_cc
RUN cargo build --release
```

나머지(unibench 타겟 빌드 ~100줄)는 베이스라인 Dockerfile 그대로 복사하면
된다.

## 현재 상태

| | |
|---|---|
| 소스 | 베이스라인과 동일 (패치 3개 적용 상태) |
| `Cargo.toml` | 패키지명 + `reusing_core` 의존 + 피처 3개 |
| 빌드 | `cargo check` 통과 (44초) |
| `main.rs` 배선 | **미착수** |
| 하네스 디렉터리 | **미착수** |

즉 지금은 **이름만 다른 베이스라인 퍼저**다. `reusing_core`에 로직이 들어간
뒤 `main.rs`에 다음을 배선한다.

1. `mod` 선언 — `reusing_core` 사용
2. `-r <pool_dir>` CLI 옵션 (clap 필드)
3. `load_initial_inputs()` 직후 `attach_seed_taint()` 호출
4. `tuple_list!`에 `ReusingStage` + `ReusingEnergyStage` 삽입

## 빌드

```bash
docker run -it --rm \
  -v ~/LibAFL_reusing:/src -v libafl_target:/build \
  -e CARGO_TARGET_DIR=/build -e LIBAFL_EDGES_MAP_SIZE_MAX=4194304 \
  -e CFLAGS= -e CXXFLAGS= \
  -w /src/fuzzers/reusing_forkserver_cc \
  --entrypoint bash unifuzz/unibench:forkserver_libafl
# 안에서
cargo build --release
```

`LIBAFL_EDGES_MAP_SIZE_MAX=4194304`는 커버리지 맵 크기로 컴파일 타임에
박히는 값이다. 빼먹으면 베이스라인과 다른 바이너리가 나온다.
