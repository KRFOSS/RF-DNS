# 컴파일 속도 최적화 가이드

이 프로젝트는 다음과 같은 컴파일 속도 최적화가 적용되어 있습니다:

## 적용된 최적화

### 1. 프로파일 최적화 (Cargo.toml)
- **dev 프로파일**: 개발 중 빠른 컴파일을 위한 설정
  - `debug = 1`: 디버그 정보 축소
  - `opt-level = 0`: 최적화 비활성화
  - `incremental = true`: 증분 컴파일 활성화
  - `codegen-units = 256`: 병렬 컴파일 단위 증가

- **dev-fast 프로파일**: 더 빠른 개발용 프로파일
  - `opt-level = 1`: 최소 최적화
  - `debug = false`: 디버그 정보 비활성화

- **의존성 최적화**: 의존성 패키지들은 최적화된 상태로 컴파일

### 2. 빌드 설정 (.cargo/config.toml)
- **병렬 작업**: `jobs = 8`로 병렬 컴파일 작업 수 증가
- **타겟 최적화**: `target-cpu=native`로 현재 CPU에 최적화
- **스파스 레지스트리**: 더 빠른 의존성 다운로드

### 3. 의존성 최적화
- **선택적 기능**: 필요한 기능만 활성화
- **default-features = false**: 불필요한 기본 기능 비활성화
- **rustls 사용**: OpenSSL 대신 Rust 네이티브 TLS 사용

## 사용 방법

### 빠른 개발 빌드
```bash
cargo build --profile dev-fast
```

### 스크립트 사용
```bash
./build-fast.sh
```

### 일반 개발 빌드
```bash
cargo build
```

### 릴리즈 빌드
```bash
cargo build --release
```

## 추가 최적화 팁

### 1. sccache 사용
```bash
# sccache 설치
cargo install sccache

# 환경 변수 설정
export RUSTC_WRAPPER=sccache

# 빌드
cargo build
```

### 2. 의존성 캐시 활용
- 의존성이 변경되지 않았다면 재컴파일하지 않음
- `Cargo.lock` 파일을 버전 관리에 포함

### 3. 코드 변경 최소화
- 자주 변경되는 코드를 별도 모듈로 분리
- 매크로 사용 최소화

### 4. 하드웨어 최적화
- SSD 사용
- 충분한 RAM (16GB 이상 권장)
- 멀티 코어 CPU 활용

## 성능 비교

| 빌드 유형 | 예상 시간 | 용도 |
|-----------|-----------|------|
| dev-fast  | 가장 빠름 | 개발 중 빠른 테스트 |
| dev       | 빠름     | 일반 개발 |
| release   | 느림     | 프로덕션 배포 |

## 문제 해결

### 링커 오류
현재 설정은 시스템 기본 링커를 사용합니다. 더 빠른 링커를 원한다면:

```bash
# lld 설치 (Ubuntu/Debian)
sudo apt-get install lld

# 또는 mold 설치
sudo apt-get install mold
```

### 메모리 부족
병렬 작업 수를 줄이세요:
```toml
[build]
jobs = 4  # 또는 더 적은 수
```
