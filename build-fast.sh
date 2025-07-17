#!/bin/bash

# 컴파일 속도 향상을 위한 빌드 스크립트

echo "=== 컴파일 속도 향상을 위한 빌드 시작 ==="

# 환경 변수 설정
export RUSTFLAGS="-C target-cpu=native"
export CARGO_BUILD_JOBS=8

# sccache 설치 확인 및 설치
if ! command -v sccache &> /dev/null; then
    echo "sccache 설치 중..."
    cargo install sccache
fi

# sccache 시작
export RUSTC_WRAPPER=sccache

# 빠른 개발 빌드
echo "빠른 개발 빌드 실행..."
cargo build --profile dev-fast

# 빌드 통계 출력
echo "=== 빌드 통계 ==="
sccache --show-stats

echo "=== 빌드 완료 ==="
