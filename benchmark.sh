#!/bin/bash

# 컴파일 속도 벤치마크 스크립트

echo "=== 컴파일 속도 벤치마크 ==="

# 클린 빌드
echo "1. 클린 빌드 준비..."
cargo clean > /dev/null 2>&1

# 각 프로파일별 컴파일 시간 측정
echo "2. 컴파일 시간 측정 시작..."

echo "   - dev-fast 프로파일:"
time cargo build --profile dev-fast 2>&1 | tail -5

echo "   - dev 프로파일:"
cargo clean > /dev/null 2>&1
time cargo build 2>&1 | tail -5

echo "   - release 프로파일:"
cargo clean > /dev/null 2>&1
time cargo build --release 2>&1 | tail -5

echo "=== 벤치마크 완료 ==="

# 빌드 아티팩트 크기 비교
echo "3. 바이너리 크기 비교:"
ls -la target/debug/rfdns target/release/rfdns 2>/dev/null || echo "바이너리 파일을 찾을 수 없습니다."

echo "4. 의존성 정보:"
cargo tree --depth 1
