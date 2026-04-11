#!/bin/bash
# pipeline.sh — 수집 → 파싱 → 검증 → ML 전처리 전체 파이프라인
#
# 실행 위치: kali-attacker 컨테이너 내부
# 사용법:   bash /scripts/pipeline.sh [반복횟수] [시나리오간대기초]
# 예시:     bash /scripts/pipeline.sh 10 5
#
# 단계:
#   1. run_loop.sh     — 공격 시나리오 N회 반복 실행 (로그 수집)
#   2. parse_logs.py   — 7종 로그 → dataset.csv (29컬럼, v4.0)
#   3. validate.py     — 데이터 품질 검증 (실패 시 중단)
#   4. feature_engineering.py — dataset.csv → dataset_ml.csv

set -euo pipefail

ITER=${1:-10}
DELAY=${2:-5}
LOG_DIR="/honeypot_logs"
PIPELINE_LOG="${LOG_DIR}/pipeline.log"

# 타임스탬프 함수
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# 단계 실행 + 실패 처리
run_step() {
    local step_no="$1"
    local step_name="$2"
    shift 2
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " [Step ${step_no}/4] ${step_name}"
    echo " 시작: $(ts)"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    if "$@"; then
        echo " ✅ ${step_name} 완료 ($(ts))"
    else
        echo ""
        echo " ❌ ${step_name} 실패 — 파이프라인 중단 ($(ts))"
        echo "PIPELINE FAILED at step ${step_no}: ${step_name}" >> "$PIPELINE_LOG"
        exit 1
    fi
}

# ── 시작 ──────────────────────────────────────────────────────────────────────
PIPELINE_START=$(ts)
echo "======================================================="
echo " Docker Honeypot Pipeline"
echo " 시작:       ${PIPELINE_START}"
echo " 시나리오:   ${ITER}회 × 9종"
echo " 시나리오 간 대기: ${DELAY}초"
echo "======================================================="

echo "PIPELINE START ${PIPELINE_START} iter=${ITER}" >> "$PIPELINE_LOG"

# Step 1: 공격 시나리오 실행
run_step 1 "공격 시나리오 실행 (${ITER}회)" \
    bash /scripts/run_loop.sh "$ITER" "$DELAY"

# Step 2: 로그 파싱
run_step 2 "로그 파싱 → dataset.csv" \
    python3 /scripts/parse_logs.py

# Step 3: 품질 검증
run_step 3 "데이터 품질 검증" \
    python3 /scripts/validate.py

# Step 4: ML 전처리
run_step 4 "ML 전처리 → dataset_ml.csv" \
    python3 /scripts/feature_engineering.py

# ── 완료 ──────────────────────────────────────────────────────────────────────
PIPELINE_END=$(ts)
echo ""
echo "======================================================="
echo " ✅ 파이프라인 전체 완료"
echo " 시작: ${PIPELINE_START}"
echo " 종료: ${PIPELINE_END}"
echo ""
echo " 출력 파일:"
echo "   ${LOG_DIR}/dataset.csv       (원시 로그)"
echo "   ${LOG_DIR}/dataset_ml.csv    (ML 학습용)"
echo "   ${LOG_DIR}/dataset_meta.json (메타데이터)"
echo "   ${LOG_DIR}/validate_report.json (품질 리포트)"
echo "   ${LOG_DIR}/pipeline.log      (실행 기록)"
echo "======================================================="

echo "PIPELINE SUCCESS ${PIPELINE_END}" >> "$PIPELINE_LOG"
