#!/usr/bin/env python3
"""
validate.py — dataset.csv 품질 검증

파싱 후 데이터 품질을 자동으로 체크하는 파이프라인 게이트.
검증 실패 시 exit code 1 반환 → pipeline.sh가 이후 단계를 중단한다.

검증 항목:
  [스키마]   기대 컬럼 전부 존재하는지
  [행 수]    최소 행 수(MIN_ROWS) 충족하는지
  [도메인]   event_type / event_result / transport / login_success 값 범위
  [순번]     seq_no 유일성 / session_seq_no 연속성
  [null율]   필수 컬럼의 null 비율이 임계치 이하인지
"""

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

DATASET_PATH = Path("/honeypot_logs/dataset.csv")
REPORT_PATH  = Path("/honeypot_logs/validate_report.json")

# ── 기준값 ────────────────────────────────────────────────────────────────────
MIN_ROWS = 100

EXPECTED_COLUMNS = [
    "event_id", "session_id", "seq_no", "session_seq_no",
    "timestamp", "ingest_time",
    "src_ip", "src_port", "dst_ip", "dst_port", "transport",
    "protocol", "source_honeypot", "event_type", "event_result",
    "username", "password", "login_success", "attempt_no",
    "duration", "login_attempts",
    "http_method", "http_path", "http_query",
    "command",
    "derived_has_wget", "derived_has_curl", "derived_has_reverse_shell",
    "parser_version",
]

VALID_EVENT_TYPES   = {"auth", "session", "command", "scan"}
VALID_EVENT_RESULTS = {"success", "fail", "closed", "executed", "detected", ""}
VALID_TRANSPORTS    = {"TCP", "UDP", ""}
VALID_LOGIN_SUCCESS = {"0", "1", ""}

# 필수 컬럼: null 비율이 이 임계치를 넘으면 경고
NULL_WARN_THRESHOLD = {
    "event_id":        0.0,
    "session_id":      0.0,
    "seq_no":          0.0,
    "session_seq_no":  0.0,
    "timestamp":       0.05,
    "src_ip":          0.05,
    "protocol":        0.05,
    "source_honeypot": 0.0,
    "event_type":      0.0,
    "event_result":    0.05,
    "parser_version":  0.0,
}


def load_csv(path: Path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check_schema(rows, errors, warnings):
    actual = set(rows[0].keys()) if rows else set()
    expected = set(EXPECTED_COLUMNS)
    missing = expected - actual
    extra   = actual - expected
    if missing:
        errors.append(f"[스키마] 누락된 컬럼: {sorted(missing)}")
    if extra:
        warnings.append(f"[스키마] 예상에 없는 컬럼: {sorted(extra)}")


def check_row_count(rows, errors):
    n = len(rows)
    if n < MIN_ROWS:
        errors.append(f"[행 수] {n}행 — 최소 기준 {MIN_ROWS}행 미달")
    return n


def check_domain(rows, errors, warnings):
    invalid_et = invalid_er = invalid_tr = invalid_ls = 0

    for r in rows:
        if r.get("event_type") not in VALID_EVENT_TYPES:
            invalid_et += 1
        if r.get("event_result") not in VALID_EVENT_RESULTS:
            invalid_er += 1
        if r.get("transport") not in VALID_TRANSPORTS:
            invalid_tr += 1
        if r.get("login_success") not in VALID_LOGIN_SUCCESS:
            invalid_ls += 1

    if invalid_et:
        errors.append(f"[도메인] 비정상 event_type: {invalid_et}행")
    if invalid_er:
        warnings.append(f"[도메인] 비정상 event_result: {invalid_er}행")
    if invalid_tr:
        warnings.append(f"[도메인] 비정상 transport: {invalid_tr}행")
    if invalid_ls:
        warnings.append(f"[도메인] 비정상 login_success: {invalid_ls}행")


def check_seq_no(rows, errors, warnings):
    seq_nos = [r.get("seq_no") for r in rows]

    # seq_no 유일성
    duplicates = len(seq_nos) - len(set(seq_nos))
    if duplicates:
        errors.append(f"[순번] seq_no 중복: {duplicates}건")

    # seq_no 연속성 (1부터 N까지)
    n = len(rows)
    expected = set(str(i) for i in range(1, n + 1))
    actual   = set(seq_nos)
    if expected != actual:
        warnings.append(f"[순번] seq_no 연속성 불일치 (비어있거나 순서 뒤섞임)")

    # session_seq_no: 세션별로 1부터 시작하는지
    session_seen = defaultdict(set)
    for r in rows:
        sid  = r.get("session_id", "")
        sseq = r.get("session_seq_no", "")
        session_seen[sid].add(sseq)

    bad_sessions = 0
    for sid, seqs in session_seen.items():
        try:
            nums = sorted(int(s) for s in seqs)
            if nums[0] != 1:
                bad_sessions += 1
        except (ValueError, IndexError):
            bad_sessions += 1

    if bad_sessions:
        warnings.append(f"[순번] session_seq_no가 1부터 시작하지 않는 세션: {bad_sessions}개")


def check_null_rates(rows, errors, warnings):
    n = len(rows)
    if n == 0:
        return

    null_rates = {}
    for col, threshold in NULL_WARN_THRESHOLD.items():
        null_cnt  = sum(1 for r in rows if not r.get(col))
        null_rate = null_cnt / n
        null_rates[col] = round(null_rate, 4)
        if null_rate > threshold:
            warnings.append(
                f"[null율] {col}: {null_rate*100:.1f}% "
                f"(임계치 {threshold*100:.0f}%)"
            )

    return null_rates


def build_distribution(rows, key):
    dist = defaultdict(int)
    for r in rows:
        dist[r.get(key, "")] += 1
    return dict(sorted(dist.items(), key=lambda x: -x[1]))


def main():
    print("=" * 55)
    print(" Dataset Validator")
    print(f" 대상: {DATASET_PATH}")
    print("=" * 55)

    if not DATASET_PATH.exists():
        print(f"[ERROR] 파일 없음: {DATASET_PATH}")
        sys.exit(1)

    rows = load_csv(DATASET_PATH)
    if not rows:
        print("[ERROR] 데이터가 비어있음")
        sys.exit(1)

    errors   = []
    warnings = []

    check_schema(rows, errors, warnings)
    n = check_row_count(rows, errors)
    check_domain(rows, errors, warnings)
    check_seq_no(rows, errors, warnings)
    null_rates = check_null_rates(rows, errors, warnings) or {}

    # ── 결과 출력 ──────────────────────────────────────────────────────────────
    print(f"\n 총 행 수:  {n:,}")
    print(f" 컬럼 수:  {len(rows[0].keys())}")
    print()

    if warnings:
        print(f" ⚠️  경고 {len(warnings)}건:")
        for w in warnings:
            print(f"   {w}")
    else:
        print(" ✅ 경고 없음")

    if errors:
        print(f"\n ❌ 오류 {len(errors)}건:")
        for e in errors:
            print(f"   {e}")
    else:
        print(" ✅ 오류 없음")

    # ── 리포트 저장 ────────────────────────────────────────────────────────────
    report = {
        "validated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "dataset_path": str(DATASET_PATH),
        "row_count":    n,
        "column_count": len(rows[0].keys()),
        "errors":       errors,
        "warnings":     warnings,
        "null_rates":   null_rates,
        "distributions": {
            "source_honeypot": build_distribution(rows, "source_honeypot"),
            "event_type":      build_distribution(rows, "event_type"),
            "event_result":    build_distribution(rows, "event_result"),
            "protocol":        build_distribution(rows, "protocol"),
        },
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"\n 리포트 저장: {REPORT_PATH}")
    print("=" * 55)

    # 오류 있으면 파이프라인 중단
    if errors:
        print("\n[FAIL] 품질 검증 실패 — 이후 단계 중단")
        sys.exit(1)

    print("\n[PASS] 품질 검증 통과")
    sys.exit(0)


if __name__ == "__main__":
    main()
