#!/usr/bin/env python3
"""
parse_logs.py — 허니팟 7종 로그 파서 → dataset.csv (단일 통합 파일)

실행 위치: kali-attacker 컨테이너 내부
사용법: python3 /scripts/parse_logs.py

출력 스키마 (29컬럼):
  [식별]
  event_id              UUID v4 (행별 고유 식별자)
  session_id            세션 식별자 (native 또는 src_ip+port+ts MD5 해시)
  seq_no                전체 이벤트 순번 (1, 2, 3 ...)
  session_seq_no        세션 내 이벤트 순번 (1, 2, 3 ...)

  [시각]
  timestamp             ISO 8601 UTC (이벤트 발생 시각)
  ingest_time           ISO 8601 UTC (파싱 실행 시각)

  [네트워크 5-튜플]
  src_ip                공격자 IP
  src_port              공격자 출발 포트
  dst_ip                허니팟 IP (허니팟별 고정값)
  dst_port              허니팟 포트 (정수)
  transport             TCP / UDP

  [서비스]
  protocol              SSH / HTTP / FTP / SMTP / MYSQL / RDP / SMB / MSSQL /
                        MODBUS / SNMP / S7COMM / PORTSCAN 등 (대문자 정규화)
  source_honeypot       cowrie / heralding / opencanary / snare /
                        dionaea / mailoney / conpot
  event_type            auth / session / command / scan
  event_result          auth: success/fail  session: closed
                        command: executed   scan: detected

  [인증]
  username              인증 시도 사용자명
  password              인증 시도 패스워드
  login_success         0 / 1 (auth 이벤트)
  attempt_no            세션 내 인증 시도 순번 (1, 2, 3 ...)

  [세션]
  duration              세션 길이 초
  login_attempts        세션 내 총 로그인 시도 수

  [HTTP 세부]
  http_method           GET / POST / PUT / DELETE / HEAD / OPTIONS / PATCH
  http_path             URL 경로 (/login, /admin ...)
  http_query            쿼리 문자열 (SQLi/XSS/LFI 페이로드 원문)

  [명령 — 원시]
  command               실행 명령어 또는 HTTP 전체 원본 문자열 (raw)

  [파생값 — 명시적 구분]
  derived_has_wget          0 / 1  (command 분석 결과)
  derived_has_curl          0 / 1  (command 분석 결과)
  derived_has_reverse_shell 0 / 1  (command 분석 결과)

  [메타]
  parser_version        파서 버전 (재현성 보장, 현재 4.0)
"""

import csv
import glob
import hashlib
import json
import re
import sqlite3
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

LOG_BASE           = Path("/honeypot_logs")
HERALDING_LOG_BASE = Path("/heralding_logs")
OUT_BASE           = LOG_BASE

PARSER_VERSION = "4.0"

INGEST_TIME = datetime.now(timezone.utc).isoformat()

DATASET_FIELDS = [
    # 식별
    "event_id", "session_id", "seq_no", "session_seq_no",
    # 시각
    "timestamp", "ingest_time",
    # 네트워크
    "src_ip", "src_port", "dst_ip", "dst_port", "transport",
    # 서비스
    "protocol", "source_honeypot", "event_type", "event_result",
    # 인증
    "username", "password", "login_success", "attempt_no",
    # 세션
    "duration", "login_attempts",
    # HTTP 세부
    "http_method", "http_path", "http_query",
    # 명령 (원시)
    "command",
    # 파생값
    "derived_has_wget", "derived_has_curl", "derived_has_reverse_shell",
    # 메타
    "parser_version",
]

PROTOCOL_TRANSPORT = {
    "SSH": "TCP", "HTTP": "TCP", "HTTPS": "TCP",
    "FTP": "TCP", "SMTP": "TCP", "MYSQL": "TCP",
    "RDP": "TCP", "VNC": "TCP", "SMB": "TCP", "MSSQL": "TCP",
    "TELNET": "TCP", "MODBUS": "TCP", "S7COMM": "TCP",
    "SNMP": "UDP", "PORTSCAN": "TCP", "PPTP": "TCP",
    "BACNET": "UDP", "DNP3": "TCP",
}

HONEYPOT_IP = {
    "cowrie":     "172.30.0.10",
    "heralding":  "172.30.0.11",
    "opencanary": "172.30.0.12",
    "snare":      "172.30.0.13",
    "dionaea":    "172.30.0.14",
    "mailoney":   "172.30.0.15",
    "conpot":     "172.30.0.16",
}

EVENT_RESULT_DEFAULT = {
    "auth":    "",
    "session": "closed",
    "command": "executed",
    "scan":    "detected",
}

REVERSE_SHELL_PATTERNS = [
    "nc ", "/dev/tcp", "python3 -c", "python -c",
    "bash -i", "perl -e", "ruby -r", "mkfifo",
]

_HTTP_METHOD_RE = re.compile(
    r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s+(\S+)',
    re.IGNORECASE,
)


def gen_session_id(src_ip: str, dst_port, ts: str) -> str:
    ts_min = ts[:16] if ts else ""
    key = f"{src_ip}:{dst_port}:{ts_min}"
    return hashlib.md5(key.encode()).hexdigest()[:12]


def parse_http_command(command: str):
    m = _HTTP_METHOD_RE.match(command)
    if not m:
        return "", "", ""
    method    = m.group(1).upper()
    full_path = m.group(2)
    if "?" in full_path:
        path, query = full_path.split("?", 1)
    else:
        path, query = full_path, ""
    return method, path, query


def cmd_flags(cmd: str):
    c = str(cmd)
    return (
        int("wget" in c),
        int("curl" in c),
        int(any(p in c for p in REVERSE_SHELL_PATTERNS)),
    )


def make_row(
    timestamp="", src_ip="", src_port="", dst_port="", protocol="",
    source_honeypot="", event_type="", event_result="",
    username="", password="", login_success="", attempt_no="",
    duration="", login_attempts="",
    command="", has_wget=0, has_curl=0, has_reverse_shell=0,
    session_id="",
):
    proto_upper  = protocol.upper() if protocol else ""
    transport    = PROTOCOL_TRANSPORT.get(proto_upper, "TCP")
    dst_ip       = HONEYPOT_IP.get(source_honeypot, "")

    if not session_id:
        session_id = gen_session_id(src_ip, dst_port, timestamp)

    if not event_result and event_type:
        event_result = EVENT_RESULT_DEFAULT.get(event_type, "")

    if proto_upper == "HTTP" and command:
        http_method, http_path, http_query = parse_http_command(command)
    else:
        http_method = http_path = http_query = ""

    return {
        "event_id":                str(uuid.uuid4()),
        "session_id":              session_id,
        "seq_no":                  "",   # write_csv에서 일괄 부여
        "session_seq_no":          "",   # write_csv에서 일괄 부여
        "timestamp":               timestamp,
        "ingest_time":             INGEST_TIME,
        "src_ip":                  src_ip,
        "src_port":                src_port,
        "dst_ip":                  dst_ip,
        "dst_port":                dst_port,
        "transport":               transport,
        "protocol":                proto_upper,
        "source_honeypot":         source_honeypot,
        "event_type":              event_type,
        "event_result":            event_result,
        "username":                username,
        "password":                password,
        "login_success":           login_success,
        "attempt_no":              attempt_no,
        "duration":                duration,
        "login_attempts":          login_attempts,
        "http_method":             http_method,
        "http_path":               http_path,
        "http_query":              http_query,
        "command":                 command,
        "derived_has_wget":        has_wget,
        "derived_has_curl":        has_curl,
        "derived_has_reverse_shell": has_reverse_shell,
        "parser_version":          PARSER_VERSION,
    }


# ── Cowrie ────────────────────────────────────────────────────────────────────

def parse_cowrie():
    rows     = []
    sessions = {}

    log_files = sorted(glob.glob(str(LOG_BASE / "cowrie" / "cowrie.json*")))
    if not log_files:
        print("[cowrie] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[cowrie] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                eid      = e.get("eventid", "")
                ts       = e.get("timestamp", "")
                sid      = e.get("session", "")
                src      = e.get("src_ip", "")
                src_port = str(e.get("src_port", ""))
                port     = e.get("dst_port", 2222)

                if eid in ("cowrie.login.success", "cowrie.login.failed"):
                    success = 1 if eid == "cowrie.login.success" else 0
                    sess = sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "src_port": src_port,
                        "port": port, "attempts": 0, "successes": 0,
                    })
                    sess["attempts"] += 1
                    sess["successes"] += success

                    rows.append(make_row(
                        timestamp=ts, src_ip=src, src_port=src_port,
                        dst_port=port, protocol="SSH",
                        source_honeypot="cowrie", event_type="auth",
                        event_result="success" if success else "fail",
                        username=e.get("username", ""),
                        password=e.get("password", ""),
                        login_success=success,
                        attempt_no=sess["attempts"],
                        session_id=sid,
                    ))

                elif eid == "cowrie.session.connect":
                    sessions.setdefault(sid, {
                        "start": ts, "src_ip": src, "src_port": src_port,
                        "port": port, "attempts": 0, "successes": 0,
                    })

                elif eid == "cowrie.session.closed":
                    s = sessions.get(sid, {})
                    rows.append(make_row(
                        timestamp=s.get("start", ts),
                        src_ip=s.get("src_ip", src),
                        src_port=s.get("src_port", src_port),
                        dst_port=s.get("port", port),
                        protocol="SSH",
                        source_honeypot="cowrie", event_type="session",
                        event_result="closed",
                        duration=round(float(e.get("duration", 0)), 3),
                        login_attempts=s.get("attempts", 0),
                        session_id=sid,
                    ))

                elif eid in ("cowrie.command.input", "cowrie.session.file_download"):
                    cmd = e.get("input", e.get("url", ""))
                    w, c, r = cmd_flags(cmd)
                    rows.append(make_row(
                        timestamp=ts, src_ip=src, src_port=src_port,
                        dst_port=port, protocol="SSH",
                        source_honeypot="cowrie", event_type="command",
                        event_result="executed",
                        command=cmd, has_wget=w, has_curl=c, has_reverse_shell=r,
                        session_id=sid,
                    ))

    print(f"[cowrie] {len(rows)}행")
    return rows


# ── Heralding ─────────────────────────────────────────────────────────────────

def parse_heralding():
    rows = []

    auth_file = HERALDING_LOG_BASE / "auth.csv"
    if auth_file.exists():
        print(f"[heralding] {auth_file}")
        session_attempts = {}
        with open(auth_file, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                sid      = row.get("session_id", row.get("auth_id", ""))
                src_port = row.get("source_port", "")
                session_attempts[sid] = session_attempts.get(sid, 0) + 1
                rows.append(make_row(
                    timestamp=row.get("timestamp", ""),
                    src_ip=row.get("source_ip", ""),
                    src_port=src_port,
                    dst_port=row.get("destination_port", ""),
                    protocol=row.get("protocol", "").upper(),
                    source_honeypot="heralding", event_type="auth",
                    event_result="fail",
                    username=row.get("username", ""),
                    password=row.get("password", ""),
                    login_success=0,
                    attempt_no=session_attempts[sid],
                    session_id=sid,
                ))

    session_file = HERALDING_LOG_BASE / "session.csv"
    if session_file.exists():
        print(f"[heralding] {session_file}")
        with open(session_file, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                sid      = row.get("session_id", "")
                src_port = row.get("source_port", "")
                rows.append(make_row(
                    timestamp=row.get("timestamp", ""),
                    src_ip=row.get("source_ip", ""),
                    src_port=src_port,
                    dst_port=row.get("destination_port", ""),
                    protocol=row.get("protocol", "").upper(),
                    source_honeypot="heralding", event_type="session",
                    event_result="closed",
                    duration=row.get("duration", ""),
                    login_attempts=row.get("num_auth_attempts", 1),
                    session_id=sid,
                ))

    print(f"[heralding] {len(rows)}행")
    return rows


# ── OpenCanary ────────────────────────────────────────────────────────────────

def parse_opencanary():
    LOGTYPE_MAP = {
        1001:  "PORTSCAN",
        2000:  "FTP",
        3001:  "HTTP",
        4001:  "TELNET",
        5001:  "VNC",
        6001:  "RDP",
        9001:  "SNMP",
        14001: "RDP",
    }
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "opencanary" / "*.log*")))
    if not log_files:
        print("[opencanary] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[opencanary] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                logtype  = e.get("logtype", 0)
                protocol = LOGTYPE_MAP.get(logtype, f"UNKNOWN_{logtype}")
                src_port = str(e.get("src_port", ""))
                rows.append(make_row(
                    timestamp=e.get("utc_time", ""),
                    src_ip=e.get("src_host", ""),
                    src_port=src_port,
                    dst_port=e.get("dst_port", ""),
                    protocol=protocol,
                    source_honeypot="opencanary", event_type="scan",
                    event_result="detected",
                ))

    print(f"[opencanary] {len(rows)}행")
    return rows


# ── SNARE ─────────────────────────────────────────────────────────────────────

def parse_snare():
    rows = []

    def add(ts, src_ip, raw_cmd, src_port=""):
        w, c, r = cmd_flags(raw_cmd)
        rows.append(make_row(
            timestamp=ts, src_ip=src_ip, src_port=src_port,
            dst_port=8080, protocol="HTTP",
            source_honeypot="snare", event_type="command",
            event_result="executed",
            command=raw_cmd, has_wget=w, has_curl=c, has_reverse_shell=r,
        ))

    for logfile in sorted(glob.glob(str(LOG_BASE / "snare" / "*.json*"))):
        print(f"[snare] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                path     = e.get("path", e.get("request_path", ""))
                ts       = e.get("timestamp", e.get("time", ""))
                src_ip   = e.get("peer", e.get("remote_ip", e.get("src_ip", "")))
                src_port = str(e.get("src_port", e.get("peer_port", "")))
                method   = e.get("method", "GET")
                raw_cmd  = f"{method} {path}" if path else path
                add(ts, src_ip, raw_cmd, src_port)

    text_log = LOG_BASE / "snare" / "snare.log"
    if text_log.exists():
        print(f"[snare] {text_log}")
        pattern = re.compile(
            r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
            r'.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?'
            r'.*?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)',
            re.IGNORECASE,
        )
        with open(text_log, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = pattern.search(line)
                if m:
                    ts, src_ip   = m.group(1), m.group(2)
                    src_port     = m.group(3) or ""
                    method, path = m.group(4).upper(), m.group(5)
                    add(ts, src_ip, f"{method} {path}", src_port)

    print(f"[snare] {len(rows)}행")
    return rows


# ── Dionaea ───────────────────────────────────────────────────────────────────

_DIONAEA_PORT_PROTO = {
    "21":   "FTP",
    "445":  "SMB",
    "1433": "MSSQL",
    "1723": "PPTP",
    "3306": "MYSQL",
    "80":   "HTTP",
    "8080": "HTTP",
}


def parse_dionaea():
    rows = []

    text_log = LOG_BASE / "dionaea" / "dionaea.log"
    if text_log.exists():
        print(f"[dionaea] {text_log}")
        accept_pat = re.compile(
            r'\[(\d{8} \d{2}:\d{2}:\d{2})\].*?accepted connection from '
            r'(\d+\.\d+\.\d+\.\d+):(\d+) to '
            r'(\d+\.\d+\.\d+\.\d+):(\d+)'
        )
        with open(text_log, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = accept_pat.search(line)
                if not m:
                    continue
                date_str, src_ip, src_port, _dst_ip, dst_port = m.groups()
                try:
                    ts = datetime.strptime(date_str, "%d%m%Y %H:%M:%S").isoformat()
                except ValueError:
                    ts = date_str
                proto = _DIONAEA_PORT_PROTO.get(dst_port, "UNKNOWN")
                rows.append(make_row(
                    timestamp=ts, src_ip=src_ip, src_port=src_port,
                    dst_port=dst_port, protocol=proto,
                    source_honeypot="dionaea", event_type="session",
                    event_result="closed",
                ))
        print(f"[dionaea] {len(rows)}행 (text log)")
        return rows

    db_path = LOG_BASE / "dionaea" / "logsql.sqlite"
    if not db_path.exists():
        print("[dionaea] 로그 없음, 건너뜀")
        return rows

    print(f"[dionaea] {db_path}")
    try:
        conn = sqlite3.connect(str(db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        cur = conn.cursor()
        cur.execute("""
            SELECT c.connection_timestamp, c.remote_host, c.remote_port,
                   c.local_host, c.local_port, c.connection_protocol,
                   l.login_username, l.login_password
            FROM connections c
            LEFT JOIN logins l ON l.connection = c.id
        """)
        for row in cur.fetchall():
            try:
                ts = datetime.fromtimestamp(float(row["connection_timestamp"])).isoformat()
            except Exception:
                ts = str(row["connection_timestamp"] or "")

            proto    = (row["connection_protocol"] or "UNKNOWN").upper()
            src      = row["remote_host"] or ""
            src_port = str(row["remote_port"] or "")
            port     = row["local_port"] or ""

            rows.append(make_row(
                timestamp=ts, src_ip=src, src_port=src_port,
                dst_port=port, protocol=proto,
                source_honeypot="dionaea", event_type="session",
                event_result="closed",
                login_attempts=1 if row["login_username"] else 0,
            ))
            if row["login_username"]:
                rows.append(make_row(
                    timestamp=ts, src_ip=src, src_port=src_port,
                    dst_port=port, protocol=proto,
                    source_honeypot="dionaea", event_type="auth",
                    event_result="fail",
                    username=row["login_username"] or "",
                    password=row["login_password"] or "",
                    login_success=0,
                ))
        conn.close()
    except sqlite3.DatabaseError as e:
        print(f"[dionaea] DB 오류: {e}")

    print(f"[dionaea] {len(rows)}행")
    return rows


# ── Mailoney ──────────────────────────────────────────────────────────────────

def parse_mailoney():
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "mailoney" / "*.json*")))
    if not log_files:
        print("[mailoney] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[mailoney] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                src_port = str(e.get("src_port", e.get("remote_port", "")))
                rows.append(make_row(
                    timestamp=e.get("timestamp", e.get("time", "")),
                    src_ip=e.get("src_ip", e.get("remote_ip", e.get("ip", ""))),
                    src_port=src_port,
                    dst_port=25, protocol="SMTP",
                    source_honeypot="mailoney", event_type="auth",
                    event_result="fail",
                    username=e.get("username", e.get("user", "")),
                    password=e.get("password", e.get("pass", "")),
                    login_success=0,
                    attempt_no=1,
                ))

    print(f"[mailoney] {len(rows)}행")
    return rows


# ── Conpot ────────────────────────────────────────────────────────────────────

def parse_conpot():
    rows = []

    log_files = sorted(glob.glob(str(LOG_BASE / "conpot" / "*.json*")))
    if not log_files:
        print("[conpot] 로그 파일 없음")
        return rows

    for logfile in log_files:
        print(f"[conpot] {logfile}")
        with open(logfile, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue

                remote   = e.get("remote", {})
                local    = e.get("local", {})
                src_port = str(remote.get("port", e.get("remote_port", "")))
                rows.append(make_row(
                    timestamp=e.get("timestamp", ""),
                    src_ip=remote.get("ip", e.get("remote_ip", "")),
                    src_port=src_port,
                    dst_port=local.get("port", e.get("local_port", "")),
                    protocol=e.get("data_type", e.get("type", "ICS")).upper(),
                    source_honeypot="conpot", event_type="session",
                    event_result="closed",
                    duration=e.get("session_length", e.get("duration", "")),
                ))

    print(f"[conpot] {len(rows)}행")
    return rows


# ── 순번 부여 ─────────────────────────────────────────────────────────────────

def assign_sequence_numbers(rows: list) -> list:
    """
    seq_no        : 전체 이벤트 순번 (timestamp 정렬 후 1부터)
    session_seq_no: 같은 session_id 내 이벤트 순번 (1부터)
    """
    # timestamp 기준 정렬 (빈 문자열은 뒤로)
    rows.sort(key=lambda r: r.get("timestamp") or "9999")

    session_counter: dict = defaultdict(int)
    for i, row in enumerate(rows, start=1):
        row["seq_no"] = i
        sid = row.get("session_id", "")
        session_counter[sid] += 1
        row["session_seq_no"] = session_counter[sid]

    return rows


# ── CSV 출력 ──────────────────────────────────────────────────────────────────

def write_csv(rows, fields, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})
    print(f"[output] {len(rows)}행 → {path}")


# ── 메인 ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print(f" 허니팟 로그 파서  v{PARSER_VERSION}")
    print(f" LOG_BASE:    {LOG_BASE}")
    print(f" INGEST_TIME: {INGEST_TIME}")
    print("=" * 55)

    all_rows = []
    parsers = [
        parse_cowrie, parse_heralding, parse_opencanary,
        parse_snare, parse_dionaea, parse_mailoney, parse_conpot,
    ]

    for parser in parsers:
        try:
            all_rows.extend(parser())
        except Exception as ex:
            import traceback
            print(f"[!] {parser.__name__} 오류: {ex}")
            traceback.print_exc()

    print()
    print("순번 부여 중 (timestamp 정렬)...")
    all_rows = assign_sequence_numbers(all_rows)

    print("=" * 55)
    write_csv(all_rows, DATASET_FIELDS, OUT_BASE / "dataset.csv")

    hp_cnt = Counter(r["source_honeypot"] for r in all_rows)
    et_cnt = Counter(r["event_type"]      for r in all_rows)
    er_cnt = Counter(r["event_result"]    for r in all_rows)
    pr_cnt = Counter(r["protocol"]        for r in all_rows)

    print()
    print(" [허니팟별]")
    for k, v in hp_cnt.most_common():
        print(f"   {k:<12} {v:>6}행")
    print()
    print(" [event_type별]")
    for k, v in et_cnt.most_common():
        print(f"   {k:<10} {v:>6}행")
    print()
    print(" [event_result별]")
    for k, v in er_cnt.most_common():
        print(f"   {k:<10} {v:>6}행")
    print()
    print(f" 컬럼 수: {len(DATASET_FIELDS)}")

    # ── dataset_meta.json 저장 ─────────────────────────────────────────────────
    meta = {
        "schema_version":   PARSER_VERSION,
        "parser_version":   PARSER_VERSION,
        "dataset_version":  INGEST_TIME,
        "row_count":        len(all_rows),
        "column_count":     len(DATASET_FIELDS),
        "columns":          DATASET_FIELDS,
        "distributions": {
            "source_honeypot": dict(hp_cnt.most_common()),
            "event_type":      dict(et_cnt.most_common()),
            "event_result":    dict(er_cnt.most_common()),
            "protocol":        dict(pr_cnt.most_common()),
        },
    }
    meta_path = OUT_BASE / "dataset_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    print(f" 메타데이터: {meta_path}")

    print(" 완료!")
    print("=" * 55)
