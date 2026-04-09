# Docker Honeypot Lab

Docker 기반 허니팟 7종과 Kali Linux 공격자 컨테이너로 구성된 폐쇄형 사이버 공격 시뮬레이션 랩.  
6가지 공격 시나리오를 자동 실행하고, 수집된 로그를 ML 학습용 레이블된 CSV 데이터셋으로 변환한다.

> **주의:** 이 프로젝트는 교육·연구 목적의 격리된 로컬 환경 전용입니다.  
> 외부 네트워크에 절대 노출하지 마세요.

---

## 아키텍처

```
honeypot-net (172.30.0.0/24)
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  cowrie      172.30.0.10   SSH(2222) / Telnet(2223)     │ 
│  heralding   172.30.0.11   HTTP(80) / MySQL(3306)       │
│  opencanary  172.30.0.12   FTP(21) / RDP(3389) / VNC    │
│  snare       172.30.0.13   HTTP(8080)                   │
│  dionaea     172.30.0.14   SMB(445) / FTP(21) / MSSQL   │
│  mailoney    172.30.0.15   SMTP(25)                     │
│  conpot      172.30.0.16   Modbus(502) / S7(102) / SNMP │
│                                                         │
│  kali        172.30.0.20   ← 공격자 컨테이너             │
└─────────────────────────────────────────────────────────┘
```

| 컨테이너 | 이미지 | 수집 공격 유형 | 로그 포맷 |
|----------|--------|---------------|-----------|
| cowrie | `cowrie/cowrie:latest` | SSH/Telnet 브루트포스, 명령어, 리버스 셸 | JSON |
| heralding | 커스텀 빌드 | HTTP/MySQL 인증 시도 | CSV |
| opencanary | 커스텀 빌드 | FTP/RDP/VNC 접근 시도 | JSON |
| snare | 커스텀 빌드 | SQLi, XSS, LFI, 디렉터리 트래버설 | JSON |
| dionaea | `dinotools/dionaea:latest` | SMB 익스플로잇, 멀웨어 | SQLite |
| mailoney | 커스텀 구현 (asyncio) | SMTP 스팸, AUTH 시도 | JSON |
| conpot | 커스텀 구현 (asyncio) | ICS/SCADA Modbus, S7comm, SNMP | JSON |
| kali-attacker | `debian:bookworm-slim` | — | — |

---

## 요구사항

| 항목 | 내용 |
|------|------|
| OS | Windows 11 (WSL2 필수) |
| 런타임 | Docker Desktop (WSL2 백엔드) |
| RAM | 8GB 이상 권장 |
| 저장공간 | 이미지 빌드 포함 약 5GB |

---

## 빠른 시작

```bash
# 1. 저장소 클론
git clone https://github.com/<username>/docker-honeypot.git
cd docker-honeypot

# 2. 초기 설정 (로그 디렉터리 생성 + .env 생성)
bash setup.sh

# 3. .env 파일에서 로그 경로 확인/수정
#    HONEYPOT_LOGS=/mnt/d/honeypot_logs  ← 본인 드라이브로 변경

# 4. 컨테이너 빌드 및 실행
docker compose build
docker compose up -d

# 5. 상태 확인 (8개 컨테이너 모두 Up)
docker compose ps
```

---

## 공격 시나리오 실행

| 번호 | 스크립트 | 도구 | ML 레이블 |
|------|----------|------|-----------|
| 01 | `01_normal_traffic.sh` | curl, wget, nc | Etc |
| 02 | `02_port_scan.sh` | nmap | Recon |
| 03 | `03_brute_force.sh` | hydra (SSH/HTTP/MySQL) | Brute Force |
| 04 | `04_web_attacks.sh` | sqlmap, curl | Intrusion |
| 05 | `05_post_intrusion.sh` | sshpass + ssh | Intrusion |
| 06 | `06_reverse_shell.sh` | nc, python3 | Intrusion |

```bash
# 6종 시나리오 자동 실행 (약 4분 소요)
docker exec -it kali-attacker bash /scripts/run_scenarios.sh
```

---

## 데이터셋 생성

```bash
# 로그 파싱 + 레이블링 (반드시 docker exec 방식으로 실행)
docker exec kali-attacker bash -c \
  "python3 /scripts/parse_logs.py && python3 /scripts/label_data.py"
```

### 출력 파일

| 파일 | 내용 | 주요 컬럼 |
|------|------|-----------|
| `auth.csv` | 인증 시도 로그 | timestamp, src_ip, dst_port, protocol, username, password, login_success, label |
| `sessions.csv` | 세션 연결 정보 | timestamp, src_ip, dst_port, protocol, duration, login_attempts, label |
| `input.csv` | 명령어 / 페이로드 | timestamp, src_ip, command, has_wget, has_curl, has_reverse_shell, label |

### ML 클래스

| 레이블 | 설명 |
|--------|------|
| **Etc** | 정상 트래픽 |
| **Recon** | 포트스캔 / 정찰 |
| **Brute Force** | 무차별 대입 공격 |
| **Intrusion** | 침투 후 행동 / 리버스 셸 |
| **Malware** | wget/curl을 통한 악성코드 다운로드 |

---

## 디렉터리 구조

```
docker-honeypot/
├── docker-compose.yml
├── .env.example          ← cp .env.example .env 후 수정
├── setup.sh              ← 초기 설정 스크립트
│
├── honeypots/
│   ├── cowrie/           cowrie.cfg, userdb.txt
│   ├── heralding/        Dockerfile, heralding.yml
│   ├── opencanary/       Dockerfile, opencanary.conf
│   ├── snare/            Dockerfile
│   ├── dionaea/          dionaea.cfg
│   ├── mailoney/         Dockerfile, honeypot.py
│   └── conpot/           Dockerfile, honeypot.py
│
├── kali/
│   └── Dockerfile
│
├── attack_scenarios/
│   ├── 01_normal_traffic.sh
│   ├── 02_port_scan.sh
│   ├── 03_brute_force.sh
│   ├── 04_web_attacks.sh
│   ├── 05_post_intrusion.sh
│   └── 06_reverse_shell.sh
│
└── scripts/
    ├── run_scenarios.sh  ← 시나리오 실행 + 타임스탬프 기록
    ├── parse_logs.py     ← 7종 로그 파싱 → CSV
    └── label_data.py     ← 레이블링
```

로그 출력 경로 (repo 외부):
```
/mnt/d/honeypot_logs/
├── cowrie/cowrie.json
├── conpot/conpot.json
├── ...
├── auth.csv
├── sessions.csv
└── input.csv
```

---

## 레이블링 방식

1. **타임스탬프 기반**: 각 시나리오의 시작~종료 시각(`scenario_times.json`)에 로그 타임스탬프를 매칭
2. **Rule-based 보완**:

| 조건 | 레이블 |
|------|--------|
| `has_reverse_shell == 1` | Intrusion |
| `has_wget == 1` 또는 `has_curl == 1` | Malware |
| `login_attempts >= 10` | Brute Force |
| `protocol == PORTSCAN` | Recon |
| `source_honeypot == conpot` | Recon |
| 매칭 없음 | Etc |

---

## 라이선스

MIT License — 교육 및 연구 목적으로 자유롭게 사용 가능.  
본 저장소의 코드를 실제 시스템 공격에 사용하는 것은 위법입니다.
