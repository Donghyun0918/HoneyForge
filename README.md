# Docker Honeypot Lab

Docker 기반 허니팟 7종과 Kali Linux 공격자 컨테이너로 구성된 폐쇄형 사이버 공격 시뮬레이션 랩.  
9가지 공격 시나리오를 자동 실행하고, 수집된 로그를 ML 학습용 레이블된 단일 CSV 데이터셋으로 변환한다.

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
│  tanner      172.30.0.17   SNARE 분석 서버 (포트 8090)   │
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
| opencanary | 커스텀 빌드 | FTP/RDP/VNC 접근 시도, 포트스캔 탐지 | JSON |
| snare | 커스텀 빌드 | SQLi, XSS, LFI, 디렉터리 트래버설 | Text/JSON |
| tanner | 커스텀 스텁 | SNARE 분석 서버 (로컬) | — |
| dionaea | `dinotools/dionaea:latest` | SMB 익스플로잇, FTP, MSSQL 멀웨어 | SQLite |
| mailoney | 커스텀 구현 | SMTP 스팸, AUTH 브루트포스 | JSON |
| conpot | 커스텀 구현 | ICS/SCADA Modbus, S7comm, SNMP | JSON |
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
git clone https://github.com/Donghyun0918/Docker-honeypot.git
cd Docker-honeypot

# 2. 초기 설정 (로그 디렉터리 생성 + .env 생성)
bash setup.sh

# 3. .env 파일에서 로그 경로 확인/수정
#    HONEYPOT_LOGS=/mnt/d/honeypot_logs  ← 본인 드라이브로 변경

# 4. 컨테이너 빌드 및 실행
docker compose build
docker compose up -d

# 5. 상태 확인 (9개 컨테이너 모두 Up)
docker compose ps
```

---

## 공격 시나리오

### 전술 라이브러리 기반 랜덤화 시스템

각 시나리오는 실행할 때마다 전술 풀에서 무작위로 전술을 선택하고, 유저명·패스워드·페이로드·강도·타겟을 랜덤화한다. 동일한 시나리오를 반복해도 매번 다른 공격 패턴이 생성된다.

```
attack_scenarios/
├── lib/
│   ├── common.sh            # IP 상수, 유저/패스워드/페이로드 풀, 유틸 함수
│   │                        # (유저 50+, 패스워드 60+, SQLi 13종, XSS 10종,
│   │                        #  LFI 10종, 리버스셸 7종, C2 URL 7종)
│   ├── tactics_normal.sh    # 정상 트래픽 전술 8종
│   ├── tactics_recon.sh     # 정찰 전술 12종
│   ├── tactics_brute.sh     # 브루트포스 전술 11종
│   ├── tactics_intrusion.sh # 침투 전술 9종
│   ├── tactics_malware.sh   # 악성코드 전술 8종
│   └── tactics_ics.sh       # ICS/SCADA 전술 8종
└── 01~09_*.sh               # 실행마다 전술 N개 랜덤 선택
```

**랜덤화 요소:**

| 요소 | 범위 |
|------|------|
| 전술 조합 | 풀에서 매 실행마다 4~8종 무작위 선택 |
| 유저명 | 50+ 항목 풀에서 샘플링 |
| 패스워드 | 60+ 항목 풀에서 N개 샘플링 |
| 페이로드 | SQLi·XSS·LFI·리버스셸 각 10~13종 풀 |
| 공격 강도 | 요청 수, hydra 스레드 수 랜덤 |
| 타겟 | 복수 허니팟 중 랜덤 선택 |
| 타이밍 | 요청 간격 랜덤 |

### 시나리오 목록

| 번호 | 스크립트 | ML 레이블 | 전술 풀 | 대상 허니팟 |
|------|----------|-----------|---------|------------|
| 01 | `01_normal_traffic.sh` | Etc | 8종 중 4~7 선택 | heralding, snare, cowrie, conpot |
| 02 | `02_port_scan.sh` | Recon | 12종 중 4~7 선택 | opencanary, 전체 네트워크 |
| 03 | `03_brute_force.sh` | Brute Force | 11종 중 4~7 선택 | cowrie, heralding, mailoney |
| 04 | `04_web_attacks.sh` | Intrusion | 8종 중 4~6 선택 | snare(SQLi·XSS·LFI·RFI·CMD) |
| 05 | `05_post_intrusion.sh` | Intrusion | 명령어 랜덤 조합 | cowrie(시스템 정찰·권한상승) |
| 06 | `06_reverse_shell.sh` | Intrusion | 7종 기법 랜덤 | cowrie(nc·python·perl·php·ruby) |
| 07 | `07_malware_upload.sh` | Malware | 8종 중 4~6 선택 | cowrie(wget·curl·C2), dionaea(FTP) |
| 08 | `08_credential_stuffing.sh` | Brute Force | 10종 중 5~8 선택 | opencanary·dionaea·cowrie·heralding |
| 09 | `09_ics_attack.sh` | Recon | 8종 중 4~6 선택 | conpot(Modbus·SNMP·S7·BACnet·DNP3) |

### 실행

```bash
# 단일 실행 (9종 순차)
docker exec -it kali-attacker bash /scripts/run_scenarios.sh

# 대용량 데이터셋 수집 (40회 × 9종, 약 2~3시간)
docker exec -it kali-attacker bash /scripts/run_loop.sh 40 5
#                                                        ↑   ↑
#                                               반복 횟수   시나리오간 대기(초)
```

---

## 데이터셋 생성

```bash
# 로그 파싱 + 레이블링 (반드시 docker exec 방식으로 실행)
docker exec kali-attacker bash -c \
  "python3 /scripts/parse_logs.py && python3 /scripts/label_data.py"
```

### 출력 파일: `dataset.csv` (단일 통합 파일, 15컬럼)

레이블 없는 순수 피처 데이터셋. 레이블링은 별도로 `label_data.py`를 선택적으로 실행한다.

| 컬럼 | 설명 | 유효 event_type |
|------|------|----------------|
| `timestamp` | ISO 8601 UTC | 전체 |
| `src_ip` | 공격자 IP | 전체 |
| `dst_port` | 대상 포트 | 전체 |
| `protocol` | SSH / HTTP / FTP / SMTP / MySQL / RDP / PORTSCAN 등 | 전체 |
| `source_honeypot` | cowrie / heralding / opencanary / snare / dionaea / mailoney / conpot | 전체 |
| `event_type` | **auth / session / command / scan** | 전체 |
| `username` | 인증 시도 사용자명 | auth |
| `password` | 인증 시도 패스워드 | auth |
| `login_success` | 0 / 1 | auth |
| `duration` | 세션 길이 (초) | session |
| `login_attempts` | 세션 내 로그인 시도 수 | session |
| `command` | 실행 명령어 또는 HTTP 경로 | command |
| `has_wget` | 0 / 1 | command |
| `has_curl` | 0 / 1 | command |
| `has_reverse_shell` | 0 / 1 | command |

---

## 레이블링 (선택)

`dataset.csv`는 레이블 없는 순수 피처 파일이다. 필요 시 아래 명령어로 레이블을 추가할 수 있다.

```bash
docker exec kali-attacker python3 /scripts/label_data.py
```

`label_data.py`는 `dataset.csv`에 `label` 컬럼을 추가하여 덮어쓴다.

**레이블링 전략:**

1. **타임스탬프 기반**: 각 시나리오의 시작~종료 시각(`scenario_times.json`)에 로그 타임스탬프를 매칭
2. **Rule-based 보완** (타임스탬프 매칭 실패 시):

| 조건 | 레이블 |
|------|--------|
| `has_reverse_shell == 1` | Intrusion |
| `event_type == command` + `has_wget/curl == 1` | Malware |
| `event_type == scan` / `protocol == PORTSCAN` | Recon |
| `source_honeypot == conpot` | Recon |
| `protocol == SMTP` | Brute Force |
| `login_attempts >= 10` | Brute Force |
| 매칭 없음 | Etc |

**ML 클래스:** Etc / Recon / Brute Force / Intrusion / Malware

---

## 디렉터리 구조

```
Docker-honeypot/
├── docker-compose.yml
├── .env.example
├── setup.sh
│
├── honeypots/
│   ├── cowrie/           cowrie.cfg, userdb.txt
│   ├── heralding/        Dockerfile, heralding.yml
│   ├── opencanary/       Dockerfile, opencanary.conf
│   ├── snare/            Dockerfile
│   ├── tanner/           Dockerfile, stub.py
│   ├── dionaea/          dionaea.cfg
│   ├── mailoney/         Dockerfile, honeypot.py
│   └── conpot/           Dockerfile, honeypot.py
│
├── kali/
│   └── Dockerfile
│
├── attack_scenarios/
│   ├── lib/              ← 전술 라이브러리 (6개 파일)
│   └── 01~09_*.sh        ← 랜덤화 시나리오 스크립트
│
└── scripts/
    ├── run_scenarios.sh  ← 9종 시나리오 1회 실행
    ├── run_loop.sh       ← N회 반복 실행 (대용량 수집)
    ├── parse_logs.py     ← 7종 허니팟 로그 → dataset.csv
    └── label_data.py     ← 타임스탬프 + rule-based 레이블링
```

로그 출력 경로 (repo 외부):
```
/mnt/d/honeypot_logs/
├── cowrie/     cowrie.json*
├── heralding/  auth.csv, session.csv
├── opencanary/ opencanary.log*
├── snare/      snare.log
├── dionaea/    logsql.sqlite
├── mailoney/   *.json
├── conpot/     *.json
└── dataset.csv     ← 최종 통합 데이터셋
```

---

## 라이선스

MIT License — 교육 및 연구 목적으로 자유롭게 사용 가능.  
본 저장소의 코드를 실제 시스템 공격에 사용하는 것은 위법입니다.
