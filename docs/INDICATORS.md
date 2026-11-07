# NIKKE PC 런처 침해 사고 — 침해 지표(IOC)와 복구 절차 정리

이 문서는 `NikkeCheck`가 검사하는 항목의 근거를 정리한 것입니다.
기준일: 2026-11-07. 확인한 출처는 맨 아래에 있습니다.

## 1. 사고 요약

| 시각 (KST, UTC+9) | 내용 | 출처 |
|---|---|---|
| 2026-09-27 10:59 | 일부 게임 서비스에 쓰이던 도메인 `insightjs.com`을 제3자가 탈취 | 공식(Inven 인용) |
| 2026-09-27 15:41~15:42 | 런처가 내려받는 공식 CDN 스크립트 4개가 변조됨 | 공식, 연구자 |
| 2026-10-24 01:40경 | 악성 에이전트가 실행된 가장 이른 보고 (UTC 10-23 16:40) | 연구자 |
| 2026-10-30 03:52 | 변조 스크립트로 악성 프로그램 유포 시작 (공식 발표 기준) | 공식 |
| 2026-11-04 00:00경 | 운영사가 이상 징후 탐지 | 공식 |
| 2026-11-04 02:04~02:23 | 변조 파일 3개를 정상 파일로 교체 | 공식 |
| 2026-11-04 12:09 | 남은 1개 파일의 CDN 캐시 갱신 완료 | 공식 |
| 2026-11-05 08:00 | 공식 PC 클라이언트에 자동 검사·삭제 기능(ACE) 적용 | 공식 |

- 영향 범위: **Windows PC 런처만** 해당합니다. 모바일 버전은 영향이 없습니다(공식).
- 점검 대상: **2026-09-27 15:41(KST) 이후 Windows PC 런처를 한 번이라도 실행한 사용자**(공식).
- 악성 에이전트(K2F)는 원격 명령 실행, 파일 열람·다운로드, 화면 캡처, NIKKE 로그인 정보 수집,
  브라우저 비밀번호·쿠키 수집, 개발자 자격 증명·API 토큰 검색, 암호화폐 지갑 확장 데이터 수집이 가능합니다.

## 2. 공식 수동 점검 절차 (Level Infinite, 2026-11-05)

1. **준비:** 네트워크 연결 해제 → NIKKE 게임, PC 런처, Google Chrome 완전 종료(트레이 아이콘 확인).
   점검이 끝날 때까지 런처를 다시 실행하지 않습니다.
2. **로그 확인:** `<설치 폴더>\Launcher\intl_service\debug.log`
   (예: `C:\NIKKE\Launcher\intl_service\debug.log`, `C:\NIKKE_GOOGLE\Launcher\intl_service\debug.log`)
   에서 `k2f_chan registered`를 검색합니다.
   - 있으면 악성 프로그램이 실행되었을 가능성이 있으므로 제거 절차를 진행합니다.
   - 없어도 위험을 완전히 배제할 수 없으므로 백신 전체 검사를 권장합니다.
3. **제거 절차 (순서 중요):**
   1. 레지스트리 `HKEY_CURRENT_USER\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` 삭제.
      **다른 경로(HKLM 등)의 같은 이름 항목은 삭제하지 않습니다.**
   2. Windows 재시작.
   3. `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\` 안에서
      **이름이 정확히 64자리 16진수**이고 **`platform_experience_helper.dll`을 포함한** 하위 폴더만 삭제.
      `PlatformExperienceHelper` 폴더 전체는 정상 Chrome 파일이 있을 수 있으므로 삭제하지 않습니다.
   4. `<설치 폴더>\Launcher\log\tinyget`에서 크기가 **205,135바이트**이고 이름이
      `tinyget.<날짜>-<시간>.log` 형식인 파일 삭제.
   5. `%APPDATA%\nikke_launcher\tbs_cache` 폴더 전체 삭제.
4. **계정 보안:** 깨끗한 다른 기기에서 해당 PC에서 쓰던 모든 계정의 비밀번호 변경,
   API 키·액세스 토큰 폐기 후 재발급.
5. **시스템 검사:** 백신 최신화 후 전체 검사 + Microsoft Defender 오프라인 검사.

## 3. 연구자 분석으로 보강한 지표 (MotherSphere)

공식 절차가 놓치는 부분을 보완하기 위해 아래 지표도 검사합니다.

### 로그 문자열 (`Launcher\intl_service\*.log`)

| 문자열 | 의미 | 판정 |
|---|---|---|
| `k2f_chan registered` | 에이전트가 다운로드되어 시작됨 (공식 기준) | 감염 확인 |
| `agent started as <컴퓨터 이름>` | 서버 응답을 받고 동작 시작 | 감염 확인 |
| `adopted <uuid>` | 에이전트 ID 할당 | 감염 확인 |
| `lua downloaded to log\tinyget\...` | 페이로드 다운로드 | 위험 |
| `startup failed: EIO` | 시작했지만 ID를 받지 못함 (비ASCII 사용자 이름) | 위험 |
| `insightjs` | 공격자 도메인 관련 기록 | 위험 |

### 파일

| 위치 | 지표 | 판정 |
|---|---|---|
| `Launcher\log\tinyget\*` | 파일이 `1B 4C 4A`(LuaJIT 바이트코드)로 시작 | 감염 확인 |
| `Launcher\log\tinyget\tinyget.*.log` | 205,135바이트 (공식 기준) | 감염 확인 |
| `Launcher\log\tinyget\k2f.lua` | 10/23 빌드, 165,108바이트 | 감염 확인 |
| 페이로드 SHA-256 | `cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec` (205,135B), `60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1` (165,108B) | 감염 확인 |
| `%APPDATA%\nikke_launcher*\tbs_cache\Local Storage\leveldb\` | `k2f.agent.state` 키 (압축된 `.ldb`도 해제해서 검사) | 감염 확인 |
| `%APPDATA%\nikke_launcher*\tbs_cache\Code Cache\js\` | `dd65fa4d61079e7e_0`, `ce2fd3f1007a9fe9_0`, `1416c638b3830103_0`, `fd520c7c0f65c2d7_0` | 위험 (로더 실행) |
| `%APPDATA%\nikke_launcher*\tbs_cache\` 전체 | `insightjs` 또는 `String.fromCharCode(111,114,103)` (gzip 해제 후 포함) | 위험 |
| `%APPDATA%\nikke_launcher*\tbs_cache\TransportSecurity` | 공격자 도메인의 HSTS 기록 (해시된 호스트명) | 위험 |
| `%TEMP%\k2f-bcreds-*.db` | 브라우저 자격 증명 수집 작업 | 감염 확인 |
| `%TEMP%\k2f_screen_*.jpg / .png` | 화면 캡처 | 감염 확인 |
| `%TEMP%\k2f-keyscan-*.db` | 10/23 빌드의 수집 작업 | 감염 확인 |
| `Chrome\Application\PlatformExperienceHelper\` | `platform_experience_helper.dll(.old)`, `old-clsid.txt` (정상은 `.exe`만 있음) | 위험 (수동 확인) |

런처 데이터 폴더는 `nikke_launcher`(글로벌), `nikke_launcher_hmt`(HMT), `nikke_launcher_google`(Google Play PC)
세 가지가 있으며, 공식 안내는 첫 번째만 언급합니다.

변조된 CDN 스크립트(SHA-256, gzip 해제 후 비교):

| 파일 | 크기 | SHA-256 |
|---|---|---|
| `aegis-fix.min.js` | 69,731 | `04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d` |
| `images.7fec4c32.js` | 4,358 | `21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce` |
| `FeedList.feb647c9.js` | 5,808 | `2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203` |
| `vue-bucket.min.js` | 135,273 | `3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193` |

### 네트워크

- 도메인: `insightjs.com`, `analytics.insightjs.com`, `insightjs.org`
  (인증서에만 보인 이름: `www.` `api.` `cdn.` `portal.` `docs.insightjs.com`)
- IP: `89.127.233.127`, `89.126.250.172`
- DNS 캐시(`ipconfig /displaydns`)에 `insightjs`가 있으면 최근 조회 기록으로 판단합니다.

### 지속성 (Persistence)

- 유일하게 확인된 지속성: HKCU COM 등록 + Chrome 위장 DLL.
- 에이전트에는 예약 작업, Run 키, 서비스, WMI, 시작프로그램 폴더를 만드는 코드가 없습니다.
  (단, 원격 `exec` 명령으로 무엇이든 실행할 수 있었으므로 감염 확인 시 Windows 재설치가 가장 안전합니다.)
- DLL은 피해자마다 따로 빌드된 것으로 보여 해시가 공통 지표가 아닙니다. 경로·조건으로 판별합니다.

### 지표가 아닌 것 (오탐 주의)

- `%LOCALAPPDATA%\Temp\onominan.tmp` — 연구자가 철회한 지표.
- `HKLM\...\CLSID\{E77CC89B-...}` → `wpc.dll` — Windows 자녀 보호 기능의 정상 항목.
- `kernelscv[.]cfd`, `nikke_bootstrap.dll`, `NikkeUpdate`, `NIKKE_Helper` — 이 사고와 무관.
  댓글로 퍼진 가짜 "해결 명령어" `iex (irm ...)`는 실행하면 안 됩니다.

## 4. 출처

- 공식 수동 점검 공지: https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7
- 공식 X 공지: https://x.com/NIKKE_en/status/2117817602659770434
- 연구자 분석(MotherSphere): https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
- BleepingComputer: https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/
- Malwarebytes: https://www.malwarebytes.com/blog/news/2026/11/nikke-pc-launcher-compromise-put-players-passwords-and-personal-files-at-risk
- Inven Global: https://www.invenglobal.com/articles/28158/level-infinite-apologizes-for-nikke-pc-launcher-issue-accepts-reports-of-secondary-damages
