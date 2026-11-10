# NikkeCheck — NIKKE PC 런처 보안 점검·복구 도구

2026년 11월에 공개된 **승리의 여신: 니케 Windows PC 런처 침해 사고**의 흔적을 검사하고,
공식 안내에 따라 악성 구성요소를 제거하는 Windows 전용 프로그램입니다.

- **2026-09-27 15:41(KST) 이후 Windows PC 런처를 한 번이라도 실행했다면** 점검 대상입니다(공식 공지).
- 모바일 버전은 영향이 없습니다.
- 설치 없이 실행되는 단일 exe입니다 (.NET Framework 4.8 — Windows 10 1903 이상, Windows 11에 기본 포함).
- **검사는 읽기 전용**이며, 어떤 정보도 인터넷으로 보내지 않습니다. 인터넷 연결을 끊고 실행해도 됩니다.

> ⚠ 이 도구는 Level Infinite/SHIFT UP의 공식 프로그램이 아닙니다. 공식 공지와 공개된 보안 연구를 바탕으로 만든 비공식 도구입니다.

## 다운로드

[최신 Release](https://github.com/iskasian7/nikke_check/releases/latest)에서 `NikkeCheck.exe`를 받으세요.
받은 파일이 변조되지 않았는지는 PowerShell에서 아래 명령으로 SHA-256을 구해, Release에 함께 올린
`NikkeCheck.exe.sha256`의 값과 비교해 확인할 수 있습니다.

```powershell
Get-FileHash .\NikkeCheck.exe -Algorithm SHA256
```

## 사용법

1. 니케 게임, PC 런처(트레이 아이콘 포함), Google Chrome을 완전히 종료합니다.
   가능하면 네트워크 연결도 끊습니다(공식 권장).
2. **점검이 끝날 때까지 NIKKE 런처를 다시 실행하지 마세요.** 11월 5일 이후 런처는 실행 시 증거 로그를 지울 수 있습니다.
3. `NikkeCheck.exe`를 실행하면 자동으로 검사합니다.
   설치 폴더를 찾지 못하면 **[설치 폴더 추가…]**로 지정하세요
   (바탕화면 NIKKE 아이콘 → 오른쪽 클릭 → [파일 위치 열기]).
4. 결과가 나오면 필요에 따라
   - **[증거 백업…]** — 로그·캐시·레지스트리 정보를 zip으로 보관 (복구 전에 자동으로도 만듭니다)
   - **[복구 실행…]** — 체크한 항목만 공식 순서대로 삭제
   - **[보고서 저장…]** — 결과를 텍스트 파일로 저장
   - **[차단 해제…]** — 이 프로그램이 추가한 hosts·방화벽 차단을 되돌림 (차단이 있을 때만 활성화)
5. 감염이 확인되면 **반드시 다른 깨끗한 기기에서** 비밀번호를 바꾸고, 모든 세션 로그아웃,
   API 키·토큰 재발급, 암호화폐 지갑 이전을 진행하세요. 가장 안전한 방법은 Windows 재설치입니다.

## 검사 항목

| 항목 | 위치 | 근거 |
|---|---|---|
| 런처 로그의 `k2f_chan registered` 등 | `<설치 폴더>\Launcher\intl_service\debug.log` | 공식 + 연구자 |
| 악성 에이전트 파일 (205,135바이트, LuaJIT, 알려진 해시) | `<설치 폴더>\Launcher\log\tinyget\` | 공식 + 연구자 |
| 공격자 서버 통신 기록 | `<설치 폴더>\Launcher\log\` | 연구자 |
| 악성 COM 등록 | `HKCU\Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}` | 공식 |
| Chrome 위장 DLL | `%LOCALAPPDATA%\Google\Chrome\User Data\PlatformExperienceHelper\<64자리>\platform_experience_helper.dll` | 공식 |
| 에이전트 상태·변조 스크립트 캐시·HSTS 기록 | `%APPDATA%\nikke_launcher*\tbs_cache\` (글로벌·HMT·Google Play 빌드 모두) | 공식 + 연구자 |
| 에이전트 작업 파일 (비밀번호 수집, 스크린샷) | `%TEMP%\k2f-*` | 연구자 |
| DNS 캐시의 공격자 도메인 | `ipconfig /displaydns` | 연구자 |
| 차단 설정 | hosts 파일, Windows 방화벽 | 연구자 |

압축된 LevelDB(`.ldb`)와 gzip으로 저장된 캐시도 풀어서 검사합니다. 지표의 상세 근거는
[docs/INDICATORS.md](docs/INDICATORS.md)에, 설계·검사/복구 로직·테스트·소스 전문은
[docs/NikkeCheck_개발문서.docx](docs/NikkeCheck_개발문서.docx)에 정리되어 있습니다.

## 복구 항목 (공식 순서)

1. HKCU의 악성 CLSID 레지스트리 삭제 (HKLM의 같은 이름 항목은 Windows 정상 항목이라 건드리지 않음)
2. `tinyget` 폴더의 악성 에이전트 파일 삭제
3. `%TEMP%`의 에이전트 작업 파일 삭제
4. 런처 로컬 캐시(`tbs_cache`) 삭제
5. Chrome 위장 DLL이 들어 있는 **64자리 폴더만** 삭제 (`PlatformExperienceHelper` 폴더 자체는 유지)
6. (선택) 공격자 도메인·IP 차단 — hosts 파일 + Windows 방화벽, 관리자 권한 확인 창이 뜸

- 각 항목은 **삭제 직전에 조건을 다시 확인**하며, 조건이 맞지 않으면 건너뜁니다.
- 차단은 **[차단 해제…]**로 되돌릴 수 있습니다. hosts 파일에서는 이 프로그램이 추가한 구역
  (`# NikkeCheck: ...` 줄과 그 아래 `0.0.0.0 <공격자 도메인>` 줄)만 지우고, 사용자가 직접 넣은 줄은 그대로 둡니다.
  바꾸기 전마다 `hosts.nikkecheck-날짜.bak` 백업을 만들며, 방화벽 규칙은 이름(`NikkeCheck - Block NIKKE launcher attacker IPs`)으로 삭제합니다.
  연구자는 CDN 침해 경로가 밝혀지지 않아 차단 유지를 권장합니다.
- DLL이 사용 중이라 지우지 못하면 재부팅 후 프로그램이 한 번 자동 실행되어 마저 지웁니다(HKCU RunOnce).
- `debug.log`는 감염 증거이므로 지우지 않습니다. 그래서 복구 후에도 "감염 이력 있음"으로 표시됩니다.
- 증거 백업은 기본으로 `%USERPROFILE%\NIKKE_점검백업`에 저장됩니다(클라우드 동기화 폴더를 피하기 위해).
  백업에는 로그인 티켓·쿠키가 들어 있을 수 있으니 공개된 곳에 올리지 마세요.
  변조된 스크립트가 들어 있어 백신이 백업 파일을 격리할 수 있습니다.

## 명령줄

```
NikkeCheck.exe                              GUI
NikkeCheck.exe --report 결과.txt            읽기 전용 검사 후 보고서 저장 (종료 코드 0 정상 / 1 주의 / 2 위험 / 3 감염 확인)
NikkeCheck.exe --report 결과.txt --add-root D:\Games\NIKKE
```

## 빌드

.NET SDK(8 이상)가 필요합니다. 결과물은 `dist\NikkeCheck.exe`입니다.

```powershell
.\build.ps1
```

`tools\New-InfectedSandbox.ps1`은 **가짜** 감염 환경(악성코드 없음)을 만들어 화면과 복구 흐름을
시험하는 개발용 스크립트입니다. `NIKKECHECK_SANDBOX` 환경 변수로 지정하면 실제 PC 대신 그 폴더를 검사합니다.

## 주의

- 댓글·커뮤니티에 올라온 "해결 명령어"(PowerShell `iex (irm ...)` 등)를 실행하지 마세요. 가짜 해결법으로 위장한 악성코드가 퍼졌습니다.
- 이 도구는 **알려진 흔적만** 찾고 지웁니다. 흔적이 없어도 위험을 완전히 배제할 수 없으므로 백신 전체 검사와
  Microsoft Defender 오프라인 검사를 함께 하세요.
- 서명되지 않은 exe라 처음 실행할 때 SmartScreen 경고가 뜰 수 있습니다.

## 근거 자료

- 공식 수동 점검 공지 (Level Infinite, 2026-11-05): https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7
- 연구자 분석 (MotherSphere): https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5
- BleepingComputer: https://www.bleepingcomputer.com/news/security/nikke-pc-game-launcher-hacked-to-spread-remote-access-data-stealing-malware/
- Malwarebytes: https://www.malwarebytes.com/blog/news/2026/11/nikke-pc-launcher-compromise-put-players-passwords-and-personal-files-at-risk
