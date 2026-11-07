namespace NikkeCheck.Core
{
    public static class Guidance
    {
        public static string For(ScanResult r)
        {
            if (r.Overall >= Severity.High) return Infected;
            return r.LauncherTraceFound ? Clean : NoLauncher;
        }

        public const string NoLauncher =
@"[안내]
- 이 PC에서 NIKKE PC 런처 설치·사용 흔적을 찾지 못했습니다. 레지스트리와 Chrome 위장 DLL도 발견되지 않았습니다.
- 런처를 다른 위치에 설치했거나 이미 삭제했다면 [설치 폴더 추가]로 지정해 다시 검사하세요.
  (런처를 삭제했더라도 레지스트리·Chrome DLL은 남아 있을 수 있으며, 이 두 항목은 위 결과에 포함되어 있습니다)";

        public const string Infected =
@"[감염이 확인되었거나 의심될 때 해야 할 일]
1. 비밀번호는 반드시 이 PC가 아닌 깨끗한 기기(휴대폰 등)에서 바꾸세요.
   NIKKE/Level Infinite 계정 → 이메일 → Discord → 은행·결제 → 브라우저에 저장된 모든 사이트 순서로 바꾸고, 2단계 인증을 켜세요.
2. 모든 서비스에서 '모든 기기 로그아웃'을 하세요 (Google, Discord, Steam, GitHub 등).
   쿠키를 빼앗기면 비밀번호 없이도 로그인될 수 있습니다.
3. 이 PC에서 쓰거나 저장한 API 키, 액세스 토큰, SSH 키를 폐기하고 새로 발급하세요.
4. 암호화폐 지갑(브라우저 확장 지갑 포함)을 썼다면 새 지갑(새 복구 구문)을 만들어 자산을 옮기세요.
   기존 복구 구문은 노출된 것으로 보세요.
5. 백신을 최신으로 업데이트한 뒤 전체 검사와 Microsoft Defender 오프라인 검사를 실행하세요.
   (연구자 보고: Defender 오프라인 검사가 DLL을 놓친 사례가 있어, 백신 결과만으로 안심하면 안 됩니다)
6. 악성 에이전트는 원격으로 아무 명령이나 실행할 수 있었습니다. 가장 안전한 방법은 Windows 재설치입니다.
7. 계정 도용, 금전 피해 같은 2차 피해는 NIKKE 공식 고객센터에 문의하세요. 기록은 보관하되 개인정보를 함부로 넘기지 마세요.";

        public const string Clean =
@"[흔적이 없을 때 권장 사항]
- 공식 안내: 'k2f_chan registered'가 없어도 위험을 완전히 배제할 수는 없습니다. 백신을 최신으로 업데이트하고 전체 검사를 하세요.
- 변조된 스크립트가 런처 캐시(tbs_cache)에 남아 있을 수 있으므로 [복구 실행]에서 캐시 삭제를 권장합니다.
- 11월 5일 08:00 이후 공식 런처에는 자동 검사·삭제 기능(ACE)이 있지만, 실행하면 로그를 지울 수 있습니다.
  이 도구로 먼저 점검하고 필요하면 [증거 백업]을 해 두세요.";

        public const string Common =
@"[주의]
- 댓글·커뮤니티에 올라온 '해결 명령어'(예: PowerShell의 iex / irm 명령)는 실행하지 마세요. 가짜 해결법으로 위장한 악성코드가 퍼졌습니다.
- 백업 파일과 런처 로그에는 로그인 티켓·쿠키가 들어 있을 수 있습니다. 공개된 곳에 올리지 마세요.
- 모바일 버전은 이번 사고와 관계없습니다(공식). 모바일로만 플레이했다면 따로 조치할 필요가 없습니다.";
    }
}
