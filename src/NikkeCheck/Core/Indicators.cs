using System;
using System.Collections.Generic;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Indicators of compromise for the NIKKE PC launcher incident (Nov 2026).
    /// Sources: Level Infinite manual check notice (2026-11-05) and MotherSphere's analysis.
    /// See docs/INDICATORS.md for the reasoning behind each entry.
    /// </summary>
    public static class Indicators
    {
        public const string OfficialNoticeUrl = "https://nikke-en.com/newsdetail.html?content_id=ecdccd40a55a5a46aaa9abda64d436082db7";
        public const string OfficialKoreanSiteUrl = "https://nikke-kr.com/";
        public const string ResearchUrl = "https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5";

        /// <summary>2026-09-27 15:41 KST — CDN scripts tampered. Anyone who ran the launcher after this should check.</summary>
        public static readonly DateTime CompromiseStartUtc = new DateTime(2026, 9, 27, 6, 41, 0, DateTimeKind.Utc);
        /// <summary>2026-11-04 02:30 KST — publisher client fix.</summary>
        public static readonly DateTime FixUtc = new DateTime(2026, 11, 3, 17, 30, 0, DateTimeKind.Utc);

        // ---- Registry persistence (official step 3-①) ----
        public const string MaliciousClsid = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
        public const string HkcuClsidPath = @"Software\Classes\CLSID\" + MaliciousClsid;
        public const string HkcuClsidWowPath = @"Software\Classes\WOW6432Node\CLSID\" + MaliciousClsid;
        public const string HklmClsidPath = @"SOFTWARE\Classes\CLSID\" + MaliciousClsid;
        public const string RunOnceKey = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        public const string RunOnceValueName = "NikkeCheckResume";

        // ---- Chrome DLL persistence (official step 3-③) ----
        public const string PlatformExperienceHelperDir = "PlatformExperienceHelper";
        public const string ChromeDllName = "platform_experience_helper.dll";
        /// <summary>Files the agent's Chrome installer/uninstaller touches inside Chrome's Application folder. Legit Chrome only ships the .exe there.</summary>
        public static readonly string[] ChromeAppSuspiciousFiles =
        {
            "platform_experience_helper.dll",
            "platform_experience_helper.dll.old",
            "old-clsid.txt",
        };

        // ---- Launcher log (official step 2) ----
        public const string LogAgentRegistered = "k2f_chan registered";

        // ---- Payload (official step 3-④ + research) ----
        public const long OfficialPayloadSize = 205135;
        public const long Oct23PayloadSize = 165108;
        public static readonly byte[] LuaJitMagic = { 0x1B, 0x4C, 0x4A };

        public static readonly HashSet<string> KnownPayloadSha256 = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec", // insight.bundle, 205,135 B
            "60fd53ab7356384ba2161b9bc84420cd170905011a2f3ca09f3e38fe3122f3a1", // Oct 23 build (k2f.lua), 165,108 B
        };

        // ---- Tampered CDN scripts (research) ----
        public static readonly HashSet<string> KnownModifiedScriptSha256 = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "04471ccf9f6ebac477ba4ca6b408a56621bccd16118c3112720adb35e6422e3d", // aegis-fix.min.js
            "21d2fa4b6cdd15da3d5246687a01ef84fb848668144258b110606db5eb5ea7ce", // images.7fec4c32.js
            "2f2aac505f486067af6831d6c75ea74df63acb1ed4e4002709c5962c68bd9203", // FeedList.feb647c9.js
            "3aaafbd612f04501a6fdb0bb8b2f8a87796223e5584ac18ea5eb180feeafb193", // vue-bucket.min.js
        };
        public static readonly HashSet<long> ModifiedScriptSizes = new HashSet<long> { 69731, 4358, 5808, 135273 };

        /// <summary>Code Cache entries created by the modified loaders (aegis, images, feedlist, vue).</summary>
        public static readonly HashSet<string> CodeCacheLoaderEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "dd65fa4d61079e7e_0", "ce2fd3f1007a9fe9_0", "1416c638b3830103_0", "fd520c7c0f65c2d7_0",
        };

        public const string DomainMarker = "insightjs";
        public const string OrgFallbackMarker = "String.fromCharCode(111,114,103)";
        public const string AgentStateKey = "k2f.agent";

        // ---- Network ----
        public static readonly string[] AttackerDomains = { "insightjs.com", "analytics.insightjs.com", "insightjs.org" };
        public static readonly string[] HostsBlockDomains =
        {
            "insightjs.com", "analytics.insightjs.com", "insightjs.org",
            "www.insightjs.com", "api.insightjs.com", "cdn.insightjs.com", "portal.insightjs.com", "docs.insightjs.com",
        };
        public static readonly string[] AttackerIps = { "89.127.233.127", "89.126.250.172" };

        // ---- Launcher layout ----
        /// <summary>%APPDATA% folders: global, HMT and Google Play PC builds.</summary>
        public const string LauncherDataPrefix = "nikke_launcher";
        public static readonly string[] LauncherProcessNames = { "nikke_launcher", "nikke_launcher_hmt", "nikke_launcher_google", "tbs_browser", "nikke" };

        // ---- Agent temp files (research) ----
        public static readonly TempPattern[] TempPatterns =
        {
            new TempPattern("k2f-bcreds-*", "브라우저에 저장된 비밀번호·쿠키를 빼내는 작업에 쓰인 임시 파일"),
            new TempPattern("k2f_screen_*", "화면 캡처(스크린샷) 파일"),
            new TempPattern("k2f-keyscan-*", "키·비밀 정보 수집 작업에 쓰인 임시 파일 (10/23 빌드)"),
        };
    }

    public sealed class TempPattern
    {
        public TempPattern(string pattern, string meaning) { Pattern = pattern; Meaning = meaning; }
        public string Pattern { get; }
        public string Meaning { get; }
    }
}
