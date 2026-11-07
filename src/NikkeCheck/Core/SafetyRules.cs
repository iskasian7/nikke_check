using System;
using System.IO;
using System.Text.RegularExpressions;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Conditions an item must meet to be deleted. The scanner uses them to propose actions, and the
    /// remediator re-checks them right before deleting, so nothing outside the official criteria is touched.
    /// </summary>
    public static class SafetyRules
    {
        private static readonly Regex TinygetLogName = new Regex(@"^tinyget\..+\.log$", RegexOptions.IgnoreCase);

        /// <summary>Official 3-③: a 64-hex folder inside PlatformExperienceHelper that contains platform_experience_helper.dll.</summary>
        public static bool IsMaliciousChromeDllFolder(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            dir = dir.TrimEnd('\\', '/');
            return FileUtil.IsHex64(Path.GetFileName(dir))
                   && string.Equals(FileUtil.ParentName(dir), Indicators.PlatformExperienceHelperDir, StringComparison.OrdinalIgnoreCase)
                   && File.Exists(Path.Combine(dir, Indicators.ChromeDllName));
        }

        /// <summary>Official 3-⑤: %APPDATA%\nikke_launcher*\tbs_cache.</summary>
        public static bool IsLauncherCache(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return false;
            dir = dir.TrimEnd('\\', '/');
            return string.Equals(Path.GetFileName(dir), "tbs_cache", StringComparison.OrdinalIgnoreCase)
                   && FileUtil.ParentName(dir).StartsWith(Indicators.LauncherDataPrefix, StringComparison.OrdinalIgnoreCase);
        }

        public static bool IsAllowedRegistryKey(string subKey) =>
            string.Equals(subKey, Indicators.HkcuClsidPath, StringComparison.OrdinalIgnoreCase)
            || string.Equals(subKey, Indicators.HkcuClsidWowPath, StringComparison.OrdinalIgnoreCase);

        /// <summary>
        /// Official 3-④ plus research: a file inside Launcher\log\tinyget that is the agent
        /// (LuaJIT bytecode, 205,135-byte tinyget.*.log, k2f.lua, or a known payload hash).
        /// </summary>
        public static bool IsPayloadFile(string path, out string reasons)
        {
            reasons = null;
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
            if (!IsInsideTinyget(path)) return false;

            var fi = new FileInfo(path);
            string name = fi.Name;
            var why = new System.Collections.Generic.List<string>();

            byte[] head = null;
            try { head = FileUtil.ReadHead(path, 4); } catch (Exception) { }
            if (FileUtil.StartsWith(head, Indicators.LuaJitMagic))
                why.Add("LuaJIT 바이트코드(1B 4C 4A)로 시작 — 악성 에이전트 파일");
            if (fi.Length == Indicators.OfficialPayloadSize && TinygetLogName.IsMatch(name))
                why.Add("크기 205,135바이트의 tinyget.*.log — 공식 공지의 삭제 대상");
            if (string.Equals(name, "k2f.lua", StringComparison.OrdinalIgnoreCase))
                why.Add("k2f.lua — 10/23 빌드의 에이전트 파일명");

            bool hashCandidate = fi.Length == Indicators.OfficialPayloadSize || fi.Length == Indicators.Oct23PayloadSize || why.Count > 0;
            if (hashCandidate && fi.Length < 64L * 1024 * 1024)
            {
                try
                {
                    string sha = FileUtil.Sha256(path);
                    if (Indicators.KnownPayloadSha256.Contains(sha))
                        why.Add("알려진 악성 페이로드 해시와 일치 (SHA-256 " + sha + ")");
                }
                catch (Exception) { }
            }

            if (why.Count == 0) return false;
            reasons = string.Join("\r\n", why);
            return true;
        }

        public static bool IsInsideTinyget(string path)
        {
            string dir = Path.GetDirectoryName(path) ?? "";
            return dir.IndexOf(@"\Launcher\log\tinyget", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>A k2f-* agent work file directly inside the user's temp folder.</summary>
        public static bool IsAgentTempFile(string path, string tempDir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(tempDir)) return false;
            string dir = (Path.GetDirectoryName(path) ?? "").TrimEnd('\\');
            if (!string.Equals(dir, tempDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return false;
            string name = Path.GetFileName(path);
            foreach (var p in Indicators.TempPatterns)
            {
                string prefix = p.Pattern.TrimEnd('*');
                if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }
    }

    public sealed class SafetyException : Exception
    {
        public SafetyException(string message) : base(message) { }
    }
}
