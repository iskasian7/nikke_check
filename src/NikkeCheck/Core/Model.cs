using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace NikkeCheck.Core
{
    public enum Severity
    {
        Ok = 0,
        Info = 1,
        Warning = 2,
        High = 3,
        Critical = 4,
    }

    public static class SeverityText
    {
        public static string Label(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return "감염 확인";
                case Severity.High: return "위험";
                case Severity.Warning: return "주의";
                case Severity.Info: return "정보";
                default: return "정상";
            }
        }
    }

    public enum ActionType
    {
        DeleteRegistryKey,
        DeleteFile,
        DeleteLauncherCache,
        DeleteChromeDllFolder,
    }

    public sealed class RemediationAction
    {
        public ActionType Type { get; set; }
        /// <summary>File/folder path, or HKCU subkey (without the test prefix) for registry actions.</summary>
        public string Target { get; set; }
        public RegistryView View { get; set; } = RegistryView.Registry64;
        public string Description { get; set; }
        /// <summary>Execution order. Mirrors the official order: registry → files → cache → DLL folder.</summary>
        public int Order { get; set; }
        public bool DefaultSelected { get; set; } = true;

        public override string ToString() => Description;
    }

    public sealed class Finding
    {
        public Severity Severity { get; set; }
        public string Category { get; set; }
        public string Title { get; set; }
        public string Detail { get; set; }
        public string Path { get; set; }
        public RemediationAction Action { get; set; }
    }

    public sealed class ScanResult
    {
        public DateTime StartedAt { get; set; }
        public DateTime FinishedAt { get; set; }
        public List<Finding> Findings { get; } = new List<Finding>();
        public List<string> InstallRoots { get; } = new List<string>();
        public List<string> LauncherDataDirs { get; } = new List<string>();
        public List<string> Errors { get; } = new List<string>();

        /// <summary>The hosts section or firewall rule added by this tool is present (so it can be removed).</summary>
        public bool NikkeCheckBlockPresent { get; set; }

        public Severity Overall => Findings.Count == 0 ? Severity.Ok : Findings.Max(f => f.Severity);

        public bool LauncherTraceFound => InstallRoots.Count > 0 || LauncherDataDirs.Count > 0;

        public IEnumerable<Finding> Sorted =>
            Findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category, StringComparer.Ordinal);

        public List<RemediationAction> Actions =>
            Findings.Where(f => f.Action != null).Select(f => f.Action).OrderBy(a => a.Order).ToList();

        public bool Has(Severity s) => Findings.Any(f => f.Severity == s);

        /// <summary>
        /// Malicious components that can still be removed (registry entry, DLL, payload, agent temp files).
        /// When none remain but Critical log evidence does, the PC was infected and has been cleaned.
        /// </summary>
        public bool ActiveThreatsRemain =>
            Findings.Any(f => f.Severity == Severity.Critical && (f.Action != null || f.Category == "런처 캐시"));

        public string VerdictTitle
        {
            get
            {
                switch (Overall)
                {
                    case Severity.Critical:
                        return ActiveThreatsRemain
                            ? "감염 흔적 발견 — 악성 프로그램이 이 PC에서 실행된 흔적이 있습니다"
                            : "감염 이력 있음 — 알려진 악성 구성요소는 제거된 상태입니다";
                    case Severity.High: return "의심 흔적 발견 — 변조된 런처 스크립트나 공격자 서버 접속 흔적이 있습니다";
                    case Severity.Warning: return "확인 필요 — 판단 근거가 부족하거나 직접 확인해야 할 항목이 있습니다";
                    default:
                        return LauncherTraceFound
                            ? "알려진 감염 흔적 없음"
                            : "NIKKE PC 런처 사용 흔적 없음";
                }
            }
        }

        public string VerdictSummary
        {
            get
            {
                int c = Findings.Count(f => f.Severity == Severity.Critical);
                int h = Findings.Count(f => f.Severity == Severity.High);
                int w = Findings.Count(f => f.Severity == Severity.Warning);
                string counts = $"감염 확인 {c} · 위험 {h} · 주의 {w}";
                switch (Overall)
                {
                    case Severity.Critical:
                        return ActiveThreatsRemain
                            ? counts + "  |  [복구 실행]으로 알려진 흔적을 제거한 뒤, 반드시 다른 깨끗한 기기에서 비밀번호를 바꾸세요. 가장 안전한 방법은 Windows 재설치입니다."
                            : counts + "  |  로그에 감염 기록이 남아 있습니다(증거로 보존). 레지스트리·DLL·페이로드는 남아 있지 않습니다. 계정 보안 조치와 백신 검사를 꼭 진행하고, 가능하면 Windows 재설치를 권장합니다.";
                    case Severity.High:
                        return counts + "  |  변조된 스크립트가 이 PC에서 실행되었을 수 있습니다. [복구 실행]과 백신 전체 검사를 진행하고 계정 보안 조치를 권장합니다.";
                    case Severity.Warning:
                        return counts + "  |  아래 '주의' 항목의 설명을 확인하세요.";
                    default:
                        return LauncherTraceFound
                            ? "알려진 침해 지표가 없습니다. 다만 공식 안내대로 흔적이 없어도 위험을 완전히 배제할 수는 없으므로 백신 전체 검사를 권장합니다."
                            : "설치 폴더를 다른 위치에 두었다면 [설치 폴더 추가]로 지정한 뒤 다시 검사하세요.";
                }
            }
        }
    }
}
