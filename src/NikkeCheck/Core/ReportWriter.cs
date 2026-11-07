using System;
using System.Linq;
using System.Reflection;
using System.Text;

namespace NikkeCheck.Core
{
    public static class ReportWriter
    {
        public static string Version =>
            Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

        public static string Build(ScanResult r, RemediationResult remediation = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("NIKKE PC 런처 보안 점검 보고서");
            sb.AppendLine(new string('=', 60));
            sb.AppendLine($"도구 버전   : NikkeCheck {Version}");
            sb.AppendLine($"검사 시각   : {r.StartedAt:yyyy-MM-dd HH:mm:ss} (소요 {(r.FinishedAt - r.StartedAt).TotalSeconds:0.0}초)");
            sb.AppendLine($"Windows     : {Environment.OSVersion.VersionString}");
            sb.AppendLine();
            sb.AppendLine($"판정        : [{SeverityText.Label(r.Overall)}] {r.VerdictTitle}");
            sb.AppendLine($"요약        : {r.VerdictSummary}");
            sb.AppendLine();

            sb.AppendLine("설치 폴더");
            if (r.InstallRoots.Count == 0) sb.AppendLine("  (찾지 못함)");
            foreach (var p in r.InstallRoots) sb.AppendLine("  " + p);
            sb.AppendLine("런처 데이터 폴더");
            if (r.LauncherDataDirs.Count == 0) sb.AppendLine("  (없음)");
            foreach (var p in r.LauncherDataDirs) sb.AppendLine("  " + p);
            sb.AppendLine();

            sb.AppendLine("검사 결과");
            sb.AppendLine(new string('-', 60));
            int i = 1;
            foreach (var f in r.Sorted)
            {
                sb.AppendLine($"{i++,2}. [{SeverityText.Label(f.Severity)}] ({f.Category}) {f.Title}");
                if (!string.IsNullOrEmpty(f.Path)) sb.AppendLine("    경로: " + f.Path);
                if (!string.IsNullOrEmpty(f.Detail))
                    foreach (var line in f.Detail.Replace("\r\n", "\n").Split('\n'))
                        sb.AppendLine("    " + line);
                if (f.Action != null) sb.AppendLine("    조치: " + f.Action.Description);
                sb.AppendLine();
            }

            if (r.Errors.Count > 0)
            {
                sb.AppendLine("검사 중 오류 (해당 항목은 확인하지 못했을 수 있음)");
                foreach (var e in r.Errors) sb.AppendLine("  - " + e);
                sb.AppendLine();
            }

            if (remediation != null)
            {
                sb.AppendLine("복구 작업 기록");
                sb.AppendLine(new string('-', 60));
                foreach (var l in remediation.Log) sb.AppendLine("  " + l);
                sb.AppendLine();
            }

            sb.AppendLine(Guidance.For(r));
            sb.AppendLine();
            sb.AppendLine(Guidance.Common);
            sb.AppendLine();
            sb.AppendLine("근거 자료");
            sb.AppendLine("  공식 수동 점검 공지: " + Indicators.OfficialNoticeUrl);
            sb.AppendLine("  연구자 분석(MotherSphere): " + Indicators.ResearchUrl);
            return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
        }
    }
}
