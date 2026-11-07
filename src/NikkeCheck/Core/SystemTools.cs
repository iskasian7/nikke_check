using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace NikkeCheck.Core
{
    public static class ProcessTools
    {
        public static List<Process> FindRunning(IEnumerable<string> names)
        {
            var list = new List<Process>();
            foreach (var n in names)
            {
                try { list.AddRange(Process.GetProcessesByName(n)); }
                catch (Exception) { }
            }
            return list;
        }

        /// <summary>Runs a console tool and captures stdout. Returns null on failure or timeout.</summary>
        public static string RunCapture(string file, string args, int timeoutMs, out int exitCode)
        {
            exitCode = -1;
            try
            {
                Encoding enc;
                try { enc = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage); }
                catch (Exception) { enc = Encoding.Default; }

                var psi = new ProcessStartInfo(file, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    StandardOutputEncoding = enc,
                    StandardErrorEncoding = enc,
                };
                using (var p = Process.Start(psi))
                {
                    var stdout = new StringBuilder();
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (stdout) stdout.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (stdout) stdout.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch (Exception) { }
                        return null;
                    }
                    p.WaitForExit();
                    exitCode = p.ExitCode;
                    lock (stdout) return stdout.ToString();
                }
            }
            catch (Exception) { return null; }
        }

        public static bool IsAdministrator()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception) { return false; }
        }
    }

    /// <summary>Masks session tickets/cookies so log excerpts can be shown or shared safely.</summary>
    public static class Redactor
    {
        private static readonly Regex Params = new Regex(
            @"(?i)\b(login_ticket|biz_ticket|ticket|token|access_token|uid|openid|sig|session|password|passwd|agent_pass)(\s*[=:]\s*""?)([^&\s"",;]+)",
            RegexOptions.Compiled);

        private static readonly Regex CookieHeader = new Regex(@"(?i)(cookie\s*:\s*).*", RegexOptions.Compiled);

        public static string Redact(string line)
        {
            if (string.IsNullOrEmpty(line)) return line;
            line = CookieHeader.Replace(line, "$1***");
            return Params.Replace(line, "$1$2***");
        }
    }
}
