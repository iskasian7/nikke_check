using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Blocks the attacker domains (hosts file) and IPs (Windows Firewall).
    /// Writing either needs admin rights, so the GUI re-launches this exe with --apply-blocks via UAC.
    /// </summary>
    public static class HostsBlocker
    {
        public const string FirewallRuleName = "NikkeCheck - Block NIKKE launcher attacker IPs";
        private const string HostsComment = "# NikkeCheck: NIKKE PC launcher compromise (2026-11)";

        public sealed class HostsStatus
        {
            public List<string> Blocked { get; } = new List<string>();
            public List<string> Missing { get; } = new List<string>();
        }

        public static HostsStatus GetStatus(string hostsPath)
        {
            var st = new HostsStatus();
            var blocked = ReadBlockedHosts(hostsPath);
            foreach (var d in Indicators.HostsBlockDomains)
                (blocked.Contains(d) ? st.Blocked : st.Missing).Add(d);
            return st;
        }

        private static HashSet<string> ReadBlockedHosts(string hostsPath)
        {
            var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(hostsPath) || !File.Exists(hostsPath)) return blocked;
            string[] lines;
            try { lines = File.ReadAllLines(hostsPath); }
            catch (Exception) { return blocked; }

            foreach (var raw in lines)
            {
                string line = raw;
                int hash = line.IndexOf('#');
                if (hash >= 0) line = line.Substring(0, hash);
                var parts = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                string ip = parts[0];
                if (ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::" && ip != "::1") continue;
                for (int i = 1; i < parts.Length; i++) blocked.Add(parts[i]);
            }
            return blocked;
        }

        /// <summary>Appends missing domains to the hosts file after making a backup copy. Returns the domains added.</summary>
        public static List<string> ApplyHosts(string hostsPath, TextWriter log)
        {
            var missing = GetStatus(hostsPath).Missing;
            if (missing.Count == 0)
            {
                log.WriteLine("hosts: 이미 모두 차단되어 있습니다.");
                return missing;
            }

            if (File.Exists(hostsPath)) BackupAndUnlock(hostsPath, log);

            var sb = new StringBuilder();
            if (File.Exists(hostsPath) && !EndsWithNewline(hostsPath)) sb.Append("\r\n");
            sb.Append("\r\n").Append(HostsComment).Append("\r\n");
            foreach (var d in missing) sb.Append("0.0.0.0 ").Append(d).Append("\r\n");
            File.AppendAllText(hostsPath, sb.ToString(), Encoding.ASCII);
            log.WriteLine("hosts 차단 추가: " + string.Join(", ", missing));
            return missing;
        }

        /// <summary>True when the hosts file still has the block section this tool appended.</summary>
        public static bool HasNikkeCheckBlock(string hostsPath)
        {
            if (string.IsNullOrEmpty(hostsPath) || !File.Exists(hostsPath)) return false;
            try
            {
                foreach (var line in File.ReadAllLines(hostsPath))
                    if (line.Trim() == HostsComment) return true;
            }
            catch (Exception) { }
            return false;
        }

        /// <summary>
        /// Removes only what <see cref="ApplyHosts"/> appended: the NikkeCheck header line, the
        /// "0.0.0.0 &lt;attacker domain&gt;" lines directly under it, and the blank separator line before it.
        /// Everything else (including a user's own entries for the same domains) is kept byte-for-byte.
        /// Returns the number of domain lines removed.
        /// </summary>
        public static int RemoveHosts(string hostsPath, TextWriter log)
        {
            if (string.IsNullOrEmpty(hostsPath) || !File.Exists(hostsPath))
            {
                log.WriteLine("hosts 파일이 없습니다.");
                return 0;
            }

            // Latin-1 maps every byte to one char, so non-ASCII comments (ANSI or UTF-8) survive unchanged.
            var latin1 = Encoding.GetEncoding(28591);
            var lines = SplitKeepingLineEndings(latin1.GetString(File.ReadAllBytes(hostsPath)));
            var keep = new List<string>(lines.Count);
            var removedDomains = new List<string>();
            bool foundHeader = false;

            for (int i = 0; i < lines.Count; i++)
            {
                if (lines[i].Trim() != HostsComment)
                {
                    keep.Add(lines[i]);
                    continue;
                }
                foundHeader = true;
                if (keep.Count > 0 && keep[keep.Count - 1].Trim().Length == 0) keep.RemoveAt(keep.Count - 1);
                int j = i + 1;
                while (j < lines.Count && IsBlockLine(lines[j], out string domain))
                {
                    removedDomains.Add(domain);
                    j++;
                }
                i = j - 1;
            }

            if (!foundHeader)
            {
                log.WriteLine("hosts: 이 프로그램이 추가한 차단 항목이 없습니다.");
                return 0;
            }

            BackupAndUnlock(hostsPath, log);
            File.WriteAllBytes(hostsPath, latin1.GetBytes(string.Concat(keep)));
            log.WriteLine("hosts 차단 해제: " + (removedDomains.Count > 0 ? string.Join(", ", removedDomains) : "(표시 줄만 정리)"));
            return removedDomains.Count;
        }

        private static bool IsBlockLine(string line, out string domain)
        {
            domain = null;
            var parts = line.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || parts[0] != "0.0.0.0") return false;
            if (Array.IndexOf(Indicators.HostsBlockDomains, parts[1].ToLowerInvariant()) < 0) return false;
            domain = parts[1];
            return true;
        }

        private static List<string> SplitKeepingLineEndings(string text)
        {
            var list = new List<string>();
            int start = 0;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] != '\n') continue;
                list.Add(text.Substring(start, i - start + 1));
                start = i + 1;
            }
            if (start < text.Length) list.Add(text.Substring(start));
            return list;
        }

        private static void BackupAndUnlock(string hostsPath, TextWriter log)
        {
            string stamp = hostsPath + ".nikkecheck-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string backup = stamp + ".bak";
            for (int n = 2; File.Exists(backup); n++) backup = stamp + "-" + n + ".bak";
            File.Copy(hostsPath, backup, false);
            log.WriteLine("hosts 백업: " + backup);

            var attr = File.GetAttributes(hostsPath);
            if ((attr & FileAttributes.ReadOnly) != 0) File.SetAttributes(hostsPath, attr & ~FileAttributes.ReadOnly);
        }

        private static bool EndsWithNewline(string path)
        {
            using (var fs = FileUtil.OpenShared(path))
            {
                if (fs.Length == 0) return true;
                fs.Seek(-1, SeekOrigin.End);
                int b = fs.ReadByte();
                return b == '\n';
            }
        }

        public static bool FirewallRuleExists()
        {
            ProcessTools.RunCapture("netsh.exe", $"advfirewall firewall show rule name=\"{FirewallRuleName}\"", 15000, out int code);
            return code == 0;
        }

        public static bool AddFirewallRules(TextWriter log)
        {
            if (FirewallRuleExists())
            {
                log.WriteLine("방화벽: 차단 규칙이 이미 있습니다.");
                return true;
            }
            string ips = string.Join(",", Indicators.AttackerIps);
            bool ok = true;
            foreach (var dir in new[] { "out", "in" })
            {
                string output = ProcessTools.RunCapture("netsh.exe",
                    $"advfirewall firewall add rule name=\"{FirewallRuleName}\" dir={dir} action=block remoteip={ips} enable=yes profile=any",
                    20000, out int code);
                log.WriteLine($"방화벽 규칙({dir}) 추가: " + (code == 0 ? "성공" : "실패 " + (output ?? "").Trim()));
                ok &= code == 0;
            }
            return ok;
        }

        public static bool RemoveFirewallRules(TextWriter log)
        {
            if (!FirewallRuleExists())
            {
                log.WriteLine("방화벽: 이 프로그램이 만든 차단 규칙이 없습니다.");
                return true;
            }
            // "delete rule name=..." removes every rule with that name (both directions).
            string output = ProcessTools.RunCapture("netsh.exe", $"advfirewall firewall delete rule name=\"{FirewallRuleName}\"", 20000, out int code);
            log.WriteLine("방화벽 차단 규칙 삭제: " + (code == 0 ? "성공" : "실패 " + (output ?? "").Trim()));
            return code == 0;
        }

        /// <summary>Entry point for the elevated helper process (NikkeCheck.exe --apply-blocks|--remove-blocks --log file).</summary>
        public static int RunElevatedEntry(string logPath, bool remove)
        {
            var log = new StringWriter();
            int exit = 0;
            try
            {
                if (!ProcessTools.IsAdministrator())
                {
                    log.WriteLine("관리자 권한이 없어 차단 설정을 바꾸지 못했습니다.");
                    exit = 5;
                }
                else
                {
                    var ctx = ScanContext.FromEnvironment();
                    try
                    {
                        if (remove) RemoveHosts(ctx.HostsPath, log);
                        else ApplyHosts(ctx.HostsPath, log);
                    }
                    catch (Exception ex) { log.WriteLine("hosts 수정 실패: " + ex.Message); exit = 1; }
                    bool fwOk = remove ? RemoveFirewallRules(log) : AddFirewallRules(log);
                    if (!fwOk) exit = exit == 0 ? 2 : exit;
                    ProcessTools.RunCapture("ipconfig.exe", "/flushdns", 15000, out _);
                    log.WriteLine("DNS 캐시를 비웠습니다.");
                }
            }
            catch (Exception ex)
            {
                log.WriteLine("오류: " + ex.Message);
                exit = 9;
            }
            if (!string.IsNullOrEmpty(logPath))
            {
                try { File.WriteAllText(logPath, log.ToString(), new UTF8Encoding(true)); } catch (Exception) { }
            }
            return exit;
        }

        /// <summary>Starts the elevated helper (UAC prompt) to apply or remove the blocks. Returns false when the user declined.</summary>
        public static bool RequestElevated(string exePath, bool remove, out string log)
        {
            string logPath = Path.Combine(Path.GetTempPath(), "nikkecheck-blocks-" + Guid.NewGuid().ToString("N") + ".txt");
            log = null;
            try
            {
                var psi = new ProcessStartInfo(exePath, $"{(remove ? "--remove-blocks" : "--apply-blocks")} --log \"{logPath}\"")
                {
                    UseShellExecute = true,
                    Verb = "runas",
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                using (var p = Process.Start(psi))
                {
                    p.WaitForExit(120000);
                }
                log = File.Exists(logPath) ? File.ReadAllText(logPath) : "차단 도우미가 결과를 남기지 않았습니다.";
                return true;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                log = "관리자 권한 요청이 취소되어 차단 설정을 바꾸지 않았습니다.";
                return false;
            }
            finally
            {
                try { if (File.Exists(logPath)) File.Delete(logPath); } catch (Exception) { }
            }
        }
    }
}
