using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using NikkeCheck.Core;
using Xunit;

namespace NikkeCheck.Tests
{
    public class ScanAndRepairTests
    {
        private static void BuildInfected(FakeEnvironment env)
        {
            env.WriteDebugLog(
                "[2026-11-03 09:47:01] intl_service start",
                "[2026-11-03 09:47:05] lua downloaded to log\\tinyget\\tinyget.20261103-004700.log",
                "[2026-11-03 09:47:05] k2f_chan registered",
                "[2026-11-03 09:47:06] adopted 6f1c2a3b-1d2e-4f5a-9b8c-7d6e5f4a3b2c",
                "[2026-11-03 09:47:06] agent started as DESKTOP-TEST login_ticket=SECRETTICKET");
            env.AddPayload();
            env.WriteText(Path.Combine(env.TinygetDir, "tinyget.mem.log"), "HTTP/1.1 200\r\nReferer: https://analytics.insightjs.com/\r\n");

            // Agent state in a WAL .log and in a compressed table under the Google Play build's data folder.
            env.WriteText(Path.Combine(env.TbsCache(), "Local Storage", "leveldb", "000003.log"),
                "\u0001_https://launcher\0\u0001k2f.agent.state{\"agent_id\":\"x\"}");
            var entries = new List<KeyValuePair<byte[], byte[]>>
            {
                new KeyValuePair<byte[], byte[]>(TestData.LocalStorageKey("https://launcher", "k1"), new byte[] { 1, 0 }),
                new KeyValuePair<byte[], byte[]>(TestData.LocalStorageKey("https://launcher", "k2f.agent.state"), new byte[] { 1, (byte)'{', (byte)'}' }),
            };
            env.WriteFile(Path.Combine(env.TbsCache("nikke_launcher_google"), "Local Storage", "leveldb", "000005.ldb"), TestData.BuildTable(entries, true));

            // HTTP cache entry with a gzip-encoded modified script.
            env.WriteFile(Path.Combine(env.TbsCache(), "Cache", "Cache_Data", "f_000123"),
                TestData.Concat(Encoding.ASCII.GetBytes("1/0/https://sg-gpts.playerinfinite.com/comm/assets/lib/aegis-fix.min.js\0"),
                    TestData.Gzip("!function(){var h=String.fromCharCode(111,114,103);}();")));
            // Code Cache loader entry.
            env.WriteText(Path.Combine(env.TbsCache(), "Code Cache", "js", "dd65fa4d61079e7e_0"), "_keyhttps://insightjs.com/l.js?f=aegis");
            // HSTS record for the attacker host (hashed host name).
            env.WriteText(Path.Combine(env.TbsCache(), "TransportSecurity"),
                "{\"sts\":[{\"expiry\":1.8E9,\"host\":\"" + Scanner.HstsHostHash("analytics.insightjs.com") + "\",\"mode\":\"force-https\"}],\"version\":2}");

            env.AddInfectedRegistry();
            env.AddChromeDll();
            env.AddLegitChromeFiles();

            env.WriteFile(Path.Combine(env.TempDir, "k2f_screen_1762130000_1.jpg"), new byte[] { 0xFF, 0xD8 });
            env.WriteFile(Path.Combine(env.TempDir, "k2f-bcreds-1762130000-ab12.db"), new byte[] { 1 });
            env.WriteFile(Path.Combine(env.TempDir, "unrelated.tmp"), new byte[] { 1 });
        }

        [Fact]
        public void Infected_pc_is_detected_on_every_indicator()
        {
            using (var env = new FakeEnvironment())
            {
                BuildInfected(env);
                var r = new Scanner(env.Context()).Run();

                Assert.Empty(r.Errors);
                Assert.Equal(Severity.Critical, r.Overall);
                Assert.True(r.ActiveThreatsRemain);

                Finding Crit(string text) => r.Findings.SingleOrDefault(f => f.Severity == Severity.Critical && f.Title.Contains(text));

                Assert.NotNull(Crit("k2f_chan registered"));
                Assert.NotNull(Crit("동작을 시작한 기록"));
                Assert.NotNull(Crit("adopted"));
                Assert.NotNull(Crit("악성 COM 등록"));
                Assert.Equal(ActionType.DeleteRegistryKey, Crit("악성 COM 등록").Action.Type);
                Assert.Equal(ActionType.DeleteChromeDllFolder, Crit("Chrome 위장 악성 DLL").Action.Type);
                Assert.Equal(env.DllFolder, Crit("Chrome 위장 악성 DLL").Action.Target);
                Assert.Equal(ActionType.DeleteFile, Crit("악성 에이전트 파일").Action.Type);
                Assert.Contains("[nikke_launcher]", Crit("k2f.agent.state) 발견 [nikke_launcher]").Title);
                Assert.NotNull(Crit("[nikke_launcher_google]"));
                Assert.Equal(2, r.Findings.Count(f => f.Severity == Severity.Critical && f.Category == "임시 파일"));

                Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Category == "다운로드 기록");
                Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Title.Contains("HTTP 캐시"));
                Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Title.Contains("Code Cache"));
                Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Title.Contains("TransportSecurity"));
                Assert.Equal(2, r.Findings.Count(f => f.Action?.Type == ActionType.DeleteLauncherCache));

                // Sample lines are redacted; legit Chrome files and the empty 64-'a' folder get no delete action.
                Assert.DoesNotContain(r.Findings, f => (f.Detail ?? "").Contains("SECRETTICKET"));
                Assert.DoesNotContain(r.Actions, a => a.Target.Contains("LoadFeatures") || a.Target.EndsWith(new string('a', 64)));
                Assert.Contains(r.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("DLL은 없음"));
            }
        }

        [Fact]
        public void Clean_pc_has_no_high_findings()
        {
            using (var env = new FakeEnvironment())
            {
                env.WriteDebugLog("[2026-11-06 10:00:00] intl_service start", "[2026-11-06 10:00:01] FETCH_LIST suc success");
                env.WriteText(Path.Combine(env.TbsCache(), "Cache", "Cache_Data", "f_000001"), "https://na-webassets.playerinfinite.com/comm/nikke_launcher/assets/images.64d80e3e.js");
                env.WriteFile(Path.Combine(env.TinygetDir, "tinyget.20261106-100000.log"), Encoding.ASCII.GetBytes("curl perform success total=1024"));
                env.AddLegitChromeFiles();

                var r = new Scanner(env.Context()).Run();

                Assert.Empty(r.Errors);
                Assert.True(r.Overall < Severity.High, string.Join("\n", r.Findings.Where(f => f.Severity >= Severity.High).Select(f => f.Title)));
                Assert.Contains(r.Findings, f => f.Severity == Severity.Ok && f.Title.Contains("미발견"));
                Assert.Contains(r.Findings, f => f.Severity == Severity.Ok && f.Category == "Chrome DLL");
                Assert.DoesNotContain(r.Actions, a => a.Type != ActionType.DeleteLauncherCache);
            }
        }

        [Fact]
        public void Missing_debug_log_is_a_warning_not_a_clean_bill()
        {
            using (var env = new FakeEnvironment())
            {
                Directory.CreateDirectory(env.TbsCache());
                var r = new Scanner(env.Context()).Run();
                Assert.Contains(r.Findings, f => f.Severity == Severity.Warning && f.Title.Contains("debug.log 파일이 없음"));
                Assert.Equal(Severity.Warning, r.Overall);
            }
        }

        [Fact]
        public void Repair_removes_only_the_malicious_items_and_keeps_evidence()
        {
            using (var env = new FakeEnvironment())
            {
                BuildInfected(env);
                var ctx = env.Context();
                var scan = new Scanner(ctx).Run();

                var opt = new RemediationOptions { BackupDirectory = env.BackupDir, ScheduleResumeAfterReboot = false };
                opt.Actions.AddRange(scan.Actions);
                var res = Remediator.Run(ctx, scan, opt);

                Assert.Empty(res.Failed);
                Assert.Empty(res.PendingReboot);
                Assert.True(res.RebootRecommended);

                // Removed
                Assert.False(env.RegistryExists(Indicators.HkcuClsidPath));
                Assert.False(Directory.Exists(env.DllFolder));
                Assert.False(File.Exists(Path.Combine(env.TinygetDir, "tinyget.20261103-004700.log")));
                Assert.False(Directory.Exists(env.TbsCache()));
                Assert.False(Directory.Exists(env.TbsCache("nikke_launcher_google")));
                Assert.Empty(Directory.GetFiles(env.TempDir, "k2f*"));

                // Kept
                Assert.True(File.Exists(Path.Combine(env.PlatformHelper, "LoadFeatures")));
                Assert.True(File.Exists(Path.Combine(env.PlatformHelper, "Settings", "state.json")));
                Assert.True(Directory.Exists(Path.Combine(env.PlatformHelper, new string('a', 64))));
                Assert.True(File.Exists(env.DebugLog));
                Assert.True(File.Exists(Path.Combine(env.TinygetDir, "tinyget.mem.log")));
                Assert.True(File.Exists(Path.Combine(env.TempDir, "unrelated.tmp")));
                Assert.True(Directory.Exists(env.LauncherData()));

                // Backup has the evidence
                Assert.True(File.Exists(res.BackupPath));
                using (var zip = ZipFile.OpenRead(res.BackupPath))
                {
                    var names = zip.Entries.Select(e => e.FullName).ToList();
                    Assert.Contains("report.txt", names);
                    Assert.Contains("install1_NIKKE/Launcher/intl_service/debug.log", names);
                    Assert.Contains("install1_NIKKE/Launcher/log/tinyget/tinyget.20261103-004700.log", names);
                    Assert.Contains(names, n => n.StartsWith("appdata/nikke_launcher/tbs_cache/Local Storage/leveldb/"));
                    Assert.Contains(names, n => n.StartsWith("temp/k2f_screen_"));
                    using (var reader = new StreamReader(zip.GetEntry("registry_hkcu_clsid.txt").Open()))
                        Assert.Contains(Indicators.ChromeDllName, reader.ReadToEnd());
                }

                // Rescan: the log still proves a past infection, but nothing removable is left.
                var after = new Scanner(ctx).Run();
                Assert.Equal(Severity.Critical, after.Overall);
                Assert.False(after.ActiveThreatsRemain);
                Assert.StartsWith("감염 이력 있음", after.VerdictTitle);
                Assert.DoesNotContain(after.Actions, a => a.Type != ActionType.DeleteLauncherCache);
            }
        }

        [Fact]
        public void Locked_dll_is_left_intact_and_deferred_to_after_reboot()
        {
            using (var env = new FakeEnvironment())
            {
                env.AddChromeDll();
                var ctx = env.Context();
                var scan = new Scanner(ctx).Run();
                var dllAction = scan.Actions.Single(a => a.Type == ActionType.DeleteChromeDllFolder);

                var opt = new RemediationOptions { CreateBackup = false, ScheduleResumeAfterReboot = true, ResumeCommand = "\"C:\\x\\NikkeCheck.exe\" --resume" };
                opt.Actions.Add(dllAction);

                RemediationResult res;
                using (new FileStream(Path.Combine(env.DllFolder, Indicators.ChromeDllName), FileMode.Open, FileAccess.Read, FileShare.None))
                    res = Remediator.Run(ctx, scan, opt);

                Assert.Single(res.PendingReboot);
                Assert.True(res.RebootRequired);
                Assert.True(res.ResumeScheduled);
                Assert.True(File.Exists(Path.Combine(env.DllFolder, Indicators.ChromeDllName)));
                Assert.True(File.Exists(Path.Combine(env.DllFolder, "service_util.dll"))); // nothing half-deleted
                using (var hkcu = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64))
                using (var runOnce = hkcu.OpenSubKey(env.RegistryPrefix + Indicators.RunOnceKey))
                    Assert.Equal(opt.ResumeCommand, runOnce?.GetValue(Indicators.RunOnceValueName));

                // "After reboot": the file is no longer locked.
                var opt2 = new RemediationOptions { CreateBackup = false };
                opt2.Actions.Add(dllAction);
                var res2 = Remediator.Run(ctx, scan, opt2);
                Assert.Single(res2.Succeeded);
                Assert.False(Directory.Exists(env.DllFolder));
            }
        }

        [Fact]
        public void Repair_refuses_targets_outside_the_official_criteria()
        {
            using (var env = new FakeEnvironment())
            {
                env.AddLegitChromeFiles();
                string otherCache = Path.Combine(env.AppData, "SomeOtherApp", "tbs_cache");
                env.WriteText(Path.Combine(otherCache, "x"), "x");
                string normalFile = env.WriteText(Path.Combine(env.Install, "Launcher", "log", "launcher.log"), "hello");
                string smallTinyget = env.WriteText(Path.Combine(env.TinygetDir, "tinyget.20261106-100000.log"), "curl perform success");

                var opt = new RemediationOptions { CreateBackup = false };
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteChromeDllFolder, Target = env.PlatformHelper, Description = "parent" });
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteChromeDllFolder, Target = Path.Combine(env.PlatformHelper, new string('a', 64)), Description = "hex without dll" });
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteLauncherCache, Target = otherCache, Description = "other cache" });
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteFile, Target = normalFile, Description = "normal log" });
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteFile, Target = smallTinyget, Description = "small tinyget log" });
                opt.Actions.Add(new RemediationAction { Type = ActionType.DeleteRegistryKey, Target = @"Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}", Description = "other clsid" });

                var res = Remediator.Run(env.Context(), new ScanResult(), opt);

                Assert.Equal(6, res.Failed.Count);
                Assert.Empty(res.Succeeded);
                Assert.True(File.Exists(Path.Combine(env.PlatformHelper, "LoadFeatures")));
                Assert.True(Directory.Exists(Path.Combine(env.PlatformHelper, new string('a', 64))));
                Assert.True(Directory.Exists(otherCache));
                Assert.True(File.Exists(normalFile));
                Assert.True(File.Exists(smallTinyget));
            }
        }

        [Fact]
        public void Hosts_blocking_appends_once_and_keeps_existing_lines()
        {
            using (var env = new FakeEnvironment())
            {
                Assert.Equal(Indicators.HostsBlockDomains.Length, HostsBlocker.GetStatus(env.HostsPath).Missing.Count);

                var added = HostsBlocker.ApplyHosts(env.HostsPath, new StringWriter());
                Assert.Equal(Indicators.HostsBlockDomains.Length, added.Count);
                Assert.Empty(HostsBlocker.GetStatus(env.HostsPath).Missing);

                string text = File.ReadAllText(env.HostsPath);
                Assert.StartsWith("127.0.0.1 localhost\r\n", text);
                Assert.Contains("0.0.0.0 analytics.insightjs.com", text);

                Assert.Empty(HostsBlocker.ApplyHosts(env.HostsPath, new StringWriter()));
                Assert.Single(Directory.GetFiles(env.Root, "hosts.nikkecheck-*.bak"));
            }
        }

        [Theory]
        [InlineData("127.0.0.1 localhost\r\n")]
        [InlineData("# comment\r\n127.0.0.1 localhost\r\n\r\n")]
        [InlineData("127.0.0.1 localhost\n::1 localhost\n")]
        public void Unblock_restores_the_hosts_file_byte_for_byte(string original)
        {
            using (var env = new FakeEnvironment())
            {
                File.WriteAllText(env.HostsPath, original, Encoding.ASCII);
                HostsBlocker.ApplyHosts(env.HostsPath, new StringWriter());
                Assert.True(HostsBlocker.HasNikkeCheckBlock(env.HostsPath));

                int removed = HostsBlocker.RemoveHosts(env.HostsPath, new StringWriter());

                Assert.Equal(Indicators.HostsBlockDomains.Length, removed);
                Assert.Equal(original, File.ReadAllText(env.HostsPath, Encoding.ASCII));
                Assert.False(HostsBlocker.HasNikkeCheckBlock(env.HostsPath));
                Assert.Equal(2, Directory.GetFiles(env.Root, "hosts.nikkecheck-*.bak").Length); // one per change
            }
        }

        [Fact]
        public void Unblock_keeps_user_entries_and_non_ascii_comments()
        {
            using (var env = new FakeEnvironment())
            {
                // The user's own block for the same domain, plus a UTF-8 Korean comment.
                byte[] original = Encoding.UTF8.GetBytes("# 내가 직접 막음\r\n0.0.0.0 insightjs.com\r\n127.0.0.1 localhost");
                File.WriteAllBytes(env.HostsPath, original);

                var added = HostsBlocker.ApplyHosts(env.HostsPath, new StringWriter());
                Assert.DoesNotContain("insightjs.com", added); // already blocked by the user
                HostsBlocker.RemoveHosts(env.HostsPath, new StringWriter());

                byte[] after = File.ReadAllBytes(env.HostsPath);
                // Only difference: the newline that terminated the user's last line before the block was appended.
                Assert.Equal(TestData.Concat(original, Encoding.ASCII.GetBytes("\r\n")), after);
                Assert.Contains("insightjs.com", HostsBlocker.GetStatus(env.HostsPath).Blocked);
            }
        }

        [Fact]
        public void Unblock_without_our_block_changes_nothing()
        {
            using (var env = new FakeEnvironment())
            {
                File.WriteAllText(env.HostsPath, "0.0.0.0 analytics.insightjs.com\r\n", Encoding.ASCII);
                Assert.Equal(0, HostsBlocker.RemoveHosts(env.HostsPath, new StringWriter()));
                Assert.Equal("0.0.0.0 analytics.insightjs.com\r\n", File.ReadAllText(env.HostsPath));
                Assert.Empty(Directory.GetFiles(env.Root, "hosts.nikkecheck-*.bak"));
            }
        }

        [Fact]
        public void Scan_reports_whether_our_block_is_present()
        {
            using (var env = new FakeEnvironment())
            {
                Assert.False(new Scanner(env.Context()).Run().NikkeCheckBlockPresent);
                HostsBlocker.ApplyHosts(env.HostsPath, new StringWriter());
                Assert.True(new Scanner(env.Context()).Run().NikkeCheckBlockPresent);
                HostsBlocker.RemoveHosts(env.HostsPath, new StringWriter());
                Assert.False(new Scanner(env.Context()).Run().NikkeCheckBlockPresent);
            }
        }

        [Fact]
        public void Report_contains_verdict_and_sources()
        {
            using (var env = new FakeEnvironment())
            {
                BuildInfected(env);
                var r = new Scanner(env.Context()).Run();
                string report = ReportWriter.Build(r);
                Assert.Contains("[감염 확인]", report);
                Assert.Contains(Indicators.OfficialNoticeUrl, report);
                Assert.DoesNotContain("SECRETTICKET", report);
            }
        }
    }
}
