using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Read-only scan. Nothing here writes, deletes or sends anything.
    /// </summary>
    public sealed class Scanner
    {
        private const long MaxScanBytes = 16L * 1024 * 1024;
        private const int MaxDecompressedBytes = 8 * 1024 * 1024;
        private const int MaxSamples = 3;
        private const int MaxListedPaths = 6;

        private static readonly Needle DomainNeedle = new Needle(Indicators.DomainMarker);
        private static readonly Needle OrgMarkerNeedle = new Needle(Indicators.OrgFallbackMarker);
        private static readonly Needle AgentStateNeedle = new Needle(Indicators.AgentStateKey);

        private static readonly LogPattern[] LogPatterns =
        {
            new LogPattern(Indicators.LogAgentRegistered, null, Severity.Critical,
                "악성 에이전트 실행 흔적 'k2f_chan registered' 발견 (공식 판정 기준)",
                "공식 공지: 이 문자열이 있으면 악성 프로그램이 PC에서 실행되었을 가능성이 있습니다. 복구 절차를 진행하세요."),
            new LogPattern("agent started as", null, Severity.Critical,
                "악성 에이전트가 공격자 서버와 연결되어 동작을 시작한 기록",
                "서버 응답을 받고 동작한 흔적입니다. 원격 명령 실행, 파일·비밀번호 탈취가 가능했던 상태로 간주하세요."),
            new LogPattern(null, new Regex(@"\badopted [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-", RegexOptions.Compiled), Severity.Critical,
                "악성 에이전트 식별자 할당 기록 ('adopted <uuid>')",
                "공격자 서버가 이 PC에 에이전트 ID를 발급한 흔적입니다."),
            new LogPattern("lua downloaded to log", null, Severity.High,
                "악성 페이로드(Lua) 다운로드 기록",
                "공격자 서버에서 에이전트 파일을 내려받은 흔적입니다."),
            new LogPattern("startup failed: EIO", null, Severity.High,
                "악성 에이전트 시작 시도 기록 (시작 실패)",
                "에이전트가 실행되었지만 사용자 이름(비영문) 문제로 ID를 받지 못한 흔적입니다. 실행 자체는 되었으므로 감염 가능성이 높습니다."),
            new LogPattern(Indicators.DomainMarker, null, Severity.High,
                "공격자 도메인(insightjs) 관련 기록",
                "런처가 공격자 도메인에 접속한 흔적입니다."),
        };

        private readonly ScanContext _ctx;
        private ScanResult _r;
        private Action<string> _progress;

        public Scanner(ScanContext ctx)
        {
            _ctx = ctx;
        }

        public ScanResult Run(Action<string> progress = null)
        {
            _progress = progress;
            _r = new ScanResult { StartedAt = DateTime.Now };

            Step("실행 중인 프로그램 확인", CheckEnvironment);
            Step("NIKKE 설치 폴더 찾는 중", LocateInstalls);
            foreach (var root in _r.InstallRoots.ToList())
            {
                Step("런처 로그 검사: " + root, () => CheckIntlService(root));
                Step("다운로드 폴더 검사: " + root, () => CheckTinyget(root));
                Step("런처 로그 폴더 검사: " + root, () => CheckLauncherLogs(root));
            }
            foreach (var dataDir in _r.LauncherDataDirs.ToList())
                Step("런처 캐시 검사: " + dataDir, () => CheckLauncherData(dataDir));
            Step("레지스트리 검사", CheckRegistry);
            Step("Chrome 위장 DLL 검사", CheckChromeDll);
            Step("임시 폴더 검사", CheckTemp);
            Step("DNS 캐시 검사", CheckDnsCache);
            Step("차단 설정 확인", CheckBlocks);

            if (!_r.LauncherTraceFound && _r.Overall < Severity.High)
            {
                Add(Severity.Info, "설치 위치", "이 PC에서 NIKKE PC 런처 사용 흔적을 찾지 못함",
                    "설치 폴더와 런처 데이터 폴더(%APPDATA%\\nikke_launcher*)가 없습니다. 런처를 다른 위치에 설치했다면 [설치 폴더 추가]로 지정한 뒤 다시 검사하세요.");
            }

            _r.FinishedAt = DateTime.Now;
            return _r;
        }

        private void Step(string name, Action action)
        {
            _progress?.Invoke(name);
            try { action(); }
            catch (Exception ex) { _r.Errors.Add(name + ": " + ex.Message); }
        }

        private Finding Add(Severity s, string category, string title, string detail, string path = null, RemediationAction action = null)
        {
            var f = new Finding { Severity = s, Category = category, Title = title, Detail = detail, Path = path, Action = action };
            _r.Findings.Add(f);
            return f;
        }

        // ------------------------------------------------------------------ environment

        private void CheckEnvironment()
        {
            if (_ctx.CheckProcesses)
            {
                var running = ProcessTools.FindRunning(Indicators.LauncherProcessNames);
                if (running.Count > 0)
                {
                    string names = string.Join(", ", running.Select(p => p.ProcessName + ".exe").Distinct());
                    Add(Severity.Warning, "준비", "NIKKE 런처/게임이 실행 중입니다",
                        "실행 중: " + names + "\r\n공식 안내에 따라 게임과 런처를 완전히 종료하세요(화면 오른쪽 아래 트레이 아이콘까지). " +
                        "11월 5일 이후 런처는 실행 시 로그를 지울 수 있으므로, 점검이 끝날 때까지 런처를 다시 켜지 마세요.");
                }
                foreach (var p in running) p.Dispose();

                var chrome = Process.GetProcessesByName("chrome");
                if (chrome.Length > 0)
                {
                    Add(Severity.Info, "준비", "Google Chrome이 실행 중입니다",
                        "악성 DLL은 Chrome에 로드됩니다. 공식 안내대로 복구 전에 Chrome을 완전히 종료하세요.");
                }
                foreach (var p in chrome) p.Dispose();
            }

            if (_ctx.CheckNetwork)
            {
                bool online = false;
                try { online = NetworkInterface.GetIsNetworkAvailable(); } catch (Exception) { }
                if (online)
                {
                    Add(Severity.Info, "준비", "네트워크에 연결되어 있습니다",
                        "공식 안내는 점검을 시작하기 전에 네트워크 연결을 끊을 것을 권장합니다(감염된 경우 공격자와의 통신 차단). " +
                        "이 프로그램은 인터넷을 사용하지 않으므로 연결을 끊고 실행해도 됩니다.");
                }
            }
        }

        private void LocateInstalls()
        {
            var notes = new List<string>();
            _r.InstallRoots.AddRange(InstallLocator.Find(_ctx, notes));
            _r.LauncherDataDirs.AddRange(_ctx.FindLauncherDataDirs());

            if (_r.InstallRoots.Count > 0)
            {
                Add(Severity.Info, "설치 위치", $"NIKKE 설치 폴더 {_r.InstallRoots.Count}곳 발견",
                    string.Join("\r\n", notes), _r.InstallRoots[0]);
            }
            else if (_r.LauncherDataDirs.Count > 0)
            {
                Add(Severity.Warning, "설치 위치", "런처 사용 흔적은 있으나 설치 폴더를 찾지 못함",
                    "런처 데이터 폴더는 있지만 설치 폴더(예: C:\\NIKKE)를 찾지 못했습니다. 설치 폴더의 Launcher\\intl_service\\debug.log가 " +
                    "공식 판정의 핵심 자료이므로, [설치 폴더 추가]로 지정한 뒤 다시 검사하세요.\r\n" +
                    "런처 데이터: " + string.Join(", ", _r.LauncherDataDirs));
            }
        }

        // ------------------------------------------------------------------ install folder

        private void CheckIntlService(string root)
        {
            string dir = Path.Combine(root, "Launcher", "intl_service");
            string debugLog = Path.Combine(dir, "debug.log");

            var logFiles = FileUtil.TryGetFiles(dir)
                .Where(f => Path.GetFileName(f).IndexOf(".log", StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            if (!File.Exists(debugLog))
            {
                Add(Severity.Warning, "런처 로그", "debug.log 파일이 없음 — 로그로는 판정할 수 없습니다",
                    debugLog + "\r\n런처를 실행한 적이 없거나, 11월 5일 이후 업데이트된 런처(자동 검사 기능)가 로그를 지웠을 수 있습니다. " +
                    "레지스트리·Chrome DLL·캐시 검사 결과를 함께 확인하세요.", debugLog);
            }

            bool anyHit = false;
            foreach (var f in logFiles)
                anyHit |= ScanLogFile(f);

            if (File.Exists(debugLog))
            {
                if (!anyHit)
                {
                    Add(Severity.Ok, "런처 로그", "debug.log에서 'k2f_chan registered' 미발견",
                        "공식 판정 문자열이 없습니다. 단, 공식 안내에 따르면 이 문자열이 없어도 보안 위험을 완전히 배제할 수는 없습니다.", debugLog);
                }
                try
                {
                    var fi = new FileInfo(debugLog);
                    if (fi.CreationTimeUtc > Indicators.FixUtc)
                    {
                        Add(Severity.Info, "런처 로그", "debug.log가 사고 조치(11/4) 이후 새로 만들어졌습니다",
                            "생성 시각: " + FileUtil.FormatTime(fi.CreationTimeUtc) + "\r\n이전 기록이 지워졌을 수 있으므로, 로그에 흔적이 없다는 결과만으로 안전하다고 보기 어렵습니다.",
                            debugLog);
                    }
                }
                catch (Exception) { }
            }
        }

        /// <summary>Returns true when a High/Critical pattern was found.</summary>
        private bool ScanLogFile(string path)
        {
            var hits = LogPatterns.Select(p => new LogHit(p)).ToArray();
            using (var fs = FileUtil.OpenShared(path))
            using (var reader = new StreamReader(fs, new UTF8Encoding(false), true))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    foreach (var h in hits)
                    {
                        if (!h.Pattern.IsMatch(line)) continue;
                        h.Count++;
                        if (h.Samples.Count < MaxSamples)
                            h.Samples.Add(FileUtil.Truncate(Redactor.Redact(line.Trim()), 240));
                    }
                }
            }

            bool any = false;
            foreach (var h in hits.Where(x => x.Count > 0))
            {
                any = true;
                var sb = new StringBuilder();
                sb.AppendLine(h.Pattern.Explanation);
                sb.AppendLine();
                sb.AppendLine($"파일: {path}");
                sb.AppendLine($"일치한 줄: {h.Count}개 (앞의 {h.Samples.Count}개, 민감 정보 가림)");
                foreach (var s in h.Samples) sb.AppendLine("  " + s);
                Add(h.Pattern.Severity, "런처 로그", h.Pattern.Title, sb.ToString().TrimEnd(), path);
            }
            return any;
        }

        private void CheckTinyget(string root)
        {
            string dir = Path.Combine(root, "Launcher", "log", "tinyget");
            if (!Directory.Exists(dir)) return;

            var downloadLogs = new List<string>();
            foreach (var f in FileUtil.EnumerateFiles(dir, true, 20000))
            {
                if (SafetyRules.IsPayloadFile(f, out string reasons))
                {
                    var fi = new FileInfo(f);
                    string sha = SafeSha(f);
                    Add(Severity.Critical, "악성 파일", "악성 에이전트 파일 발견: " + fi.Name,
                        reasons + "\r\n\r\n크기: " + FileUtil.FormatSize(fi.Length) +
                        "\r\n수정 시각: " + FileUtil.FormatTime(fi.LastWriteTimeUtc) +
                        (sha != null ? "\r\nSHA-256: " + sha : ""),
                        f,
                        new RemediationAction
                        {
                            Type = ActionType.DeleteFile,
                            Target = f,
                            Order = 20,
                            Description = "악성 에이전트 파일 삭제: " + f,
                        });
                    continue;
                }

                // Text logs (tinyget.mem.log, download logs) that mention the attacker host.
                try
                {
                    byte[] data = FileUtil.ReadAllShared(f, 4L * 1024 * 1024);
                    if (data != null && DomainNeedle.FoundIn(data))
                    {
                        bool success = ByteSearch.ContainsAscii(data, "curl perform success")
                                       && (ByteSearch.ContainsAscii(data, "total=205135") || ByteSearch.ContainsAscii(data, "total=165108"));
                        downloadLogs.Add(f + (success ? "  [다운로드 완료 기록]" : ""));
                    }
                }
                catch (Exception) { }
            }

            if (downloadLogs.Count > 0)
            {
                Add(Severity.High, "다운로드 기록", "공격자 서버(insightjs)와 통신한 다운로드 기록",
                    "런처의 다운로드 모듈(tinyget)이 공격자 서버에 접속한 기록입니다. 증거이므로 삭제 대상은 아닙니다(백업에 포함).\r\n\r\n" +
                    ListPaths(downloadLogs), downloadLogs[0].Split(new[] { "  [" }, StringSplitOptions.None)[0]);
            }
        }

        private void CheckLauncherLogs(string root)
        {
            string dir = Path.Combine(root, "Launcher", "log");
            if (!Directory.Exists(dir)) return;
            string tinyget = Path.Combine(dir, "tinyget");
            var hits = new List<string>();
            foreach (var f in FileUtil.EnumerateFiles(dir, true, 20000))
            {
                if (FileUtil.IsUnder(f, tinyget)) continue;
                try
                {
                    byte[] data = FileUtil.ReadAllShared(f, MaxScanBytes);
                    if (data != null && DomainNeedle.FoundIn(data)) hits.Add(f);
                }
                catch (Exception) { }
            }
            if (hits.Count > 0)
            {
                Add(Severity.High, "런처 로그", "런처 로그에 공격자 도메인(insightjs) 기록",
                    "런처가 공격자 도메인에 접속한 흔적입니다.\r\n\r\n" + ListPaths(hits), hits[0]);
            }
        }

        // ------------------------------------------------------------------ launcher data (tbs_cache)

        private void CheckLauncherData(string dataDir)
        {
            string cache = Path.Combine(dataDir, "tbs_cache");
            string label = Path.GetFileName(dataDir);
            if (!Directory.Exists(cache)) return;

            string leveldb = Path.Combine(cache, "Local Storage", "leveldb");
            string codeCacheJs = Path.Combine(cache, "Code Cache", "js");

            var agentHits = new List<string>();
            var hashHits = new List<string>();
            var loaderHits = new List<string>();
            var domainHits = new Dictionary<string, List<string>>();
            var needles = new[] { AgentStateNeedle };

            foreach (var f in FileUtil.EnumerateFiles(cache, true))
            {
                byte[] data;
                try
                {
                    var fi = new FileInfo(f);
                    if (fi.Length == 0 || fi.Length > MaxScanBytes) continue;
                    data = FileUtil.ReadAllShared(f, MaxScanBytes);
                }
                catch (Exception) { continue; }
                if (data == null) continue;

                if (FileUtil.IsUnder(f, leveldb))
                {
                    bool agent = AgentStateNeedle.FoundIn(data);
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    if (!agent && (ext == ".ldb" || ext == ".sst"))
                        agent = LevelDbTable.Search(data, needles) != null;
                    if (agent) agentHits.Add(f);
                }

                bool domain = DomainNeedle.FoundIn(data) || OrgMarkerNeedle.FoundIn(data);
                string matchedHash = MatchModifiedScript(data);
                if (!domain || matchedHash == null)
                {
                    foreach (var body in GzipTools.DecompressMembers(data, MaxDecompressedBytes))
                    {
                        if (!domain && (DomainNeedle.FoundIn(body) || OrgMarkerNeedle.FoundIn(body))) domain = true;
                        if (matchedHash == null) matchedHash = MatchModifiedScript(body);
                    }
                }

                if (matchedHash != null) hashHits.Add(f + "  (SHA-256 " + matchedHash + ")");
                if (domain)
                {
                    string cat = CacheCategory(f, cache);
                    if (!domainHits.TryGetValue(cat, out var list)) domainHits[cat] = list = new List<string>();
                    list.Add(f);
                }
                if (FileUtil.IsUnder(f, codeCacheJs) && Indicators.CodeCacheLoaderEntries.Contains(Path.GetFileName(f)))
                    loaderHits.Add(f);
            }

            var hstsHits = CheckHsts(Path.Combine(cache, "TransportSecurity"));

            if (agentHits.Count > 0)
            {
                Add(Severity.Critical, "런처 캐시", $"악성 에이전트 상태 데이터(k2f.agent.state) 발견 [{label}]",
                    "에이전트가 실행되어 자신의 상태(agent_id 등)를 런처 저장소에 기록한 흔적입니다.\r\n\r\n" + ListPaths(agentHits),
                    agentHits[0]);
            }
            if (loaderHits.Count > 0)
            {
                Add(Severity.High, "런처 캐시", $"변조된 로더 스크립트가 실행된 흔적 (Code Cache) [{label}]",
                    "연구자 분석에 따르면 이 항목은 변조된 로더가 실행되었다는 증거입니다(에이전트 실행 여부는 로그·레지스트리 결과로 판단).\r\n\r\n" +
                    ListPaths(loaderHits), loaderHits[0]);
            }
            if (hashHits.Count > 0)
            {
                Add(Severity.High, "런처 캐시", $"변조된 런처 스크립트 원본이 캐시에 남아 있음 (해시 일치) [{label}]",
                    "변조된 CDN 스크립트와 정확히 같은 파일입니다. 런처가 이 캐시를 다시 불러올 수 있으므로 캐시 삭제가 필요합니다.\r\n\r\n" +
                    ListPaths(hashHits), hashHits[0].Split(new[] { "  (" }, StringSplitOptions.None)[0]);
            }
            foreach (var kv in domainHits)
            {
                Add(Severity.High, "런처 캐시", $"공격자 도메인/변조 스크립트 흔적 — {kv.Key} [{label}]",
                    "캐시 파일에 공격자 도메인(insightjs) 또는 변조 스크립트의 표식이 남아 있습니다. 변조된 스크립트가 이 PC의 런처에서 로드되었다는 뜻입니다.\r\n\r\n" +
                    ListPaths(kv.Value), kv.Value[0]);
            }
            if (hstsHits.Count > 0)
            {
                Add(Severity.High, "런처 캐시", $"공격자 도메인과 HTTPS 통신한 기록 (TransportSecurity) [{label}]",
                    "런처 내장 브라우저가 다음 도메인에 HTTPS로 접속한 기록이 있습니다: " + string.Join(", ", hstsHits),
                    Path.Combine(cache, "TransportSecurity"));
            }
            if (agentHits.Count + loaderHits.Count + hashHits.Count + domainHits.Count + hstsHits.Count == 0)
            {
                Add(Severity.Ok, "런처 캐시", $"런처 캐시에서 알려진 흔적 없음 [{label}]", cache, cache);
            }

            Add(Severity.Info, "런처 캐시", $"런처 로컬 캐시 삭제 권장: {label}\\tbs_cache",
                "공식 복구 절차 ⑤입니다. 변조된 스크립트가 캐시에 남아 있으면 런처가 다시 불러올 수 있으므로 삭제를 권장합니다. " +
                "삭제 후 런처를 처음 실행할 때 다시 로그인해야 할 수 있습니다. (삭제 전에 증거 백업을 권장합니다)",
                cache,
                new RemediationAction
                {
                    Type = ActionType.DeleteLauncherCache,
                    Target = cache,
                    Order = 40,
                    Description = "런처 로컬 캐시 삭제: " + cache,
                });
        }

        private static string MatchModifiedScript(byte[] data)
        {
            if (data == null || !Indicators.ModifiedScriptSizes.Contains(data.Length)) return null;
            string sha = FileUtil.Sha256(data);
            return Indicators.KnownModifiedScriptSha256.Contains(sha) ? sha : null;
        }

        private static string CacheCategory(string file, string cache)
        {
            string rel = file.Substring(cache.Length).TrimStart('\\');
            if (rel.StartsWith("Code Cache", StringComparison.OrdinalIgnoreCase)) return "코드 캐시";
            if (rel.StartsWith("Cache", StringComparison.OrdinalIgnoreCase)) return "HTTP 캐시";
            if (rel.StartsWith("Local Storage", StringComparison.OrdinalIgnoreCase)) return "로컬 저장소";
            if (rel.StartsWith("Service Worker", StringComparison.OrdinalIgnoreCase)) return "서비스 워커";
            return "기타 캐시 파일";
        }

        /// <summary>
        /// Chromium stores HSTS hosts as base64(SHA-256(DNS-wire-format host)), so the attacker domains
        /// cannot be found by plain text search in TransportSecurity.
        /// </summary>
        private static List<string> CheckHsts(string path)
        {
            var hits = new List<string>();
            if (!File.Exists(path)) return hits;
            string text;
            try
            {
                byte[] data = FileUtil.ReadAllShared(path, MaxScanBytes);
                if (data == null) return hits;
                text = Encoding.UTF8.GetString(data);
            }
            catch (Exception) { return hits; }

            foreach (var domain in Indicators.HostsBlockDomains)
            {
                string h = HstsHostHash(domain);
                if (text.IndexOf(h, StringComparison.Ordinal) >= 0 || text.IndexOf(h.Replace("/", "\\/"), StringComparison.Ordinal) >= 0)
                    hits.Add(domain);
            }
            return hits;
        }

        public static string HstsHostHash(string host)
        {
            var ms = new MemoryStream();
            foreach (var label in host.TrimEnd('.').ToLowerInvariant().Split('.'))
            {
                byte[] b = Encoding.ASCII.GetBytes(label);
                ms.WriteByte((byte)b.Length);
                ms.Write(b, 0, b.Length);
            }
            ms.WriteByte(0);
            using (var sha = SHA256.Create())
                return Convert.ToBase64String(sha.ComputeHash(ms.ToArray()));
        }

        // ------------------------------------------------------------------ registry

        private void CheckRegistry()
        {
            bool found = false;
            foreach (var sub in new[] { Indicators.HkcuClsidPath, Indicators.HkcuClsidWowPath })
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(_ctx.Hkcu(sub)))
                {
                    if (key == null) continue;
                    found = true;
                    string inproc = null;
                    using (var ip = key.OpenSubKey("InprocServer32"))
                        inproc = ip?.GetValue("") as string;

                    Add(Severity.Critical, "레지스트리", "악성 COM 등록 발견 (HKCU CLSID " + Indicators.MaliciousClsid + ")",
                        "Chrome이 실행될 때 악성 DLL을 불러오도록 만든 등록 항목입니다(공식 복구 절차 ①).\r\n" +
                        "InprocServer32 = " + (string.IsNullOrEmpty(inproc) ? "(비어 있음 — 악성 프로그램이 일부 정리한 흔적, 그래도 삭제 대상)" : inproc) +
                        "\r\n\r\n※ HKEY_LOCAL_MACHINE의 같은 이름 항목은 Windows 정상 항목이므로 삭제하지 않습니다.",
                        "HKEY_CURRENT_USER\\" + sub,
                        new RemediationAction
                        {
                            Type = ActionType.DeleteRegistryKey,
                            Target = sub,
                            View = RegistryView.Registry64,
                            Order = 10,
                            Description = "레지스트리 삭제: HKEY_CURRENT_USER\\" + sub,
                        });
                }
            }
            if (!found)
            {
                Add(Severity.Ok, "레지스트리", "HKCU에 악성 CLSID 등록 없음",
                    "공식 복구 절차 ①의 레지스트리 항목이 없습니다.", "HKEY_CURRENT_USER\\" + Indicators.HkcuClsidPath);
            }

            if (!_ctx.CheckHklm) return;
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var ip = hklm.OpenSubKey(Indicators.HklmClsidPath + "\\InprocServer32"))
            {
                string v = ip?.GetValue("") as string;
                if (v != null && v.IndexOf("platform_experience_helper", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Add(Severity.Critical, "레지스트리", "HKLM CLSID가 악성 DLL을 가리킴 (수동 조치 필요)",
                        "HKEY_LOCAL_MACHINE의 " + Indicators.MaliciousClsid + " 항목이 정상(wpc.dll)이 아닌 악성 DLL을 가리킵니다: " + v +
                        "\r\n관리자 권한으로 변경된 것으로 보여 이 도구는 자동으로 고치지 않습니다. Windows 재설치를 권장합니다.",
                        "HKEY_LOCAL_MACHINE\\" + Indicators.HklmClsidPath);
                }
            }
        }

        // ------------------------------------------------------------------ Chrome DLL

        private void CheckChromeDll()
        {
            bool any = false;
            foreach (var userData in _ctx.ChromeUserDataDirs())
            {
                string peh = Path.Combine(userData, Indicators.PlatformExperienceHelperDir);
                if (!Directory.Exists(peh)) continue;
                foreach (var sub in FileUtil.TryGetDirectories(peh))
                {
                    if (!FileUtil.IsHex64(Path.GetFileName(sub))) continue;
                    string dll = Path.Combine(sub, Indicators.ChromeDllName);
                    if (SafetyRules.IsMaliciousChromeDllFolder(sub))
                    {
                        any = true;
                        var fi = new FileInfo(dll);
                        string sha = SafeSha(dll);
                        Add(Severity.Critical, "Chrome DLL", "Chrome 위장 악성 DLL 발견 (platform_experience_helper.dll)",
                            "64자리 16진수 이름의 폴더에 들어 있는 악성 DLL입니다(공식 복구 절차 ③). 크롬 확장 지갑의 복구 구문·개인 키를 가로챌 수 있는 코드가 확인되었습니다.\r\n" +
                            "크기: " + FileUtil.FormatSize(fi.Length) + "\r\n만든 시각: " + FileUtil.FormatTime(fi.CreationTimeUtc) +
                            (sha != null ? "\r\nSHA-256: " + sha + " (피해자마다 다르게 빌드됨)" : "") +
                            "\r\n\r\n이 64자리 폴더만 삭제합니다. 상위 PlatformExperienceHelper 폴더에는 정상 Chrome 파일이 있을 수 있어 건드리지 않습니다.",
                            dll,
                            new RemediationAction
                            {
                                Type = ActionType.DeleteChromeDllFolder,
                                Target = sub,
                                Order = 50,
                                Description = "Chrome 위장 DLL 폴더 삭제: " + sub,
                            });
                    }
                    else
                    {
                        Add(Severity.Warning, "Chrome DLL", "64자리 폴더가 있으나 DLL은 없음",
                            "악성 프로그램이 스스로 DLL을 정리하고 남긴 흔적일 수 있습니다. 공식 기준(DLL이 있을 때만 삭제)에 따라 자동 삭제하지 않습니다.",
                            sub);
                    }
                }
            }
            if (!any)
            {
                Add(Severity.Ok, "Chrome DLL", "Chrome 위장 악성 DLL 없음",
                    "PlatformExperienceHelper 안에 64자리 16진수 폴더 + platform_experience_helper.dll 조합이 없습니다(공식 복구 절차 ③).",
                    Path.Combine(_ctx.LocalAppData ?? "", "Google", "Chrome", "User Data", Indicators.PlatformExperienceHelperDir));
            }

            // Files the agent's Chrome installer drops into Chrome's Application folder (legit Chrome only has the .exe there).
            var suspicious = new List<string>();
            foreach (var app in _ctx.ChromeApplicationDirs())
            {
                if (!Directory.Exists(app)) continue;
                var dirs = new List<string> { Path.Combine(app, Indicators.PlatformExperienceHelperDir) };
                dirs.AddRange(FileUtil.TryGetDirectories(app).Select(v => Path.Combine(v, Indicators.PlatformExperienceHelperDir)));
                foreach (var d in dirs.Where(Directory.Exists))
                    foreach (var name in Indicators.ChromeAppSuspiciousFiles)
                    {
                        string p = Path.Combine(d, name);
                        if (File.Exists(p)) suspicious.Add(p);
                    }
            }
            if (suspicious.Count > 0)
            {
                Add(Severity.High, "Chrome DLL", "Chrome 설치 폴더에 비정상 파일 (수동 확인 필요)",
                    "정상 Chrome의 PlatformExperienceHelper 폴더에는 platform_experience_helper.exe만 있습니다. 악성 프로그램의 설치·정리 흔적일 수 있습니다. " +
                    "자동 삭제하지 않으며, Chrome을 제거 후 다시 설치하는 것을 권장합니다.\r\n\r\n" + ListPaths(suspicious), suspicious[0]);
            }
        }

        // ------------------------------------------------------------------ temp / network

        private void CheckTemp()
        {
            if (string.IsNullOrEmpty(_ctx.TempDir) || !Directory.Exists(_ctx.TempDir)) return;
            foreach (var p in Indicators.TempPatterns)
            {
                foreach (var f in FileUtil.TryGetFiles(_ctx.TempDir, p.Pattern))
                {
                    var fi = new FileInfo(f);
                    Add(Severity.Critical, "임시 파일", "악성 에이전트 작업 흔적: " + fi.Name,
                        p.Meaning + "입니다. 에이전트가 이 PC에서 실제로 명령을 수행했다는 뜻입니다.\r\n" +
                        "수정 시각: " + FileUtil.FormatTime(fi.LastWriteTimeUtc),
                        f,
                        new RemediationAction
                        {
                            Type = ActionType.DeleteFile,
                            Target = f,
                            Order = 30,
                            Description = "에이전트 임시 파일 삭제: " + f,
                        });
                }
            }
        }

        private void CheckDnsCache()
        {
            if (!_ctx.CheckDnsCache) return;
            string output = ProcessTools.RunCapture("ipconfig.exe", "/displaydns", 20000, out _);
            if (output == null) return;
            var hits = Indicators.HostsBlockDomains
                .Where(d => Regex.IsMatch(output, @"(^|\s)" + Regex.Escape(d) + @"(\s|$)", RegexOptions.IgnoreCase | RegexOptions.Multiline))
                .ToList();
            if (hits.Count > 0)
            {
                Add(Severity.High, "네트워크", "DNS 캐시에 공격자 도메인 조회 기록",
                    "마지막 재부팅 이후 이 PC가 다음 도메인의 주소를 조회했습니다: " + string.Join(", ", hits) +
                    "\r\nhosts 파일로 차단해 둔 경우에도 조회 기록은 남을 수 있습니다.");
            }
        }

        private void CheckBlocks()
        {
            var st = HostsBlocker.GetStatus(_ctx.HostsPath);
            bool fw = _ctx.CheckFirewall && HostsBlocker.FirewallRuleExists();
            _r.NikkeCheckBlockPresent = fw || HostsBlocker.HasNikkeCheckBlock(_ctx.HostsPath);
            if (st.Missing.Count == 0 && (fw || !_ctx.CheckFirewall))
            {
                Add(Severity.Ok, "차단 설정", "공격자 도메인·IP가 차단되어 있음",
                    "hosts: " + string.Join(", ", st.Blocked) +
                    (_ctx.CheckFirewall ? "\r\n방화벽: " + HostsBlocker.FirewallRuleName + " (" + string.Join(", ", Indicators.AttackerIps) + ")" : "") +
                    (_r.NikkeCheckBlockPresent ? "\r\n이 프로그램이 추가한 차단은 [차단 해제…]로 되돌릴 수 있습니다(연구자는 유지를 권장)." : ""),
                    _ctx.HostsPath);
                return;
            }
            Add(Severity.Info, "차단 설정", "공격자 도메인·IP 차단 안 됨",
                $"hosts 파일 차단: {st.Blocked.Count}/{st.Blocked.Count + st.Missing.Count}개" +
                (_ctx.CheckFirewall ? $", 방화벽 IP 차단 규칙: {(fw ? "있음" : "없음")}" : "") +
                "\r\n연구자는 공격자 도메인·IP 차단을 권장합니다(CDN 침해 경로가 밝혀지지 않아 재발 가능). " +
                "[복구 실행]에서 hosts·방화벽 차단을 선택할 수 있습니다(관리자 권한 필요).",
                _ctx.HostsPath);
        }

        // ------------------------------------------------------------------ helpers

        private static string SafeSha(string path)
        {
            try { return FileUtil.Sha256(path); }
            catch (Exception) { return null; }
        }

        private static string ListPaths(List<string> paths)
        {
            var sb = new StringBuilder();
            foreach (var p in paths.Take(MaxListedPaths)) sb.AppendLine(p);
            if (paths.Count > MaxListedPaths) sb.AppendLine($"… 외 {paths.Count - MaxListedPaths}개");
            return sb.ToString().TrimEnd();
        }

        private sealed class LogPattern
        {
            public LogPattern(string text, Regex regex, Severity severity, string title, string explanation)
            {
                Text = text;
                Regex = regex;
                Severity = severity;
                Title = title;
                Explanation = explanation;
            }

            public string Text { get; }
            public Regex Regex { get; }
            public Severity Severity { get; }
            public string Title { get; }
            public string Explanation { get; }

            public bool IsMatch(string line) =>
                Regex != null ? Regex.IsMatch(line) : line.IndexOf(Text, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private sealed class LogHit
        {
            public LogHit(LogPattern p) { Pattern = p; }
            public LogPattern Pattern { get; }
            public int Count { get; set; }
            public List<string> Samples { get; } = new List<string>();
        }
    }
}
