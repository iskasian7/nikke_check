using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Copies the evidence into a zip before anything is deleted: launcher logs, tinyget folder,
    /// tbs_cache, agent temp files, the registry entry, and DLL metadata (the DLL itself is not copied
    /// so antivirus does not quarantine the whole backup).
    /// </summary>
    public static class BackupWriter
    {
        /// <summary>%USERPROFILE%\NIKKE_점검백업 — deliberately not Desktop/Documents, which are often synced to OneDrive.</summary>
        public static string DefaultDirectoryFor(ScanContext ctx) =>
            ctx?.SandboxRoot != null
                ? Path.Combine(ctx.SandboxRoot, "Backup")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "NIKKE_점검백업");

        public static string Create(ScanContext ctx, ScanResult scan, string destDir, Action<string> progress = null)
        {
            Directory.CreateDirectory(destDir);
            string zipPath = Path.Combine(destDir, "NIKKE_점검백업_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".zip");
            var errors = new List<string>();
            int files = 0;

            using (var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create))
            {
                AddText(zip, "report.txt", ReportWriter.Build(scan));

                for (int i = 0; i < scan.InstallRoots.Count; i++)
                {
                    string root = scan.InstallRoots[i];
                    string prefix = $"install{i + 1}_{SafeName(Path.GetFileName(root.TrimEnd('\\')))}/Launcher/";
                    progress?.Invoke("백업: " + root);
                    files += AddDirectory(zip, Path.Combine(root, "Launcher", "intl_service"), prefix + "intl_service/", errors);
                    files += AddDirectory(zip, Path.Combine(root, "Launcher", "log"), prefix + "log/", errors);
                }

                foreach (var dataDir in scan.LauncherDataDirs)
                {
                    progress?.Invoke("백업: " + dataDir);
                    string prefix = "appdata/" + SafeName(Path.GetFileName(dataDir)) + "/tbs_cache/";
                    files += AddDirectory(zip, Path.Combine(dataDir, "tbs_cache"), prefix, errors);
                }

                foreach (var f in scan.Findings.Where(x => x.Action?.Type == ActionType.DeleteFile && x.Category == "임시 파일"))
                    files += AddFile(zip, f.Action.Target, "temp/" + Path.GetFileName(f.Action.Target), errors) ? 1 : 0;

                AddText(zip, "registry_hkcu_clsid.txt", DumpRegistry(ctx));
                AddText(zip, "chrome_dll_info.txt", DescribeDlls(scan));

                var summary = new StringBuilder();
                summary.AppendLine($"백업 시각: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                summary.AppendLine($"백업한 파일 수: {files}");
                summary.AppendLine("주의: 이 백업에는 로그인 티켓·쿠키 같은 민감 정보가 들어 있을 수 있습니다. 공개된 곳에 올리지 마세요.");
                if (errors.Count > 0)
                {
                    summary.AppendLine();
                    summary.AppendLine("복사하지 못한 파일:");
                    foreach (var e in errors) summary.AppendLine("  " + e);
                }
                AddText(zip, "backup_info.txt", summary.ToString());
            }
            return zipPath;
        }

        private static int AddDirectory(ZipArchive zip, string dir, string entryPrefix, List<string> errors)
        {
            if (!Directory.Exists(dir)) return 0;
            int count = 0;
            string baseDir = dir.TrimEnd('\\') + "\\";
            foreach (var f in FileUtil.EnumerateFiles(dir, true))
            {
                string rel = f.Substring(baseDir.Length).Replace('\\', '/');
                if (AddFile(zip, f, entryPrefix + rel, errors)) count++;
            }
            return count;
        }

        private static bool AddFile(ZipArchive zip, string path, string entryName, List<string> errors)
        {
            try
            {
                using (var src = FileUtil.OpenShared(path))
                {
                    var entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);
                    try { entry.LastWriteTime = File.GetLastWriteTime(path); } catch (Exception) { }
                    using (var dst = entry.Open()) src.CopyTo(dst);
                }
                return true;
            }
            catch (Exception ex)
            {
                errors.Add(path + " — " + ex.Message);
                return false;
            }
        }

        private static void AddText(ZipArchive zip, string name, string text)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
            using (var w = new StreamWriter(entry.Open(), new UTF8Encoding(true)))
                w.Write(text);
        }

        private static string DumpRegistry(ScanContext ctx)
        {
            var sb = new StringBuilder();
            foreach (var sub in new[] { Indicators.HkcuClsidPath, Indicators.HkcuClsidWowPath })
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(ctx.Hkcu(sub)))
                {
                    sb.AppendLine("[HKEY_CURRENT_USER\\" + sub + "]");
                    if (key == null)
                    {
                        sb.AppendLine("  (없음)");
                        continue;
                    }
                    DumpKey(key, sb, "  ");
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        private static void DumpKey(RegistryKey key, StringBuilder sb, string indent)
        {
            foreach (var name in key.GetValueNames())
            {
                object v = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                sb.AppendLine($"{indent}{(name.Length == 0 ? "(기본값)" : name)} = {v}");
            }
            foreach (var subName in key.GetSubKeyNames())
            {
                using (var sub = key.OpenSubKey(subName))
                {
                    if (sub == null) continue;
                    sb.AppendLine($"{indent}[{subName}]");
                    DumpKey(sub, sb, indent + "  ");
                }
            }
        }

        private static string DescribeDlls(ScanResult scan)
        {
            var sb = new StringBuilder();
            var dlls = scan.Findings.Where(f => f.Action?.Type == ActionType.DeleteChromeDllFolder).ToList();
            if (dlls.Count == 0) return "Chrome 위장 DLL 없음\r\n";
            foreach (var f in dlls)
            {
                sb.AppendLine(f.Path);
                sb.AppendLine(f.Detail);
                foreach (var file in FileUtil.EnumerateFiles(f.Action.Target, true, 200))
                {
                    try
                    {
                        var fi = new FileInfo(file);
                        sb.AppendLine($"  {fi.Name}  {fi.Length:N0} B  생성 {FileUtil.FormatTime(fi.CreationTimeUtc)}  SHA-256 {FileUtil.Sha256(file)}");
                    }
                    catch (Exception ex) { sb.AppendLine($"  {file}  (읽기 실패: {ex.Message})"); }
                }
                sb.AppendLine();
            }
            return sb.ToString();
        }

        private static string SafeName(string s)
        {
            if (string.IsNullOrEmpty(s)) return "root";
            foreach (var c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_');
            return s.Replace(' ', '_');
        }
    }
}
