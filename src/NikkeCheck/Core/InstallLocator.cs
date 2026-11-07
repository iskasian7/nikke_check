using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Finds NIKKE PC install folders (the folder that contains "Launcher", e.g. C:\NIKKE or C:\NIKKE_GOOGLE).
    /// Sources: drive roots, uninstall entries, desktop/start-menu shortcuts, running launcher, Steam libraries.
    /// </summary>
    public static class InstallLocator
    {
        private static readonly string[] NameHints = { "nikke", "니케", "勝利の女神", "胜利女神" };

        public static List<string> Find(ScanContext ctx, List<string> notes)
        {
            var found = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Consider(string candidate, string source)
            {
                string root = Normalize(candidate);
                if (root == null) return;
                if (seen.Add(root))
                {
                    found.Add(root);
                    notes?.Add($"{root}  (발견 경로: {source})");
                }
            }

            foreach (var r in ctx.ExtraInstallRoots) Consider(r, "직접 지정");

            if (ctx.DiscoverInstalls)
            {
                Safe(() => FromDriveRoots(Consider));
                Safe(() => FromUninstallEntries(Consider));
                Safe(() => FromShortcuts(Consider));
                Safe(() => FromRunningLauncher(Consider));
                Safe(() => FromSteam(Consider));
            }
            return found;
        }

        /// <summary>
        /// Maps any path inside an install (exe, Launcher folder, the root itself) to the install root,
        /// i.e. the folder that has a "Launcher" subfolder. Returns null when it is not a NIKKE install.
        /// </summary>
        public static string Normalize(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return null;
            try
            {
                path = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
                int comma = path.IndexOf(".exe,", StringComparison.OrdinalIgnoreCase);
                if (comma > 0) path = path.Substring(0, comma + 4);
                if (File.Exists(path)) path = Path.GetDirectoryName(path);
                if (!Directory.Exists(path)) return null;

                string dir = Path.GetFullPath(path).TrimEnd('\\');
                for (int depth = 0; depth < 4 && !string.IsNullOrEmpty(dir); depth++)
                {
                    if (string.Equals(Path.GetFileName(dir), "Launcher", StringComparison.OrdinalIgnoreCase)
                        && LooksLikeLauncherDir(dir))
                        return Path.GetDirectoryName(dir);
                    string launcher = Path.Combine(dir, "Launcher");
                    if (Directory.Exists(launcher) && LooksLikeLauncherDir(launcher))
                        return dir;
                    dir = Path.GetDirectoryName(dir);
                }
            }
            catch (Exception) { }
            return null;
        }

        private static bool LooksLikeLauncherDir(string launcherDir)
        {
            if (Directory.Exists(Path.Combine(launcherDir, "intl_service"))) return true;
            if (Directory.Exists(Path.Combine(launcherDir, "log"))) return true;
            return FileUtil.TryGetFiles(launcherDir, "nikke_launcher*.exe").Length > 0;
        }

        private static void FromDriveRoots(Action<string, string> consider)
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType != DriveType.Fixed || !drive.IsReady) continue;
                }
                catch (Exception) { continue; }

                string root = drive.RootDirectory.FullName;
                foreach (var parent in new[]
                         {
                             root,
                             Path.Combine(root, "Program Files"),
                             Path.Combine(root, "Program Files (x86)"),
                             Path.Combine(root, "Games"),
                         })
                {
                    if (!Directory.Exists(parent)) continue;
                    foreach (var d in FileUtil.TryGetDirectories(parent, "*NIKKE*"))
                        consider(d, "드라이브 검색");
                }
            }
        }

        private static void FromUninstallEntries(Action<string, string> consider)
        {
            const string sub = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            var hives = new[]
            {
                (RegistryHive.LocalMachine, RegistryView.Registry64),
                (RegistryHive.LocalMachine, RegistryView.Registry32),
                (RegistryHive.CurrentUser, RegistryView.Registry64),
            };
            foreach (var (hive, view) in hives)
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var uninstall = baseKey.OpenSubKey(sub))
                {
                    if (uninstall == null) continue;
                    foreach (var name in uninstall.GetSubKeyNames())
                    {
                        using (var app = uninstall.OpenSubKey(name))
                        {
                            if (app == null) continue;
                            string display = app.GetValue("DisplayName") as string;
                            if (!HasNameHint(display) && !HasNameHint(name)) continue;
                            foreach (var valueName in new[] { "InstallLocation", "DisplayIcon", "UninstallString", "InstallPath" })
                            {
                                if (app.GetValue(valueName) is string v && v.Length > 0)
                                    consider(ExtractPath(v), "설치 정보(레지스트리)");
                            }
                        }
                    }
                }
            }
        }

        private static void FromShortcuts(Action<string, string> consider)
        {
            var folders = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            };
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return;
            object shell = Activator.CreateInstance(shellType);
            try
            {
                foreach (var folder in folders)
                {
                    foreach (var lnk in FileUtil.EnumerateFiles(folder, true, 5000))
                    {
                        if (!lnk.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!HasNameHint(Path.GetFileNameWithoutExtension(lnk))) continue;
                        string target = ResolveShortcut(shellType, shell, lnk);
                        if (!string.IsNullOrEmpty(target)) consider(target, "바로가기 " + Path.GetFileName(lnk));
                    }
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }

        private static string ResolveShortcut(Type shellType, object shell, string lnkPath)
        {
            object link = null;
            try
            {
                link = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                return link.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty, null, link, null) as string;
            }
            catch (Exception) { return null; }
            finally
            {
                if (link != null) Marshal.FinalReleaseComObject(link);
            }
        }

        private static void FromRunningLauncher(Action<string, string> consider)
        {
            foreach (var name in new[] { "nikke_launcher", "nikke_launcher_hmt", "nikke_launcher_google" })
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { consider(ImagePath(p.Id), "실행 중인 런처"); }
                    catch (Exception) { }
                    finally { p.Dispose(); }
                }
            }
        }

        private const uint ProcessQueryLimitedInformation = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool QueryFullProcessImageName(IntPtr process, int flags, System.Text.StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// The launcher runs elevated (requireAdministrator), so Process.MainModule is denied from a normal
        /// process. PROCESS_QUERY_LIMITED_INFORMATION is still granted for the same user's processes.
        /// </summary>
        private static string ImagePath(int pid)
        {
            IntPtr h = OpenProcess(ProcessQueryLimitedInformation, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                var sb = new System.Text.StringBuilder(1024);
                int size = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref size) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        private static void FromSteam(Action<string, string> consider)
        {
            string steam;
            using (var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam"))
                steam = key?.GetValue("SteamPath") as string;
            if (string.IsNullOrEmpty(steam)) return;
            steam = steam.Replace('/', '\\');

            var libraries = new List<string> { steam };
            string vdf = Path.Combine(steam, "steamapps", "libraryfolders.vdf");
            if (File.Exists(vdf))
            {
                foreach (Match m in Regex.Matches(File.ReadAllText(vdf), "\"path\"\\s+\"(.+?)\""))
                    libraries.Add(m.Groups[1].Value.Replace(@"\\", @"\"));
            }
            foreach (var lib in libraries)
            {
                string common = Path.Combine(lib, "steamapps", "common");
                foreach (var d in FileUtil.TryGetDirectories(common, "*NIKKE*"))
                    consider(d, "Steam 라이브러리");
            }
        }

        private static bool HasNameHint(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            foreach (var h in NameHints)
                if (s.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            return false;
        }

        private static string ExtractPath(string value)
        {
            value = value.Trim();
            if (value.StartsWith("\""))
            {
                int close = value.IndexOf('"', 1);
                return close > 1 ? value.Substring(1, close - 1) : value.Trim('"');
            }
            int exe = value.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            return exe > 0 ? value.Substring(0, exe + 4) : value;
        }

        private static void Safe(Action a)
        {
            try { a(); }
            catch (Exception) { }
        }
    }
}
