using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Where to look. Production values come from the signed-in user's environment;
    /// tests point everything at a temporary folder and an isolated registry key.
    /// </summary>
    public sealed class ScanContext
    {
        public string AppData { get; set; }
        public string LocalAppData { get; set; }
        public string TempDir { get; set; }
        public string ProgramFiles { get; set; }
        public string ProgramFilesX86 { get; set; }
        public string HostsPath { get; set; }

        /// <summary>Prepended to every HKCU subkey. Empty in production; a sandbox key in tests.</summary>
        public string RegistryPrefix { get; set; } = "";

        public List<string> ExtraInstallRoots { get; } = new List<string>();

        public bool DiscoverInstalls { get; set; } = true;
        public bool CheckProcesses { get; set; } = true;
        public bool CheckNetwork { get; set; } = true;
        public bool CheckDnsCache { get; set; } = true;
        public bool CheckFirewall { get; set; } = true;
        public bool CheckHklm { get; set; } = true;

        /// <summary>Set when NIKKECHECK_SANDBOX points at a fake PC (tools/New-InfectedSandbox.ps1). Developer/QA use only.</summary>
        public string SandboxRoot { get; private set; }

        public static ScanContext FromEnvironment()
        {
            string sandbox = Environment.GetEnvironmentVariable("NIKKECHECK_SANDBOX");
            if (!string.IsNullOrEmpty(sandbox) && Directory.Exists(sandbox))
                return Sandbox(sandbox);

            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            return new ScanContext
            {
                AppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                TempDir = Path.GetTempPath(),
                ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                HostsPath = Path.Combine(windir, "System32", "drivers", "etc", "hosts"),
            };
        }

        private static ScanContext Sandbox(string root)
        {
            root = Path.GetFullPath(root);
            var ctx = new ScanContext
            {
                SandboxRoot = root,
                AppData = Path.Combine(root, "AppData", "Roaming"),
                LocalAppData = Path.Combine(root, "AppData", "Local"),
                TempDir = Path.Combine(root, "Temp"),
                ProgramFiles = Path.Combine(root, "Program Files"),
                ProgramFilesX86 = Path.Combine(root, "Program Files (x86)"),
                HostsPath = Path.Combine(root, "hosts"),
                RegistryPrefix = @"Software\NikkeCheckSandbox\",
                DiscoverInstalls = false,
                CheckDnsCache = false,
                CheckFirewall = false,
                CheckHklm = false,
            };
            foreach (var d in FileUtil.TryGetDirectories(root, "NIKKE*")) ctx.ExtraInstallRoots.Add(d);
            return ctx;
        }

        public string Hkcu(string subKey) => RegistryPrefix + subKey;

        /// <summary>%APPDATA%\nikke_launcher, nikke_launcher_hmt, nikke_launcher_google, ...</summary>
        public List<string> FindLauncherDataDirs()
        {
            var list = new List<string>();
            if (string.IsNullOrEmpty(AppData) || !Directory.Exists(AppData)) return list;
            try
            {
                foreach (var d in Directory.GetDirectories(AppData, Indicators.LauncherDataPrefix + "*"))
                    list.Add(d);
            }
            catch (Exception) { }
            list.Sort(StringComparer.OrdinalIgnoreCase);
            return list;
        }

        public IEnumerable<string> ChromeUserDataDirs()
        {
            if (string.IsNullOrEmpty(LocalAppData)) yield break;
            foreach (var channel in new[] { "Chrome", "Chrome Beta", "Chrome Dev", "Chrome SxS" })
                yield return Path.Combine(LocalAppData, "Google", channel, "User Data");
        }

        public IEnumerable<string> ChromeApplicationDirs()
        {
            var roots = new[] { LocalAppData, ProgramFiles, ProgramFilesX86 }
                .Where(r => !string.IsNullOrEmpty(r))
                .Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var r in roots)
                yield return Path.Combine(r, "Google", "Chrome", "Application");
        }
    }
}
