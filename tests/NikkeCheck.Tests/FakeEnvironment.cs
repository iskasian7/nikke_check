using System;
using System.IO;
using System.Text;
using Microsoft.Win32;
using NikkeCheck.Core;

namespace NikkeCheck.Tests
{
    /// <summary>
    /// A throwaway "PC": temp folders standing in for C:\NIKKE, %APPDATA%, %LOCALAPPDATA%, %TEMP%,
    /// plus an isolated HKCU\Software\NikkeCheckTest\{guid} key standing in for HKCU.
    /// </summary>
    internal sealed class FakeEnvironment : IDisposable
    {
        public const string Hex64 = "3f9a1c0b7d2e4f6a8b9c0d1e2f3a4b5c6d7e8f9012345678abcdef0123456789";

        private readonly string _id = Guid.NewGuid().ToString("N");

        public FakeEnvironment()
        {
            Root = Path.Combine(Path.GetTempPath(), "nikkecheck-test-" + _id);
            Install = Path.Combine(Root, "NIKKE");
            AppData = Path.Combine(Root, "AppData", "Roaming");
            LocalAppData = Path.Combine(Root, "AppData", "Local");
            TempDir = Path.Combine(Root, "Temp");
            ProgramFiles = Path.Combine(Root, "Program Files");
            HostsPath = Path.Combine(Root, "hosts");
            BackupDir = Path.Combine(Root, "Backup");
            foreach (var d in new[] { Install, AppData, LocalAppData, TempDir, ProgramFiles })
                Directory.CreateDirectory(d);
            Directory.CreateDirectory(Path.Combine(Install, "Launcher", "intl_service"));
            File.WriteAllText(HostsPath, "127.0.0.1 localhost");
        }

        public string Root { get; }
        public string Install { get; }
        public string AppData { get; }
        public string LocalAppData { get; }
        public string TempDir { get; }
        public string ProgramFiles { get; }
        public string HostsPath { get; }
        public string BackupDir { get; }
        public string RegistryPrefix => @"Software\NikkeCheckTest\" + _id + @"\";

        public string DebugLog => Path.Combine(Install, "Launcher", "intl_service", "debug.log");
        public string TinygetDir => Path.Combine(Install, "Launcher", "log", "tinyget");
        public string LauncherData(string name = "nikke_launcher") => Path.Combine(AppData, name);
        public string TbsCache(string name = "nikke_launcher") => Path.Combine(LauncherData(name), "tbs_cache");
        public string PlatformHelper => Path.Combine(LocalAppData, "Google", "Chrome", "User Data", "PlatformExperienceHelper");
        public string DllFolder => Path.Combine(PlatformHelper, Hex64);

        public ScanContext Context()
        {
            var ctx = new ScanContext
            {
                AppData = AppData,
                LocalAppData = LocalAppData,
                TempDir = TempDir,
                ProgramFiles = ProgramFiles,
                ProgramFilesX86 = ProgramFiles,
                HostsPath = HostsPath,
                RegistryPrefix = RegistryPrefix,
                DiscoverInstalls = false,
                CheckProcesses = false,
                CheckNetwork = false,
                CheckDnsCache = false,
                CheckFirewall = false,
                CheckHklm = false,
            };
            ctx.ExtraInstallRoots.Add(Install);
            return ctx;
        }

        public void WriteDebugLog(params string[] lines) =>
            File.WriteAllLines(DebugLog, lines, new UTF8Encoding(false));

        public string WriteFile(string path, byte[] data)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path));
            File.WriteAllBytes(path, data);
            return path;
        }

        public string WriteText(string path, string text) => WriteFile(path, Encoding.UTF8.GetBytes(text));

        /// <summary>LuaJIT payload exactly 205,135 bytes, named like the official notice describes.</summary>
        public string AddPayload(string name = "tinyget.20261103-004700.log")
        {
            var data = new byte[Indicators.OfficialPayloadSize];
            data[0] = 0x1B; data[1] = 0x4C; data[2] = 0x4A; data[3] = 0x01;
            return WriteFile(Path.Combine(TinygetDir, name), data);
        }

        public void AddInfectedRegistry()
        {
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hkcu.CreateSubKey(RegistryPrefix + Indicators.HkcuClsidPath + @"\InprocServer32"))
                key.SetValue("", Path.Combine(DllFolder, Indicators.ChromeDllName));
        }

        public bool RegistryExists(string sub)
        {
            using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
            using (var key = hkcu.OpenSubKey(RegistryPrefix + sub))
                return key != null;
        }

        public void AddChromeDll()
        {
            WriteFile(Path.Combine(DllFolder, Indicators.ChromeDllName), Encoding.ASCII.GetBytes("MZ fake dll"));
            WriteFile(Path.Combine(DllFolder, "service_util.dll"), Encoding.ASCII.GetBytes("MZ fake"));
        }

        /// <summary>Legit Chrome content that must survive: LoadFeatures file and a non-hex sibling folder.</summary>
        public void AddLegitChromeFiles()
        {
            WriteFile(Path.Combine(PlatformHelper, "LoadFeatures"), new byte[0]);
            WriteFile(Path.Combine(PlatformHelper, "Settings", "state.json"), Encoding.ASCII.GetBytes("{}"));
            // Same name pattern but no DLL inside: must not be deleted.
            WriteFile(Path.Combine(PlatformHelper, new string('a', 64), "other.txt"), Encoding.ASCII.GetBytes("x"));
        }

        public void Dispose()
        {
            try
            {
                using (var hkcu = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                {
                    hkcu.DeleteSubKeyTree(@"Software\NikkeCheckTest\" + _id, false);
                    using (var parent = hkcu.OpenSubKey(@"Software\NikkeCheckTest"))
                    {
                        if (parent != null && parent.SubKeyCount == 0 && parent.ValueCount == 0)
                        {
                            parent.Close();
                            hkcu.DeleteSubKey(@"Software\NikkeCheckTest", false);
                        }
                    }
                }
            }
            catch (Exception) { }
            try { if (Directory.Exists(Root)) FileUtil.DeleteDirectoryTree(Root); } catch (Exception) { }
        }
    }
}
