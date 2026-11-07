using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace NikkeCheck.Core
{
    public sealed class RemediationOptions
    {
        public bool CreateBackup { get; set; } = true;
        public string BackupDirectory { get; set; } = BackupWriter.DefaultDirectoryFor(null);
        public List<RemediationAction> Actions { get; } = new List<RemediationAction>();
        /// <summary>When a DLL folder is still locked, register a one-time RunOnce entry to resume after reboot.</summary>
        public bool ScheduleResumeAfterReboot { get; set; } = true;
        /// <summary>Command line for RunOnce, e.g. "C:\path\NikkeCheck.exe" --resume</summary>
        public string ResumeCommand { get; set; }
    }

    public sealed class RemediationResult
    {
        public string BackupPath { get; set; }
        public List<string> Log { get; } = new List<string>();
        public List<RemediationAction> Succeeded { get; } = new List<RemediationAction>();
        public List<RemediationAction> Failed { get; } = new List<RemediationAction>();
        public List<RemediationAction> PendingReboot { get; } = new List<RemediationAction>();
        public bool ResumeScheduled { get; set; }

        public bool RebootRequired => PendingReboot.Count > 0;
        /// <summary>The official guide restarts Windows after removing the registry entry.</summary>
        public bool RebootRecommended => RebootRequired || Succeeded.Any(a => a.Type == ActionType.DeleteRegistryKey);
    }

    /// <summary>
    /// Applies the selected actions in the official order (registry → files → cache → DLL folder).
    /// Every target is re-validated with <see cref="SafetyRules"/> right before it is deleted.
    /// </summary>
    public static class Remediator
    {
        public static RemediationResult Run(ScanContext ctx, ScanResult scan, RemediationOptions opt, Action<string> progress = null)
        {
            var res = new RemediationResult();

            if (opt.CreateBackup)
            {
                progress?.Invoke("증거 백업 만드는 중…");
                res.BackupPath = BackupWriter.Create(ctx, scan, opt.BackupDirectory, progress);
                res.Log.Add("증거 백업: " + res.BackupPath);
            }

            foreach (var a in opt.Actions.OrderBy(x => x.Order))
            {
                progress?.Invoke(a.Description);
                try
                {
                    switch (a.Type)
                    {
                        case ActionType.DeleteRegistryKey: DeleteRegistry(ctx, a); break;
                        case ActionType.DeleteFile: DeleteFile(ctx, a); break;
                        case ActionType.DeleteLauncherCache: DeleteCache(a); break;
                        case ActionType.DeleteChromeDllFolder: DeleteDllFolder(a); break;
                    }
                    res.Succeeded.Add(a);
                    res.Log.Add("완료: " + a.Description);
                }
                catch (SafetyException ex)
                {
                    res.Failed.Add(a);
                    res.Log.Add("건너뜀(안전 조건 불일치): " + a.Description + " — " + ex.Message);
                }
                catch (Exception ex) when (a.Type == ActionType.DeleteChromeDllFolder && (ex is IOException || ex is UnauthorizedAccessException))
                {
                    res.PendingReboot.Add(a);
                    res.Log.Add("재부팅 후 삭제 필요(DLL 사용 중): " + a.Target);
                }
                catch (Exception ex)
                {
                    res.Failed.Add(a);
                    res.Log.Add("실패: " + a.Description + " — " + ex.Message);
                }
            }

            if (res.PendingReboot.Count > 0 && opt.ScheduleResumeAfterReboot && !string.IsNullOrEmpty(opt.ResumeCommand))
            {
                try
                {
                    using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, RegistryView.Registry64))
                    using (var key = baseKey.CreateSubKey(ctx.Hkcu(Indicators.RunOnceKey)))
                        key.SetValue(Indicators.RunOnceValueName, opt.ResumeCommand, RegistryValueKind.String);
                    res.ResumeScheduled = true;
                    res.Log.Add("재부팅 후 1회 자동 실행 등록 (RunOnce): " + opt.ResumeCommand);
                }
                catch (Exception ex)
                {
                    res.Log.Add("재부팅 후 자동 실행 등록 실패: " + ex.Message);
                }
            }

            if (!string.IsNullOrEmpty(res.BackupPath))
            {
                try
                {
                    string logPath = Path.ChangeExtension(res.BackupPath, null) + "_복구기록.txt";
                    File.WriteAllLines(logPath, res.Log, new System.Text.UTF8Encoding(true));
                }
                catch (Exception) { }
            }
            return res;
        }

        private static void DeleteRegistry(ScanContext ctx, RemediationAction a)
        {
            if (!SafetyRules.IsAllowedRegistryKey(a.Target))
                throw new SafetyException("허용된 HKCU CLSID 경로가 아닙니다.");
            using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, a.View))
            {
                string full = ctx.Hkcu(a.Target);
                baseKey.DeleteSubKeyTree(full, false);
                using (var check = baseKey.OpenSubKey(full))
                    if (check != null) throw new IOException("삭제 후에도 레지스트리 항목이 남아 있습니다.");
            }
        }

        private static void DeleteFile(ScanContext ctx, RemediationAction a)
        {
            if (!File.Exists(a.Target)) return; // already gone
            bool ok = SafetyRules.IsPayloadFile(a.Target, out _) || SafetyRules.IsAgentTempFile(a.Target, ctx.TempDir);
            if (!ok) throw new SafetyException("악성 파일 조건(크기·내용·위치)과 일치하지 않습니다.");
            FileUtil.DeleteFileForce(a.Target);
        }

        private static void DeleteCache(RemediationAction a)
        {
            if (!Directory.Exists(a.Target)) return;
            if (!SafetyRules.IsLauncherCache(a.Target))
                throw new SafetyException("%APPDATA%\\nikke_launcher*\\tbs_cache 폴더가 아닙니다.");
            FileUtil.DeleteDirectoryTree(a.Target);
        }

        private static void DeleteDllFolder(RemediationAction a)
        {
            if (!Directory.Exists(a.Target)) return;
            if (!SafetyRules.IsMaliciousChromeDllFolder(a.Target))
                throw new SafetyException("64자리 16진수 폴더 + platform_experience_helper.dll 조건과 일치하지 않습니다.");
            // Delete the DLL first: if it is loaded somewhere this throws before anything else is touched,
            // and the folder stays intact for the post-reboot pass.
            FileUtil.DeleteFileForce(Path.Combine(a.Target, Indicators.ChromeDllName));
            FileUtil.DeleteDirectoryTree(a.Target);
        }
    }
}
