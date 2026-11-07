using System;
using System.IO;
using System.Text;
using System.Windows.Forms;
using NikkeCheck.Core;
using NikkeCheck.UI;

namespace NikkeCheck
{
    internal static class Program
    {
        /// <summary>
        /// NikkeCheck.exe                         GUI
        /// NikkeCheck.exe --resume                GUI, finishes deletions left for after reboot
        /// NikkeCheck.exe --report out.txt        read-only scan, writes report, exit code 0/1/2/3 (clean/warn/high/critical)
        ///                [--add-root C:\Games\NIKKE]
        /// NikkeCheck.exe --apply-blocks --log f  internal: elevated hosts/firewall helper
        /// NikkeCheck.exe --remove-blocks --log f internal: elevated helper that undoes the above
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            if (HasArg(args, "--apply-blocks"))
                return HostsBlocker.RunElevatedEntry(GetArg(args, "--log"), remove: false);
            if (HasArg(args, "--remove-blocks"))
                return HostsBlocker.RunElevatedEntry(GetArg(args, "--log"), remove: true);

            if (HasArg(args, "--report"))
                return RunHeadless(args);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += (s, e) =>
                MessageBox.Show("예상하지 못한 오류가 발생했습니다.\r\n\r\n" + e.Exception.Message, "NikkeCheck",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Run(new MainForm(HasArg(args, "--resume")));
            return 0;
        }

        private static int RunHeadless(string[] args)
        {
            string output = GetArg(args, "--report");
            try
            {
                var ctx = ScanContext.FromEnvironment();
                for (int i = 0; i < args.Length - 1; i++)
                    if (string.Equals(args[i], "--add-root", StringComparison.OrdinalIgnoreCase))
                        ctx.ExtraInstallRoots.Add(args[i + 1]);

                var result = new Scanner(ctx).Run();
                string report = ReportWriter.Build(result);
                if (string.IsNullOrEmpty(output)) output = "NikkeCheck_report.txt";
                File.WriteAllText(output, report, new UTF8Encoding(true));

                switch (result.Overall)
                {
                    case Severity.Critical: return 3;
                    case Severity.High: return 2;
                    case Severity.Warning: return 1;
                    default: return 0;
                }
            }
            catch (Exception ex)
            {
                try { File.WriteAllText((output ?? "NikkeCheck_report.txt") + ".error.txt", ex.ToString()); } catch (Exception) { }
                return 10;
            }
        }

        private static bool HasArg(string[] args, string name)
        {
            foreach (var a in args)
                if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string GetArg(string[] args, string name)
        {
            for (int i = 0; i < args.Length - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
            return null;
        }
    }
}
