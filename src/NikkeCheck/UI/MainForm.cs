using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using NikkeCheck.Core;

namespace NikkeCheck.UI
{
    public sealed class MainForm : Form
    {
        private readonly ScanContext _ctx = ScanContext.FromEnvironment();
        private readonly List<Label> _wrapLabels = new List<Label>();
        private bool _resume;
        private bool _busy;
        private bool _remediating;
        private ScanResult _result;
        private RemediationResult _lastRemediation;

        private TableLayoutPanel _verdictPanel;
        private Label _verdictTitle;
        private Label _verdictSummary;
        private ListView _list;
        private TextBox _details;
        private SplitContainer _split;
        private Button _btnScan, _btnAddFolder, _btnBackup, _btnFix, _btnReport, _btnUnblock, _btnDefender;
        private ToolStripStatusLabel _status;
        private ToolStripProgressBar _progress;

        public MainForm(bool resume)
        {
            _resume = resume;
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Malgun Gothic", 9F);
            Text = "NIKKE PC 런처 보안 점검·복구 도구 v" + ReportWriter.Version +
                   (_ctx.SandboxRoot != null ? "  [샌드박스: " + _ctx.SandboxRoot + "]" : "");
            ClientSize = new Size(1060, 760);
            MinimumSize = new Size(820, 600);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = SystemIcons.Shield;
            BuildUi();
            ResumeLayout(true);

            Shown += (s, e) =>
            {
                UpdateWrap();
                _split.SplitterDistance = Math.Max(120, (int)(_split.Height * 0.56));
                StartScan();
            };
            Resize += (s, e) => UpdateWrap();
            FormClosing += (s, e) =>
            {
                if (_remediating)
                {
                    MessageBox.Show(this, "복구 작업이 진행 중입니다. 끝날 때까지 기다려 주세요.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                    e.Cancel = true;
                }
            };
        }

        // ------------------------------------------------------------------ layout

        private float Scale1 => DeviceDpi / 96f;

        private void BuildUi()
        {
            var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 4, Margin = Padding.Empty, Padding = Padding.Empty };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.Controls.Add(BuildHeader(), 0, 0);
            root.Controls.Add(BuildVerdict(), 0, 1);
            root.Controls.Add(BuildToolbar(), 0, 2);
            root.Controls.Add(BuildBody(), 0, 3);

            var strip = new StatusStrip();
            _status = new ToolStripStatusLabel("준비") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            _progress = new ToolStripProgressBar { Style = ProgressBarStyle.Marquee, Visible = false, Width = 160 };
            strip.Items.Add(_status);
            strip.Items.Add(_progress);

            Controls.Add(root);
            Controls.Add(strip);
        }

        private Control BuildHeader()
        {
            var panel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1,
                BackColor = Theme.HeaderBack, Padding = new Padding(16, 12, 16, 10), Margin = Padding.Empty,
            };
            var title = new Label
            {
                Text = "NIKKE PC 런처 보안 점검·복구 도구", AutoSize = true, ForeColor = Theme.HeaderText,
                Font = new Font(Font.FontFamily, 14F, FontStyle.Bold), Margin = new Padding(0, 0, 0, 4),
            };
            var sub = new Label
            {
                Text = "2026년 9월 27일 15:41(한국 시간) 이후 Windows PC 런처를 한 번이라도 실행했다면 점검하세요. " +
                       "검사는 파일을 읽기만 하고 어떤 정보도 인터넷으로 보내지 않습니다. " +
                       "점검이 끝날 때까지 NIKKE 런처를 다시 실행하지 마세요(업데이트된 런처가 증거 로그를 지울 수 있음).",
                AutoSize = true, ForeColor = Theme.HeaderSubText, Margin = new Padding(0, 0, 0, 6),
            };
            _wrapLabels.Add(sub);
            var links = new FlowLayoutPanel { AutoSize = true, Margin = Padding.Empty, WrapContents = true, BackColor = Theme.HeaderBack };
            links.Controls.Add(MakeLink("공식 수동 점검 공지", Indicators.OfficialNoticeUrl));
            links.Controls.Add(MakeLink("니케 공식 홈페이지 (고객센터)", Indicators.OfficialKoreanSiteUrl));
            links.Controls.Add(MakeLink("연구자 기술 분석", Indicators.ResearchUrl));
            panel.Controls.Add(title);
            panel.Controls.Add(sub);
            panel.Controls.Add(links);
            return panel;
        }

        private LinkLabel MakeLink(string text, string url)
        {
            var l = new LinkLabel
            {
                Text = text, AutoSize = true, LinkColor = Theme.Link, ActiveLinkColor = Color.White,
                VisitedLinkColor = Theme.Link, Margin = new Padding(0, 0, 18, 0),
            };
            l.LinkClicked += (s, e) => OpenUrl(url);
            return l;
        }

        private Control BuildVerdict()
        {
            _verdictPanel = new TableLayoutPanel
            {
                Dock = DockStyle.Fill, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, ColumnCount = 1,
                Padding = new Padding(16, 10, 16, 10), Margin = Padding.Empty,
            };
            _verdictTitle = new Label { AutoSize = true, Font = new Font(Font.FontFamily, 12.5F, FontStyle.Bold), Margin = new Padding(0, 0, 0, 3) };
            _verdictSummary = new Label { AutoSize = true, Margin = Padding.Empty };
            _wrapLabels.Add(_verdictTitle);
            _wrapLabels.Add(_verdictSummary);
            _verdictPanel.Controls.Add(_verdictTitle);
            _verdictPanel.Controls.Add(_verdictSummary);
            SetVerdict(null);
            return _verdictPanel;
        }

        private Control BuildToolbar()
        {
            var bar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(12, 8, 12, 2), Margin = Padding.Empty, WrapContents = true,
            };
            _btnScan = MakeButton("다시 검사", (s, e) => StartScan());
            _btnAddFolder = MakeButton("설치 폴더 추가…", (s, e) => AddFolder());
            _btnBackup = MakeButton("증거 백업…", (s, e) => Backup());
            _btnFix = MakeButton("복구 실행…", (s, e) => Fix());
            _btnFix.Font = new Font(Font, FontStyle.Bold);
            _btnReport = MakeButton("보고서 저장…", (s, e) => SaveReport());
            _btnUnblock = MakeButton("차단 해제…", (s, e) => Unblock());
            _btnDefender = MakeButton("Windows 보안 열기", (s, e) => OpenUrl("windowsdefender://threat/"));
            bar.Controls.AddRange(new Control[] { _btnScan, _btnAddFolder, _btnBackup, _btnFix, _btnReport, _btnUnblock, _btnDefender });
            return bar;
        }

        private static Button MakeButton(string text, EventHandler onClick)
        {
            var b = new Button
            {
                Text = text, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Padding = new Padding(10, 4, 10, 4), Margin = new Padding(0, 0, 8, 4), UseVisualStyleBackColor = true,
            };
            b.Click += onClick;
            return b;
        }

        private Control BuildBody()
        {
            _split = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, Margin = new Padding(12, 4, 12, 8), SplitterWidth = 6,
            };
            _list = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false,
            };
            float k = Scale1;
            _list.Columns.Add("판정", (int)(78 * k));
            _list.Columns.Add("분류", (int)(96 * k));
            _list.Columns.Add("내용", (int)(480 * k));
            _list.Columns.Add("경로", (int)(300 * k));
            _list.Resize += (s, e) => FitColumns();
            _list.SelectedIndexChanged += (s, e) => ShowSelected();
            _list.DoubleClick += (s, e) => OpenSelectedLocation();
            var menu = new ContextMenuStrip();
            menu.Items.Add("파일 위치 열기", null, (s, e) => OpenSelectedLocation());
            menu.Items.Add("경로 복사", null, (s, e) => CopySelectedPath());
            _list.ContextMenuStrip = menu;

            _details = new TextBox
            {
                Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical,
                BackColor = Color.White, Font = new Font("Malgun Gothic", 9.5F), WordWrap = true,
            };
            _split.Panel1.Controls.Add(_list);
            _split.Panel2.Controls.Add(_details);
            return _split;
        }

        /// <summary>Sizes the first two columns to their text and lets the path column take the remaining width.</summary>
        private void FitColumns()
        {
            if (_list.Columns.Count < 4 || _list.ClientSize.Width <= 0) return;
            int pad = (int)(18 * Scale1);
            int Measure(int col, int min)
            {
                int w = TextRenderer.MeasureText(_list.Columns[col].Text, _list.Font).Width;
                foreach (ListViewItem it in _list.Items)
                    w = Math.Max(w, TextRenderer.MeasureText(it.SubItems[col].Text, _list.Font).Width);
                return Math.Max(min, w + pad);
            }
            _list.Columns[0].Width = Measure(0, (int)(60 * Scale1));
            _list.Columns[1].Width = Measure(1, (int)(70 * Scale1));
            int used = _list.Columns[0].Width + _list.Columns[1].Width + _list.Columns[2].Width;
            _list.Columns[3].Width = Math.Max((int)(200 * Scale1), _list.ClientSize.Width - used - 4);
        }

        private void UpdateWrap()
        {
            int width = Math.Max(240, ClientSize.Width - (int)(40 * Scale1));
            foreach (var l in _wrapLabels) l.MaximumSize = new Size(width, 0);
        }

        // ------------------------------------------------------------------ scan

        private void StartScan()
        {
            if (_busy) return;
            SetBusy(true, "검사 중…");
            _list.Items.Clear();
            _details.Text = "검사 중입니다. 런처 캐시 파일이 많으면 1~2분 걸릴 수 있습니다.";
            SetVerdict(null);
            RunBackground(() => new Scanner(_ctx).Run(msg => Ui(() => _status.Text = msg)), OnScanDone);
        }

        private void OnScanDone(ScanResult r, Exception err)
        {
            if (err != null)
            {
                SetBusy(false, "검사 실패");
                MessageBox.Show(this, "검사 중 오류가 발생했습니다.\r\n\r\n" + err.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            _result = r;
            SetBusy(false, $"검사 완료 ({(r.FinishedAt - r.StartedAt).TotalSeconds:0.0}초) — 항목을 선택하면 설명이 아래에 표시됩니다.");
            PopulateList();
            SetVerdict(r);
            _details.Text = BuildOverview();

            if (_resume)
            {
                _resume = false;
                HandleResume();
            }
        }

        private void PopulateList()
        {
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (var f in _result.Sorted)
            {
                var item = new ListViewItem(SeverityText.Label(f.Severity))
                {
                    Tag = f, BackColor = Theme.RowBack(f.Severity), ForeColor = Theme.RowText(f.Severity), UseItemStyleForSubItems = true,
                };
                item.SubItems.Add(f.Category);
                item.SubItems.Add(f.Title);
                item.SubItems.Add(f.Path ?? "");
                _list.Items.Add(item);
            }
            FitColumns();
            _list.EndUpdate();
        }

        private void SetVerdict(ScanResult r)
        {
            bool scanned = r != null;
            var sev = r?.Overall ?? Severity.Ok;
            _verdictPanel.BackColor = Theme.VerdictBack(sev, scanned);
            _verdictTitle.ForeColor = _verdictSummary.ForeColor = Theme.VerdictText(sev, scanned);
            _verdictTitle.Text = scanned ? r.VerdictTitle : "검사 중…";
            _verdictSummary.Text = scanned
                ? r.VerdictSummary
                : "설치 폴더의 런처 로그, 레지스트리, Chrome 폴더, 런처 캐시, 임시 폴더를 확인하고 있습니다.";
        }

        private string BuildOverview()
        {
            var r = _result;
            var sb = new StringBuilder();
            sb.AppendLine($"[{SeverityText.Label(r.Overall)}] {r.VerdictTitle}");
            sb.AppendLine(r.VerdictSummary);
            sb.AppendLine();
            sb.AppendLine("설치 폴더: " + (r.InstallRoots.Count == 0 ? "(찾지 못함)" : string.Join(", ", r.InstallRoots)));
            sb.AppendLine("런처 데이터: " + (r.LauncherDataDirs.Count == 0 ? "(없음)" : string.Join(", ", r.LauncherDataDirs)));
            if (r.Errors.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("검사하지 못한 부분:");
                foreach (var e in r.Errors) sb.AppendLine("  - " + e);
            }
            if (_lastRemediation != null)
            {
                sb.AppendLine();
                sb.AppendLine("[최근 복구 기록]");
                foreach (var l in _lastRemediation.Log) sb.AppendLine("  " + l);
            }
            sb.AppendLine();
            sb.AppendLine(Guidance.For(r));
            sb.AppendLine();
            sb.AppendLine(Guidance.Common);
            sb.AppendLine();
            sb.AppendLine("※ 목록에서 항목을 선택하면 자세한 설명이 여기에 표시됩니다. 두 번 클릭하면 파일 위치를 엽니다.");
            return CrLf(sb.ToString());
        }

        private Finding Selected() =>
            _list.SelectedItems.Count == 0 ? null : _list.SelectedItems[0].Tag as Finding;

        private void ShowSelected()
        {
            var f = Selected();
            if (f == null)
            {
                if (_result != null) _details.Text = BuildOverview();
                return;
            }
            var sb = new StringBuilder();
            sb.AppendLine($"[{SeverityText.Label(f.Severity)}] {f.Title}");
            sb.AppendLine("분류: " + f.Category);
            if (!string.IsNullOrEmpty(f.Path)) sb.AppendLine("경로: " + f.Path);
            sb.AppendLine();
            sb.AppendLine(f.Detail);
            sb.AppendLine();
            sb.AppendLine("복구 시 조치: " + (f.Action != null ? f.Action.Description : "자동 조치 없음"));
            _details.Text = CrLf(sb.ToString());
        }

        /// <summary>TextBox needs CRLF; verbatim strings in source may carry bare LF.</summary>
        private static string CrLf(string s) => s.Replace("\r\n", "\n").Replace("\n", "\r\n");

        // ------------------------------------------------------------------ actions

        private void AddFolder()
        {
            using (var dlg = new FolderBrowserDialog
            {
                Description = "NIKKE 설치 폴더를 선택하세요 (예: C:\\NIKKE).\r\n바탕화면 NIKKE 아이콘 → 오른쪽 클릭 → [파일 위치 열기]로 확인할 수 있습니다.",
                ShowNewFolderButton = false,
            })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                string root = InstallLocator.Normalize(dlg.SelectedPath);
                if (root == null)
                {
                    MessageBox.Show(this,
                        "선택한 폴더에서 NIKKE 런처(Launcher 폴더)를 찾지 못했습니다.\r\n바탕화면 NIKKE 아이콘을 오른쪽 클릭 → [파일 위치 열기]로 설치 폴더를 확인하세요.",
                        Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (!_ctx.ExtraInstallRoots.Contains(root, StringComparer.OrdinalIgnoreCase))
                    _ctx.ExtraInstallRoots.Add(root);
                StartScan();
            }
        }

        private void Backup()
        {
            if (_result == null || _busy) return;
            using (var dlg = new FolderBrowserDialog
            {
                Description = "증거 백업(zip)을 저장할 폴더를 선택하세요.\r\nOneDrive 같은 클라우드 동기화 폴더는 피하세요(로그인 정보가 들어 있을 수 있음).",
                SelectedPath = Directory.Exists(BackupWriter.DefaultDirectoryFor(_ctx))
                    ? BackupWriter.DefaultDirectoryFor(_ctx)
                    : Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                string dir = dlg.SelectedPath;
                var scan = _result;
                SetBusy(true, "증거 백업 중…");
                RunBackground(() => BackupWriter.Create(_ctx, scan, dir, msg => Ui(() => _status.Text = msg)), (path, err) =>
                {
                    SetBusy(false, err == null ? "백업 완료: " + path : "백업 실패");
                    if (err != null)
                    {
                        MessageBox.Show(this, "백업을 만들지 못했습니다.\r\n\r\n" + err.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                    if (MessageBox.Show(this,
                            "증거 백업을 만들었습니다.\r\n" + path +
                            "\r\n\r\n백신이 이 파일을 악성으로 격리할 수 있습니다(변조된 스크립트가 들어 있기 때문). 공개된 곳에 올리지 마세요.\r\n\r\n폴더를 열까요?",
                            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                        RevealInExplorer(path);
                });
            }
        }

        private void SaveReport()
        {
            if (_result == null) return;
            using (var dlg = new SaveFileDialog
            {
                Filter = "텍스트 파일 (*.txt)|*.txt",
                FileName = $"NIKKE_점검보고서_{DateTime.Now:yyyyMMdd_HHmmss}.txt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            })
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    File.WriteAllText(dlg.FileName, ReportWriter.Build(_result, _lastRemediation), new UTF8Encoding(true));
                    _status.Text = "보고서 저장: " + dlg.FileName;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "보고서를 저장하지 못했습니다.\r\n\r\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void Fix()
        {
            if (_result == null || _busy) return;
            using (var dlg = new RemediationDialog(_result, _ctx))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK) return;
                var opt = dlg.BuildOptions();
                bool block = dlg.ApplyBlocks;
                if (opt.Actions.Count == 0 && !block) return;
                if (opt.Actions.Count > 0 && !EnsureProcessesClosed(opt)) return;
                opt.ResumeCommand = "\"" + Application.ExecutablePath + "\" --resume";
                RunRemediation(opt, block);
            }
        }

        private void RunRemediation(RemediationOptions opt, bool block)
        {
            SetBusy(true, "복구 중…");
            _remediating = true;
            var scan = _result;
            string exe = Application.ExecutablePath;
            RunBackground(() =>
            {
                var res = Remediator.Run(_ctx, scan, opt, msg => Ui(() => _status.Text = msg));
                if (block && _ctx.SandboxRoot != null)
                {
                    // Sandbox: write the fake hosts file directly, never the real one.
                    var w = new StringWriter();
                    HostsBlocker.ApplyHosts(_ctx.HostsPath, w);
                    foreach (var line in w.ToString().Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                        res.Log.Add("차단(샌드박스): " + line);
                }
                else if (block)
                {
                    Ui(() => _status.Text = "공격자 도메인·IP 차단 중 (관리자 권한 확인)…");
                    HostsBlocker.RequestElevated(exe, false, out string blockLog);
                    foreach (var line in (blockLog ?? "").Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
                        res.Log.Add("차단: " + line);
                }
                return res;
            }, (res, err) =>
            {
                _remediating = false;
                if (err != null)
                {
                    SetBusy(false, "복구 중단");
                    if (opt.CreateBackup)
                    {
                        var ans = MessageBox.Show(this,
                            "증거 백업을 만들지 못해 복구를 시작하지 않았습니다.\r\n\r\n" + err.Message +
                            "\r\n\r\n백업 없이 복구를 계속할까요? (권장하지 않음 — 감염 여부를 확인할 증거가 사라집니다)",
                            Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                        if (ans == DialogResult.Yes)
                        {
                            opt.CreateBackup = false;
                            RunRemediation(opt, block);
                        }
                    }
                    else
                    {
                        MessageBox.Show(this, "복구 중 오류가 발생했습니다.\r\n\r\n" + err.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    return;
                }
                _lastRemediation = res;
                SetBusy(false, "복구 완료");
                ShowRemediationSummary(res);
                StartScan();
            });
        }

        private void ShowRemediationSummary(RemediationResult res)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"완료 {res.Succeeded.Count}개 · 실패 {res.Failed.Count}개 · 재부팅 후 처리 {res.PendingReboot.Count}개");
            if (!string.IsNullOrEmpty(res.BackupPath)) sb.AppendLine("증거 백업: " + res.BackupPath);
            foreach (var l in res.Log.Where(x => x.StartsWith("실패") || x.StartsWith("건너뜀") || x.StartsWith("차단")))
                sb.AppendLine("  " + l);
            sb.AppendLine();

            if (res.RebootRequired)
            {
                sb.AppendLine("Chrome 위장 DLL이 사용 중이라 바로 지우지 못했습니다. Windows를 재부팅한 뒤 " +
                              (res.ResumeScheduled
                                  ? "이 프로그램이 자동으로 다시 실행되어 남은 항목을 지웁니다."
                                  : "이 프로그램을 다시 실행해 [복구 실행]을 눌러 주세요."));
                sb.AppendLine();
                sb.AppendLine("지금 재부팅할까요? (열려 있는 작업을 먼저 저장하세요)");
                if (MessageBox.Show(this, sb.ToString(), "복구 결과", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes)
                    Reboot();
            }
            else if (res.RebootRecommended)
            {
                sb.AppendLine("공식 안내에 따라 레지스트리 항목을 지운 뒤에는 Windows를 재부팅하는 것을 권장합니다.");
                sb.AppendLine("재부팅 후 이 프로그램으로 한 번 더 검사해 주세요. 지금 재부팅할까요?");
                if (MessageBox.Show(this, sb.ToString(), "복구 결과", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
                    Reboot();
            }
            else
            {
                sb.AppendLine("다시 검사해 결과를 확인합니다.");
                MessageBox.Show(this, sb.ToString(), "복구 결과", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void Unblock()
        {
            if (_busy || _result == null || !_result.NikkeCheckBlockPresent) return;
            var ans = MessageBox.Show(this,
                "이 프로그램이 추가한 공격자 도메인·IP 차단을 해제합니다.\r\n\r\n" +
                "• hosts 파일: 이 프로그램이 추가한 줄만 지웁니다 (지우기 전에 원본을 백업합니다)\r\n" +
                "• Windows 방화벽: '" + HostsBlocker.FirewallRuleName + "' 규칙을 삭제합니다\r\n\r\n" +
                "연구자는 CDN 침해 경로가 밝혀지지 않아 차단을 유지할 것을 권장합니다.\r\n" +
                "그래도 해제할까요? (관리자 권한 확인 창이 뜹니다)",
                "차단 해제", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (ans != DialogResult.Yes) return;

            SetBusy(true, "차단 해제 중 (관리자 권한 확인)…");
            string exe = Application.ExecutablePath;
            RunBackground(() =>
            {
                if (_ctx.SandboxRoot != null)
                {
                    // Sandbox: edit the fake hosts file directly, never the real one or the firewall.
                    var w = new StringWriter();
                    HostsBlocker.RemoveHosts(_ctx.HostsPath, w);
                    return w.ToString();
                }
                HostsBlocker.RequestElevated(exe, true, out string log);
                return log;
            }, (log, err) =>
            {
                SetBusy(false, err == null ? "차단 해제 완료" : "차단 해제 실패");
                MessageBox.Show(this,
                    err != null ? "차단을 해제하지 못했습니다.\r\n\r\n" + err.Message : CrLf(log ?? ""),
                    "차단 해제 결과", MessageBoxButtons.OK, err != null ? MessageBoxIcon.Error : MessageBoxIcon.Information);
                StartScan();
            });
        }

        private void HandleResume()
        {
            var pending = _result.Actions
                .Where(a => a.Type == ActionType.DeleteChromeDllFolder || a.Type == ActionType.DeleteRegistryKey)
                .ToList();
            if (pending.Count == 0)
            {
                string msg = _result.Overall == Severity.Critical
                    ? "재부팅 후 다시 검사했습니다. 아직 남은 감염 흔적이 있으니 목록을 확인하세요."
                    : "재부팅 후 다시 검사했습니다. 레지스트리 항목과 Chrome 위장 DLL이 모두 제거되었습니다.\r\n\r\n" +
                      "아래 안내에 따라 깨끗한 다른 기기에서 비밀번호 변경 등 계정 보안 조치를 꼭 진행하세요.";
                MessageBox.Show(this, msg, Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var ans = MessageBox.Show(this,
                "재부팅 전에 지우지 못한 항목이 남아 있습니다.\r\n\r\n" +
                string.Join("\r\n", pending.Select(p => "• " + p.Description)) + "\r\n\r\n지금 삭제할까요?",
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (ans != DialogResult.Yes) return;

            var opt = new RemediationOptions { CreateBackup = false, ScheduleResumeAfterReboot = false };
            opt.Actions.AddRange(pending);
            if (!EnsureProcessesClosed(opt)) return;
            RunRemediation(opt, false);
        }

        private bool EnsureProcessesClosed(RemediationOptions opt)
        {
            if (_ctx.SandboxRoot != null) return true; // fake files: never touch the user's real Chrome/launcher
            var names = new List<string>(Indicators.LauncherProcessNames);
            if (opt.Actions.Any(a => a.Type == ActionType.DeleteChromeDllFolder || a.Type == ActionType.DeleteRegistryKey))
                names.Add("chrome");

            bool killFailed = false;
            while (true)
            {
                var procs = ProcessTools.FindRunning(names);
                if (procs.Count == 0) return true;
                string list = string.Join(", ", procs.Select(p => p.ProcessName + ".exe").Distinct(StringComparer.OrdinalIgnoreCase));
                string msg = "다음 프로그램이 실행 중입니다:\r\n" + list +
                             "\r\n\r\n복구하려면 모두 종료해야 합니다.\r\n\r\n" +
                             "[예] 지금 강제로 종료\r\n[아니요] 직접 종료한 뒤 다시 확인\r\n[취소] 복구 중단\r\n\r\n" +
                             "Chrome은 다시 열면 탭을 복원할 수 있지만, 작성 중인 내용이 있다면 먼저 저장하세요.";
                if (killFailed)
                    msg += "\r\n\r\n※ 일부 프로그램은 권한 문제로 종료하지 못했습니다(NIKKE 런처는 관리자 권한으로 실행됨). " +
                           "트레이 아이콘 → 종료, 또는 작업 관리자에서 종료하세요.";

                var ans = MessageBox.Show(this, msg, "실행 중인 프로그램", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);
                if (ans == DialogResult.Cancel)
                {
                    foreach (var p in procs) p.Dispose();
                    return false;
                }
                killFailed = false;
                if (ans == DialogResult.Yes)
                {
                    foreach (var p in procs)
                    {
                        try
                        {
                            p.Kill();
                            p.WaitForExit(5000);
                        }
                        catch (Exception) { killFailed = true; }
                    }
                    Thread.Sleep(800);
                }
                foreach (var p in procs) p.Dispose();
            }
        }

        // ------------------------------------------------------------------ helpers

        private void OpenSelectedLocation()
        {
            var f = Selected();
            if (string.IsNullOrEmpty(f?.Path)) return;
            if (f.Path.StartsWith("HKEY_", StringComparison.OrdinalIgnoreCase))
            {
                CopySelectedPath();
                MessageBox.Show(this, "레지스트리 경로를 복사했습니다. 레지스트리 편집기(regedit) 주소창에 붙여 넣으면 확인할 수 있습니다.\r\n" + f.Path,
                    Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            RevealInExplorer(f.Path);
        }

        private void CopySelectedPath()
        {
            var f = Selected();
            if (string.IsNullOrEmpty(f?.Path)) return;
            try { Clipboard.SetText(f.Path); } catch (Exception) { }
        }

        private static void RevealInExplorer(string path)
        {
            try
            {
                if (File.Exists(path)) Process.Start("explorer.exe", "/select,\"" + path + "\"");
                else if (Directory.Exists(path)) Process.Start("explorer.exe", "\"" + path + "\"");
                else
                {
                    string dir = Path.GetDirectoryName(path);
                    if (dir != null && Directory.Exists(dir)) Process.Start("explorer.exe", "\"" + dir + "\"");
                }
            }
            catch (Exception) { }
        }

        private static void OpenUrl(string url)
        {
            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
            catch (Exception) { }
        }

        private void Reboot()
        {
            if (_ctx.SandboxRoot != null)
            {
                MessageBox.Show(this, "샌드박스 모드에서는 실제로 재부팅하지 않습니다.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo("shutdown.exe", "/r /t 15 /c \"NIKKE 점검 도구: 복구를 마치기 위해 15초 후 재부팅합니다.\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                });
            }
            catch (Exception) { }
        }

        private void SetBusy(bool busy, string status)
        {
            _busy = busy;
            foreach (var b in new[] { _btnScan, _btnAddFolder, _btnBackup, _btnFix, _btnReport })
                b.Enabled = !busy && (b == _btnScan || b == _btnAddFolder || _result != null);
            _btnUnblock.Enabled = !busy && _result != null && _result.NikkeCheckBlockPresent;
            _progress.Visible = busy;
            _status.Text = status;
            UseWaitCursor = busy;
        }

        private void RunBackground<T>(Func<T> work, Action<T, Exception> done)
        {
            var t = new Thread(() =>
            {
                T result = default(T);
                Exception error = null;
                try { result = work(); }
                catch (Exception ex) { error = ex; }
                Ui(() => done(result, error));
            })
            { IsBackground = true };
            t.SetApartmentState(ApartmentState.STA); // WScript.Shell (shortcut lookup) and UAC launch
            t.Start();
        }

        private void Ui(Action a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            try { BeginInvoke(a); }
            catch (InvalidOperationException) { }
        }
    }
}
