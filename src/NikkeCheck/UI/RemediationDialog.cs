using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;
using NikkeCheck.Core;

namespace NikkeCheck.UI
{
    public sealed class RemediationDialog : Form
    {
        private readonly CheckedListBox _actions;
        private readonly CheckBox _chkBackup;
        private readonly CheckBox _chkBlock;
        private readonly CheckBox _chkResume;
        private readonly TextBox _backupDir;

        public bool ApplyBlocks => _chkBlock.Enabled && _chkBlock.Checked;

        public RemediationDialog(ScanResult result, ScanContext ctx)
        {
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Malgun Gothic", 9F);
            Text = "복구 실행";
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(780, 580);
            MinimumSize = new Size(640, 480);
            MinimizeBox = false;
            MaximizeBox = false;
            ShowInTaskbar = false;
            Icon = SystemIcons.Shield;

            List<RemediationAction> items = result.Actions;
            bool alreadyBlocked = result.Findings.Any(f => f.Category == "차단 설정" && f.Severity == Severity.Ok);

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, Padding = new Padding(14) };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var intro = new Label
            {
                AutoSize = true,
                MaximumSize = new Size(740, 0),
                Margin = new Padding(0, 0, 0, 8),
                Text = "아래 항목을 공식 안내 순서(① 레지스트리 → ④ 다운로드 파일 → ⑤ 런처 캐시 → ③ Chrome DLL 폴더)로 처리합니다.\r\n" +
                       "체크한 항목만 처리하며, 목록에 없는 파일·레지스트리는 건드리지 않습니다. 각 항목은 삭제 직전에 조건을 다시 확인합니다." +
                       (items.Count == 0 ? "\r\n\r\n※ 삭제할 악성 항목이 발견되지 않았습니다." : ""),
            };

            _actions = new CheckedListBox
            {
                Dock = DockStyle.Fill, CheckOnClick = true, HorizontalScrollbar = true, IntegralHeight = false,
                Margin = new Padding(0, 0, 0, 8),
            };
            foreach (var a in items) _actions.Items.Add(a, a.DefaultSelected);

            _chkBackup = new CheckBox
            {
                AutoSize = true, Checked = true, Margin = new Padding(0, 2, 0, 2),
                Text = "복구 전에 증거 백업 만들기 (강력 권장 — 삭제하면 감염 여부를 확인할 증거가 사라집니다)",
            };

            var backupRow = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, ColumnCount = 3, Margin = new Padding(18, 0, 0, 6) };
            backupRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            backupRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            backupRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            backupRow.Controls.Add(new Label { Text = "저장 위치:", AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(0, 6, 6, 0) }, 0, 0);
            _backupDir = new TextBox { Text = BackupWriter.DefaultDirectoryFor(ctx), Dock = DockStyle.Fill };
            backupRow.Controls.Add(_backupDir, 1, 0);
            var browse = new Button { Text = "찾아보기…", AutoSize = true, Margin = new Padding(6, 0, 0, 0) };
            browse.Click += (s, e) =>
            {
                using (var dlg = new FolderBrowserDialog { Description = "증거 백업을 저장할 폴더 (클라우드 동기화 폴더는 피하세요)" })
                    if (dlg.ShowDialog(this) == DialogResult.OK) _backupDir.Text = dlg.SelectedPath;
            };
            backupRow.Controls.Add(browse, 2, 0);
            _chkBackup.CheckedChanged += (s, e) => backupRow.Enabled = _chkBackup.Checked;

            _chkBlock = new CheckBox
            {
                AutoSize = true, Margin = new Padding(0, 2, 0, 2),
                Checked = !alreadyBlocked, Enabled = !alreadyBlocked,
                Text = alreadyBlocked
                    ? "공격자 도메인·IP 차단 (이미 적용되어 있음)"
                    : "공격자 도메인·IP 차단 (hosts 파일 + Windows 방화벽 — 관리자 권한 확인 창이 뜹니다)",
            };

            _chkResume = new CheckBox
            {
                AutoSize = true, Checked = true, Margin = new Padding(0, 2, 0, 8),
                Text = "사용 중이라 지우지 못한 항목이 있으면 재부팅 후 이 프로그램을 자동으로 한 번 다시 실행",
            };

            var warning = new Label
            {
                AutoSize = true, MaximumSize = new Size(740, 0), ForeColor = Color.FromArgb(160, 0, 0), Margin = new Padding(0, 0, 0, 10),
                Text = "⚠ 이 복구는 알려진 흔적만 제거합니다. 감염이 확인되었다면 가장 안전한 방법은 Windows 재설치이며, " +
                       "비밀번호 변경은 반드시 다른 깨끗한 기기에서 하세요.",
            };

            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = Padding.Empty };
            var cancel = new Button { Text = "취소", AutoSize = true, Padding = new Padding(10, 4, 10, 4), DialogResult = DialogResult.Cancel };
            var ok = new Button { Text = "복구 시작", AutoSize = true, Padding = new Padding(14, 4, 14, 4), Font = new Font(Font, FontStyle.Bold) };
            ok.Click += (s, e) => OnOk();
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            AcceptButton = ok;
            CancelButton = cancel;

            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            for (int i = 0; i < 6; i++) layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.Controls.Add(intro, 0, 0);
            layout.Controls.Add(_actions, 0, 1);
            layout.Controls.Add(_chkBackup, 0, 2);
            layout.Controls.Add(backupRow, 0, 3);
            layout.Controls.Add(_chkBlock, 0, 4);
            layout.Controls.Add(_chkResume, 0, 5);
            layout.Controls.Add(warning, 0, 6);
            layout.Controls.Add(buttons, 0, 7);
            Controls.Add(layout);
            ResumeLayout(true);
        }

        private void OnOk()
        {
            if (_actions.CheckedItems.Count == 0 && !ApplyBlocks)
            {
                MessageBox.Show(this, "선택한 항목이 없습니다.", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (_chkBackup.Checked && string.IsNullOrWhiteSpace(_backupDir.Text))
            {
                MessageBox.Show(this, "백업 저장 위치를 지정하세요.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            DialogResult = DialogResult.OK;
            Close();
        }

        public RemediationOptions BuildOptions()
        {
            var opt = new RemediationOptions
            {
                CreateBackup = _chkBackup.Checked && _actions.CheckedItems.Count > 0,
                BackupDirectory = _backupDir.Text.Trim(),
                ScheduleResumeAfterReboot = _chkResume.Checked,
            };
            foreach (var o in _actions.CheckedItems) opt.Actions.Add((RemediationAction)o);
            return opt;
        }
    }
}
