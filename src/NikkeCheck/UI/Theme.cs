using System.Drawing;
using NikkeCheck.Core;

namespace NikkeCheck.UI
{
    internal static class Theme
    {
        public static readonly Color HeaderBack = Color.FromArgb(28, 34, 48);
        public static readonly Color HeaderText = Color.White;
        public static readonly Color HeaderSubText = Color.FromArgb(200, 208, 222);
        public static readonly Color Link = Color.FromArgb(132, 190, 255);

        public static Color VerdictBack(Severity s, bool scanned)
        {
            if (!scanned) return Color.FromArgb(236, 239, 244);
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(198, 40, 40);
                case Severity.High: return Color.FromArgb(230, 108, 0);
                case Severity.Warning: return Color.FromArgb(249, 214, 92);
                default: return Color.FromArgb(46, 125, 50);
            }
        }

        public static Color VerdictText(Severity s, bool scanned) =>
            !scanned || s == Severity.Warning ? Color.FromArgb(33, 33, 33) : Color.White;

        public static Color RowBack(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(255, 220, 220);
                case Severity.High: return Color.FromArgb(255, 232, 206);
                case Severity.Warning: return Color.FromArgb(255, 247, 208);
                case Severity.Ok: return Color.FromArgb(230, 245, 230);
                default: return Color.White;
            }
        }

        public static Color RowText(Severity s)
        {
            switch (s)
            {
                case Severity.Critical: return Color.FromArgb(150, 0, 0);
                case Severity.High: return Color.FromArgb(140, 60, 0);
                default: return Color.FromArgb(33, 33, 33);
            }
        }
    }
}
