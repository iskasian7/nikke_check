using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NikkeCheck.Core
{
    public static class FileUtil
    {
        /// <summary>Opens for reading without blocking the launcher (or anything else) that may hold the file.</summary>
        public static FileStream OpenShared(string path) =>
            new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920);

        /// <summary>Reads the whole file, or returns null when it is larger than <paramref name="maxBytes"/>.</summary>
        public static byte[] ReadAllShared(string path, long maxBytes)
        {
            using (var fs = OpenShared(path))
            {
                long len = fs.Length;
                if (len > maxBytes) return null;
                var buf = new byte[len];
                int read = 0;
                while (read < len)
                {
                    int n = fs.Read(buf, read, (int)(len - read));
                    if (n <= 0) break;
                    read += n;
                }
                if (read != len) Array.Resize(ref buf, read);
                return buf;
            }
        }

        public static byte[] ReadHead(string path, int count)
        {
            using (var fs = OpenShared(path))
            {
                var buf = new byte[count];
                int read = 0;
                while (read < count)
                {
                    int n = fs.Read(buf, read, count - read);
                    if (n <= 0) break;
                    read += n;
                }
                if (read != count) Array.Resize(ref buf, read);
                return buf;
            }
        }

        public static bool StartsWith(byte[] data, byte[] prefix)
        {
            if (data == null || data.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++)
                if (data[i] != prefix[i]) return false;
            return true;
        }

        public static string Sha256(string path)
        {
            using (var fs = OpenShared(path))
            using (var sha = SHA256.Create())
                return Hex(sha.ComputeHash(fs));
        }

        public static string Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
                return Hex(sha.ComputeHash(data));
        }

        public static string Hex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>Enumerates files, skipping folders we cannot read and never following junctions/symlinks.</summary>
        public static IEnumerable<string> EnumerateFiles(string dir, bool recursive, int maxFiles = 300000)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) yield break;
            var stack = new Stack<string>();
            stack.Push(dir);
            int count = 0;
            while (stack.Count > 0)
            {
                string d = stack.Pop();
                string[] files = TryGetFiles(d);
                foreach (var f in files)
                {
                    yield return f;
                    if (++count >= maxFiles) yield break;
                }
                if (!recursive) continue;
                foreach (var s in TryGetDirectories(d))
                {
                    if (IsReparsePoint(s)) continue;
                    stack.Push(s);
                }
            }
        }

        public static string[] TryGetFiles(string dir, string pattern = "*")
        {
            try { return Directory.GetFiles(dir, pattern); }
            catch (Exception) { return new string[0]; }
        }

        public static string[] TryGetDirectories(string dir, string pattern = "*")
        {
            try { return Directory.GetDirectories(dir, pattern); }
            catch (Exception) { return new string[0]; }
        }

        public static bool IsReparsePoint(string path)
        {
            try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
            catch (Exception) { return true; }
        }

        public static bool IsHex64(string name)
        {
            if (name == null || name.Length != 64) return false;
            foreach (char c in name)
            {
                bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
            return true;
        }

        public static bool IsUnder(string path, string dir)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(dir)) return false;
            string d = dir.TrimEnd('\\', '/') + "\\";
            return path.StartsWith(d, StringComparison.OrdinalIgnoreCase);
        }

        public static string ParentName(string path)
        {
            string parent = Path.GetDirectoryName(path.TrimEnd('\\', '/'));
            return parent == null ? "" : Path.GetFileName(parent);
        }

        /// <summary>Deletes a folder tree. Clears read-only flags and removes junctions without following them.</summary>
        public static void DeleteDirectoryTree(string dir)
        {
            var di = new DirectoryInfo(dir);
            if (!di.Exists) return;
            if ((di.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                di.Delete(false);
                return;
            }
            foreach (var f in di.GetFiles())
            {
                if ((f.Attributes & FileAttributes.ReadOnly) != 0) f.Attributes = FileAttributes.Normal;
                f.Delete();
            }
            foreach (var s in di.GetDirectories())
                DeleteDirectoryTree(s.FullName);
            if ((di.Attributes & FileAttributes.ReadOnly) != 0) di.Attributes &= ~FileAttributes.ReadOnly;
            di.Delete(false);
        }

        public static void DeleteFileForce(string path)
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return;
            if ((fi.Attributes & FileAttributes.ReadOnly) != 0) fi.Attributes = FileAttributes.Normal;
            fi.Delete();
        }

        public static string FormatSize(long bytes) => bytes.ToString("N0") + " 바이트";

        public static string FormatTime(DateTime utc) => utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

        public static string Truncate(string s, int max) =>
            s == null || s.Length <= max ? s : s.Substring(0, max) + "…";
    }
}
