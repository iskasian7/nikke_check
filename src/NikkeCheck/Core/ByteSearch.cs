using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace NikkeCheck.Core
{
    /// <summary>A string searched for as both ASCII/UTF-8 and UTF-16LE bytes (Chromium stores both).</summary>
    public sealed class Needle
    {
        public Needle(string text)
        {
            Text = text;
            Ascii = Encoding.ASCII.GetBytes(text);
            Utf16 = Encoding.Unicode.GetBytes(text);
        }

        public string Text { get; }
        public byte[] Ascii { get; }
        public byte[] Utf16 { get; }

        public bool FoundIn(byte[] data) => data != null && FoundIn(data, data.Length);

        public bool FoundIn(byte[] data, int length) =>
            ByteSearch.IndexOf(data, length, Ascii, 0) >= 0 || ByteSearch.IndexOf(data, length, Utf16, 0) >= 0;
    }

    public static class ByteSearch
    {
        public static int IndexOf(byte[] hay, int hayLength, byte[] needle, int start)
        {
            if (hay == null || needle.Length == 0) return -1;
            int last = hayLength - needle.Length;
            byte first = needle[0];
            for (int i = start; i <= last; i++)
            {
                if (hay[i] != first) continue;
                int j = 1;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        public static bool ContainsAscii(byte[] data, string text) =>
            IndexOf(data, data.Length, Encoding.ASCII.GetBytes(text), 0) >= 0;
    }

    public static class GzipTools
    {
        private static readonly byte[] Magic = { 0x1F, 0x8B, 0x08 };

        /// <summary>
        /// Finds gzip members embedded in a Chromium cache entry and returns their decompressed bytes.
        /// Partial output is kept when a member is truncated or corrupt.
        /// </summary>
        public static List<byte[]> DecompressMembers(byte[] data, int maxOutputBytes, int maxMembers = 8)
        {
            var result = new List<byte[]>();
            int pos = 0;
            while (result.Count < maxMembers)
            {
                int off = ByteSearch.IndexOf(data, data.Length, Magic, pos);
                if (off < 0) break;
                var output = new MemoryStream();
                try
                {
                    using (var input = new MemoryStream(data, off, data.Length - off, false))
                    using (var gz = new GZipStream(input, CompressionMode.Decompress))
                    {
                        var buf = new byte[16384];
                        int n;
                        while ((n = gz.Read(buf, 0, buf.Length)) > 0)
                        {
                            output.Write(buf, 0, n);
                            if (output.Length >= maxOutputBytes) break;
                        }
                    }
                }
                catch (InvalidDataException) { }
                catch (IOException) { }
                if (output.Length > 0) result.Add(output.ToArray());
                pos = off + Magic.Length;
            }
            return result;
        }
    }
}
