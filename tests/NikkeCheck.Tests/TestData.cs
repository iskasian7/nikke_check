using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace NikkeCheck.Tests
{
    /// <summary>Test-only writers: a literal-only Snappy encoder and a tiny LevelDB table builder.</summary>
    internal static class TestData
    {
        public static byte[] SnappyCompressLiteral(byte[] data)
        {
            var ms = new MemoryStream();
            WriteVarint(ms, (ulong)data.Length);
            int pos = 0;
            while (pos < data.Length)
            {
                int n = Math.Min(65536, data.Length - pos);
                if (n <= 60) ms.WriteByte((byte)((n - 1) << 2));
                else if (n <= 256)
                {
                    ms.WriteByte(60 << 2);
                    ms.WriteByte((byte)(n - 1));
                }
                else
                {
                    ms.WriteByte(61 << 2);
                    ms.WriteByte((byte)((n - 1) & 0xFF));
                    ms.WriteByte((byte)((n - 1) >> 8));
                }
                ms.Write(data, pos, n);
                pos += n;
            }
            return ms.ToArray();
        }

        public static void WriteVarint(Stream s, ulong v)
        {
            while (v >= 0x80)
            {
                s.WriteByte((byte)(v | 0x80));
                v >>= 7;
            }
            s.WriteByte((byte)v);
        }

        public static byte[] BuildBlock(IList<KeyValuePair<byte[], byte[]>> entries, int restartInterval = 16)
        {
            var ms = new MemoryStream();
            var restarts = new List<uint>();
            byte[] last = new byte[0];
            for (int i = 0; i < entries.Count; i++)
            {
                byte[] key = entries[i].Key;
                byte[] value = entries[i].Value;
                int shared = 0;
                if (i % restartInterval == 0) restarts.Add((uint)ms.Length);
                else
                    while (shared < last.Length && shared < key.Length && last[shared] == key[shared]) shared++;
                WriteVarint(ms, (ulong)shared);
                WriteVarint(ms, (ulong)(key.Length - shared));
                WriteVarint(ms, (ulong)value.Length);
                ms.Write(key, shared, key.Length - shared);
                ms.Write(value, 0, value.Length);
                last = key;
            }
            if (restarts.Count == 0) restarts.Add(0);
            foreach (var r in restarts) ms.Write(BitConverter.GetBytes(r), 0, 4);
            ms.Write(BitConverter.GetBytes((uint)restarts.Count), 0, 4);
            return ms.ToArray();
        }

        public static byte[] BuildTable(IList<KeyValuePair<byte[], byte[]>> entries, bool compress)
        {
            var file = new MemoryStream();

            (long off, long size) WriteBlock(byte[] block, bool snappy)
            {
                long off = file.Length;
                byte[] data = snappy ? SnappyCompressLiteral(block) : block;
                file.Write(data, 0, data.Length);
                file.WriteByte(snappy ? (byte)1 : (byte)0);
                file.Write(new byte[4], 0, 4); // CRC (not verified by the reader)
                return (off, data.Length);
            }

            byte[] Handle(long off, long size)
            {
                var h = new MemoryStream();
                WriteVarint(h, (ulong)off);
                WriteVarint(h, (ulong)size);
                return h.ToArray();
            }

            var data1 = WriteBlock(BuildBlock(entries), compress);
            var meta = WriteBlock(BuildBlock(new List<KeyValuePair<byte[], byte[]>>()), false);
            // Like LevelDB's FindShortSuccessor: the index key is a shortened successor, not the full last key.
            var lastKey = entries[entries.Count - 1].Key;
            var shortKey = new[] { (byte)(lastKey[0] + 1) };
            var index = WriteBlock(BuildBlock(new List<KeyValuePair<byte[], byte[]>>
            {
                new KeyValuePair<byte[], byte[]>(shortKey, Handle(data1.off, data1.size)),
            }), false);

            var footer = new MemoryStream();
            byte[] mh = Handle(meta.off, meta.size);
            byte[] ih = Handle(index.off, index.size);
            footer.Write(mh, 0, mh.Length);
            footer.Write(ih, 0, ih.Length);
            while (footer.Length < 40) footer.WriteByte(0);
            footer.Write(BitConverter.GetBytes(0xdb4775248b80fb57UL), 0, 8);
            byte[] f = footer.ToArray();
            file.Write(f, 0, f.Length);
            return file.ToArray();
        }

        /// <summary>Chromium localStorage key: "_" + origin + "\0" + "\x01" (Latin-1 marker) + key, plus an 8-byte LevelDB sequence suffix.</summary>
        public static byte[] LocalStorageKey(string origin, string key)
        {
            var bytes = new List<byte>();
            bytes.AddRange(Encoding.ASCII.GetBytes("_" + origin));
            bytes.Add(0);
            bytes.Add(1);
            bytes.AddRange(Encoding.ASCII.GetBytes(key));
            bytes.AddRange(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0 });
            return bytes.ToArray();
        }

        public static byte[] Gzip(string text)
        {
            var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionMode.Compress, true))
            {
                var b = Encoding.UTF8.GetBytes(text);
                gz.Write(b, 0, b.Length);
            }
            return ms.ToArray();
        }

        public static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();
    }
}
