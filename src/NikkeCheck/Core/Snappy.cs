using System;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Raw Snappy decompressor (the block format LevelDB uses for compressed table blocks).
    /// Needed because Chromium's Local Storage keeps older data in Snappy-compressed .ldb files,
    /// where a plain text search can miss "k2f.agent.state".
    /// </summary>
    public static class Snappy
    {
        private const int MaxOutput = 64 * 1024 * 1024;

        public static byte[] Decompress(byte[] src) => Decompress(src, 0, src.Length);

        public static byte[] Decompress(byte[] src, int offset, int length)
        {
            int pos = offset;
            int end = offset + length;
            if (end > src.Length) throw new FormatException("snappy: input out of range");

            uint ulen = ReadVarint32(src, ref pos, end);
            if (ulen > MaxOutput) throw new FormatException("snappy: output too large");
            var dst = new byte[ulen];
            int d = 0;

            while (pos < end)
            {
                byte tag = src[pos++];
                int len, off;
                switch (tag & 3)
                {
                    case 0: // literal
                        len = tag >> 2;
                        if (len >= 60)
                        {
                            int extra = len - 59;
                            if (pos + extra > end) throw new FormatException("snappy: truncated literal length");
                            len = 0;
                            for (int i = 0; i < extra; i++) len |= src[pos++] << (8 * i);
                        }
                        len += 1;
                        if (len <= 0 || pos + len > end || d + len > dst.Length) throw new FormatException("snappy: bad literal");
                        Buffer.BlockCopy(src, pos, dst, d, len);
                        pos += len;
                        d += len;
                        break;

                    case 1: // copy, 1-byte offset
                        if (pos + 1 > end) throw new FormatException("snappy: truncated copy1");
                        len = ((tag >> 2) & 7) + 4;
                        off = ((tag >> 5) << 8) | src[pos++];
                        Copy(dst, ref d, off, len);
                        break;

                    case 2: // copy, 2-byte offset
                        if (pos + 2 > end) throw new FormatException("snappy: truncated copy2");
                        len = (tag >> 2) + 1;
                        off = src[pos] | (src[pos + 1] << 8);
                        pos += 2;
                        Copy(dst, ref d, off, len);
                        break;

                    default: // copy, 4-byte offset
                        if (pos + 4 > end) throw new FormatException("snappy: truncated copy4");
                        len = (tag >> 2) + 1;
                        off = src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16) | (src[pos + 3] << 24);
                        pos += 4;
                        Copy(dst, ref d, off, len);
                        break;
                }
            }

            if (d != dst.Length) throw new FormatException("snappy: length mismatch");
            return dst;
        }

        private static void Copy(byte[] dst, ref int d, int off, int len)
        {
            if (off <= 0 || off > d || d + len > dst.Length) throw new FormatException("snappy: bad copy");
            // Byte-by-byte: source and destination may overlap (run-length style copies).
            int s = d - off;
            for (int i = 0; i < len; i++) dst[d + i] = dst[s + i];
            d += len;
        }

        public static uint ReadVarint32(byte[] buf, ref int pos, int end)
        {
            uint result = 0;
            for (int shift = 0; shift <= 28; shift += 7)
            {
                if (pos >= end) throw new FormatException("varint: truncated");
                byte b = buf[pos++];
                result |= (uint)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return result;
            }
            throw new FormatException("varint: too long");
        }

        public static ulong ReadVarint64(byte[] buf, ref int pos, int end)
        {
            ulong result = 0;
            for (int shift = 0; shift <= 63; shift += 7)
            {
                if (pos >= end) throw new FormatException("varint: truncated");
                byte b = buf[pos++];
                result |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) return result;
            }
            throw new FormatException("varint: too long");
        }
    }
}
