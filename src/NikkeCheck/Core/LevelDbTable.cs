using System;
using System.Collections.Generic;

namespace NikkeCheck.Core
{
    /// <summary>
    /// Minimal LevelDB table (.ldb/.sst) reader: walks the index block, decompresses each data block
    /// and rebuilds the prefix-compressed keys so a key like "k2f.agent.state" can be found even when
    /// it shares a prefix with the previous key.
    /// </summary>
    public static class LevelDbTable
    {
        private const ulong TableMagic = 0xdb4775248b80fb57UL;
        private const int FooterLength = 48;

        /// <summary>Returns the first needle found in any key or value, or null.</summary>
        public static string Search(byte[] file, IList<Needle> needles)
        {
            if (file == null || file.Length < FooterLength) return null;
            if (BitConverter.ToUInt64(file, file.Length - 8) != TableMagic) return null;

            List<KeyValuePair<byte[], byte[]>> index;
            try
            {
                int pos = file.Length - FooterLength;
                int end = file.Length - 8;
                Snappy.ReadVarint64(file, ref pos, end); // metaindex offset
                Snappy.ReadVarint64(file, ref pos, end); // metaindex size
                ulong indexOffset = Snappy.ReadVarint64(file, ref pos, end);
                ulong indexSize = Snappy.ReadVarint64(file, ref pos, end);
                byte[] indexBlock = ReadBlock(file, indexOffset, indexSize);
                if (indexBlock == null) return null;
                index = ParseBlock(indexBlock);
            }
            catch (FormatException) { return null; }

            foreach (var handle in index)
            {
                try
                {
                    int p = 0;
                    ulong off = Snappy.ReadVarint64(handle.Value, ref p, handle.Value.Length);
                    ulong size = Snappy.ReadVarint64(handle.Value, ref p, handle.Value.Length);
                    byte[] block = ReadBlock(file, off, size);
                    if (block == null) continue;
                    foreach (var kv in ParseBlock(block))
                    {
                        foreach (var n in needles)
                        {
                            if (n.FoundIn(kv.Key) || n.FoundIn(kv.Value)) return n.Text;
                        }
                    }
                }
                catch (FormatException) { }
            }
            return null;
        }

        /// <summary>Reads a block plus its 5-byte trailer (compression type + CRC). Supports raw and Snappy.</summary>
        public static byte[] ReadBlock(byte[] file, ulong offset, ulong size)
        {
            if (offset + size + 5 > (ulong)file.Length || size > int.MaxValue) return null;
            int off = (int)offset;
            int len = (int)size;
            byte type = file[off + len];
            if (type == 0)
            {
                var copy = new byte[len];
                Buffer.BlockCopy(file, off, copy, 0, len);
                return copy;
            }
            if (type == 1) return Snappy.Decompress(file, off, len);
            return null; // unknown compression
        }

        public static List<KeyValuePair<byte[], byte[]>> ParseBlock(byte[] block)
        {
            var list = new List<KeyValuePair<byte[], byte[]>>();
            if (block.Length < 4) return list;
            uint restarts = BitConverter.ToUInt32(block, block.Length - 4);
            long limit = block.Length - 4 - 4L * restarts;
            if (limit < 0) return list;

            int pos = 0;
            int end = (int)limit;
            byte[] lastKey = new byte[0];
            while (pos < end)
            {
                uint shared = Snappy.ReadVarint32(block, ref pos, end);
                uint nonShared = Snappy.ReadVarint32(block, ref pos, end);
                uint valueLen = Snappy.ReadVarint32(block, ref pos, end);
                if (shared > lastKey.Length || (long)pos + nonShared + valueLen > end) break;

                var key = new byte[shared + nonShared];
                Buffer.BlockCopy(lastKey, 0, key, 0, (int)shared);
                Buffer.BlockCopy(block, pos, key, (int)shared, (int)nonShared);
                pos += (int)nonShared;

                var value = new byte[valueLen];
                Buffer.BlockCopy(block, pos, value, 0, (int)valueLen);
                pos += (int)valueLen;

                list.Add(new KeyValuePair<byte[], byte[]>(key, value));
                lastKey = key;
            }
            return list;
        }
    }
}
