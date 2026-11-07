using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NikkeCheck.Core;
using Xunit;

namespace NikkeCheck.Tests
{
    public class SnappyTests
    {
        [Fact]
        public void Decodes_literal()
        {
            var src = new byte[] { 5, (5 - 1) << 2, (byte)'h', (byte)'e', (byte)'l', (byte)'l', (byte)'o' };
            Assert.Equal("hello", Encoding.ASCII.GetString(Snappy.Decompress(src)));
        }

        [Fact]
        public void Decodes_overlapping_copy_with_1_byte_offset()
        {
            // "abc" literal + copy(len 9, offset 3)
            var src = new byte[] { 12, 0x08, (byte)'a', (byte)'b', (byte)'c', ((9 - 4) << 2) | 1, 3 };
            Assert.Equal("abcabcabcabc", Encoding.ASCII.GetString(Snappy.Decompress(src)));
        }

        [Fact]
        public void Decodes_copy_with_2_byte_offset()
        {
            var src = new byte[] { 12, 0x08, (byte)'x', (byte)'y', (byte)'z', ((9 - 1) << 2) | 2, 3, 0 };
            Assert.Equal("xyzxyzxyzxyz", Encoding.ASCII.GetString(Snappy.Decompress(src)));
        }

        [Fact]
        public void Round_trips_long_literals()
        {
            var data = Enumerable.Range(0, 70000).Select(i => (byte)(i * 7)).ToArray();
            Assert.Equal(data, Snappy.Decompress(TestData.SnappyCompressLiteral(data)));
        }

        [Fact]
        public void Rejects_copy_before_start()
        {
            var src = new byte[] { 8, ((4 - 4) << 2) | 1, 9 };
            Assert.Throws<FormatException>(() => Snappy.Decompress(src));
        }
    }

    public class LevelDbTests
    {
        private static List<KeyValuePair<byte[], byte[]>> Entries() => new List<KeyValuePair<byte[], byte[]>>
        {
            // Sorted keys sharing the prefix "..\x01k", so the second key's stored bytes start at "2f.agent".
            new KeyValuePair<byte[], byte[]>(TestData.LocalStorageKey("https://launcher.local", "k1"), new byte[] { 1, (byte)'x' }),
            new KeyValuePair<byte[], byte[]>(TestData.LocalStorageKey("https://launcher.local", "k2f.agent.state"),
                TestData.Concat(new byte[] { 1 }, Encoding.ASCII.GetBytes("{\"agent_id\":\"1\",\"poll_interval_seconds\":1800}"))),
        };

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void Finds_prefix_compressed_key_that_plain_search_misses(bool compress)
        {
            byte[] table = TestData.BuildTable(Entries(), compress);
            var needle = new Needle(Indicators.AgentStateKey);

            Assert.False(needle.FoundIn(table)); // plain text search misses it
            Assert.Equal(Indicators.AgentStateKey, LevelDbTable.Search(table, new[] { needle }));
        }

        [Fact]
        public void Clean_table_has_no_hit()
        {
            var entries = new List<KeyValuePair<byte[], byte[]>>
            {
                new KeyValuePair<byte[], byte[]>(TestData.LocalStorageKey("https://launcher.local", "lang"), new byte[] { 1, (byte)'k', (byte)'o' }),
            };
            Assert.Null(LevelDbTable.Search(TestData.BuildTable(entries, true), new[] { new Needle(Indicators.AgentStateKey) }));
        }

        [Fact]
        public void Ignores_garbage()
        {
            Assert.Null(LevelDbTable.Search(new byte[100], new[] { new Needle("x") }));
            Assert.Null(LevelDbTable.Search(new byte[3], new[] { new Needle("x") }));
        }
    }

    public class MiscTests
    {
        [Fact]
        public void Redactor_masks_tickets_and_cookies()
        {
            string line = "GET /api?login_ticket=SECRET1&uid=12345&sig=abc HTTP/1.1";
            string r = Redactor.Redact(line);
            Assert.DoesNotContain("SECRET1", r);
            Assert.DoesNotContain("12345", r);
            Assert.Contains("login_ticket=***", r);
            Assert.Equal("Cookie: ***", Redactor.Redact("Cookie: a=b; c=d"));
        }

        [Fact]
        public void Hex64_requires_exactly_64_hex_chars()
        {
            Assert.True(FileUtil.IsHex64(FakeEnvironment.Hex64));
            Assert.False(FileUtil.IsHex64("LoadFeatures"));
            Assert.False(FileUtil.IsHex64(new string('a', 63)));
            Assert.False(FileUtil.IsHex64(new string('g', 64)));
        }

        [Fact]
        public void Gzip_members_inside_cache_entry_are_decompressed()
        {
            byte[] entry = TestData.Concat(Encoding.ASCII.GetBytes("https://example/aegis-fix.min.js\0header"),
                TestData.Gzip("var u='https://insightjs.com/l.js?f=aegis';"), new byte[] { 0xD8, 0x41, 0x0D });
            var bodies = GzipTools.DecompressMembers(entry, 1 << 20);
            Assert.Contains(bodies, b => new Needle("insightjs").FoundIn(b));
        }

        [Fact]
        public void Hsts_hash_is_base64_sha256()
        {
            string h = Scanner.HstsHostHash("analytics.insightjs.com");
            Assert.Equal(44, h.Length);
            Assert.Equal(h, Scanner.HstsHostHash("Analytics.InsightJS.com."));
        }
    }
}
