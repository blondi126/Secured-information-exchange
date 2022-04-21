namespace Encoder
{
    public static class Hash
    {
        public static int GetHash(string value)
        {
            var num = 5381;
            var num2 = num;
            for (var i = 0; i < value.Length; i += 2)
            {
                num = (((num << 5) + num) ^ value[i]);

                if (i + 1 < value.Length)
                    num2 = (((num2 << 5) + num2) ^ value[i + 1]);
            }
            return num + num2 * 1566083941;
        }

        public static uint RsHash(string value)
        {
            const uint b = 378551;
            uint a = 63689;
            uint hash = 0;

            foreach (var item in value)
            {
                hash = hash * a + (byte)(item);
                a *= b;
            }
            return hash;
        }

        public static uint JsHash(string value)
        {
            return value.Aggregate<char, uint>(1315423911, (current, item) => current ^ ((current << 5) + (byte) (item) + (current >> 2)));
        }

        public static long ElfHash(string value)
        {
            long hash = 0;

            foreach (var item in value)
            {
                hash = (hash << 4) + (byte)(item);
                long x;
                if ((x = hash & 0xF0000000L) == 0) continue;
                hash ^= (x >> 24);
                hash &= ~x;
            }

            if (hash < 0)
                return hash * (-1);

            return hash;
        }

        // FAQ6 Hash Function
        // From Bob Jenkins Hash Function FAQ: http://burtleburtle.net/bob/hash/hashfaq.html
        public static uint Bob_faq6_hash(string value)
        {
            uint hash = 0;

            foreach (var item in value)
            {
                hash += (byte)(item);
                hash += (hash << 10);
                hash ^= (hash >> 6);
            }
            hash += (hash << 3);
            hash ^= (hash >> 11);
            hash += (hash << 15);
            return hash;
        }
    }
}
