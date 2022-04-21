namespace Encoder
{
    public static class Hash
    {
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