﻿namespace Encoder
{
    public static class PrimeNumbers
    {
        private static readonly List<int> List = new()
        {
            20995031, 20995063, 20995069, 20995087, 20995109, 20995123, 20995127, 20995129, 20995141, 20995147,
            20995193, 20995199, 20995201, 20995207, 20995213, 20995231, 20995237, 20995267, 20995279, 20995283,
            20995291, 20995301, 20995307, 20995349, 20995369, 20995379, 20995393, 20995409, 20995411, 20995421,
            20995427, 20995439, 20995489, 20995517, 20995537, 20995547, 20995571, 20995591, 20995609, 20995621,
            20995631, 20995633, 20995657, 20995693, 20995717, 20995721, 20995771, 20995781, 20995783, 20995787,
            20995831, 20995837, 20995859, 20995873, 20995883, 20995889, 20995903, 20995939, 20995943, 20995957,
            20995967, 20995973, 20995993, 20996009, 20996011, 20996023, 20996047, 20996051, 20996069, 20996099,
            20996117, 20996123, 20996149, 20996179, 20996201, 20996219, 20996237, 20996243, 20996251, 20996293,
            20996299, 20996303, 20996359, 20996369, 20996407, 20996413, 20996419, 20996431, 20996441, 20996461,
            20996467, 20996473, 20996477, 20996489, 20996497, 20996531, 20996557, 20996567, 20996597, 20996611,
            20996621, 20996659, 20996671, 20996681, 20996687, 20996713, 20996719, 20996741, 20996753, 20996777,
            20996803, 20996849, 20996863, 20996891, 20996893, 20996959, 20996977, 20997017, 20997047, 20997059,
            20997101, 20997103, 20997107, 20997113, 20997139, 20997143, 20997149, 20997181, 20997187, 20997211,
            20997217, 20997253, 20997269, 20997293, 20997311, 20997313, 20997349, 20997377, 20997407, 20997419,
            20997437, 20997443, 20997461, 20997467, 20997491, 20997511, 20997517, 20997521, 20997523, 20997539,
            20997541, 20997553, 20997583, 20997619, 20997637, 20997649, 20997659, 20997701, 20997709, 20997719,
            20997731, 20997761, 20997829, 20997841, 20997877, 20997901, 20997913, 20997917, 20997931, 20997937,
            20997961, 20997971, 20997973, 20997989, 20998007, 20998013, 20998031, 20998051, 20998063, 20998069,
            20998093, 20998139, 20998141, 20998151, 20998157, 20998163, 20998169, 20998177, 20998189, 20998223,
            20998259, 20998261, 20998267, 20998297, 20998303, 20998387, 20998399, 20998433, 20998459, 20998489,
            20998511, 20998529, 20998531, 20998583, 20998589, 20998603, 20998619, 20998633, 20998673, 20998727,
            20998729, 20998739, 20998771, 20998777, 20998787, 20998829, 20998841, 20998843, 20998853, 20998877,
            20998891, 20998897, 20998909, 20998937, 20998951, 20998963, 20998969, 20998993, 20999003, 20999021,
            20999039, 20999051, 20999057, 20999087, 20999101, 20999141, 20999149, 20999159, 20999171, 20999191,
            20999197, 20999203, 20999243, 20999261, 20999263, 20999269, 20999273, 20999317, 20999357, 20999359,
            20999383, 20999401, 20999423, 20999443, 20999467, 20999477, 20999479, 20999513, 20999551, 20999593,
            20999597, 20999623, 20999651, 20999659, 20999663, 20999669, 20999681, 20999711, 20999723, 20999729,
            20999767, 20999789, 20999791, 20999843, 20999887, 20999893, 20999899, 20999917, 20999939, 20999941,
            20999977, 20999999, 20999999
        };

        public static int GetRandomNum()
        {
            return List[new Random().Next(PrimeNumbers.List.Count)];
        }

        public static int GetPRoot(int p)
        {
            for (var i = 2; i < p; i++)
                if (IsPRoot(p, i))
                    return i;
            return 0;
        }

        private static bool IsPRoot(long p, long a)
        {
            long last = 1;
            var set = new HashSet<long>();
            for (long i = 0; i < p - 1; i++)
            {
                last = (last * a) % p;
                if (set.Contains(last)) // Если повтор
                    return false;
                set.Add(last);
            }
            return true;
        }
    }
}