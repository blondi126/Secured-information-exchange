namespace Encoder
{
    public static class RSA
    {
        private static long _e;
        private static long _d;
        private static long _n;
        static RSA()
        {
            GenerateKeys();
        }


        private static void GenerateKeys()
        {
            var p = (long)PrimeNumbers.GetRandomNum();
            var q = (long)PrimeNumbers.GetRandomNum();
            _n = p * q;

            var phi = (p - 1) * (q - 1);
            for (var i = 3; i < phi; i++)
            {
                var e = GCD(phi, i);
                if (e != 1) 
                    continue;

                _e = i;
                break;
            }

            _d = ModInverse(_e, phi);
        }

        private static long GCD(long a, long b)
        {
            if (a == 0) return b;
            if (b == 0) return a;
            if (a == b) return a;
            if (a == 1 || b == 1) return 1;
            if ((a % 2 == 0) && (b % 2 == 0)) return 2 * GCD(a / 2, b / 2);
            if ((a % 2 == 0) && (b % 2 != 0)) return GCD(a / 2, b);
            if ((a % 2 != 0) && (b % 2 == 0)) return GCD(a, b / 2);
            return GCD(b, (long)Math.Abs(a - b));
        }

        private static long ModInverse(long a, long n)
        {
            var n0 = n; 
            (long x, long y) = (1, 0);

            while (a > 1)
            {
                var q = a / n;
                (a, n) = (n, a % n);
                (x, y) = (y, x - q * y);
            }
            return x < 0 ? x + n0 : x;
        }

        public static KeyPair GetOpenKey()
        {
            return new KeyPair()
            {
                Key1 = _e,
                Key2 = _n
            };
        }

        public static KeyPair GetCloseKey()
        {
            return new KeyPair()
            {
                Key1 = _d,
                Key2 = _n
            };
        }
    }
}