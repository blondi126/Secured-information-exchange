using System.Numerics;

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
                var e = Gcd(phi, i);
                if (e != 1)
                    continue;

                _e = i;
                break;
            }
            _d = ModInverse(_e, phi);
        }

        private static long Gcd(long a, long b)
        {
            if (a == 0) return b;
            if (b == 0) return a;
            if (a == b) return a;
            if (a == 1 || b == 1) return 1;
            if ((a % 2 == 0) && (b % 2 == 0)) return 2 * Gcd(a / 2, b / 2);
            if ((a % 2 == 0) && (b % 2 != 0)) return Gcd(a / 2, b);
            if ((a % 2 != 0) && (b % 2 == 0)) return Gcd(a, b / 2);
            return Gcd(b, (long)Math.Abs(a - b));
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

        public static IEnumerable<byte> GenerateDigitalSign(byte[] data, KeyPair keyPair)
        {
            var message = new BigInteger(data);

            var num = BigInteger.ModPow(message, keyPair.Key1, keyPair.Key2);
            var numBytes = num.ToByteArray();

            var result = new byte[numBytes.Length + 1];
            numBytes.CopyTo(result, 1);

            var size = BitConverter.GetBytes(numBytes.Length).ToArray()[0];
            result[0] = size;

            return result;
        }

        public static bool VerifySignature(byte[] signature, byte[] messageHash, KeyPair keyPair)
        {
            var sign = new BigInteger(signature);

            var messagePrototype = BigInteger.ModPow(sign, keyPair.Key1, keyPair.Key2);

            return messagePrototype == new BigInteger(messageHash);
        }
    }
}