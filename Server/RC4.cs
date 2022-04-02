using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Server
{
    public class RC4
    {
        private readonly byte[] S = new byte[256];
        private int _x = 0;
        private int _y = 0;

        public RC4(byte[] key)
        {
            KSA(key);
        }

        private void KSA(byte[] key)
        {
            var keyLength = key.Length;

            for (var i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
            }

            var j = 0;
            for (var i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % keyLength]) % 256;
                Swap(S, i, j);
            }
        }

        private static void Swap(byte[] array, int index1, int index2)
        {
            (array[index1], array[index2]) = (array[index2], array[index1]);
        }

        public byte[] Encode(byte[] data)
        {
            var cipher = new byte[data.Length];

            for (var m = 0; m < data.Length; m++)
            {
                cipher[m] = (byte)(data[m] ^ PRGA());
            }

            return cipher;
        }

        private byte PRGA()
        {
            _x = (_x + 1) % 256;
            _y = (_y + S[_x]) % 256;

            Swap(S,_x,_y);

            return S[(S[_x] + S[_y]) % 256];
        }

        public byte[] Decode(byte[] encryptedData, int size)
        {
            var data = encryptedData.Take(size).ToArray();

            return Encode(data);
        }
    }
}
