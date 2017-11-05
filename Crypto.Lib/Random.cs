using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoRandom
    {
        public static byte[] Generate(int length)
        {
            using (var randomProvider = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[length];

                randomProvider.GetBytes(randomNumber);

                return randomNumber;
            }
        }
    }
}