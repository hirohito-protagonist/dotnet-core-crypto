using System;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoRsa
    {
        public static byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            byte[] cipher;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(publicKey);
                cipher = rsa.Encrypt(data, true);
            }
            return cipher;
        }

        public static byte[] Decrypt(byte[] data, RSAParameters privateKey)
        {
            byte[] cipher;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(privateKey);
                cipher = rsa.Decrypt(data, true);
            }
            return cipher;
        }
    }
}