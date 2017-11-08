using System;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoHash
    {
        public static byte[] Sha1(byte[] data)
        {
            using (var sha = SHA1.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Sha256(byte[] data)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Sha512(byte[] data)
        {
            using (var sha = SHA512.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Md5(byte[] data)
        {
            using (var md = MD5.Create())
            {
                return md.ComputeHash(data);
            }
        }

        public static byte[] Combine(byte[] first, byte[] second)
        {
            var result = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, result, 0, first.Length);
            Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
            return result;
        }

        public static byte[] Password(byte[] password, int saltKeyLength = 32)
        {
            return CryptoHash.Sha256(CryptoHash.Combine(password, CryptoRandom.Generate(saltKeyLength)));
        }        
    }
}