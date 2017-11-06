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
    }
}