using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoHmac
    {
        public static byte[] Sha1(byte[] data, byte[] key)
        {
            using (var sha = new HMACSHA1(key))
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Sha256(byte[] data, byte[] key)
        {
            using (var sha = new HMACSHA256(key))
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Sha512(byte[] data, byte[] key)
        {
            using (var sha = new HMACSHA512(key))
            {
                return sha.ComputeHash(data);
            }
        }

        public static byte[] Md5(byte[] data, byte[] key)
        {
            using (var md = new HMACMD5(key))
            {
                return md.ComputeHash(data);
            }
        }
    }
}