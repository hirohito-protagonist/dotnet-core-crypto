using System;
using System.IO;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoDes
    {
        public static byte[] Encrypt(string plainText, byte[] key, byte[] iv)
        {
            using (var des = DES.Create())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;

                des.Key = key;
                des.IV = iv;

                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(cryptoStream))
                        {
                            swEncrypt.Write(plainText);
                        }
                        return memoryStream.ToArray();
                    }                    
                }
            }
        }

        public static string Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var des = DES.Create())
            {
                des.Mode = CipherMode.CBC;
                des.Padding = PaddingMode.PKCS7;

                des.Key = key;
                des.IV = iv;

                using (var memoryStream = new MemoryStream(data))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, des.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}