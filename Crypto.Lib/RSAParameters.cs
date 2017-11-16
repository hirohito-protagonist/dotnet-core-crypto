using System;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoRSAParameters
    {
        public RSAParameters publicKey { get; set; }
        public RSAParameters privateKey { get; set; }

        public void GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {                
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
            }
        }
    }
}