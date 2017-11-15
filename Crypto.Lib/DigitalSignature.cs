using System;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoDigitalSignature
    {
        public static byte[] Sign(byte[] data, RSAParameters privateKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(privateKey);
                
                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);                
                rsaFormatter.SetHashAlgorithm("SHA256");

                return rsaFormatter.CreateSignature(data);
            }
        }

        public static bool Verify(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.ImportParameters(publicKey);

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm("SHA256");

                return rsaDeformatter.VerifySignature(data, signature);
            }
        }
    }
}