using System;
using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoHybridIntegrity
    {
        public static CryptoEncryptedPacket Encrypt(string plainText, CryptoRSAParameters rsaParameters)
        {
            var sessionKey = CryptoRandom.Generate(32);
            var encryptedPacket = new CryptoEncryptedPacket { Iv = CryptoRandom.Generate(16) };
            encryptedPacket.EncryptedData = CryptoAes.Encrypt(plainText, sessionKey, encryptedPacket.Iv);
            encryptedPacket.EncryptedSessionKey = CryptoRsa.Encrypt(sessionKey, rsaParameters.publicKey);
            encryptedPacket.Hmac = CryptoHmac.Sha256(encryptedPacket.EncryptedData, sessionKey);
            encryptedPacket.Signature = CryptoDigitalSignature.Sign(encryptedPacket.Hmac, rsaParameters.privateKey);
            return encryptedPacket;
        }

        public static string Decrypt(CryptoEncryptedPacket encryptedPacket, CryptoRSAParameters rsaParameters)
        {
            var decryptedSessionKey = CryptoRsa.Decrypt(encryptedPacket.EncryptedSessionKey, rsaParameters.privateKey);
            var hmacToCheck = CryptoHmac.Sha256(encryptedPacket.EncryptedData, decryptedSessionKey);

            if (!Compare(encryptedPacket.Hmac, hmacToCheck))
            {
                throw new CryptographicException("HMAC for decyrption does not match encrypted packet");
            }

            if (!CryptoDigitalSignature.Verify(encryptedPacket.Hmac, encryptedPacket.Signature, rsaParameters.publicKey))
            {
                throw new CryptographicException("Digital Signature can not be verified");
            }
            return CryptoAes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);
        }

        private static bool Compare(byte[] data1, byte[] data2)
        {
            var result = data1.Length == data2.Length;

            for (var i = 0; i < data1.Length && i < data2.Length; ++i)
            {
                result &= data1[i] == data2[i];
            }

            return result;
        }
    }
}