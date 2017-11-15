using System.Security.Cryptography;

namespace Crypto.Lib
{
    public class CryptoHybrid
    {
        public static CryptoEncryptedPacket Encrypt(string plainText, RSAParameters publicKey)
        {
            var sessionKey = CryptoRandom.Generate(32);
            var encryptedPacket = new CryptoEncryptedPacket { Iv = CryptoRandom.Generate(16) };
            encryptedPacket.EncryptedData = CryptoAes.Encrypt(plainText, sessionKey, encryptedPacket.Iv);
            encryptedPacket.EncryptedSessionKey = CryptoRsa.Encrypt(sessionKey, publicKey);

            return encryptedPacket;
        }

        public static string Decrypt(CryptoEncryptedPacket encryptedPacket, RSAParameters privateKey)
        {
            var decryptedSessionKey = CryptoRsa.Decrypt(encryptedPacket.EncryptedSessionKey, privateKey);

            return CryptoAes.Decrypt(encryptedPacket.EncryptedData, decryptedSessionKey, encryptedPacket.Iv);
        }
    }
}