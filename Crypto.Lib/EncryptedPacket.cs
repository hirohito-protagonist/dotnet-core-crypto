namespace Crypto.Lib
{
    public class CryptoEncryptedPacket
    {
        public byte[] EncryptedSessionKey;
        public byte[] EncryptedData;
        public byte[] Iv;
        public byte[] Hmac;
        public byte[] Signature;
    }
}