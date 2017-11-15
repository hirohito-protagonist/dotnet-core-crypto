using System;
using System.Text;
using System.Security.Cryptography;
using Crypto.Lib;

namespace Crypto.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"Random {Convert.ToBase64String(CryptoRandom.Generate(32))}");

            Console.WriteLine("-------------------------------------------");

            var message = "Hiro universe";
            var messageBytes = Encoding.UTF8.GetBytes(message);
        
            Console.WriteLine($"MD5 message: {message} hash: {Convert.ToBase64String(CryptoHash.Md5(messageBytes))}");
            Console.WriteLine($"SHA1 message: {message} hash: {Convert.ToBase64String(CryptoHash.Sha1(messageBytes))}");
            Console.WriteLine($"SHA256 message: {message} hash: {Convert.ToBase64String(CryptoHash.Sha256(messageBytes))}");
            Console.WriteLine($"SHA512 message: {message} hash: {Convert.ToBase64String(CryptoHash.Sha512(messageBytes))}");

            var key = CryptoRandom.Generate(32);

            Console.WriteLine($"HMAC MD5 message: {message} hash: {Convert.ToBase64String(CryptoHmac.Md5(messageBytes, key))}");
            Console.WriteLine($"HMAC SHA1 message: {message} hash: {Convert.ToBase64String(CryptoHmac.Sha1(messageBytes, key))}");
            Console.WriteLine($"HMAC SHA256 message: {message} hash: {Convert.ToBase64String(CryptoHmac.Sha256(messageBytes, key))}");
            Console.WriteLine($"HMAC SHA512 message: {message} hash: {Convert.ToBase64String(CryptoHmac.Sha512(messageBytes, key))}");

            Console.WriteLine("-------------------------------------------"); 
            Console.WriteLine("Passsword hash with salt");
            Console.WriteLine($"Password: {message}");
            Console.WriteLine($"Password hashed: {Convert.ToBase64String(CryptoHash.Password(messageBytes))}");

            Console.WriteLine("-------------------------------------------"); 
            var salt = CryptoRandom.Generate(32);
            Console.WriteLine("Passsword hash with salt - Based Key Derivation Function - PBKDF2");
            Console.WriteLine($"Password: {message}");
            Console.WriteLine($"Password hashed 100 rounds: {Convert.ToBase64String(CryptoHash.Password(messageBytes, salt, 100))}");
            Console.WriteLine($"Password hashed 1000 rounds: {Convert.ToBase64String(CryptoHash.Password(messageBytes, salt, 1000))}");
            Console.WriteLine($"Password hashed 10000 rounds: {Convert.ToBase64String(CryptoHash.Password(messageBytes, salt, 10000))}");

            Console.WriteLine("-------------------------------------------");
            var desKey = CryptoRandom.Generate(8);
            var desIv = CryptoRandom.Generate(8);
            var desEncryptedMessage = CryptoDes.Encrypt(message, desKey, desIv);
            var desDecryptedMessage = CryptoDes.Decrypt(desEncryptedMessage, desKey, desIv);
            Console.WriteLine("DES Encryption");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Key: {Convert.ToBase64String(desKey)}");
            Console.WriteLine($"IV: {Convert.ToBase64String(desIv)}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(desEncryptedMessage)}");
            Console.WriteLine($"Decrypted: {desDecryptedMessage}");

            Console.WriteLine("-------------------------------------------");
            var tripleDesKey = CryptoRandom.Generate(16);
            var tripleDesIv = CryptoRandom.Generate(8);
            var tripleDesEncryptedMessage = CryptoTripleDes.Encrypt(message, tripleDesKey, tripleDesIv);
            var tripleDesDecryptedMessage = CryptoTripleDes.Decrypt(tripleDesEncryptedMessage, tripleDesKey, tripleDesIv);
            Console.WriteLine("Triple DES Encryption");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Key: {Convert.ToBase64String(tripleDesKey)}");
            Console.WriteLine($"IV: {Convert.ToBase64String(tripleDesIv)}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(tripleDesEncryptedMessage)}");
            Console.WriteLine($"Decrypted: {tripleDesDecryptedMessage}");

            Console.WriteLine("-------------------------------------------");
            var aesKey = CryptoRandom.Generate(32);
            var aesIv = CryptoRandom.Generate(16);
            var aesEncryptedMessage = CryptoAes.Encrypt(message, aesKey, aesIv);
            var aesDecryptedMessage = CryptoAes.Decrypt(aesEncryptedMessage, aesKey, aesIv);
            Console.WriteLine("AES Encryption");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Key: {Convert.ToBase64String(aesKey)}");
            Console.WriteLine($"IV: {Convert.ToBase64String(aesIv)}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(aesEncryptedMessage)}");
            Console.WriteLine($"Decrypted: {aesDecryptedMessage}");

            
            RSAParameters publicKey;
            RSAParameters privateKey;

            using (var rsa = new RSACryptoServiceProvider(2048))
            {               
                publicKey = rsa.ExportParameters(false);
                privateKey = rsa.ExportParameters(true);
            }
            Console.WriteLine("-------------------------------------------");
            var rsaEncryptedMessage = CryptoRsa.Encrypt(messageBytes, publicKey);
            var rsaDecryptedMessage = CryptoRsa.Decrypt(rsaEncryptedMessage, privateKey);
            Console.WriteLine("RSA Encryption");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(rsaEncryptedMessage)}");
            Console.WriteLine($"Decrypted: {Encoding.Default.GetString(rsaDecryptedMessage)}");

            Console.WriteLine("-------------------------------------------");
            var hybridEncryptedPacket = CryptoHybrid.Encrypt(message, publicKey);
            var hybridDecryptedMessage = CryptoHybrid.Decrypt(hybridEncryptedPacket, privateKey);
            Console.WriteLine("Hybrid Encryption using AES and RSA");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Encrypted: {Convert.ToBase64String(hybridEncryptedPacket.EncryptedData)}");
            Console.WriteLine($"Decrypted: {hybridDecryptedMessage}");

            Console.WriteLine("-------------------------------------------");
            var hashedMessage = CryptoHash.Sha256(messageBytes);
            var signature = CryptoDigitalSignature.Sign(hashedMessage, privateKey);
            var verify = CryptoDigitalSignature.Verify(hashedMessage, signature, publicKey);
            Console.WriteLine("Digital Signature");
            Console.WriteLine($"Text: {message}");
            Console.WriteLine($"Signature: {Convert.ToBase64String(signature)}");
            Console.WriteLine("Is Verified: " + (verify ? "true" : "false"));
        }
    }
}
