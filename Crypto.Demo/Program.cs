using System;
using System.Text;
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
        }
    }
}
