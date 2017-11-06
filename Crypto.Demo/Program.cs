﻿using System;
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
        }
    }
}