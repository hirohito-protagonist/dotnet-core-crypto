using System;
using Crypto.Lib;

namespace Crypto.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Random " + Convert.ToBase64String(CryptoRandom.Generate(32)));
        }
    }
}
