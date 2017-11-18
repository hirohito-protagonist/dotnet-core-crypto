using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Crypto.Lib
{
    public class CryptoSecureString
    {
        
        public static SecureString ToSecureString(char[] str)
        {
            var secureString = new SecureString();
            Array.ForEach(str, secureString.AppendChar);

            return secureString;
        }

        public static char[] CharacterData(SecureString secureString)
        {
            char[] bytes;
            var ptr = IntPtr.Zero;

            try
            {
                ptr = Marshal.SecureStringToBSTR(secureString);
                bytes = new char[secureString.Length];
                Marshal.Copy(ptr, bytes, 0, secureString.Length);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.ZeroFreeBSTR(ptr);
                }
            }

            return bytes;            
        }

        public static string ConvertToUnsecureString(SecureString secureString)
        {
            if (secureString == null)
            {
                throw new ArgumentNullException("secureString");
            }

            var result = IntPtr.Zero;

            try
            {
                result = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(result);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(result);
            }
        }
    }
}