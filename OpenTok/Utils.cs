using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Nyhren.OpenTokSDK
{
    class Utils
    {
        public static string EncodeHMAC(string input, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            HMACSHA1 hmac = new HMACSHA1(keyBytes);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashedValue = hmac.ComputeHash(inputBytes);

            // iterates over bytes and converts them each to a 2 digit hexidecimal string representation,
            // concatenates, and converts to lower case
            string encodedInput = string.Concat(hashedValue.Select(b => string.Format("{0:X2}", b)).ToArray());
            return encodedInput.ToLowerInvariant();
        }

        public static int GetRandomNumber()
        {
            Random random = new Random();
            return random.Next(0, 999999);
        }
    }
}
