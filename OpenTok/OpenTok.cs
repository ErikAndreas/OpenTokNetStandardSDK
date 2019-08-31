using System;
using System.IO;
using System.Net.Http;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Nyhren.OpenTokSDK
{
    /** Implementation of the Tokbox OpenTok REST api https://tokbox.com/developer/rest/ and 
    * port of a few SDK methods, see https://github.com/opentok/Opentok-.NET-SDK
    */
    public class OpenTok
    {
        /** see https://docs.microsoft.com/en-us/azure/azure-functions/manage-connections#httpclient-example-c
         * also https://twitter.com/jeffhollan/status/1101142393103908865
         */
        private static HttpClient client;

        static OpenTok()
        {
            client = new HttpClient();
            client.DefaultRequestHeaders.Add("Accept", "application/json");
        }

        public static async Task<string> CreateSessionAsync(string secret, string apiKey)
        {
            var token = GetTokboxToken(secret, apiKey);
            // can't add to default headers since client is static
            var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "https://api.opentok.com/session/create");
            httpRequestMessage.Headers.Add("X-OPENTOK-AUTH", token);
            httpRequestMessage.Content = new StringContent("", Encoding.UTF8, "application/x-www-form-urlencoded");
            var response = await client.SendAsync(httpRequestMessage);

            using (var reader = new StreamReader(await response.Content.ReadAsStreamAsync()))
            {
                String result = await reader.ReadToEndAsync();
                dynamic jsonResult = JsonConvert.DeserializeObject(result);
                return jsonResult[0]?.session_id;
            }
        }

        public static string GenerateToken(string secret, string apiKey, string sessionId, string role, string data, double ttl)
        {
            double createTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            double expireTime = createTime + ttl; // seconds since epoch
            int nonce = GetRandomNumber();
            return GenerateToken(secret, apiKey, sessionId, role, expireTime, data, createTime, nonce);
        }


        // http://jasonwatmore.com/post/2018/08/14/aspnet-core-21-jwt-authentication-tutorial-with-example-api
        // https://stackoverflow.com/a/52645563
        // https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/982
        private static string GetTokboxToken(string secret, string apiKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = new JwtSecurityToken(
                issuer: apiKey,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
                    SecurityAlgorithms.HmacSha256)
            );
            token.Payload["ist"] = "project";
            token.Payload["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var jwt = tokenHandler.WriteToken(token);
            return jwt;
        }

        private static string GenerateToken(string secret, string apiKey, string sessionId, string role, double expireTime, string data, double createTime, int nonce)
        {
            string dataString = BuildDataString(sessionId, role, expireTime, data, createTime, nonce);
            return BuildTokenString(secret, apiKey, dataString);
        }

        private static string BuildDataString(string sessionId, string role, double expireTime, string connectionData, double createTime, int nonce)
        {
            StringBuilder dataStringBuilder = new StringBuilder();
            dataStringBuilder.Append(string.Format("session_id={0}", sessionId));
            dataStringBuilder.Append(string.Format("&create_time={0}", (long)createTime));
            dataStringBuilder.Append(string.Format("&nonce={0}", nonce));
            dataStringBuilder.Append(string.Format("&role={0}", role));
            dataStringBuilder.Append(string.Format("&expire_time={0}", (long)expireTime));
            if (!String.IsNullOrEmpty(connectionData))
            {
                dataStringBuilder.Append(string.Format("&connection_data={0}", HttpUtility.UrlEncode(connectionData)));
            }
            return dataStringBuilder.ToString();
        }

        private static string BuildTokenString(string secret, string apiKey, string dataString)
        {
            string signature = EncodeHMAC(dataString, secret);

            StringBuilder innerBuilder = new StringBuilder();
            innerBuilder.Append(string.Format("partner_id={0}", apiKey));
            innerBuilder.Append(string.Format("&sig={0}:{1}", signature, dataString));

            byte[] innerBuilderBytes = Encoding.UTF8.GetBytes(innerBuilder.ToString());
            return "T1==" + Convert.ToBase64String(innerBuilderBytes);
        }

        private static string EncodeHMAC(string input, string key)
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

        private static int GetRandomNumber()
        {
            Random random = new Random();
            return random.Next(0, 999999);
        }
    }
}