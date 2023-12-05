using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json.Linq;

namespace Esia.SignProvider.Core
{
    public static class TokenValidator
    {
        public static bool VerifyToken(string accessToken, X509Certificate2 certificate)
        {
            if (string.IsNullOrEmpty(accessToken)) 
                throw new ArgumentNullException(nameof(accessToken));

            var parts = accessToken.Split('.');
            var header = Encoding.UTF8.GetString(Base64Decode(parts[0]));
            var headerObject = JObject.Parse(header);

            return parts.Length > 2 
                   && VerifySignature(headerObject.Value<string>("alg"), $"{parts[0]}.{parts[1]}", parts[2], certificate);
        }
        
        private static bool VerifySignature(string alg, string message, string signature, X509Certificate2 certificate)
        {
            if (certificate is null)
                return false;
            
            var bytes = Encoding.UTF8.GetBytes(message);
            var signatureBytes = Base64Decode(signature);
            
            return alg.ToUpperInvariant() switch
            {
                "GOST3410_2012_256" => Gost34112012SignProvider.Verify(bytes, signatureBytes, certificate.PublicKey),
                "RS256" => new RSACryptoServiceProvider().VerifyData(bytes, signatureBytes, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1),
                _ => false
            };
        }

        private static bool Test(string tokenStr)
        {
            var tokenParts = tokenStr.Split('.');

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters
                {
                    Modulus = FromBase64Url("w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJAjEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aDJWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzekuGcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSjRHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6FKjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ"),
                    Exponent = FromBase64Url("AQAB")
                });

            var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            return rsaDeformatter.VerifySignature(hash, FromBase64Url(tokenParts[2]));
        }

        private static byte[] FromBase64Url(string base64Url)
        {
            var padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }
        
        private static byte[] Base64Decode(string input)
        {
            input = input.Replace('-', '+').Replace('_', '/');
            switch ( input.Length % 4 )
            {
                case 0:
                    break;
                case 2:
                    input = $"{input}==";
                    break;
                case 3:
                    input = $"{input}=";
                    break;
                default:
                    throw new Exception("Illegal base64url string!");
            }
            return Convert.FromBase64String(input);
        }
    }
}