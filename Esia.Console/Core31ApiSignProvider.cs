using System.Net.Http.Json;
using Esia.Authentication;

namespace Esia.Console
{
    public class Core31ApiSignProvider : ISignProvider
    {
        private const string EsiaSignApiUrl = "https://localhost:8045";

        public byte[] SignMessage(byte[] message)
        {
            var base64String = Convert.ToBase64String(message);
            var result = new HttpClient().PostAsJsonAsync($"{EsiaSignApiUrl}/sign/detached",
                base64String).Result;
            
            result.EnsureSuccessStatusCode();
            var signature = result.Content.ReadAsStringAsync().Result;
            return Convert.FromBase64String(signature);
        }

        public bool VerifyMessage(string alg, byte[] message, byte[] signature)
        {
            var response = new HttpClient().PostAsJsonAsync($"{EsiaSignApiUrl}/verify", new Dictionary<string, string>
            {
                { "Alg", alg },
                { "Data", Convert.ToBase64String(message) },
                { "Signature", Convert.ToBase64String(signature) }
            }).Result;
            
            return response.IsSuccessStatusCode && response.Content.ReadFromJsonAsync<bool>().Result;
        }
    }
}