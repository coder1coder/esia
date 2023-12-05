using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace Esia.Authentication
{
    public sealed class EsiaAuthenticationService : IEsiaAuthenticationService
    {
        public EsiaAuthenticationService(IOptionsMonitor<EsiaAuthenticationOptions> options)
        {
            Options = options.Get(EsiaDefaults.AuthenticationScheme);
        }

        public EsiaAuthenticationService(EsiaAuthenticationOptions options)
        {
            Options = options;
        }

        private EsiaAuthenticationOptions Options { get; }

        public string BuildRedirectUri(string callbackUri = null)
        {
            if ( string.IsNullOrEmpty(callbackUri) ) callbackUri = Options.CallbackPath;

            // Setup required params
            var timestamp = DateTime.UtcNow.ToString("yyyy.MM.dd HH:mm:ss +0000");
            var state = Options.State.ToString("D");
            var scope = string.Join(" ", Options.Scope);
            // Create signature in PKCS#7 detached signature UTF-8
            var clientSecret = BuildClientSecret(scope, timestamp, Options.ClientId, state, bytes =>
                Options.SignProvider.SignMessage(bytes));

            var parameters = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { "scope", scope },
                { "response_type", "code" },
                { "state", state },
                { "timestamp", timestamp },
                { "access_type", Options.AccessType == AccessType.Online ? "online" : "offline" },
                { "redirect_uri", callbackUri },
                { "client_secret", clientSecret }
            };

            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
        }

        /// <summary>
        ///     Returns response for access token by authorization code
        /// </summary>
        /// <param name="httpClient"></param>
        /// <param name="authCode">Authorization code</param>
        /// <param name="callbackUri">Callback uri for ESIA.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>Token response</returns>
        public Task<OAuthTokenResponse> GetOAuthTokenAsync(HttpClient httpClient, string authCode, string callbackUri = null,
            CancellationToken cancellationToken = default)
        {
            if ( httpClient == null ) throw new ArgumentNullException(nameof(httpClient));

            return InternalGetOAuthTokenAsync(httpClient, authCode, callbackUri, TokenRequest.ByAuthCode, cancellationToken);
        }

        public Task<OAuthTokenResponse> GetOAuthTokenByRefreshAsync(HttpClient httpClient, string refreshToken, string callbackUri = null,
            CancellationToken cancellationToken = default)
        {
            if ( httpClient == null ) throw new ArgumentNullException(nameof(httpClient));

            return InternalGetOAuthTokenAsync(httpClient, refreshToken, callbackUri, TokenRequest.ByRefresh, cancellationToken);
        }

        public Task<OAuthTokenResponse> GetOAuthTokenByCredentialsAsync(HttpClient httpClient, string callbackUri = null,
            CancellationToken cancellationToken = default)
        {
            if ( httpClient == null ) throw new ArgumentNullException(nameof(httpClient));

            return InternalGetOAuthTokenAsync(httpClient, string.Empty, callbackUri, TokenRequest.ByCredential, cancellationToken);
        }

        public bool VerifyToken(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken) ) throw new ArgumentNullException(nameof(accessToken));

            var parts = accessToken.Split('.');
            var header = Encoding.UTF8.GetString(Base64Decode(parts[0]));
            var headerObject = JObject.Parse(header);

            return parts.Length > 2 && VerifySignature(headerObject.Value<string>("alg"), $"{parts[0]}.{parts[1]}", parts[2]);
        }

        private async Task<OAuthTokenResponse> InternalGetOAuthTokenAsync(HttpClient httpClient, string code, string callbackUri,
            TokenRequest request, CancellationToken cancellationToken)
        {
            var timestamp = DateTime.UtcNow.ToString("yyyy.MM.dd HH:mm:ss +0000");
            var state = Options.State.ToString("D");
            var scope = string.Join(" ", Options.Scope);
            var clientSecret = BuildClientSecret(scope, timestamp, Options.ClientId, state, (bytes) 
                => Options.SignProvider.SignMessage(bytes));
            
            string paramName;
            string paramValue;
            string grantType;

            switch (request)
            {
                case TokenRequest.ByRefresh:
                    paramName = "refresh_token";
                    paramValue = code;
                    grantType = "refresh_token";
                    break;
                case TokenRequest.ByCredential:
                    paramName = "response_type";
                    paramValue = "token";
                    grantType = "client_credentials";
                    break;
                case TokenRequest.ByAuthCode:
                default:
                    paramName = "code";
                    paramValue = code;
                    grantType = "authorization_code";
                    break;
            }

            var requestParams = new Dictionary<string, string>
            {
                { "client_id", Options.ClientId },
                { paramName, paramValue },
                { "grant_type", grantType },
                { "state", state },
                { "scope", scope },
                { "timestamp", timestamp },
                { "token_type", "Bearer" },
                { "client_secret", clientSecret }
            };

            if ( request != TokenRequest.ByCredential ) requestParams.Add("redirect_uri", callbackUri);

            // Build request content with params
            var requestContent = new FormUrlEncodedContent(requestParams);
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, Options.TokenEndpoint);

            requestMessage.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            requestMessage.Content = requestContent;

            var response = await httpClient.SendAsync(requestMessage, cancellationToken);

            if ( response.IsSuccessStatusCode )
            {
                var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));

                return OAuthTokenResponse.Success(payload);
            }

            var error = "OAuth token endpoint failure: " + await Display(response);

            return OAuthTokenResponse.Failed(new Exception(error));
        }

        /// <summary>
        /// Builds request signature
        /// </summary>
        /// <returns>Signature</returns>
        private static string BuildClientSecret(string scope, string timestamp, string clientId, string state, Func<byte[], byte[]> signMessageAction)
        {
            var signMessage = $"{scope}{timestamp}{clientId}{state}";
            var bytes = Encoding.UTF8.GetBytes(signMessage);
            var encodedSignature = signMessageAction.Invoke(bytes);
            return Base64UrlEncode(encodedSignature);
        }

        /// <summary>
        /// Verifies message signature
        /// </summary>
        private bool VerifySignature(string alg, string message, string signature)
        {
            var bytes = Encoding.UTF8.GetBytes(message);
            var signatureBytes = Base64Decode(signature);
            return Options.SignProvider.VerifyMessage(alg, bytes, signatureBytes);
        }

        private static string Base64UrlEncode(byte[] input)
        {
            if ( input == null ) throw new ArgumentNullException(nameof(input));

            if ( input.Length < 1 ) return string.Empty;

            int endPos;

            var base64Str = Convert.ToBase64String(input);

            for ( endPos = base64Str.Length; endPos > 0; endPos-- )
                if ( base64Str[endPos - 1] != '=' )
                    break;

            var base64Chars = new char[endPos + 1];
            base64Chars[endPos] = (char)('0' + base64Str.Length - endPos);

            for (var iter = 0; iter < endPos; iter++ )
            {
                var c = base64Str[iter];

                base64Chars[iter] = c switch
                {
                    '+' => '-',
                    '/' => '_',
                    '=' => c,
                    _ => c
                };
            }

            return new string(base64Chars);
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

            return Convert.FromBase64String(input); // Standard base64 decoder
        }

        private static async Task<string> Display(HttpResponseMessage response)
        {
            var output = new StringBuilder();

            output.Append("Status: " + response.StatusCode + ";");
            output.Append("Headers: " + response.Headers + ";");
            output.Append("Body: " + await response.Content.ReadAsStringAsync() + ";");

            return output.ToString();
        }
    }
}