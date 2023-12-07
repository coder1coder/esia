using System.Security.Cryptography.X509Certificates;
using EsiaLibCore.Terminal;
using EsiaNET;
using EsiaNET.AspNetCore.Authentication;
using LibCore;

Initializer.Initialize();

const string certificateSerialNumber = "7c000bc6b4ef83375e4afb36410005000bc6b4";

var defaultSignProvider = new SignProvider(certificateSerialNumber, StoreLocation.CurrentUser, StoreName.My);

await GetToken(defaultSignProvider);

return;

async Task GetToken(ISignProvider signProvider)
{
    const string clientId = "MZRV24";

    var options = new EsiaAuthenticationOptions
    {
        ClientId = clientId,
        AuthorizationEndpoint = EsiaConsts.EsiaAuthTestUrl,
        TokenEndpoint = EsiaConsts.EsiaTokenTestUrl,
        SignProvider = signProvider,
        VerifyTokenSignature = true,
        AccessType = AccessType.Offline,
        SaveTokens = true,
        RestOptions = new EsiaRestOptions
        {
            RestUri = "http://esia-portal1.test.gosuslugi.ru/rs"
        },
        Scope = { "openid", "snils" },
    };

    var authService = new EsiaAuthenticationService(new EsiaOptionsMonitor(options));
    
    const string callBackUrl = "http://localhost";
    var getAuthCodeUrl = authService.BuildRedirectUri(callBackUrl);

    var authCode = AuthCodeGetHelper.Get(getAuthCodeUrl, "EsiaTest002@yandex.ru", "11111111", callBackUrl);

    if (string.IsNullOrEmpty(authCode))
    {
        Console.WriteLine("Auth code not found");
        return;
    }
    
    var response = await authService.GetOAuthTokenAsync(new HttpClient(), authCode, callBackUrl);
    Console.WriteLine(!string.IsNullOrEmpty(response.Error?.Message)
        ? response.Error?.Message
        : response.AccessToken);
}