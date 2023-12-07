using System.Security.Cryptography.X509Certificates;
using EsiaLibCore.Terminal;
using EsiaNET;
using EsiaNET.AspNetCore.Authentication;

LibCore.Initializer.Initialize();

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
        VerifyTokenSignature = false,
        SaveTokens = true,
        Scope = { "openid", "snils" }
    };

    var authService = new EsiaAuthenticationService(new EsiaOptionsMonitor(options));
    
    try
    {
        var response = await authService.GetOAuthTokenByCredentialsAsync(new HttpClient(), string.Empty);
        Console.WriteLine(response.Error?.Message);
        Console.WriteLine(response.AccessToken);
    }
    catch (Exception e)
    {
        Console.WriteLine(e);
    }
}