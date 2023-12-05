using System.Text;
using Esia.Authentication;
using Esia.Authentication.Esia;
using Esia.Console;
using Esia.SignProvider.LibCore;
using Microsoft.AspNetCore.Authentication.OAuth;

const string clientId = "MZRV24";
const string testClientId = "MZ2";

var options = new EsiaAuthenticationOptions
{
    Scope = { "id_doc", "openid", "fullname", "snils" },
    ClientId = testClientId,
    AccessType = AccessType.Offline,
    AuthorizationEndpoint = EsiaConstants.EsiaAuthTestUrl,
    TokenEndpoint = EsiaConstants.EsiaTokenTestUrl,
    
    SignProvider = 
        //new LibCoreSignProvider()
        new Core31ApiSignProvider()
         ,
    VerifyTokenSignature = false,
    SaveTokens = true,
    Events = new OAuthEvents
    {
        OnCreatingTicket = c =>
        {
            var accessToken = c.AccessToken;
            return Task.CompletedTask;
        }
    }
};

var signedMessage = options.SignProvider.SignMessage(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));
Console.WriteLine(string.Join(", ", signedMessage));

var authService = new EsiaAuthenticationService(options);
var tokenIsValid = authService.VerifyToken("eyJ2ZXIiOjEsInR5cCI6IkpXVCIsInNidCI6ImFjY2VzcyIsImFsZyI6IlJTMjU2In0.eyJuYmYiOjE3MDE3MDA3ODEsInNjb3BlIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcL3Vzcl9zZWM_bW9kZT13Jm9pZD0xMDAwNzMzMDY4IGh0dHA6XC9cL2VzaWEuZ29zdXNsdWdpLnJ1XC91c3JfaW5mP21vZGU9dyZvaWQ9MTAwMDczMzA2OCBodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvdXNyX3RybT9tb2RlPXcmb2lkPTEwMDA3MzMwNjggb3BlbmlkIiwiaXNzIjoiaHR0cDpcL1wvZXNpYS1wb3J0YWwxLnRlc3QuZ29zdXNsdWdpLnJ1XC8iLCJ1cm46ZXNpYTpzaWQiOiJjNTdjYWFmYy03MTJhLWQyOWMtMWU0NC1iZmMyYjI2ZTkzOWQiLCJ1cm46ZXNpYTpzYmpfaWQiOjEwMDA3MzMwNjgsImV4cCI6MTcwMTcxMTU4MSwiaWF0IjoxNzAxNzAwNzgxLCJjbGllbnRfaWQiOiJQR1UifQ.tVmDRC2Nw_pcu6UisYAGgekUfuQtdhfJMF3mYrmkD45ScnVhmLUNUIOAh3IbkLVgRdjSwPHd4RkrVZn8OuAYoS5-NrWv8B7byG7gBQzTyQJE-cY7Yovsn9jhjjow38dY8ZAjXRqHU4Jo_dbxMTj6oisH4uAzwten5SvC7hrdsauWU5CTIvu3j0pVrEmurAsn358-IP5w8JAxPXPmXCrHdr2BK0rTIRoeNhb6VaDi6mzBArK0brh5KcgpaNzTVzLNR4fb1_Z7L5eGluV6ul8STwOacQgvf4k4n9-FxsPZDf6B-Ign-YOTN60bTS_Hm226IDcVVaVNj9kbSMfMsTe6Gg");

Console.WriteLine(tokenIsValid);


try
{
    var response = await authService.GetOAuthTokenByCredentialsAsync(new HttpClient(), string.Empty);
    Console.WriteLine(response.AccessToken);
}
catch (Exception e)
{
    Console.WriteLine(e);
}