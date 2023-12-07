using EsiaNET.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace EsiaLibCore.Terminal;

public class EsiaOptionsMonitor: IOptionsMonitor<EsiaAuthenticationOptions>
{
    public EsiaOptionsMonitor(EsiaAuthenticationOptions options)
    {
        CurrentValue = options;
    }

    public EsiaAuthenticationOptions Get(string name) => CurrentValue;

    public IDisposable OnChange(Action<EsiaAuthenticationOptions, string> listener)
    {
        throw new NotImplementedException();
    }

    public EsiaAuthenticationOptions CurrentValue { get; }
}