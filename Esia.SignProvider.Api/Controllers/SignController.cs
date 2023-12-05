using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Esia.SignProvider.Common;
using Esia.SignProvider.Core;
using Microsoft.AspNetCore.Mvc;

namespace Esia.SignProvider.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SignController : ControllerBase
    {
        [HttpPost("detached")]
        public Task<string> SignDetached([FromBody] string data)
        {
            var bytes = Convert.FromBase64String(data);
            const string mz12 = "7c000bbd82f106bf993b58ba490004000bbd82";
            const string mz13 = "1200630e882c97260aaecc37c9000100630e88";
            using var certificate = CertificateStore.FindBySerialNumberOrThrow(mz12, StoreLocation.CurrentUser, StoreName.My);
            var response = Gost34112012SignProvider.SignDetached(bytes, certificate);
            return Task.FromResult(Convert.ToBase64String(response));
        }
    }
}