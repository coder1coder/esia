using System;
using System.Threading.Tasks;
using Esia.SignProvider.Api.Contracts;
using Esia.SignProvider.Core;
using Microsoft.AspNetCore.Mvc;

namespace Esia.SignProvider.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class VerifyController : ControllerBase
    {
        [HttpPost]
        public Task<bool> Verify([FromBody] VerifyRequest request)
        {
            if (request?.Data is null) return Task.FromResult(false);
            if (request.Signature is null) return Task.FromResult(false);
            
            var dataBytes = Convert.FromBase64String(request.Data);
            var signatureBytes = Convert.FromBase64String(request.Signature);
            return Task.FromResult(Gost34112012SignProvider.Verify(dataBytes, signatureBytes));
        }
    }
}