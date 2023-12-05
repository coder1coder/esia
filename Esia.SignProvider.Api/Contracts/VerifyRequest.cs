namespace Esia.SignProvider.Api.Contracts
{
    public class VerifyRequest
    {
        public string Data { get; set; }
        public string Signature { get; set; }
    }
}