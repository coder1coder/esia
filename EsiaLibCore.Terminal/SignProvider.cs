using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using EsiaNET.AspNetCore.Authentication;
using LibCore.Security.Cryptography;

namespace EsiaLibCore.Terminal;

public class SignProvider: ISignProvider
{
    private readonly string _serialNumber;
    private readonly StoreLocation _storeLocation;
    private readonly StoreName _storeName;
    
    public SignProvider(string serialNumber, StoreLocation storeLocation, StoreName storeName)
    {
        _serialNumber = serialNumber;
        _storeLocation = storeLocation;
        _storeName = storeName;
    }
    
    public byte[] SignMessage(byte[] message)
    {
        using var certificate = CertificateStore.FindBySerialNumberOrThrow(_serialNumber, _storeLocation, _storeName);
        {
            var contentInfo = new ContentInfo(message);
            var signedCms = new SignedCms(contentInfo, true);
            var cmsSigner = new CmsSigner(certificate);
            signedCms.ComputeSignature(cmsSigner);
            var signature = signedCms.Encode();
            // Console.WriteLine($"CMS Sign: {Convert.ToBase64String(signature)}");
            return signature;
        }
    }

    public bool VerifyMessage(string alg, byte[] message, byte[] signature)
    {
        try
        {
            const string mz13 = "1200630e882c97260aaecc37c9000100630e88";
            using var certificate = CertificateStore.FindBySerialNumberOrThrow(mz13, StoreLocation.CurrentUser, StoreName.My);
            {
                //Переварачиваем байты, так как используется RAW подпись
                Array.Reverse(signature, 0, signature.Length);
                var csp = (Gost3410_2012_256CryptoServiceProvider) certificate.PublicKey.Key;
                return csp.VerifyData(message, signature, CpHashAlgorithmName.Gost3411_2012_256);
            }
        }
        catch (Exception)
        {
            return false;
        }
    }
}