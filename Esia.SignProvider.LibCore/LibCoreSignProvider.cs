using System;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using Esia.Authentication;

namespace Esia.SignProvider.LibCore;

public class LibCoreSignProvider: ISignProvider
{
    public byte[] SignMessage(byte[] message)
    {
        const string mz13 = "1200630e882c97260aaecc37c9000100630e88";
        using var gostCert = LibCoreCertificateStore.FindBySerialNumberOrThrow(mz13, StoreLocation.CurrentUser, StoreName.My);
        {
            var contentInfo = new ContentInfo(message);
            var signedCms = new SignedCms(contentInfo, true);
            var cmsSigner = new CmsSigner(gostCert);
            signedCms.ComputeSignature(cmsSigner);
            return signedCms.Encode();
        }
    }

    public bool VerifyMessage(string alg, byte[] message, byte[] signature)
    {
        throw new NotImplementedException();
    }
}