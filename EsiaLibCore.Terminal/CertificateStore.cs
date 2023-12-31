﻿using System.Security.Cryptography.X509Certificates;

namespace EsiaLibCore.Terminal
{
    public static class CertificateStore
    {
        public static X509Certificate2 FindBySerialNumberOrThrow(string serialNumber, StoreLocation storeLocation, StoreName storeName)
        {
            var certificateStore = new X509Store(storeName, storeLocation);
            certificateStore.Open(OpenFlags.OpenExistingOnly);
            var certificate = certificateStore.Certificates.Find(X509FindType.FindBySerialNumber, serialNumber, false)
                .FirstOrDefault();
            
            certificateStore.Close();
            
            if (certificate == null)
                throw new Exception("Certificate not found");
        
            return certificate;
        }
    }
}

