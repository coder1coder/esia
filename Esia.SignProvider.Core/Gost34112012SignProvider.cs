using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Esia.SignProvider.Core
{
    public static class Gost34112012SignProvider
    {

        /// <summary>
        /// Групповой идентификатор криптографических параметров алгоритмов
        /// Алгоритм ГОСТ Р 34.10-2012 для ключей длины 256 бит, используемый при экспорте/импорте ключей
        /// </summary>
        /// <remarks><see cref="http://cpdn.cryptopro.ru/content/csp40/html/group___pro_c_s_p_ex_DP8.html"/></remarks>
        private const string EsiaGost34112012AlgOid = "1.2.643.7.1.1.1.1"; 
        
        public static byte[] SignDetached(byte[] data, X509Certificate2 certificate)
        {
            var contentInfo = new ContentInfo(data);
            var signedCms = new SignedCms(contentInfo, true);
            var cmsSigner = new CmsSigner(certificate);
            signedCms.ComputeSignature(cmsSigner);
            return signedCms.Encode();
        }

        public static bool Verify(byte[] data, byte[] signature)
        {
            var contentInfo = new ContentInfo(new Oid(EsiaGost34112012AlgOid), data);
            var signedCms = new SignedCms(contentInfo, true);
            Array.Reverse(signature, 0, signature.Length);

            try
            {
                signedCms.Decode(signature);
                signedCms.CheckSignature(true);
            }
            catch (CryptographicException)
            {
                return false;
            }

            return true;
        }
        
        /// <summary>
        /// Проверка подписи JWT в формате HEADER.PAYLOAD.SIGNATURE.
        /// </summary>
        /// <param name="data">HEADER.PAYLOAD в формате Base64url</param>
        /// <param name="signature">SIGNATURE в формате Base64url</param>
        /// <param name="publicKey">Публичный ключ</param>
        /// <returns></returns>
        public static bool Verify(byte[] data, byte[] signature, PublicKey publicKey)
        {
            if (publicKey is null)
                return false;
            
            using var provider = new Gost3411_2012_256CryptoServiceProvider();
            var csp = (Gost3410_2012_256CryptoServiceProvider) publicKey.Key;
            return csp.VerifyData(data, signature, HashAlgorithmName.Gost3411_2012_256);
        }
    }
}