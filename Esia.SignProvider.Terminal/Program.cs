using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Esia.SignProvider.Common;
using Esia.SignProvider.Core;

namespace Esia.SignProvider.Terminal
{
    class Program
    {
        private const string EsiaGostToken = "eyJ2ZXIiOjEsInR5cCI6IkpXVCIsInNidCI6ImF1dGhvcml6YXRpb25fY29kZSIsImFsZyI6IkdPU1QzNDEwXzIwMTJfMjU2In0.eyJuYmYiOjE2MzE1MjUwODksInNjb3BlIjoib3BlbmlkIGJpbyIsImF1dGhfdGltZSI6MTYzMTUyNDcyNiwiaXNzIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcLyIsInVybjplc2lhOnNpZCI6IjkyNjE5MDhlLWM0NGQtNGMyZS1hMWFjLWZiNDE1MzM5NjA2MCIsInVybjplc2lhOmNsaWVudDpzdGF0ZSI6IjRjOWQ3YmE5LTc3MDAtNDMyMS05Nzc0LTc5YTBjNjllNTkyYiIsImF1dGhfbXRoZCI6IlBXRCIsInVybjplc2lhOnNiaiI6eyJ1cm46ZXNpYTpzYmo6dHlwIjoiUCIsInVybjplc2lhOnNiajppc190cnUiOnRydWUsInVybjplc2lhOnNiajpvaWQiOjI0NDMzNjQyMiwidXJuOmVzaWE6c2JqOm5hbSI6IjAyMi01ODgtMjM2IDQ5IiwidXJuOmVzaWE6c2JqOmVpZCI6NDgzNTczOH0sImV4cCI6MTYzMTUyNTMyOSwicGFyYW1zIjp7InJlbW90ZV9pcCI6IjkxLjc3LjI0NS4xNSIsInVzZXJfYWdlbnQiOiJNb3ppbGxhXC81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXRcLzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZVwvOTMuMC40NTc3LjYzIFNhZmFyaVwvNTM3LjM2In0sImlhdCI6MTYzMTUyNTA4OSwiY2xpZW50X2lkIjoiNzcxNjAxIn0.KDGX6JLn3O59c3yCU-DZSCH-gaXz1n4FHicM8AEQxX11sHTYFQ014sUS0ZnjjF5Gp0vvMgfNY2SoO6ksqqMWTw";
        private const string EsiaRsaToken = "eyJ2ZXIiOjEsInR5cCI6IkpXVCIsInNidCI6ImFjY2VzcyIsImFsZyI6IlJTMjU2In0.eyJuYmYiOjE3MDE3MDA3ODEsInNjb3BlIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcL3Vzcl9zZWM_bW9kZT13Jm9pZD0xMDAwNzMzMDY4IGh0dHA6XC9cL2VzaWEuZ29zdXNsdWdpLnJ1XC91c3JfaW5mP21vZGU9dyZvaWQ9MTAwMDczMzA2OCBodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvdXNyX3RybT9tb2RlPXcmb2lkPTEwMDA3MzMwNjggb3BlbmlkIiwiaXNzIjoiaHR0cDpcL1wvZXNpYS1wb3J0YWwxLnRlc3QuZ29zdXNsdWdpLnJ1XC8iLCJ1cm46ZXNpYTpzaWQiOiJjNTdjYWFmYy03MTJhLWQyOWMtMWU0NC1iZmMyYjI2ZTkzOWQiLCJ1cm46ZXNpYTpzYmpfaWQiOjEwMDA3MzMwNjgsImV4cCI6MTcwMTcxMTU4MSwiaWF0IjoxNzAxNzAwNzgxLCJjbGllbnRfaWQiOiJQR1UifQ.tVmDRC2Nw_pcu6UisYAGgekUfuQtdhfJMF3mYrmkD45ScnVhmLUNUIOAh3IbkLVgRdjSwPHd4RkrVZn8OuAYoS5-NrWv8B7byG7gBQzTyQJE-cY7Yovsn9jhjjow38dY8ZAjXRqHU4Jo_dbxMTj6oisH4uAzwten5SvC7hrdsauWU5CTIvu3j0pVrEmurAsn358-IP5w8JAxPXPmXCrHdr2BK0rTIRoeNhb6VaDi6mzBArK0brh5KcgpaNzTVzLNR4fb1_Z7L5eGluV6ul8STwOacQgvf4k4n9-FxsPZDf6B-Ign-YOTN60bTS_Hm226IDcVVaVNj9kbSMfMsTe6Gg";
        
        static void Main(string[] args)
        {
            SignData();
            VerifyGostToken(EsiaGostToken);
            VerifyRsaToken(EsiaRsaToken);
        }

        private static void SignData()
        {
            var bytes = Encoding.UTF8.GetBytes(Guid.NewGuid().ToString());
            const string mz12 = "7c000bbd82f106bf993b58ba490004000bbd82";
            const string mz13 = "1200630e882c97260aaecc37c9000100630e88";
            using var certificate = CertificateStore.FindBySerialNumberOrThrow(mz12, StoreLocation.CurrentUser, StoreName.My);
            var signed = Gost34112012SignProvider.SignDetached(bytes, certificate);
            Console.WriteLine(string.Join(", ", signed));
        }

        private static void VerifyGostToken(string accessToken)
        {
            const string testEsiaGost2012 = "014018b300ffafd593465c5c2de413c849";
            using var certificate = CertificateStore.FindBySerialNumberOrThrow(testEsiaGost2012, StoreLocation.LocalMachine, StoreName.My);
            var tokenValidationResult = TokenValidator.VerifyToken(accessToken, certificate);
            Console.WriteLine("GOST token validation: " + tokenValidationResult);
        }

        private static void VerifyRsaToken(string accessToken)
        {
            const string rsaFromConnection = "559cbf8e3e6ea8de4c8b8fb2";
            using var certificate = CertificateStore.FindBySerialNumberOrThrow(rsaFromConnection, StoreLocation.LocalMachine, StoreName.My);
            var tokenValidationResult = TokenValidator.VerifyToken(accessToken, certificate);
            Console.WriteLine("RSA token validation: " + tokenValidationResult);
        }
    }
}