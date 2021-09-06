using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.IO;
namespace NETFrameworkDome
{
    class Program
    {
        public static string SignatureMessage(string certFileName, string password, byte[] dataTobeSign)
        {

            byte[] pfxCert = File.ReadAllBytes(certFileName);
            SecureString pwd = new SecureString();
            char[] pwdCharArray = password.ToCharArray();
            for (int i = 0; i < pwdCharArray.Length; i++)
            {
                pwd.AppendChar(pwdCharArray[i]);
            }

            X509Certificate2 cert = new X509Certificate2(pfxCert, pwd);

            CmsSigner signer = new CmsSigner(cert);
            signer.DigestAlgorithm = new Oid("1.3.14.3.2.26", "sha1");
            signer.IncludeOption = X509IncludeOption.EndCertOnly;

            ContentInfo signedData = new ContentInfo(dataTobeSign);
            SignedCms cms = new SignedCms(signedData, true);
            cms.ComputeSignature(signer);
            byte[] signature = cms.Encode();
            return Convert.ToBase64String(signature);
        }
        static void Main(string[] args)
        {
            var input = File.ReadAllText("datas.txt");
            var bytes = Encoding.UTF8.GetBytes(input);
            var str = SignatureMessage(@"95566SW010001585.pfx", "kys12345", bytes);
            Console.WriteLine(str);
            Console.ReadKey();
        }
    }
}
