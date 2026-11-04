using System.Security.Cryptography;
using System.Text.Json;

namespace AuthEngineMiddleman.Helpers;

public static class AuthEngineSignatureHelper
{
    public static byte[] Sign<T>(T obj, string privateKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(privateKey), out _);

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(obj);
        return rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static bool Verify<T>(T obj, byte[] signature, string publicKey)
    {
        using RSA rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out _);

        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(obj);
        return rsa.VerifyData(bytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
