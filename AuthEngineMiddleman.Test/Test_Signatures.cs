using System.Security.Cryptography;
using System.Text.Json;
using AuthEngineMiddleman.Helpers;

namespace AuthEngineMiddleman.Test;

public class Test_Signatures
{
    public class SignedData_Test
    {
        public required string Name { get; set; }
        public required Guid RandomId { get; set; }

        public required byte[] Signature { get; set; }
    }

    [Test]
    public async Task Test_Signature()
    {
        SignedData_Test signClass = new SignedData_Test
        {
            Name = "Test",
            RandomId = Guid.NewGuid(),

            Signature = []
        };

        using RSA rsa = RSA.Create(3072);
        string privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
        string publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        byte[] signature = AuthEngineSignatureHelper.Sign(signClass, privateKey);
        signClass.Signature = signature;

        // simulate response from api
        string json = JsonSerializer.Serialize(signClass);
        SignedData_Test res = JsonSerializer.Deserialize<SignedData_Test>(json)!;

        byte[] retrievedSignature = signClass.Signature;
        signClass.Signature = [];

        Is.True.Equals(AuthEngineSignatureHelper.Verify(signClass, retrievedSignature, publicKey));
    }

    [Test]
    public async Task Test_Signature_Fail()
    {
        SignedData_Test signClass = new SignedData_Test
        {
            Name = "Test",
            RandomId = Guid.NewGuid(),

            Signature = []
        };

        using RSA rsa = RSA.Create(3072);
        string privateKey = Convert.ToBase64String(rsa.ExportPkcs8PrivateKey());
        string publicKey = Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo());

        byte[] signature = AuthEngineSignatureHelper.Sign(signClass, privateKey);
        signClass.Signature = signature;

        signClass.RandomId = Guid.NewGuid();

        // simulate response from api
        string json = JsonSerializer.Serialize(signClass);
        SignedData_Test res = JsonSerializer.Deserialize<SignedData_Test>(json)!;

        byte[] retrievedSignature = signClass.Signature;
        signClass.Signature = [];

        Is.False.Equals(AuthEngineSignatureHelper.Verify(signClass, retrievedSignature, publicKey));
    }
}
