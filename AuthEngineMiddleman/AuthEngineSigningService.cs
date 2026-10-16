using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using AuthEngineShared;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace AuthEngineMiddleman;

public class AuthEngineSigningService(string _authServiceUrl, string? _publicKey = null) : IDisposable
{
    private RSA? _rsa;
    private RsaSecurityKey? _key;

    public async Task Setup()
    {
        string? publicKey = _publicKey;

        if (string.IsNullOrEmpty(publicKey))
        {
            using (HttpClient client = new HttpClient())
            {
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, Path.Combine(_authServiceUrl, "api", "auth", "publickey"));
                HttpResponseMessage res = await client.SendAsync(req);

                try
                {
                    res.EnsureSuccessStatusCode();
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Failed to get public key for authservice.\n{e.Message}");
                    throw;
                }

                string json = await res.Content.ReadAsStringAsync();
                publicKey = JsonDocument.Parse(json).RootElement.GetProperty("key").GetString() ?? throw new InvalidDataException("Public key from authservice is invalid");
            }
        }

        _rsa = RSA.Create();

        _rsa.ImportFromPem(publicKey.Replace("\\n", "\n"));
        _key = new RsaSecurityKey(_rsa) { KeyId = "NexxAuth" };
    }

    public void HandleSigning(JwtBearerOptions options)
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "NexxAuth",

            ValidateAudience = true,
            ValidAudience = "NexxAuth",

            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,

            IssuerSigningKey = _key,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],

            RoleClaimType = ClaimTypes.Role,
            ClockSkew = TimeSpan.FromSeconds(30)
        };

        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                if (context.Request.Cookies.TryGetValue(AuthEngineConsts.AUTHENGINE_COOKIEAUTH, out string? cookie))
                    context.Token = cookie;

                if (context.Request.Headers.TryGetValue(AuthEngineConsts.AUTHENGINE_HEADERAUTH, out StringValues token))
                    context.Token = token;

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.Write(context.Exception?.Message);
                return Task.CompletedTask;
            }
        };
    }

    public void Dispose()
    {
        _rsa?.Dispose();
    }
}
