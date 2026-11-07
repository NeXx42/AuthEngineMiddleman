using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthEngineShared;

namespace AuthEngineMiddleman.Auth;

public class AuthEngineMiddlemanService
{
    private readonly string _authServiceUrl;
    private readonly string? _authServiceToken;

    public AuthEngineMiddlemanService(string authServiceUrl, string? authServiceToken = null)
    {
        _authServiceUrl = authServiceUrl;
        _authServiceToken = authServiceToken;
    }

    public async Task<string?> Authenticate(string email, string password)
    {
        try
        {
            string? token = await SendRequestToAuthService<string>(HttpMethod.Post, "auth", new
            {
                email,
                password
            });

            return token;
        }
        catch
        {
            throw;
        }
    }

    public async Task<string?> Register(string email, string displayName, string password)
    {
        try
        {
            string? token = await SendRequestToAuthService<string>(HttpMethod.Post, "auth/register", new
            {
                email,
                displayName,
                password
            });

            return token;
        }
        catch
        {
            throw;
        }
    }

    public async Task<UserObject[]> GetUsers()
    {
        try
        {
            UserObject[]? usrs = await SendRequestToAuthService<UserObject[]>(HttpMethod.Get, "admin/users", null);

            if (usrs == null)
                return [];

            return usrs;
        }
        catch
        {
            throw;
        }
    }

    public struct PublicKeyContainer
    {
        public string Key { get; set; }
    }

    public async Task<string> GetPublicKey()
    {
        return (await SendRequestToAuthService<PublicKeyContainer>(HttpMethod.Get, "auth/publickey", null))!.Key;
    }

    public async Task<T?> SendRequestToAuthService<T>(HttpMethod method, string path, object? json)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpRequestMessage msg = new HttpRequestMessage(method, Path.Combine(_authServiceUrl, "api", path));

                if (!string.IsNullOrEmpty(_authServiceToken))
                    msg.Headers.Add(AuthEngineConsts.AUTHENGINE_HEADERAUTH, _authServiceToken);

                if (json != null)
                    msg.Content = new StringContent(JsonSerializer.Serialize(json), Encoding.UTF8, "application/json");

                HttpResponseMessage res = await client.SendAsync(msg);
                res.EnsureSuccessStatusCode();

                string resText = await res.Content!.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(resText, new JsonSerializerOptions()
                {
                    PropertyNameCaseInsensitive = true
                });
            }
        }
        catch
        {
            throw;
        }
    }
}
