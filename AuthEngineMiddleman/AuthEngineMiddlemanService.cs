using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthEngineShared;

namespace AuthEngineMiddleman;

public class AuthEngineMiddlemanService
{
    private readonly string _authServiceUrl;
    private readonly string _authServiceToken;

    public AuthEngineMiddlemanService(string authServiceUrl, string authServiceToken)
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

    public async Task<UserObject?> DecodePrincipal(ClaimsPrincipal user)
    {
        string? userGuid = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        string? displayName = user.FindFirst(ClaimTypes.Name)?.Value;
        string? email = user.FindFirst(ClaimTypes.Email)?.Value;
        string? role = user.FindFirst(ClaimTypes.Role)?.Value;
        string[] scopes = user.FindAll(ClaimTypes.Authentication).Select(v => v.Value).ToArray();

        if (Guid.TryParse(userGuid, out Guid id))
        {
            UserRoles userRole = UserRoles.None;
            Enum.TryParse(role, ignoreCase: true, out userRole);

            List<UserScopes> userScopes = new(scopes.Length);

            foreach (string s in scopes)
                if (Enum.TryParse(s, out UserScopes scope))
                    userScopes.Add(scope);

            return new UserObject()
            {
                Id = id,
                Email = email!,
                DisplayName = displayName!,
                Scopes = userScopes.ToArray(),
            };
        }

        return null;
    }

    public async Task<T?> SendRequestToAuthService<T>(HttpMethod method, string path, object? json)
    {
        try
        {
            using (HttpClient client = new HttpClient())
            {
                HttpRequestMessage msg = new HttpRequestMessage(method, Path.Combine(_authServiceUrl, "api", path));
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
