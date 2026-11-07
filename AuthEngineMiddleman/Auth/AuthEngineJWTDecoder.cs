using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthEngineShared;

namespace AuthEngineMiddleman.Auth;

public static class AuthEngineJWTDecoder
{
    /// <summary>
    /// doesn't validate the jwt
    /// </summary>
    /// <param name="jwtToken"></param>
    /// <returns></returns>
    public static UserObject? DecodePrincipal(string jwtToken)
    {
        JwtSecurityToken token = new JwtSecurityTokenHandler().ReadJwtToken(jwtToken);
        return DecodePrincipal(new ClaimsPrincipal(new ClaimsIdentity(token.Claims, "jwt")));
    }

    public static UserObject? DecodePrincipal(ClaimsPrincipal user)
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
}
