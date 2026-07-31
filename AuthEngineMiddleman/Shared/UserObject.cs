namespace AuthEngineShared;

public class UserObject
{
    public Guid Id { get; set; }
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public UserRoles Role { get; set; }
    public UserScopes[] Scopes { get; set; } = [];
}
