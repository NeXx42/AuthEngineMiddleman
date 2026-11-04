namespace AuthEngineMiddleman.Shared;

public class SignedEntitlement
{
    public required Guid UserId { get; set; }
    public required Guid AppId { get; set; }
    public required string UserName { get; set; }
    public required string HardwareId { get; set; }
    public required byte[] Signature { get; set; }
}