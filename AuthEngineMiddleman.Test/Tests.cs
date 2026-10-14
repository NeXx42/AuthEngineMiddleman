namespace AuthEngineMiddleman.Test;

public class Tests
{
    private AuthEngineMiddlemanService _service;
    private const string TestUserEmail = "test@gmail.com";

    [SetUp]
    public async Task Setup()
    {
        _service = new AuthEngineMiddlemanService("http://localhost:5050", Guid.Empty.ToString());

        string? usr = await _service.Authenticate(TestUserEmail, "test123");

        if (string.IsNullOrEmpty(usr))
            await _service.Register(TestUserEmail, "test", "test123");
    }

    [Test]
    public async Task GetUsers()
    {
        var res = await _service.GetUsers();
        var testUsr = res.FirstOrDefault(r => r.Email?.Equals(TestUserEmail) ?? false);

        Is.Not.Null.Equals(testUsr);
    }
}
