namespace Katasec.OciClient.Tests;

/// <summary>
/// Integration tests against ghcr.io/katasec. Requires GITHUB_TOKEN env var.
/// Run with: GITHUB_TOKEN=$(gh auth token) dotnet test
/// </summary>
[Trait("Category", "Integration")]
public class OciClientIntegrationTests
{
    private const string Registry = "ghcr.io";
    private const string Org      = "katasec";

    private static OciClient Client()
    {
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN")
            ?? throw new InvalidOperationException("GITHUB_TOKEN env var required for integration tests");
        return new OciClient(token);
    }

    [Fact]
    public async Task PullManifest_KubernetesArchitect_ReturnsManifestWithOneLayer()
    {
        using var client = Client();

        var manifest = await client.PullManifestAsync(Registry, $"{Org}/kubernetes-architect", "0.1.0");

        Assert.Equal(2, manifest.SchemaVersion);
        Assert.Single(manifest.Layers);
        Assert.Equal(OciClient.ExpertLayerMediaType, manifest.Layers[0].MediaType);
        Assert.StartsWith("sha256:", manifest.Layers[0].Digest);
    }

    [Fact]
    public async Task PullExpert_KubernetesArchitect_ContainsFrontmatter()
    {
        using var client = Client();

        var content = await client.PullExpertAsync(Registry, $"{Org}/kubernetes-architect", "0.1.0");

        Assert.StartsWith("---", content.TrimStart());
        Assert.Contains("name: KubernetesArchitect", content);
    }

    [Theory]
    [InlineData("kubernetes-architect")]
    [InlineData("security-architect")]
    [InlineData("principal-reviewer")]
    [InlineData("pitch-drafter")]
    [InlineData("pitch-critic")]
    [InlineData("pitch-judge")]
    [InlineData("pitch-reviser")]
    [InlineData("pitch-writer")]
    [InlineData("context-overloaded")]
    [InlineData("quality-judge")]
    public async Task PullExpert_AllPackages_HaveFrontmatter(string packageName)
    {
        using var client = Client();

        var content = await client.PullExpertAsync(Registry, $"{Org}/{packageName}", "0.1.0");

        Assert.StartsWith("---", content.TrimStart());
        Assert.Contains("name:", content);
    }

    [Fact]
    public async Task PushAndPull_RoundTrip_ContentMatches()
    {
        using var client = Client();

        var expertMd = """
            ---
            name: TestExpert
            input: Test input
            output: Test output
            ---

            You are a test expert. This artifact was pushed by the OciClient integration test.
            """;

        var testName = $"{Org}/test-expert-{DateTime.UtcNow:yyyyMMddHHmmss}";

        await client.PushExpertAsync(Registry, testName, "test", expertMd);

        var pulled = await client.PullExpertAsync(Registry, testName, "test");

        Assert.Equal(expertMd, pulled);
    }
}
