using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Katasec.OciClient.Tests;

/// <summary>
/// The immutable manifest digest a caller pins instead of a moving tag. The registry's own
/// <c>Docker-Content-Digest</c> header is optional in the distribution spec, so both the
/// header-present and header-absent paths are real; the point of these tests is that the digest
/// always describes the exact response that was parsed, and that exactly one manifest request is
/// made either way.
///
/// The registry is a stubbed <see cref="HttpMessageHandler"/> rather than a loopback listener:
/// the client addresses registries over https, so a real socket would need a trusted certificate
/// to prove nothing about digests. The handler is reached through the assembly-internal test
/// constructor; the public surface has no handler or endpoint knob.
/// </summary>
public class OciPullDigestTests
{
    private const string Registry = "registry.test";
    private const string Name = "katasec/expert";
    private const string ExpertContent = "# Expert\n\nDo the thing.\n";

    // A digest the registry declares that is NOT the hash of the served bytes. Any test asserting
    // "the header wins" would pass by accident if it matched what the fallback would compute.
    private const string DeclaredDigest =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    [Fact]
    public async Task The_registrys_own_digest_header_is_what_gets_pinned()
    {
        var registry = new StubRegistry(ExpertContent, DeclaredDigest);
        using var client = new OciClient(registry);

        var pulled = await client.PullExpertWithDigestAsync(Registry, Name, "0.1.0");

        Assert.Equal(DeclaredDigest, pulled.ManifestDigest);
        Assert.Equal(ExpertContent, pulled.Content);
        Assert.NotEqual(registry.ComputedManifestDigest, pulled.ManifestDigest);
    }

    [Fact]
    public async Task An_uppercase_digest_header_is_normalized_rather_than_pinned_as_served()
    {
        var registry = new StubRegistry(ExpertContent, DeclaredDigest.ToUpperInvariant());
        using var client = new OciClient(registry);

        var pulled = await client.PullExpertWithDigestAsync(Registry, Name, "0.1.0");

        Assert.Equal(DeclaredDigest, pulled.ManifestDigest);
    }

    // The fallback hashes the bytes that were actually parsed, so it can never name a different
    // response than the one the layer descriptor came from.
    [Fact]
    public async Task Without_the_header_the_digest_is_computed_from_the_served_manifest_bytes()
    {
        var registry = new StubRegistry(ExpertContent, declaredDigest: null);
        using var client = new OciClient(registry);

        var pulled = await client.PullExpertWithDigestAsync(Registry, Name, "0.1.0");

        Assert.Equal(registry.ComputedManifestDigest, pulled.ManifestDigest);
        Assert.Equal(ExpertContent, pulled.Content);
    }

    [Fact]
    public async Task The_manifest_is_requested_exactly_once_whether_or_not_the_header_is_present()
    {
        foreach (var declared in new[] { DeclaredDigest, null })
        {
            var registry = new StubRegistry(ExpertContent, declared);
            using var client = new OciClient(registry);

            await client.PullExpertWithDigestAsync(Registry, Name, "0.1.0");

            Assert.Equal(1, registry.ManifestRequests);
            Assert.Equal(1, registry.BlobRequests);
        }
    }

    // A registry that reports a digest it cannot express correctly is broken. Silently computing
    // one instead would make the resulting pin look authoritative when nothing verified it.
    [Theory]
    [InlineData("not-a-digest")]
    [InlineData("sha256:abc")]
    [InlineData("sha512:1111111111111111111111111111111111111111111111111111111111111111")]
    [InlineData("sha256:zzzz111111111111111111111111111111111111111111111111111111111111")]
    [InlineData("")]
    public async Task A_malformed_digest_header_is_refused_not_silently_replaced(string declared)
    {
        var registry = new StubRegistry(ExpertContent, declared);
        using var client = new OciClient(registry);

        var failure = await Assert.ThrowsAsync<OciException>(
            () => client.PullExpertWithDigestAsync(Registry, Name, "0.1.0"));

        Assert.Contains("Docker-Content-Digest", failure.Message, StringComparison.Ordinal);
        Assert.Equal(0, registry.BlobRequests); // Refused before any blob was fetched.
    }

    [Fact]
    public async Task A_manifest_with_no_layers_fails_before_any_blob_is_pulled()
    {
        var registry = new StubRegistry(ExpertContent, DeclaredDigest) { OmitLayers = true };
        using var client = new OciClient(registry);

        await Assert.ThrowsAsync<OciException>(
            () => client.PullExpertWithDigestAsync(Registry, Name, "0.1.0"));

        Assert.Equal(0, registry.BlobRequests);
    }

    // The compatibility wrapper: existing callers that do not pin a digest keep the exact
    // behaviour they had, and are served by the same single code path.
    [Fact]
    public async Task PullExpertAsync_returns_the_same_content_as_the_digest_aware_pull()
    {
        var registry = new StubRegistry(ExpertContent, DeclaredDigest);
        using var client = new OciClient(registry);

        var content = await client.PullExpertAsync(Registry, Name, "0.1.0");

        Assert.Equal(ExpertContent, content);
        Assert.Equal(1, registry.ManifestRequests);
    }

    [Fact]
    public async Task PullManifestAsync_still_returns_the_parsed_manifest()
    {
        var registry = new StubRegistry(ExpertContent, DeclaredDigest);
        using var client = new OciClient(registry);

        var manifest = await client.PullManifestAsync(Registry, Name, "0.1.0");

        Assert.Equal(OciClient.ExpertArtifactType, manifest.ArtifactType);
        Assert.Equal(0, registry.BlobRequests); // A manifest read pulls no blob.
    }

    /// <summary>
    /// The smallest registry that can answer a manifest and a blob request. It counts each so a
    /// test can prove "exactly one manifest request", and it exposes the digest the fallback
    /// should compute so an assertion never has to restate the hash by hand.
    /// </summary>
    private sealed class StubRegistry(string expertContent, string? declaredDigest) : HttpMessageHandler
    {
        private readonly byte[] _content = Encoding.UTF8.GetBytes(expertContent);

        public bool OmitLayers { get; init; }
        public int ManifestRequests { get; private set; }
        public int BlobRequests { get; private set; }

        public string ComputedManifestDigest =>
            "sha256:" + Convert.ToHexStringLower(SHA256.HashData(ManifestBytes()));

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;

            if (path.Contains("/manifests/", StringComparison.Ordinal))
            {
                ManifestRequests++;
                return Task.FromResult(Manifest());
            }

            if (path.Contains("/blobs/", StringComparison.Ordinal))
            {
                BlobRequests++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(_content),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private HttpResponseMessage Manifest()
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(ManifestBytes()),
            };
            response.Content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue(
                    "application/vnd.oci.image.manifest.v1+json");

            // TryAddWithoutValidation, so a deliberately malformed value reaches the client
            // instead of being rejected by HttpHeaders on the way out.
            if (declaredDigest is not null)
                response.Headers.TryAddWithoutValidation("Docker-Content-Digest", declaredDigest);

            return response;
        }

        private byte[] ManifestBytes()
        {
            var layerDigest = "sha256:" + Convert.ToHexStringLower(SHA256.HashData(_content));
            var manifest = new OciManifest(
                SchemaVersion: 2,
                MediaType: "application/vnd.oci.image.manifest.v1+json",
                Config: new OciDescriptor(OciClient.ExpertConfigMediaType, layerDigest, 0),
                Layers: OmitLayers
                    ? []
                    : [new OciDescriptor(OciClient.ExpertLayerMediaType, layerDigest, _content.Length)],
                ArtifactType: OciClient.ExpertArtifactType);

            return JsonSerializer.SerializeToUtf8Bytes(manifest, OciJsonContext.Default.OciManifest);
        }
    }
}
