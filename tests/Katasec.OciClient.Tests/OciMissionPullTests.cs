using System.Net;
using System.Security.Cryptography;
using System.Text.Json;

namespace Katasec.OciClient.Tests;

public class OciMissionPullTests
{
    private const string Registry = "registry.test";
    private const string Name = "team/mission";
    private static readonly byte[] Bundle = "verified bundle bytes"u8.ToArray();

    [Fact]
    public async Task Tag_and_digest_return_the_verified_bundle_and_same_manifest_identity()
    {
        var registry = new MissionRegistry();
        using var client = new OciClient(registry);
        var byTag = await client.PullMissionWithDigestAsync(Registry, Name, "latest");
        var byDigest = await client.PullMissionWithDigestAsync(Registry, Name, byTag.ManifestDigest);
        Assert.Equal(Bundle, byTag.Bundle);
        Assert.Equal(Hash(Bundle), byTag.LayerDigest);
        Assert.Equal(Bundle.LongLength, byTag.LayerByteLength);
        Assert.Equal(registry.ManifestDigest, byTag.ManifestDigest);
        Assert.Equal(byTag.ManifestDigest, byDigest.ManifestDigest);
        Assert.Equal(byTag.Bundle, byDigest.Bundle);
        Assert.Equal(2, registry.ManifestRequests);
        Assert.Equal(2, registry.BlobRequests);
    }

    [Fact]
    public async Task Existing_mission_pull_uses_the_same_verified_path()
    {
        var registry = new MissionRegistry { BlobBytes = "corrupt same length!!"u8.ToArray() };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionAsync(Registry, Name, "latest"));
        Assert.Equal(1, registry.ManifestRequests);
        Assert.Equal(1, registry.BlobRequests);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public async Task Nonpositive_budget_fails_without_network(long budget)
    {
        var registry = new MissionRegistry();
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            client.PullMissionWithDigestAsync(Registry, Name, "latest", maxBundleBytes: budget));
        Assert.Equal(0, registry.ManifestRequests);
    }

    public static IEnumerable<object[]> InvalidManifests()
    {
        var good = Manifest();
        yield return [good with { SchemaVersion = 1 }];
        yield return [good with { MediaType = "application/json" }];
        yield return [good with { ArtifactType = OciClient.ExpertArtifactType }];
        yield return [good with { Config = null! }];
        yield return [good with { Config = good.Config with { MediaType = OciClient.ExpertConfigMediaType } }];
        yield return [good with { Config = good.Config with { Digest = "sha256:bad" } }];
        yield return [good with { Config = good.Config with { Size = -1 } }];
        yield return [good with { Annotations = null }];
        yield return [good with { Annotations = new() { [OciClient.AnnKind] = "mission" } }];
        yield return [good with { Annotations = new() { [OciClient.AnnSchemaVersion] = "1", [OciClient.AnnKind] = "expert" } }];
        yield return [good with { Layers = null! }];
        yield return [good with { Layers = [] }];
        yield return [good with { Layers = [good.Layers[0], good.Layers[0]] }];
        yield return [good with { Layers = [null!] }];
        yield return [good with { Layers = [good.Layers[0] with { MediaType = "application/octet-stream" }] }];
        yield return [good with { Layers = [good.Layers[0] with { Digest = "sha256:bad" }] }];
        yield return [good with { Layers = [good.Layers[0] with { Size = -1 }] }];
    }

    [Theory]
    [MemberData(nameof(InvalidManifests))]
    public async Task Invalid_schema_or_descriptor_is_refused_before_blob_fetch(OciManifest manifest)
    {
        var registry = new MissionRegistry { Definition = manifest };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
        Assert.Equal(0, registry.BlobRequests);
    }

    [Fact]
    public async Task Declared_oversize_is_refused_before_blob_fetch()
    {
        var registry = new MissionRegistry();
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() =>
            client.PullMissionWithDigestAsync(Registry, Name, "latest", maxBundleBytes: Bundle.Length - 1));
        Assert.Equal(0, registry.BlobRequests);
    }

    [Fact]
    public async Task Same_size_corruption_is_detected_by_hash()
    {
        var corrupt = Bundle.ToArray();
        corrupt[0] ^= 1;
        var registry = new MissionRegistry { BlobBytes = corrupt };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
    }

    [Fact]
    public async Task Truncated_bundle_is_detected_by_actual_size()
    {
        var registry = new MissionRegistry { BlobBytes = Bundle[..^1] };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
    }

    [Fact]
    public async Task Unknown_length_stream_stops_at_descriptor_limit_plus_one_and_is_disposed()
    {
        var stream = new ObservedStream(new byte[100_000]);
        var registry = new MissionRegistry { BlobContent = new StreamContent(stream) };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
        Assert.Equal(Bundle.Length + 1, stream.BytesRead);
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Dishonest_content_length_cannot_bypass_stream_bound()
    {
        var stream = new ObservedStream(new byte[100_000]);
        var content = new StreamContent(stream);
        content.Headers.ContentLength = 1;
        var registry = new MissionRegistry { BlobContent = content };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
        Assert.Equal(Bundle.Length + 1, stream.BytesRead);
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Oversized_manifest_stream_is_bounded_before_parsing()
    {
        var stream = new ObservedStream(new byte[2 * 1024 * 1024]);
        var registry = new MissionRegistry { ManifestContent = new StreamContent(stream) };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
        Assert.Equal(1024 * 1024 + 1, stream.BytesRead);
        Assert.Equal(0, registry.BlobRequests);
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Cancellation_during_blob_read_returns_no_result_and_disposes_content()
    {
        var stream = new ObservedStream(Bundle) { WaitForCancellation = true };
        var registry = new MissionRegistry { BlobContent = new StreamContent(stream) };
        using var client = new OciClient(registry);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.PullMissionWithDigestAsync(Registry, Name, "latest", cancel.Token));
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Interrupted_blob_read_is_an_oci_error_and_disposes_content()
    {
        var stream = new ObservedStream(Bundle) { FailReading = true };
        using var client = new OciClient(new MissionRegistry { BlobContent = new StreamContent(stream) });
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Malformed_manifest_json_fails_as_oci_error()
    {
        var registry = new MissionRegistry { ManifestContent = new StringContent("{bad") };
        using var client = new OciClient(registry);
        await Assert.ThrowsAsync<OciException>(() => client.PullMissionWithDigestAsync(Registry, Name, "latest"));
    }

    private static OciManifest Manifest() => new(2, "application/vnd.oci.image.manifest.v1+json",
        new(OciClient.MissionConfigMediaType, Hash([]), 0),
        [new(OciClient.MissionBundleMediaType, Hash(Bundle), Bundle.Length)],
        OciClient.MissionArtifactType,
        new() { [OciClient.AnnSchemaVersion] = "1", [OciClient.AnnKind] = "mission" });

    private static string Hash(byte[] bytes) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));

    private sealed class MissionRegistry : HttpMessageHandler
    {
        internal OciManifest Definition { get; init; } = Manifest();
        internal byte[] BlobBytes { get; init; } = Bundle;
        internal HttpContent? BlobContent { get; init; }
        internal HttpContent? ManifestContent { get; init; }
        internal int ManifestRequests { get; private set; }
        internal int BlobRequests { get; private set; }
        internal string ManifestDigest => Hash(JsonSerializer.SerializeToUtf8Bytes(Definition, OciJsonContext.Default.OciManifest));

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.Contains("/manifests/", StringComparison.Ordinal))
            {
                ManifestRequests++;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                { Content = ManifestContent ?? new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(Definition, OciJsonContext.Default.OciManifest)) });
            }
            BlobRequests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = BlobContent ?? new ByteArrayContent(BlobBytes) });
        }
    }

    internal sealed class ObservedStream(byte[] bytes) : Stream
    {
        internal int BytesRead { get; private set; }
        internal bool Disposed { get; private set; }
        internal bool WaitForCancellation { get; init; }
        internal bool FailReading { get; init; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => BytesRead; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (FailReading) throw new IOException("interrupted stream");
            if (WaitForCancellation) await Task.Delay(Timeout.Infinite, ct);
            var count = Math.Min(buffer.Length, bytes.Length - BytesRead);
            bytes.AsMemory(BytesRead, count).CopyTo(buffer);
            BytesRead += count;
            return count;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
