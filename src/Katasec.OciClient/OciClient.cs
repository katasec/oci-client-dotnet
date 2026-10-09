using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Katasec.OciClient;

/// <summary>
/// AOT-safe OCI Distribution Spec client.
/// Covers the operations forge needs: pull manifest, pull blob, push blob, push manifest.
/// </summary>
public class OciClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly BearerAuth _auth;

    // ---- Forge artifact schema v1 ----------------------------------------------------------
    // artifactType (OCI 1.1) is the PRIMARY discriminator — read at pull time to route BEFORE
    // pulling blobs. It (and the annotations) is the surface a cosign signature covers, so the
    // discriminator IS the trust boundary.
    public const string ExpertArtifactType  = "application/vnd.forge.expert.v1+json";
    public const string MissionArtifactType = "application/vnd.forge.mission.v1+json";

    // Config + layer media types per kind.
    public const string ExpertConfigMediaType  = "application/vnd.forge.expert.config.v1+json";
    public const string ExpertLayerMediaType   = "application/vnd.forge.expert.v1";             // expert.md
    public const string MissionConfigMediaType = "application/vnd.forge.mission.config.v1+json";
    public const string MissionBundleMediaType = "application/vnd.forge.mission.bundle.v1+tar";  // self-contained tar

    // Forge annotation keys (signed alongside artifactType). schema.version is the format-evolution
    // key people forget; kind is a human-readable mirror of artifactType. mission.experts (pinned
    // expert digests) is only meaningful when experts are REFERENCED — Forge missions are
    // self-contained (experts bundled in the tar), so it is intentionally unused.
    public const string ForgeSchemaVersion = "1";
    public const string AnnSchemaVersion   = "dev.forge.schema.version";
    public const string AnnKind            = "dev.forge.kind";
    public const string AnnMissionExperts  = "dev.forge.mission.experts";

    /// <param name="credential">
    /// A registry credential (e.g. GitHub PAT). Used as the Basic auth password
    /// when exchanging for a scoped bearer token on the first 401.
    /// Leave null for public registries.
    /// </param>
    public OciClient(string? credential = null)
    {
        _http = new HttpClient(new HttpClientHandler
        { AllowAutoRedirect = false, AutomaticDecompression = System.Net.DecompressionMethods.All });
        _auth = new BearerAuth(_http, credential);
    }

    // Test seam, internal to this assembly's test project only (see InternalsVisibleTo in
    // OciModels.cs). It exists so the digest/response handling can be exercised against a stubbed
    // registry without TLS or a live port; the public surface gains no handler or endpoint knob.
    internal OciClient(HttpMessageHandler handler, string? credential = null)
    {
        _http = new HttpClient(handler);
        _auth = new BearerAuth(_http, credential);
    }

    // -------------------------------------------------------------------------
    // Pull

    /// <summary>
    /// Pulls the manifest for the given reference (name:tag or name@digest).
    /// </summary>
    public async Task<OciManifest> PullManifestAsync(
        string registry, string name, string reference,
        CancellationToken ct = default)
        => (await PullManifestWithDigestAsync(registry, name, reference, ct)).Manifest;

    /// <summary>
    /// Pulls a manifest and the immutable digest that identifies it. One request answers both:
    /// the response bytes are read once and used for the parse and computed digest, checked against
    /// the requested digest and any <c>Docker-Content-Digest</c> header — so the digest can
    /// never describe a different response than the one that was parsed. A tag is never
    /// substituted for a digest, and a second manifest request is never issued.
    /// </summary>
    private async Task<(OciManifest Manifest, string Digest)> PullManifestWithDigestAsync(
        string registry, string name, string reference,
        CancellationToken ct)
    {
        if (reference.Contains(':')) NormalizeDigest(reference, "requested manifest digest");
        var url = $"https://{registry}/v2/{name}/manifests/{reference}";
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.oci.image.manifest.v1+json"));

        using var resp = await _auth.SendAsync(req, registry, name, ct, followRedirects: true);
        EnsureSuccess(resp);
        var body = await BoundedResponseBody.ReadAsync(resp, 1024 * 1024, "manifest", ct);
        var digest = ManifestDigest(resp, body, reference);
        try
        {
            var manifest = JsonSerializer.Deserialize(body, OciJsonContext.Default.OciManifest)
                ?? throw new OciException("The registry returned an empty manifest.");
            return (manifest, digest);
        }
        catch (JsonException)
        { throw new OciException("The registry returned a malformed manifest."); }
    }

    // Every identity is checked against the exact response bytes, before they are parsed.
    private static string ManifestDigest(
        HttpResponseMessage response, byte[] body, string reference)
    {
        var actual = ComputeDigest(body);
        if (reference.Contains(':') && NormalizeDigest(reference, "requested manifest digest") != actual)
            throw new OciException("The manifest bytes do not match the requested digest.");
        if (!response.Headers.TryGetValues(ContentDigestHeader, out var values)) return actual;
        var headers = values.ToArray();
        if (headers.Length != 1 || NormalizeDigest(headers[0], ContentDigestHeader) != actual)
            throw new OciException($"The manifest bytes do not match {ContentDigestHeader}.");
        return actual;
    }

    private static string NormalizeDigest(string? digest, string field)
    {
        var normalized = digest?.Trim().ToLowerInvariant();
        return IsSha256Digest(normalized) ? normalized! :
            throw new OciException($"The {field} is not a valid SHA-256 digest.");
    }

    private static bool IsSha256Digest(string? digest)
    {
        if (digest is not { Length: 71 } || !digest.StartsWith("sha256:", StringComparison.Ordinal))
            return false;

        foreach (var character in digest.AsSpan(7))
        {
            if (!char.IsAsciiDigit(character) && (character < 'a' || character > 'f'))
                return false;
        }

        return true;
    }

    /// <summary>
    /// Pulls a blob by digest, returning its content as a byte array.
    /// </summary>
    public async Task<byte[]> PullBlobAsync(
        string registry, string name, string digest,
        CancellationToken ct = default)
        => await PullBlobCoreAsync(registry, name, digest, null, ct);

    private async Task<byte[]> PullBlobCoreAsync(
        string registry, string name, string digest, long? maxBytes, CancellationToken ct)
    {
        var url = $"https://{registry}/v2/{name}/blobs/{digest}";
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        using var resp = await _auth.SendAsync(req, registry, name, ct, followRedirects: true);
        EnsureSuccess(resp);
        return maxBytes is { } limit
            ? await BoundedResponseBody.ReadAsync(resp, limit, "mission bundle", ct)
            : await resp.Content.ReadAsByteArrayAsync(ct);
    }

    /// <summary>
    /// Pulls an expert artifact's content together with the immutable manifest digest it resolved
    /// from — the value a caller pins in place of a moving tag. The digest is taken from the same
    /// manifest response the layer descriptor came from, before the layer blob is pulled.
    /// </summary>
    public async Task<PulledExpert> PullExpertWithDigestAsync(
        string registry, string name, string reference,
        CancellationToken ct = default)
    {
        var (manifest, digest) = await PullManifestWithDigestAsync(registry, name, reference, ct);
        var layer = manifest.Layers?.FirstOrDefault()
            ?? throw new OciException($"Manifest for {name}:{reference} has no layers");

        var bytes = await PullBlobAsync(registry, name, layer.Digest, ct);
        return new PulledExpert(Encoding.UTF8.GetString(bytes), digest);
    }

    /// <summary>
    /// Convenience: pulls the first layer of an expert artifact and returns its content. Kept as a
    /// compatibility wrapper over <see cref="PullExpertWithDigestAsync"/> so existing callers that
    /// do not pin a digest are unaffected.
    /// </summary>
    public async Task<string> PullExpertAsync(
        string registry, string name, string tag,
        CancellationToken ct = default)
        => (await PullExpertWithDigestAsync(registry, name, tag, ct)).Content;

    // -------------------------------------------------------------------------
    // Push

    /// <summary>
    /// Pushes a single blob. Returns the digest.
    /// Skips upload if the blob already exists (content-addressable check).
    /// </summary>
    public async Task<string> PushBlobAsync(
        string registry, string name, byte[] content,
        CancellationToken ct = default)
    {
        var digest = ComputeDigest(content);

        // Check if blob already exists
        using var headReq = new HttpRequestMessage(HttpMethod.Head,
            $"https://{registry}/v2/{name}/blobs/{digest}");
        using var headResp = await _auth.SendAsync(headReq, registry, name, ct);
        if (headResp.IsSuccessStatusCode)
            return digest;

        // POST to get an upload session
        using var postReq = new HttpRequestMessage(HttpMethod.Post,
            $"https://{registry}/v2/{name}/blobs/uploads/");
        using var postResp = await _auth.SendAsync(postReq, registry, name, ct);
        EnsureSuccess(postResp);

        var locationRaw = postResp.Headers.Location
            ?? throw new OciException("Registry did not return upload Location");

        // Location may be relative — resolve against the registry base
        var registryBase = new Uri($"https://{registry}");
        var uploadUrl = locationRaw.IsAbsoluteUri ? locationRaw : new Uri(registryBase, locationRaw);
        var putUrl = AppendDigest(uploadUrl, digest);
        using var putReq = new HttpRequestMessage(HttpMethod.Put, putUrl)
        {
            Content = new ByteArrayContent(content)
        };
        putReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        using var putResp = await _auth.SendAsync(putReq, registry, name, ct);
        EnsureSuccess(putResp);

        return digest;
    }

    /// <summary>
    /// Pushes an OCI manifest and returns its digest.
    /// </summary>
    public async Task<string> PushManifestAsync(
        string registry, string name, string tag,
        OciManifest manifest,
        CancellationToken ct = default)
    {
        var json = JsonSerializer.Serialize(manifest, OciJsonContext.Default.OciManifest);
        var bytes = Encoding.UTF8.GetBytes(json);

        var url = $"https://{registry}/v2/{name}/manifests/{tag}";
        using var req = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new ByteArrayContent(bytes)
        };
        req.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");

        using var resp = await _auth.SendAsync(req, registry, name, ct);
        EnsureSuccess(resp);

        return resp.Headers.TryGetValues(ContentDigestHeader, out var vals)
            ? vals.First()
            : ComputeDigest(bytes);
    }

    /// <summary>
    /// Convenience: packages and pushes a single expert.md as an OCI artifact (Forge schema v1).
    /// </summary>
    /// <param name="annotations">Optional extra manifest annotations (e.g. description, authors),
    /// merged over the standard org.opencontainers.image.* + dev.forge.* keys.</param>
    public async Task<string> PushExpertAsync(
        string registry, string name, string tag,
        string expertMdContent,
        IReadOnlyDictionary<string, string>? annotations = null,
        CancellationToken ct = default)
    {
        var content = Encoding.UTF8.GetBytes(expertMdContent);
        var digest  = await PushBlobAsync(registry, name, content, ct);
        await PushBlobAsync(registry, name, [], ct); // ensure the empty config blob exists

        var manifest = new OciManifest(
            SchemaVersion: 2,
            MediaType: "application/vnd.oci.image.manifest.v1+json",
            Config: new OciDescriptor(ExpertConfigMediaType, EmptyDigest, 0),
            Layers:
            [
                new OciDescriptor(ExpertLayerMediaType, digest, content.Length)
            ],
            ArtifactType: ExpertArtifactType,
            Annotations: BuildAnnotations("expert", name, tag, annotations));

        // Returns the manifest digest — the immutable @sha256:… reference for pinning.
        return await PushManifestAsync(registry, name, tag, manifest, ct);
    }

    /// <summary>
    /// Packages and pushes a mission as a single self-contained OCI artifact (Forge schema v1). The
    /// <paramref name="bundleTar"/> is the whole mission — <c>mission.mcl</c> + lock + experts — as a
    /// tar (see <see cref="MissionBundle"/>), so a pull needs no recursive expert fetches.
    /// </summary>
    public async Task<string> PushMissionAsync(
        string registry, string name, string tag,
        byte[] bundleTar,
        IReadOnlyDictionary<string, string>? annotations = null,
        CancellationToken ct = default)
    {
        var digest = await PushBlobAsync(registry, name, bundleTar, ct);
        await PushBlobAsync(registry, name, [], ct); // ensure the empty config blob exists

        var manifest = new OciManifest(
            SchemaVersion: 2,
            MediaType: "application/vnd.oci.image.manifest.v1+json",
            Config: new OciDescriptor(MissionConfigMediaType, EmptyDigest, 0),
            Layers:
            [
                new OciDescriptor(MissionBundleMediaType, digest, bundleTar.Length)
            ],
            ArtifactType: MissionArtifactType,
            Annotations: BuildAnnotations("mission", name, tag, annotations));

        // Returns the manifest digest — the immutable @sha256:… reference for digest-pinning.
        return await PushManifestAsync(registry, name, tag, manifest, ct);
    }

    // -------------------------------------------------------------------------
    // Type-aware pull (39.3): classify from artifactType BEFORE pulling blobs, then route.

    /// <summary>
    /// Classifies a manifest as expert vs mission from its <c>artifactType</c> discriminator,
    /// falling back to the config mediaType for legacy experts pushed before the schema existed.
    /// </summary>
    public static ForgeArtifactKind Classify(OciManifest manifest)
    {
        if (manifest.ArtifactType == ExpertArtifactType)  return ForgeArtifactKind.Expert;
        if (manifest.ArtifactType == MissionArtifactType) return ForgeArtifactKind.Mission;
        if (manifest.Config.MediaType == ExpertConfigMediaType) return ForgeArtifactKind.Expert; // legacy
        return ForgeArtifactKind.Unknown;
    }

    /// <summary>Pulls the manifest and returns its Forge kind without fetching any blob.</summary>
    public async Task<ForgeArtifactKind> ClassifyAsync(
        string registry, string name, string reference, CancellationToken ct = default)
        => Classify(await PullManifestAsync(registry, name, reference, ct));

    /// <summary>
    /// Pulls a mission's self-contained bundle tar. Throws if the reference is not a Forge mission,
    /// so a caller can't accidentally run an expert (or arbitrary artifact) as a mission.
    /// </summary>
    public async Task<byte[]> PullMissionAsync(
        string registry, string name, string tag, CancellationToken ct = default)
        => (await PullMissionWithDigestAsync(registry, name, tag, ct)).Bundle;

    /// <summary>Returns a size- and SHA-256-verified Forge bundle and its immutable manifest identity.</summary>
    public async Task<PulledMission> PullMissionWithDigestAsync(
        string registry, string name, string reference, CancellationToken ct = default,
        long maxBundleBytes = 33554432)
    {
        if (maxBundleBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBundleBytes));
        var (manifest, manifestDigest) = await PullManifestWithDigestAsync(registry, name, reference, ct);
        var layer = MissionLayer(manifest, maxBundleBytes);
        var layerDigest = NormalizeDigest(layer.Digest, "mission layer digest");
        var bundle = await PullBlobCoreAsync(registry, name, layerDigest, layer.Size, ct);
        if (bundle.LongLength != layer.Size || ComputeDigest(bundle) != layerDigest)
            throw new OciException("The mission bundle bytes do not match their descriptor.");
        return new PulledMission(bundle, manifestDigest, layerDigest, bundle.LongLength);
    }

    /// <summary>Verifies this client's supplied credential through a Bearer challenge; persists nothing.</summary>
    public Task VerifyRegistryCredentialAsync(string registry, CancellationToken ct = default) =>
        _auth.VerifyCredentialAsync(registry, ct);

    private static OciDescriptor MissionLayer(OciManifest manifest, long maxBundleBytes)
    {
        if (manifest.SchemaVersion != 2 || manifest.MediaType != "application/vnd.oci.image.manifest.v1+json" ||
            manifest.ArtifactType != MissionArtifactType || manifest.Config is null ||
            manifest.Config.MediaType != MissionConfigMediaType || manifest.Annotations is null ||
            !manifest.Annotations.TryGetValue(AnnSchemaVersion, out var schema) || schema != ForgeSchemaVersion ||
            !manifest.Annotations.TryGetValue(AnnKind, out var kind) || kind != "mission")
            throw new OciException("The manifest is not a supported Forge mission.");
        if (manifest.Layers is not { Count: 1 } || manifest.Layers[0] is not { } layer ||
            layer.MediaType != MissionBundleMediaType)
            throw new OciException("A Forge mission requires exactly one bundle layer.");
        ValidateDescriptor(manifest.Config, maxBundleBytes);
        ValidateDescriptor(layer, maxBundleBytes);
        return layer;
    }

    private static void ValidateDescriptor(OciDescriptor descriptor, long maxBytes)
    {
        NormalizeDigest(descriptor.Digest, "mission descriptor digest");
        if (descriptor.Size < 0 || descriptor.Size > maxBytes)
            throw new OciException("The mission descriptor size is outside the bundle budget.");
    }

    // -------------------------------------------------------------------------
    // Helpers

    // Standard org.opencontainers.image.* + Forge dev.forge.* annotations, with caller extras
    // merged on top. These travel in the manifest and are covered by the cosign signature.
    private static Dictionary<string, string> BuildAnnotations(
        string kind, string name, string tag, IReadOnlyDictionary<string, string>? extra)
    {
        var ann = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [AnnSchemaVersion] = ForgeSchemaVersion,
            [AnnKind]          = kind,
            ["org.opencontainers.image.title"]   = name,
            ["org.opencontainers.image.version"] = tag,
            ["org.opencontainers.image.created"] = DateTimeOffset.UtcNow.ToString("o"),
        };
        if (extra is not null)
            foreach (var kv in extra)
                ann[kv.Key] = kv.Value;
        return ann;
    }

    private static string ComputeDigest(byte[] content)
    {
        var hash = SHA256.HashData(content);
        return "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static Uri AppendDigest(Uri baseUri, string digest)
    {
        var sep = baseUri.Query.Length > 0 ? "&" : "?";
        return new Uri(baseUri, $"{baseUri.PathAndQuery}{sep}digest={Uri.EscapeDataString(digest)}");
    }

    private static void EnsureSuccess(HttpResponseMessage resp)
    {
        if (resp.IsSuccessStatusCode) return;
        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            throw new OciAuthException("The registry rejected Bearer authentication.");
        throw new OciException($"The registry returned HTTP {(int)resp.StatusCode}.");
    }

    // The registry's own digest for the manifest it just served or accepted. Optional per the
    // distribution spec, which is why both the pull and the push path have a computed fallback.
    private const string ContentDigestHeader = "Docker-Content-Digest";

    // sha256 of empty content — used as a no-op config blob
    private const string EmptyDigest =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public void Dispose() => _http.Dispose();
}
