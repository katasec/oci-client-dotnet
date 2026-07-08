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
        _http = new HttpClient();
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
    {
        var url = $"https://{registry}/v2/{name}/manifests/{reference}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.oci.image.manifest.v1+json"));

        var resp = await _auth.SendAsync(req, ct);
        await EnsureSuccessAsync(resp, ct);

        var body = await resp.Content.ReadAsStringAsync(ct);
        return JsonSerializer.Deserialize(body, OciJsonContext.Default.OciManifest)
            ?? throw new OciException($"Empty manifest response from {registry}/{name}:{reference}");
    }

    /// <summary>
    /// Pulls a blob by digest, returning its content as a byte array.
    /// </summary>
    public async Task<byte[]> PullBlobAsync(
        string registry, string name, string digest,
        CancellationToken ct = default)
    {
        var url = $"https://{registry}/v2/{name}/blobs/{digest}";
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        var resp = await _auth.SendAsync(req, ct);
        await EnsureSuccessAsync(resp, ct);
        return await resp.Content.ReadAsByteArrayAsync(ct);
    }

    /// <summary>
    /// Convenience: pulls the first layer of an expert artifact and returns its content.
    /// </summary>
    public async Task<string> PullExpertAsync(
        string registry, string name, string tag,
        CancellationToken ct = default)
    {
        var manifest = await PullManifestAsync(registry, name, tag, ct);
        var layer = manifest.Layers.FirstOrDefault()
            ?? throw new OciException($"Manifest for {name}:{tag} has no layers");

        var bytes = await PullBlobAsync(registry, name, layer.Digest, ct);
        return Encoding.UTF8.GetString(bytes);
    }

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
        var headReq = new HttpRequestMessage(HttpMethod.Head,
            $"https://{registry}/v2/{name}/blobs/{digest}");
        var headResp = await _auth.SendAsync(headReq, ct);
        if (headResp.IsSuccessStatusCode)
            return digest;

        // POST to get an upload session
        var postReq = new HttpRequestMessage(HttpMethod.Post,
            $"https://{registry}/v2/{name}/blobs/uploads/");
        var postResp = await _auth.SendAsync(postReq, ct);
        await EnsureSuccessAsync(postResp, ct);

        var locationRaw = postResp.Headers.Location
            ?? throw new OciException("Registry did not return upload Location");

        // Location may be relative — resolve against the registry base
        var registryBase = new Uri($"https://{registry}");
        var uploadUrl = locationRaw.IsAbsoluteUri ? locationRaw : new Uri(registryBase, locationRaw);
        var putUrl = AppendDigest(uploadUrl, digest);
        var putReq = new HttpRequestMessage(HttpMethod.Put, putUrl)
        {
            Content = new ByteArrayContent(content)
        };
        putReq.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

        var putResp = await _auth.SendAsync(putReq, ct);
        await EnsureSuccessAsync(putResp, ct);

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
        var req = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new ByteArrayContent(bytes)
        };
        req.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/vnd.oci.image.manifest.v1+json");

        var resp = await _auth.SendAsync(req, ct);
        await EnsureSuccessAsync(resp, ct);

        return resp.Headers.TryGetValues("Docker-Content-Digest", out var vals)
            ? vals.First()
            : ComputeDigest(bytes);
    }

    /// <summary>
    /// Convenience: packages and pushes a single expert.md as an OCI artifact (Forge schema v1).
    /// </summary>
    /// <param name="annotations">Optional extra manifest annotations (e.g. description, authors),
    /// merged over the standard org.opencontainers.image.* + dev.forge.* keys.</param>
    public async Task PushExpertAsync(
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

        await PushManifestAsync(registry, name, tag, manifest, ct);
    }

    /// <summary>
    /// Packages and pushes a mission as a single self-contained OCI artifact (Forge schema v1). The
    /// <paramref name="bundleTar"/> is the whole mission — <c>mission.mcl</c> + lock + experts — as a
    /// tar (see <see cref="MissionBundle"/>), so a pull needs no recursive expert fetches.
    /// </summary>
    public async Task PushMissionAsync(
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

        await PushManifestAsync(registry, name, tag, manifest, ct);
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
    {
        var manifest = await PullManifestAsync(registry, name, tag, ct);
        if (Classify(manifest) != ForgeArtifactKind.Mission)
            throw new OciException(
                $"{name}:{tag} is not a Forge mission (artifactType={manifest.ArtifactType ?? "none"})");

        var layer = manifest.Layers.FirstOrDefault(l => l.MediaType == MissionBundleMediaType)
            ?? manifest.Layers.FirstOrDefault()
            ?? throw new OciException($"Mission {name}:{tag} has no bundle layer");

        return await PullBlobAsync(registry, name, layer.Digest, ct);
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

    private static async Task EnsureSuccessAsync(HttpResponseMessage resp, CancellationToken ct)
    {
        if (resp.IsSuccessStatusCode) return;
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            throw new OciAuthException($"Authentication failed ({resp.StatusCode}): {body}");
        throw new OciException($"Registry returned {(int)resp.StatusCode}: {body}");
    }

    // sha256 of empty content — used as a no-op config blob
    private const string EmptyDigest =
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public void Dispose() => _http.Dispose();
}
