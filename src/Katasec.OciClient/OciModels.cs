using System.Text.Json.Serialization;

// The schema tests serialize/deserialize through the real source-gen context (OciJsonContext) to
// exercise the exact wire representation the client pushes/pulls.
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("Katasec.OciClient.Tests")]

namespace Katasec.OciClient;

/// <summary>What a Forge OCI artifact is, decided from its <c>artifactType</c> discriminator
/// (Phase 39.3). Routed at pull time before any blob is fetched.</summary>
public enum ForgeArtifactKind { Unknown, Expert, Mission }

public record OciDescriptor(
    [property: JsonPropertyName("mediaType")] string MediaType,
    [property: JsonPropertyName("digest")]    string Digest,
    [property: JsonPropertyName("size")]      long   Size);

public record OciManifest(
    [property: JsonPropertyName("schemaVersion")] int                  SchemaVersion,
    [property: JsonPropertyName("mediaType")]      string               MediaType,
    [property: JsonPropertyName("config")]         OciDescriptor        Config,
    [property: JsonPropertyName("layers")]         List<OciDescriptor>  Layers,
    // OCI 1.1 top-level discriminator — read at pull time to route BEFORE pulling blobs. This is
    // the Forge artifact type (expert vs mission); it (and the annotations) is the surface a cosign
    // signature covers, so the discriminator IS the trust boundary. Optional/null for legacy
    // artifacts pushed before the schema existed (classify falls back to the config mediaType).
    [property: JsonPropertyName("artifactType")]   string?              ArtifactType = null,
    [property: JsonPropertyName("annotations")]    Dictionary<string, string>? Annotations = null);

internal record TokenResponse(
    [property: JsonPropertyName("token")]        string? Token,
    [property: JsonPropertyName("access_token")] string? AccessToken)
{
    public string Value => Token ?? AccessToken ?? "";
}
