using System.Text.Json.Serialization;

namespace Katasec.OciClient;

public record OciDescriptor(
    [property: JsonPropertyName("mediaType")] string MediaType,
    [property: JsonPropertyName("digest")]    string Digest,
    [property: JsonPropertyName("size")]      long   Size);

public record OciManifest(
    [property: JsonPropertyName("schemaVersion")] int                  SchemaVersion,
    [property: JsonPropertyName("mediaType")]      string               MediaType,
    [property: JsonPropertyName("config")]         OciDescriptor        Config,
    [property: JsonPropertyName("layers")]         List<OciDescriptor>  Layers);

internal record TokenResponse(
    [property: JsonPropertyName("token")]        string? Token,
    [property: JsonPropertyName("access_token")] string? AccessToken)
{
    public string Value => Token ?? AccessToken ?? "";
}
