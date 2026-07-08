using System.Text.Json.Serialization;

namespace Katasec.OciClient;

// Omit null optional fields (artifactType/annotations) so manifests stay spec-clean — a legacy
// expert push emits no artifactType key at all, rather than "artifactType": null.
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(OciManifest))]
[JsonSerializable(typeof(OciDescriptor))]
[JsonSerializable(typeof(List<OciDescriptor>))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(TokenResponse))]
internal partial class OciJsonContext : JsonSerializerContext { }
