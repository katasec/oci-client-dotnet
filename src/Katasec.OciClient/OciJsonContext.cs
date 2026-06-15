using System.Text.Json.Serialization;

namespace Katasec.OciClient;

[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(OciManifest))]
[JsonSerializable(typeof(OciDescriptor))]
[JsonSerializable(typeof(List<OciDescriptor>))]
[JsonSerializable(typeof(TokenResponse))]
internal partial class OciJsonContext : JsonSerializerContext { }
