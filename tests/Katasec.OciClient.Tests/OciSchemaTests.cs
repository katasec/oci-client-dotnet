using System.Text;
using System.Text.Json;
using Katasec.OciClient;

namespace Katasec.OciClient.Tests;

/// <summary>
/// Phase 39.3 — the Forge OCI artifact schema. Proves the discriminator round-trips and classifies
/// expert vs mission, that legacy experts still classify, and that a mission bundle is
/// self-contained (packs + unpacks its experts). No live registry needed: the new surface is the
/// schema + classification + bundling; the HTTP push/pull plumbing is unchanged and exercised
/// against a real registry by the expert integration tests.
/// </summary>
public class OciSchemaTests
{
    private static OciManifest ExpertManifest() => new(
        SchemaVersion: 2,
        MediaType: "application/vnd.oci.image.manifest.v1+json",
        Config: new OciDescriptor(OciClient.ExpertConfigMediaType, "sha256:0", 0),
        Layers: [new OciDescriptor(OciClient.ExpertLayerMediaType, "sha256:aaa", 10)],
        ArtifactType: OciClient.ExpertArtifactType,
        Annotations: new Dictionary<string, string> { [OciClient.AnnKind] = "expert" });

    private static OciManifest MissionManifest() => new(
        SchemaVersion: 2,
        MediaType: "application/vnd.oci.image.manifest.v1+json",
        Config: new OciDescriptor(OciClient.MissionConfigMediaType, "sha256:0", 0),
        Layers: [new OciDescriptor(OciClient.MissionBundleMediaType, "sha256:bbb", 42)],
        ArtifactType: OciClient.MissionArtifactType,
        Annotations: new Dictionary<string, string> { [OciClient.AnnKind] = "mission" });

    [Fact]
    public void Classifies_expert_and_mission_from_artifactType()
    {
        Assert.Equal(ForgeArtifactKind.Expert, OciClient.Classify(ExpertManifest()));
        Assert.Equal(ForgeArtifactKind.Mission, OciClient.Classify(MissionManifest()));
    }

    [Fact]
    public void Legacy_expert_without_artifactType_still_classifies_via_config_mediaType()
    {
        var legacy = new OciManifest(
            SchemaVersion: 2,
            MediaType: "application/vnd.oci.image.manifest.v1+json",
            Config: new OciDescriptor(OciClient.ExpertConfigMediaType, "sha256:0", 0),
            Layers: [new OciDescriptor(OciClient.ExpertLayerMediaType, "sha256:aaa", 10)]);
        // No artifactType (null) — the pre-schema shape.
        Assert.Null(legacy.ArtifactType);
        Assert.Equal(ForgeArtifactKind.Expert, OciClient.Classify(legacy));
    }

    [Fact]
    public void Unknown_artifact_classifies_as_unknown()
    {
        var other = new OciManifest(
            SchemaVersion: 2,
            MediaType: "application/vnd.oci.image.manifest.v1+json",
            Config: new OciDescriptor("application/vnd.oci.empty.v1+json", "sha256:0", 0),
            Layers: []);
        Assert.Equal(ForgeArtifactKind.Unknown, OciClient.Classify(other));
    }

    [Fact]
    public void ArtifactType_and_annotations_survive_a_json_round_trip()
    {
        // The exact wire path: serialize/deserialize through the client's source-gen context.
        // (STJ escapes '+' as + in the string, so assert on keys + the deserialized value.)
        var json = JsonSerializer.Serialize(MissionManifest(), OciJsonContext.Default.OciManifest);
        Assert.Contains("artifactType", json);   // discriminator key is on the wire
        Assert.Contains("dev.forge.kind", json);  // annotations are on the wire

        var pulled = JsonSerializer.Deserialize(json, OciJsonContext.Default.OciManifest)!;
        Assert.Equal(OciClient.MissionArtifactType, pulled.ArtifactType);   // value survives the round-trip
        Assert.Equal(ForgeArtifactKind.Mission, OciClient.Classify(pulled));
        Assert.Equal("mission", pulled.Annotations![OciClient.AnnKind]);
    }

    [Fact]
    public void Null_artifactType_is_omitted_from_the_wire()
    {
        // Legacy expert (no artifactType) serializes WITHOUT an "artifactType" key, not as null.
        var legacy = new OciManifest(
            SchemaVersion: 2,
            MediaType: "application/vnd.oci.image.manifest.v1+json",
            Config: new OciDescriptor(OciClient.ExpertConfigMediaType, "sha256:0", 0),
            Layers: [new OciDescriptor(OciClient.ExpertLayerMediaType, "sha256:aaa", 10)]);
        var json = JsonSerializer.Serialize(legacy, OciJsonContext.Default.OciManifest);
        Assert.DoesNotContain("artifactType", json);
    }

    [Fact]
    public void Mission_bundle_is_self_contained_pack_then_unpack_round_trips()
    {
        var srcDir  = Path.Combine(Path.GetTempPath(), "forge-mission-" + Guid.NewGuid().ToString("N"));
        var destDir = Path.Combine(Path.GetTempPath(), "forge-unpack-" + Guid.NewGuid().ToString("N"));
        try
        {
            // A self-contained mission: mission.mcl + lock + an expert nested inside experts/.
            Directory.CreateDirectory(Path.Combine(srcDir, "experts", "Verifier"));
            File.WriteAllText(Path.Combine(srcDir, "mission.mcl"), "mission Guard(goal) = { Answerer Verifier }");
            File.WriteAllText(Path.Combine(srcDir, "mcl.lock"), "{ }");
            File.WriteAllText(Path.Combine(srcDir, "experts", "Verifier", "expert.md"), "---\nkind: rule\n---\ncheck");

            var tar = MissionBundle.Pack(srcDir);
            Assert.NotEmpty(tar);

            MissionBundle.Unpack(tar, destDir);

            // The bundled expert came along — no recursive fetch needed.
            Assert.Equal(
                File.ReadAllText(Path.Combine(srcDir, "mission.mcl")),
                File.ReadAllText(Path.Combine(destDir, "mission.mcl")));
            Assert.True(File.Exists(Path.Combine(destDir, "experts", "Verifier", "expert.md")));
        }
        finally
        {
            if (Directory.Exists(srcDir))  Directory.Delete(srcDir, recursive: true);
            if (Directory.Exists(destDir)) Directory.Delete(destDir, recursive: true);
        }
    }
}
