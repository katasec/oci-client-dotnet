using System.Formats.Tar;

namespace Katasec.OciClient;

/// <summary>
/// Packs/unpacks a <b>self-contained</b> mission bundle (Phase 39.3): the mission directory —
/// <c>mission.mcl</c> + <c>mcl.lock</c> + <c>experts/**</c> — as a tar, carried as the single layer
/// of a mission artifact. Self-contained means the experts travel <em>inside</em> the bundle, so a
/// pull needs no recursive expert fetches (matches OCI immutability; the mission digest pins the
/// whole thing). The tar is the blob whose <see cref="OciClient.MissionBundleMediaType"/> layer the
/// manifest points at.
/// </summary>
public static class MissionBundle
{
    /// <summary>Pack a mission directory tree into a tar byte array (paths relative to the dir).</summary>
    public static byte[] Pack(string missionDir)
    {
        if (!Directory.Exists(missionDir))
            throw new DirectoryNotFoundException($"Mission directory not found: {missionDir}");

        using var ms = new MemoryStream();
        TarFile.CreateFromDirectory(missionDir, ms, includeBaseDirectory: false);
        return ms.ToArray();
    }

    /// <summary>Unpack a mission bundle tar into <paramref name="destDir"/> (created if absent).</summary>
    public static void Unpack(byte[] bundleTar, string destDir)
    {
        Directory.CreateDirectory(destDir);
        using var ms = new MemoryStream(bundleTar);
        TarFile.ExtractToDirectory(ms, destDir, overwriteFiles: true);
    }
}
