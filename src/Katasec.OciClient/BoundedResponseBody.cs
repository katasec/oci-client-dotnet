namespace Katasec.OciClient;

// HTTP bodies are bounded while streaming, before a parser or caller observes their bytes.
internal static class BoundedResponseBody
{
    internal static async Task<byte[]> ReadAsync(
        HttpResponseMessage response, long maxBytes, string field, CancellationToken ct)
    {
        if (response.Content.Headers.ContentLength is { } length && length > maxBytes)
            throw TooLarge(field, maxBytes);

        try
        {
            await using var source = await response.Content.ReadAsStreamAsync(ct);
            return await ReadStreamAsync(source, maxBytes, field, ct);
        }
        catch (Exception exception) when (exception is IOException or HttpRequestException)
        { throw new OciException($"The {field} response read failed."); }
    }

    private static async Task<byte[]> ReadStreamAsync(Stream source, long maxBytes, string field, CancellationToken ct)
    {
        using var result = new MemoryStream();
        var buffer = new byte[81920];
        while (true)
        {
            var count = (int)Math.Min(buffer.Length, maxBytes - result.Length);
            var read = await source.ReadAsync(buffer.AsMemory(0, count == 0 ? 1 : count), ct);
            if (read == 0) return result.ToArray();
            if (result.Length + read > maxBytes) throw TooLarge(field, maxBytes);
            result.Write(buffer, 0, read);
        }
    }

    private static OciException TooLarge(string field, long limit) =>
        new($"The {field} exceeds its {limit}-byte limit.");
}
