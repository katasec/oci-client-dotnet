using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Katasec.OciClient;

// One credential context: scoped, expiring bearer exchanges and explicit download redirects.
internal partial class BearerAuth(HttpClient http, string? credential)
{
    private readonly Dictionary<(string Origin, string Repository), CachedToken> _tokens = [];
    private readonly object _cacheGate = new();

    internal Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, string registry,
        string repository, CancellationToken ct, bool followRedirects = false) =>
        SendCoreAsync(request, RegistryUri(registry), repository, followRedirects, false, ct);

    internal async Task VerifyCredentialAsync(string registry, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(credential))
            throw new OciAuthException("A registry credential is required for verification.");
        var origin = RegistryUri(registry);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(origin, "/v2/"));
        using var response = await SendCoreAsync(request, origin, "", false, true, ct);
        if (!response.IsSuccessStatusCode)
            throw new OciAuthException("Registry credential verification failed.");
    }

    private async Task<HttpResponseMessage> SendCoreAsync(HttpRequestMessage template, Uri origin,
        string repository, bool followRedirects, bool verifying, CancellationToken ct)
    {
        var uri = template.RequestUri ?? throw new OciException("A registry request URI is required.");
        var retried = false;
        var redirects = 0;
        var activeToken = verifying ? null : Cached(origin, repository);
        while (true)
        {
            RequireHttps(uri);
            var trustedTarget = IsRegistryTarget(uri, origin, repository);
            var token = trustedTarget && activeToken?.ExpiresAt > DateTimeOffset.UtcNow ? activeToken.Value : null;
            var response = await SendOnceAsync(template, uri, token, ct);
            if (response.StatusCode == HttpStatusCode.Unauthorized && trustedTarget && !retried)
            {
                var challenge = ReadChallengeAndDispose(response);
                var fetched = await FetchTokenAsync(challenge, ct);
                Remember(origin, repository, fetched);
                activeToken = fetched;
                retried = true;
                continue;
            }
            if (verifying && !retried)
            {
                response.Dispose();
                throw new OciAuthException("The registry did not provide a Bearer credential challenge.");
            }
            if (!followRedirects || !IsRedirect(response.StatusCode)) return response;
            uri = RedirectAndDispose(response, uri, ++redirects);
        }
    }

    private async Task<HttpResponseMessage> SendOnceAsync(
        HttpRequestMessage template, Uri uri, string? token, CancellationToken ct)
    {
        using var request = await CloneAsync(template, uri, ct);
        request.Headers.Authorization = token is null ? null : new AuthenticationHeaderValue("Bearer", token);
        try { return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct); }
        catch (HttpRequestException)
        { throw new OciException("The registry HTTP request failed."); }
    }

    private async Task<CachedToken> FetchTokenAsync(Challenge challenge, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, TokenUri(challenge));
        if (!string.IsNullOrWhiteSpace(credential))
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
                Convert.ToBase64String(Encoding.UTF8.GetBytes($"token:{credential}")));
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                throw new OciAuthException("The registry token exchange failed.");
            var bytes = await BoundedResponseBody.ReadAsync(response, 64 * 1024, "token response", ct);
            var token = JsonSerializer.Deserialize(bytes, OciJsonContext.Default.TokenResponse);
            if (token is null || string.IsNullOrWhiteSpace(token.Value))
                throw new OciAuthException("The registry token response contains no token.");
            var authorization = new AuthenticationHeaderValue("Bearer", token.Value);
            return new CachedToken(authorization.Parameter!, ExpiresAt(token));
        }
        catch (OperationCanceledException) { throw; }
        catch (OciAuthException) { throw; }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or FormatException or OciException)
        { throw new OciAuthException("The registry token response could not be verified."); }
    }

    internal static Uri RegistryUri(string registry)
    {
        if (string.IsNullOrWhiteSpace(registry) || registry.Any(char.IsWhiteSpace) ||
            registry.IndexOfAny(['/', '\\', '@', '?', '#']) >= 0 || registry.EndsWith(':') ||
            !Uri.TryCreate($"https://{registry}", UriKind.Absolute, out var uri) ||
            string.IsNullOrWhiteSpace(uri.Host) || uri.AbsolutePath != "/" || uri.UserInfo.Length != 0)
            throw new OciException("A registry must be a hostname with an optional port.");
        return new UriBuilder(Uri.UriSchemeHttps, uri.IdnHost, uri.Port).Uri;
    }

    private static void RequireHttps(Uri uri)
    {
        if (!uri.IsAbsoluteUri || uri.Scheme != Uri.UriSchemeHttps ||
            uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
            throw new OciAuthException("Registry and token requests require HTTPS without userinfo or fragments.");
    }

    private static bool IsRegistryTarget(Uri uri, Uri origin, string repository) =>
        uri.GetLeftPart(UriPartial.Authority).Equals(origin.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase) &&
        (repository.Length == 0 ? uri.AbsolutePath == "/v2/" :
            uri.AbsolutePath.StartsWith($"/v2/{repository}/", StringComparison.Ordinal));

    private CachedToken? Cached(Uri origin, string repository)
    {
        lock (_cacheGate)
            return _tokens.TryGetValue((origin.Authority, repository), out var token) &&
                token.ExpiresAt > DateTimeOffset.UtcNow ? token : null;
    }

    private void Remember(Uri origin, string repository, CachedToken token)
    {
        lock (_cacheGate) _tokens[(origin.Authority, repository)] = token;
    }

    private static Challenge ReadChallengeAndDispose(HttpResponseMessage response)
    {
        using (response)
        {
            var raw = response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out var headers)
                ? headers.FirstOrDefault(value => value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) : null;
            var values = ParseParameters(raw?[7..]);
            if (!values.TryGetValue("realm", out var realm) || !values.TryGetValue("service", out var service) ||
                string.IsNullOrWhiteSpace(service) || !Uri.TryCreate(realm, UriKind.Absolute, out var uri))
                throw new OciAuthException("The registry returned an unsupported Bearer challenge.");
            RequireHttps(uri);
            values.TryGetValue("scope", out var scope);
            return new Challenge(uri, service, scope);
        }
    }

    private static Dictionary<string, string> ParseParameters(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new OciAuthException("The registry returned no supported Bearer challenge.");
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var position = 0;
        foreach (Match match in ChallengeParameter().Matches(text))
        {
            if (match.Index != position || !values.TryAdd(match.Groups["key"].Value,
                match.Groups["quoted"].Success ? Unescape(match.Groups["quoted"].Value) : match.Groups["plain"].Value))
                throw new OciAuthException("The registry returned an ambiguous Bearer challenge.");
            position += match.Length;
        }
        if (position != text.Length || text.TrimEnd().EndsWith(','))
            throw new OciAuthException("The registry returned a malformed Bearer challenge.");
        return values;
    }

    [GeneratedRegex("\\G\\s*(?<key>[A-Za-z][A-Za-z0-9_-]*)\\s*=\\s*(?:\"(?<quoted>(?:[^\"\\\\]|\\\\.)*)\"|(?<plain>[^,\\s\"\\\\]+))\\s*(?:,|$)")]
    private static partial Regex ChallengeParameter();

    private static string Unescape(string text)
    {
        var result = new StringBuilder();
        for (var i = 0; i < text.Length; i++)
        {
            if (text[i] == '\\') i++;
            result.Append(text[i]);
        }
        return result.ToString();
    }

    private static Uri TokenUri(Challenge challenge)
    {
        var query = challenge.Realm.Query.TrimStart('?');
        query = AddParameter(query, "service", challenge.Service);
        query = AddParameter(query, "scope", challenge.Scope);
        return new UriBuilder(challenge.Realm) { Query = query }.Uri;
    }

    private static string AddParameter(string query, string name, string? value)
    {
        var existing = query.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2))
            .Where(pair => DecodeQuery(pair[0]).Equals(name, StringComparison.OrdinalIgnoreCase)).ToArray();
        if (existing.Length > 1 || existing.Length == 1 &&
            (value is null || existing[0].Length != 2 || DecodeQuery(existing[0][1]) != value))
            throw new OciAuthException("The token realm query conflicts with its Bearer challenge.");
        if (existing.Length == 1 || value is null) return query;
        var parameter = $"{name}={Uri.EscapeDataString(value)}";
        return query.Length == 0 ? parameter : $"{query}&{parameter}";
    }

    private static string DecodeQuery(string value) => Uri.UnescapeDataString(value.Replace("+", " "));

    private static DateTimeOffset ExpiresAt(TokenResponse token)
    {
        var issued = DateTimeOffset.UtcNow;
        if (token.IssuedAt is { } text && !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out issued))
            throw new OciAuthException("The token response has an invalid issue time.");
        var seconds = token.ExpiresIn ?? 60;
        if (seconds <= 0 || seconds > (DateTimeOffset.MaxValue - issued).TotalSeconds)
            throw new OciAuthException("The token response has an invalid lifetime.");
        var expires = issued.AddSeconds(seconds);
        if (expires <= DateTimeOffset.UtcNow)
            throw new OciAuthException("The token response is already expired.");
        return expires;
    }

    private static bool IsRedirect(HttpStatusCode status) => status is HttpStatusCode.MovedPermanently or
        HttpStatusCode.Redirect or HttpStatusCode.SeeOther or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect;

    private static Uri RedirectAndDispose(HttpResponseMessage response, Uri current, int count)
    {
        using (response)
        {
            if (count > 5 || response.Headers.Location is not { } location)
                throw new OciException("The registry download redirect limit or location is invalid.");
            var next = location.IsAbsoluteUri ? location : new Uri(current, location);
            RequireHttps(next);
            return next;
        }
    }

    private static async Task<HttpRequestMessage> CloneAsync(HttpRequestMessage template, Uri uri, CancellationToken ct)
    {
        var request = new HttpRequestMessage(template.Method, uri);
        foreach (var header in template.Headers)
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        if (template.Content is not null)
        {
            request.Content = new ByteArrayContent(await template.Content.ReadAsByteArrayAsync(ct));
            foreach (var header in template.Content.Headers)
                request.Content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }
        return request;
    }

    private sealed record Challenge(Uri Realm, string Service, string? Scope);
    private sealed record CachedToken(string Value, DateTimeOffset ExpiresAt);
}
