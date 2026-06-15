using System.Net.Http.Headers;
using System.Text.Json;

namespace Katasec.OciClient;

/// <summary>
/// Handles OCI bearer token authentication.
/// On a 401, parses WWW-Authenticate, fetches a token, and retries.
/// </summary>
internal class BearerAuth(HttpClient http, string? staticToken)
{
    private string? _cachedToken;

    public async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken ct)
    {
        Authorize(request);
        var response = await http.SendAsync(request, ct);

        if (response.StatusCode != System.Net.HttpStatusCode.Unauthorized)
            return response;

        var challenge = ParseChallenge(response.Headers.WwwAuthenticate);
        if (challenge is not { } c) return response;

        _cachedToken = await FetchTokenAsync(c, ct);

        // Rebuild the request — HttpRequestMessage cannot be resent
        var retry = Clone(request);
        Authorize(retry);
        return await http.SendAsync(retry, ct);
    }

    private void Authorize(HttpRequestMessage req)
    {
        var token = staticToken ?? _cachedToken;
        if (token is not null)
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    private async Task<string> FetchTokenAsync(
        (string Realm, string Service, string Scope) challenge,
        CancellationToken ct)
    {
        var url = $"{challenge.Realm}?service={Uri.EscapeDataString(challenge.Service)}&scope={Uri.EscapeDataString(challenge.Scope)}";
        var resp = await http.GetAsync(url, ct);
        resp.EnsureSuccessStatusCode();

        var body = await resp.Content.ReadAsStringAsync(ct);
        var token = JsonSerializer.Deserialize(body, OciJsonContext.Default.TokenResponse)
            ?? throw new OciException("Empty token response from auth server");
        return token.Value;
    }

    private static (string Realm, string Service, string Scope)? ParseChallenge(
        HttpHeaderValueCollection<AuthenticationHeaderValue> headers)
    {
        foreach (var h in headers)
        {
            if (!string.Equals(h.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
                continue;

            var parts = h.Parameter?.Split(',') ?? [];
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var part in parts)
            {
                var kv = part.Trim().Split('=', 2);
                if (kv.Length == 2)
                    dict[kv[0].Trim()] = kv[1].Trim('"');
            }

            if (dict.TryGetValue("realm",   out var realm) &&
                dict.TryGetValue("service", out var service) &&
                dict.TryGetValue("scope",   out var scope))
                return (realm, service, scope);
        }
        return null;
    }

    private static HttpRequestMessage Clone(HttpRequestMessage req)
    {
        var clone = new HttpRequestMessage(req.Method, req.RequestUri);
        foreach (var h in req.Headers)
            clone.Headers.TryAddWithoutValidation(h.Key, h.Value);
        if (req.Content is not null)
        {
            // Content was already read for the first attempt; re-set it
            clone.Content = req.Content;
        }
        return clone;
    }
}
