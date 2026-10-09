using System.Net;
using System.Net.Http.Headers;
using System.Text;

namespace Katasec.OciClient.Tests;

public class BearerAuthTests
{
    private const string Registry = "registry.test";
    private const string Repository = "team/mission";
    private const string Digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    [Fact]
    public async Task Verification_uses_anonymous_challenge_then_basic_exchange_then_bearer_retry()
    {
        var requests = new List<(string Host, string? Scheme)>();
        using var client = new OciClient(new Handler(request =>
        {
            requests.Add((request.RequestUri!.Host, request.Headers.Authorization?.Scheme));
            if (request.RequestUri.Host == "auth.test")
            {
                Assert.Equal(Convert.ToBase64String("token:secret-test"u8), request.Headers.Authorization!.Parameter);
                Assert.Contains("keep=a%2Cb", request.RequestUri.Query, StringComparison.Ordinal);
                Assert.Contains("service=registry.test", request.RequestUri.Query, StringComparison.Ordinal);
                Assert.DoesNotContain("scope=", request.RequestUri.Query, StringComparison.Ordinal);
                return Token();
            }
            return request.Headers.Authorization is null
                ? Challenge(realm: "https://auth.test/token?keep=a%2Cb") : Ok();
        }), "secret-test");
        await client.VerifyRegistryCredentialAsync(Registry);
        Assert.Equal(new[] { (Registry, (string?)null), ("auth.test", "Basic"), (Registry, "Bearer") }, requests);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task Verification_without_credential_never_sends_a_request(string? credential)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ => { count++; return Ok(); }), credential);
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(0, count);
    }

    [Fact]
    public async Task Anonymous_success_does_not_verify_a_credential()
    {
        using var client = new OciClient(new Handler(_ => Ok()), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
    }

    [Theory]
    [InlineData("http://registry.test")]
    [InlineData("https://registry.test")]
    [InlineData("user@registry.test")]
    [InlineData("registry.test/path")]
    [InlineData("registry.test?x=1")]
    [InlineData("registry.test#fragment")]
    [InlineData(" registry.test")]
    public async Task Invalid_registry_authority_is_refused_before_network(string registry)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ => { count++; return Ok(); }), "secret-test");
        await Assert.ThrowsAsync<OciException>(() => client.VerifyRegistryCredentialAsync(registry));
        Assert.Equal(0, count);
    }

    [Theory]
    [InlineData("http://auth.test/token")]
    [InlineData("https://user@auth.test/token")]
    [InlineData("https://auth.test/token#fragment")]
    [InlineData("/token")]
    public async Task Unsafe_realm_never_receives_credentials(string realm)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ => { count++; return Challenge(realm: realm); }), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(1, count);
    }

    [Theory]
    [InlineData("Basic realm=\"registry\"")]
    [InlineData("Bearer realm=\"https://auth.test/token\"")]
    [InlineData("Bearer realm=\"https://auth.test/token\", service=\"registry.test\", service=\"other\"")]
    [InlineData("Bearer realm=\"https://auth.test/token\", service=\"registry.test\", garbage")]
    [InlineData("Bearer realm=\"https://auth.test/token\", service=\"registry.test\",")]
    [InlineData("Bearer realm=\"https://auth.test/token\", service=\"unterminated")]
    public async Task Unsupported_or_ambiguous_challenge_fails_without_token_exchange(string challenge)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ =>
        {
            count++;
            var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
            response.Headers.TryAddWithoutValidation("WWW-Authenticate", challenge);
            return response;
        }), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(1, count);
    }

    [Theory]
    [InlineData("https://auth.test/token?service=other")]
    [InlineData("https://auth.test/token?service=registry.test&service=registry.test")]
    [InlineData("https://auth.test/token?scope=unexpected")]
    public async Task Conflicting_realm_query_fails_before_exchange(string realm)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ => { count++; return Challenge(realm: realm); }), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(1, count);
    }

    [Fact]
    public async Task Matching_realm_parameters_are_preserved_without_duplicates()
    {
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test")
            {
                Assert.Equal("?service=registry.test&keep=yes", request.RequestUri.Query);
                return Token();
            }
            return request.Headers.Authorization is null
                ? Challenge(realm: "https://auth.test/token?service=registry.test&keep=yes") : Ok();
        }), "secret-test");
        await client.VerifyRegistryCredentialAsync(Registry);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"token\":\"\"}")]
    [InlineData("{bad")]
    [InlineData("{\"token\":\"a\",\"expires_in\":0}")]
    [InlineData("{\"token\":\"a\",\"expires_in\":-1}")]
    [InlineData("{\"token\":\"a\",\"issued_at\":\"invalid\"}")]
    [InlineData("{\"token\":\"a\",\"issued_at\":\"2000-01-01T00:00:00Z\"}")]
    public async Task Unverifiable_token_response_fails_without_retry_or_body_disclosure(string body)
    {
        var count = 0;
        using var client = new OciClient(new Handler(request =>
        {
            count++;
            return request.RequestUri!.Host == "auth.test" ? Ok(body) : Challenge();
        }), "secret-test");
        var failure = await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(2, count);
        Assert.DoesNotContain("secret-test", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(body, failure.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"token\":\"bad\\r\\ntoken\"}", true)]
    [InlineData("{\"token\":\"bad\\u0000token\"}", true)]
    [InlineData("{\"token\":\"bad\\r\\ntoken\"}", false)]
    [InlineData("{\"token\":\"bad\\u0000token\"}", false)]
    public async Task Malformed_bearer_is_refused_before_retry_or_cache_and_next_exchange_succeeds(
        string body, bool verification)
    {
        var exchanges = 0;
        var registryRequests = 0;
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test")
                return ++exchanges == 1 ? Ok(body) : Token("valid");
            registryRequests++;
            if (request.Headers.Authorization is null) return Challenge();
            Assert.Equal("valid", request.Headers.Authorization.Parameter);
            return Ok("bundle");
        }), "secret-test");
        Func<Task> run = () => verification ? client.VerifyRegistryCredentialAsync(Registry) :
            client.PullBlobAsync(Registry, Repository, Digest);
        var failure = await Assert.ThrowsAsync<OciAuthException>(run);
        Assert.Equal(1, registryRequests);
        Assert.Equal(1, exchanges);
        Assert.DoesNotContain("secret-test", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("bad", failure.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(body, failure.Message, StringComparison.Ordinal);
        Assert.Null(failure.InnerException);
        await run();
        Assert.Equal(3, registryRequests);
        Assert.Equal(2, exchanges);
    }

    [Fact]
    public async Task Access_token_alias_is_accepted()
    {
        using var client = new OciClient(new Handler(request =>
            request.RequestUri!.Host == "auth.test" ? Ok("{\"access_token\":\"a\"}") :
            request.Headers.Authorization is null ? Challenge() : Ok()), "secret-test");
        await client.VerifyRegistryCredentialAsync(Registry);
    }

    [Fact]
    public async Task Unknown_length_token_response_stops_at_64_KiB_plus_one()
    {
        var stream = new OciMissionPullTests.ObservedStream(new byte[100_000]);
        using var client = new OciClient(new Handler(request =>
            request.RequestUri!.Host == "auth.test"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }
                : Challenge()), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(64 * 1024 + 1, stream.BytesRead);
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Cancellation_during_token_read_is_preserved()
    {
        var stream = new OciMissionPullTests.ObservedStream([]) { WaitForCancellation = true };
        using var client = new OciClient(new Handler(request =>
            request.RequestUri!.Host == "auth.test"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }
                : Challenge()), "secret-test");
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.VerifyRegistryCredentialAsync(Registry, cancel.Token));
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task Bad_credential_fails_once_without_anonymous_fallback_or_secret_body()
    {
        var count = 0;
        using var client = new OciClient(new Handler(request =>
        {
            count++;
            return request.RequestUri!.Host == "auth.test"
                ? new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("secret-test") }
                : Challenge();
        }), "secret-test");
        var failure = await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
        Assert.Equal(2, count);
        Assert.DoesNotContain("secret-test", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Repeated_401_allows_one_exchange_and_one_retry_only()
    {
        var count = 0;
        using var client = new OciClient(new Handler(request =>
        {
            count++;
            return request.RequestUri!.Host == "auth.test" ? Token() : Challenge();
        }), "secret-test");
        await Assert.ThrowsAsync<OciAuthException>(() => client.PullBlobAsync(Registry, Repository, Digest));
        Assert.Equal(3, count);
    }

    [Fact]
    public async Task Unexpired_cache_is_scoped_to_registry_and_repository()
    {
        var exchanges = 0;
        var initial = new HashSet<string>();
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test") { exchanges++; return Token(); }
            var key = request.RequestUri.Host + request.RequestUri.AbsolutePath;
            if (initial.Add(key)) Assert.Null(request.Headers.Authorization);
            return request.Headers.Authorization is null ? Challenge($"repository:{key}:pull") : Ok();
        }));
        await client.PullBlobAsync(Registry, Repository, Digest);
        await client.PullBlobAsync(Registry, Repository, Digest);
        await client.PullBlobAsync(Registry, "team/other", Digest);
        await client.PullBlobAsync("other.test", Repository, Digest);
        Assert.Equal(3, exchanges);
    }

    [Fact]
    public async Task Changed_service_or_scope_requires_a_new_exchange()
    {
        var exchanges = 0;
        var changed = false;
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test") { exchanges++; return Token($"t{exchanges}"); }
            if (request.Headers.Authorization is null) return Challenge("repository:team/mission:pull");
            if (changed && request.Headers.Authorization.Parameter == "t1")
                return Challenge("repository:team/mission:pull,push", "https://auth.test/other-service");
            return Ok();
        }));
        await client.PullBlobAsync(Registry, Repository, Digest);
        changed = true;
        await client.PullBlobAsync(Registry, Repository, Digest);
        Assert.Equal(2, exchanges);
    }

    [Fact]
    public async Task Expired_cache_is_not_sent_and_requires_fresh_exchange()
    {
        var exchanges = 0;
        var anonymous = 0;
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test")
            {
                exchanges++;
                return Ok("{\"token\":\"a\",\"expires_in\":1}");
            }
            if (request.Headers.Authorization is not null) return Ok();
            anonymous++;
            return Challenge("repository:team/mission:pull");
        }));
        await client.PullBlobAsync(Registry, Repository, Digest);
        await Task.Delay(1100);
        await client.PullBlobAsync(Registry, Repository, Digest);
        Assert.Equal(2, exchanges);
        Assert.Equal(2, anonymous);
    }

    [Fact]
    public async Task Token_and_verification_redirects_are_never_followed()
    {
        foreach (var tokenRedirect in new[] { true, false })
        {
            var count = 0;
            using var client = new OciClient(new Handler(request =>
            {
                count++;
                if (!tokenRedirect || request.RequestUri!.Host == "auth.test")
                    return Redirect("https://untrusted.test/collect");
                return Challenge();
            }), "secret-test");
            await Assert.ThrowsAsync<OciAuthException>(() => client.VerifyRegistryCredentialAsync(Registry));
            Assert.Equal(tokenRedirect ? 2 : 1, count);
        }
    }

    [Fact]
    public async Task Signed_cdn_download_strips_authorization_and_never_authenticates_there()
    {
        var foreign = 0;
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test") return Token();
            if (request.RequestUri.Host == "cdn.test")
            {
                foreign++;
                Assert.Null(request.Headers.Authorization);
                return foreign == 1 ? Ok("bundle") : Challenge(realm: "https://evil.test/collect");
            }
            return request.Headers.Authorization is null
                ? Challenge("repository:team/mission:pull") : Redirect("https://cdn.test/blob?signature=opaque");
        }), "secret-test");
        Assert.Equal("bundle", Encoding.UTF8.GetString(await client.PullBlobAsync(Registry, Repository, Digest)));
        await Assert.ThrowsAsync<OciAuthException>(() => client.PullBlobAsync(Registry, Repository, Digest));
        Assert.Equal(2, foreign);
    }

    [Fact]
    public async Task Same_origin_scoped_redirect_keeps_bearer_but_other_repository_does_not()
    {
        foreach (var destination in new[] { "team/mission", "team/other" })
        {
            using var client = new OciClient(new Handler(request =>
            {
                if (request.RequestUri!.Host == "auth.test") return Token();
                if (request.RequestUri.AbsolutePath.EndsWith("/signed", StringComparison.Ordinal))
                {
                    Assert.Equal(destination == Repository ? "Bearer" : null, request.Headers.Authorization?.Scheme);
                    return Ok();
                }
                return request.Headers.Authorization is null ? Challenge("repository:team/mission:pull") :
                    Redirect($"https://{Registry}/v2/{destination}/signed");
            }));
            await client.PullBlobAsync(Registry, Repository, Digest);
        }
    }

    [Fact]
    public async Task Intermediate_redirect_response_and_final_body_are_disposed()
    {
        var intermediate = new OciMissionPullTests.ObservedStream([]);
        var final = new OciMissionPullTests.ObservedStream("ok"u8.ToArray());
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "cdn.test")
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(final) };
            var response = Redirect("https://cdn.test/signed");
            response.Content = new StreamContent(intermediate);
            return response;
        }));
        await client.PullBlobAsync(Registry, Repository, Digest);
        Assert.True(intermediate.Disposed);
        Assert.True(final.Disposed);
    }

    [Theory]
    [InlineData("http://cdn.test/blob", 1)]
    [InlineData("https://registry.test/v2/team/mission/loop", 6)]
    public async Task Unsafe_or_excessive_download_redirects_are_bounded(string location, int expected)
    {
        var count = 0;
        using var client = new OciClient(new Handler(_ => { count++; return Redirect(location); }), "secret-test");
        await Assert.ThrowsAnyAsync<OciException>(() => client.PullBlobAsync(Registry, Repository, Digest));
        Assert.Equal(expected, count);
    }

    [Fact]
    public async Task Push_auth_retry_preserves_body_and_upload_query()
    {
        var puts = 0;
        var payload = "upload content"u8.ToArray();
        using var client = new OciClient(new Handler(async request =>
        {
            if (request.RequestUri!.Host == "auth.test") return Token();
            if (request.Method == HttpMethod.Head) return new(HttpStatusCode.NotFound);
            if (request.Method == HttpMethod.Post)
            {
                var response = new HttpResponseMessage(HttpStatusCode.Accepted);
                response.Headers.Location = new Uri("/v2/team/mission/blobs/uploads/id?state=keep", UriKind.Relative);
                return response;
            }
            puts++;
            Assert.Equal(payload, await request.Content!.ReadAsByteArrayAsync());
            Assert.Contains("state=keep&digest=sha256%3A", request.RequestUri.Query, StringComparison.Ordinal);
            return request.Headers.Authorization is null ? Challenge("repository:team/mission:pull,push") :
                new HttpResponseMessage(HttpStatusCode.Created);
        }), "secret-test");
        await client.PushBlobAsync(Registry, Repository, payload);
        Assert.Equal(2, puts);
    }

    [Fact]
    public async Task Cross_origin_upload_location_receives_no_registry_authorization()
    {
        using var client = new OciClient(new Handler(request =>
        {
            if (request.RequestUri!.Host == "auth.test") return Token();
            if (request.RequestUri.Host == "uploads.test")
            {
                Assert.Null(request.Headers.Authorization);
                return new(HttpStatusCode.Created);
            }
            if (request.Headers.Authorization is null) return Challenge("repository:team/mission:pull,push");
            if (request.Method == HttpMethod.Head) return new(HttpStatusCode.NotFound);
            var response = new HttpResponseMessage(HttpStatusCode.Accepted);
            response.Headers.Location = new Uri("https://uploads.test/signed?state=keep");
            return response;
        }), "secret-test");
        await client.PushBlobAsync(Registry, Repository, "upload"u8.ToArray());
    }

    private static HttpResponseMessage Challenge(string? scope = null, string realm = "https://auth.test/token")
    {
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        var parameters = $"realm=\"{realm}\", service=\"registry.test\"" +
            (scope is null ? "" : $", scope=\"{scope}\"");
        response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("Bearer", parameters));
        return response;
    }

    private static HttpResponseMessage Ok(string content = "") => new(HttpStatusCode.OK) { Content = new StringContent(content) };
    private static HttpResponseMessage Token(string value = "a") => Ok($"{{\"token\":\"{value}\"}}");
    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
        response.Headers.Location = new Uri(location);
        return response;
    }

    private sealed class Handler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _handle;
        internal Handler(Func<HttpRequestMessage, HttpResponseMessage> handle) : this(request => Task.FromResult(handle(request))) { }
        internal Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> handle) => _handle = handle;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => _handle(request);
    }
}
