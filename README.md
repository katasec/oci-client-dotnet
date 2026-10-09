# Katasec.OciClient

AOT-safe .NET OCI Distribution Spec client — push, pull, bearer auth.

Targets `net10.0` with `IsAotCompatible=true`. Uses STJ source generation throughout — no bare `JsonSerializerOptions` at runtime.

## Install

```bash
dotnet add package Katasec.OciClient --source "https://nuget.pkg.github.com/katasec/index.json"
```

## Usage

```csharp
using Katasec.OciClient;

// Pull an expert artifact
using var client = new OciClient(credential: Environment.GetEnvironmentVariable("GITHUB_TOKEN"));

string expertMd = await client.PullExpertAsync(
    registry:  "ghcr.io",
    name:      "katasec/kubernetes-architect",
    tag:       "0.1.0");

// Pull an expert artifact and the immutable digest to pin it by. A tag moves; the manifest
// digest does not. Both values come from the same pull, so the digest always describes the
// content you actually received.
PulledExpert pulled = await client.PullExpertWithDigestAsync(
    registry:  "ghcr.io",
    name:      "katasec/kubernetes-architect",
    reference: "0.1.0");

// pulled.ManifestDigest -> "sha256:…", re-resolvable as the reference on a later pull

// Push an expert artifact
await client.PushExpertAsync(
    registry:       "ghcr.io",
    name:           "myorg/my-expert",
    tag:            "1.0.0",
    expertMdContent: File.ReadAllText("experts/MyExpert/expert.md"));

// Pull a verified self-contained Forge mission; pin ManifestDigest for later retrieval.
PulledMission mission = await client.PullMissionWithDigestAsync(
    "ghcr.io", "katasec/forge-mission-assistant", "0.1.0");
// Bundle is the tar's bytes. LayerDigest and LayerByteLength describe those exact bytes.
// PullMissionAsync returns the same verified Bundle without the result metadata.

// Verify a supplied credential before persisting it in the calling application.
using var authenticated = new OciClient(credential: Environment.GetEnvironmentVariable("GITHUB_TOKEN"));
await authenticated.VerifyRegistryCredentialAsync("ghcr.io");
```

Manifest pulls verify SHA-256 against a requested digest and any `Docker-Content-Digest` header,
and bound manifest content to 1 MiB. Verified mission pulls require Forge schema v1 mission metadata
and exactly one bundle layer, check its declared size/hash, and stream within a 32 MiB default
budget. `maxBundleBytes` can supply a positive caller-owned budget. Retrieval does not extract or
authorize the bundle's contents; the caller owns those operations.

Authentication accepts Bearer challenges with HTTPS token realms, using the constructor credential
as the Basic password only for that exchange. Tokens expire and remain scoped to their registry,
repository and latest challenge. Verification requires a supplied credential and a successful
challenge/exchange/retry: anonymous success alone is refused. Basic registry challenges are
unsupported, and rejected credentials never fall back to anonymous access.

Manifest/blob downloads may follow five HTTPS redirects, removing Authorization across origins
or repository boundaries. Foreign download/upload URLs never receive registry credentials or
negotiate registry authentication. Token exchanges and credential verification follow no redirects.
Token responses are limited to 64 KiB. Cancellation propagates; registry/integrity failures raise
`OciException`, while authentication failures raise `OciAuthException`, without response bodies or
credentials in their messages.

## Scope

Implements the subset of the [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) needed for single-file artifact push and pull:

| Operation | Endpoint |
|-----------|----------|
| Pull manifest | `GET /v2/{name}/manifests/{ref}` |
| Pull blob | `GET /v2/{name}/blobs/{digest}` |
| Check blob exists | `HEAD /v2/{name}/blobs/{digest}` |
| Start blob upload | `POST /v2/{name}/blobs/uploads/` |
| Complete blob upload | `PUT {session_url}&digest={sha256}` |
| Push manifest | `PUT /v2/{name}/manifests/{tag}` |

Bearer token auth is handled automatically on 401.

## Expert artifact format

| Field | Value |
|-------|-------|
| Config mediaType | `application/vnd.forge.expert.config.v1+json` |
| Layer mediaType | `application/vnd.forge.expert.v1` |
| Layer content | UTF-8 encoded `expert.md` |

## License

Apache 2.0
