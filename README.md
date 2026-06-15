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
using var client = new OciClient(token: Environment.GetEnvironmentVariable("GITHUB_TOKEN"));

string expertMd = await client.PullExpertAsync(
    registry:  "ghcr.io",
    name:      "katasec/kubernetes-architect",
    tag:       "0.1.0");

// Push an expert artifact
await client.PushExpertAsync(
    registry:       "ghcr.io",
    name:           "myorg/my-expert",
    tag:            "1.0.0",
    expertMdContent: File.ReadAllText("experts/MyExpert/expert.md"));
```

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
