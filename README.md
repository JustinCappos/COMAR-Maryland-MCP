# comar-mcp

An [MCP](https://modelcontextprotocol.io) server that gives AI assistants read access to the
**Code of Maryland Regulations (COMAR)**. Every regulation it returns comes from the edition
the Maryland Division of State Documents signed with [TAF](https://github.com/openlawlibrary/taf)
(The Archive Framework), and the server checks that signature with a full
[TUF](https://theupdateframework.io) client before serving anything.

Built on:

- [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk), the official Rust MCP SDK (stdio and streamable HTTP)
- [`tough`](https://github.com/awslabs/tough), AWS's TUF client (with a small compatibility patch, see below)
- [`gix`](https://github.com/GitoxideLabs/gitoxide), pure-Rust git, used to mirror the TAF repositories

## Tools

| Tool | What it does |
|---|---|
| `get_regulation` | Text of a regulation (`COMAR 10.09.01.03`) or a whole chapter (`10.09.01`), optionally with administrative history |
| `search` | Full-text search. All words must match, and `"quoted phrases"` match exactly. Can be limited to a title, subtitle or chapter |
| `browse` | Lists titles, the subtitles of a title, the chapters of a subtitle, or the regulations of a chapter |
| `verification_status` | Shows the TUF roles, versions, expirations and signed commits behind the text being served |

Every response ends with a provenance line naming the source file, the signed content commit,
the authentication-repository commit, and the edition date.

## How verification works

Maryland publishes COMAR as a set of git repositories. One of them is the **authentication
repository** [`maryland-dsd/law`](https://github.com/maryland-dsd/law). Its tree holds ordinary
TUF metadata (`metadata/root.json`, `timestamp.json`, `snapshot.json`, `targets.json`, and the
delegated roles `law.json`, `rdf.json`, …) plus target files. Each target file records the git
commit the publisher vouches for in one content repository:

```
targets/maryland-dsd/law-xml-codified  →  {"commit": "7a87f10b…", "branch": "publication/2026-10-26", "codified-date": "2026-10-30", …}
```

On startup, and again every hour, the server:

1. Fetches a bare mirror of the authentication repository and takes the tip of `main`.
2. Runs `tough` against the files **inside that commit's tree**, read through a custom
   `Transport` that pulls blobs straight out of git and never checks anything out. This covers
   root rotation from the embedded root v1, threshold signatures, snapshot and timestamp
   consistency, the terminating delegation to the `law` role, and the hash and length of each
   target. tough's datastore keeps the last trusted metadata, which gives rollback protection
   across restarts.
3. Reads the signed `repositories.json` and `mirrors.json` targets to find the content
   repository and its mirror URL, then reads the signed commit for `maryland-dsd/law-xml-codified`.
4. Fetches that repository and builds the index from the tree of the **signed commit only**,
   which git content-addresses. A new edition is swapped in atomically once it verifies. If a
   refresh fails, the last verified edition stays in service.

Measured on 2026-11-06: about 70 s for the first clone (45 MB of mirrors on disk), about 1 s for a warm
restart, 36 titles, 3,965 chapters and 29,251 regulations.

### Expiration policy (`--expiration`)

In Maryland's live metadata, the **offline** roles have expired: `root` v5 on 2026-02-07, and
`targets` and the delegated `law` role on 2025-07-08. The **online** `timestamp` and `snapshot`
roles are re-signed with every build and are current. A stock TUF client refuses to load at all.

- `archival` (default) verifies every signature and hash, and requires `timestamp` and
  `snapshot` to be unexpired. That proves the publisher is still signing and nobody is
  replaying an old edition. Expired offline roles are reported as warnings in
  `verification_status` and in each response's footer.
- `strict` is standard TUF and refuses to serve if any role has expired. Today it fails.
- `ignore` checks signatures and hashes only.

### The tough patch

Upstream tough can't read TAF metadata, for two reasons. This repo vendors tough 0.24.0 with
[`patches/tough-taf-compat.patch`](patches/tough-taf-compat.patch) (about 100 lines), applied
through `[patch.crates-io]`. It should be sent upstream to awslabs/tough.

1. **`rsa-pkcs1v15-sha256`.** TAF signs through securesystemslib with RSASSA-PKCS1-v1_5.
   tough only knew RSA-PSS. The patch adds the scheme using aws-lc-rs's verifier.
2. **Key IDs over a trimmed PEM.** Two keys added in later root rotations are stored with a
   trailing newline after `-----END PUBLIC KEY-----`, but their key IDs were hashed over the
   stripped PEM. securesystemslib-based clients never recompute key IDs, so nobody noticed.
   tough does recompute them. The patch also accepts the trimmed-PEM ID. Because one key can
   now match two IDs, the patch also rejects metadata that lists the same key material twice,
   which would otherwise let one key count twice toward a threshold. Both cases are covered
   in `tests/tough_patch.rs` using Maryland's real root v5.

### Differences from the TAF reference client

TAF's Python updater validates **every** commit in the authentication repository's history
and checks that the content commits move forward in order. This server verifies the current
tip as a standard TUF client would, with tough's datastore preventing rollback relative to
what it has seen before. It also checks only the repository it serves, `law-xml-codified`, not
the HTML, RDF or docs repositories.

The trust anchor is `trust/maryland-dsd-law.1.root.json` (sha256
`125535d083aa3284862887bd6d556b7e1328d48fad2faa8f8eeef446d7e51b7b`). It is the root from the
repository's first commit, `df241af3` (2025-10-20). Operators should confirm it out of band
with the publisher, or pass their own with `--trusted-root`.

## Running it

Requires Rust 1.88+ (`rust-toolchain.toml` selects stable).

```bash
cargo build --release
./target/release/comar-mcp --check     # clone, verify, index, print a summary, exit
```

### Self-hosted, for a desktop client (stdio)

Claude Desktop / Claude Code config:

```json
{
  "mcpServers": {
    "comar": {
      "command": "/path/to/comar-mcp/target/release/comar-mcp"
    }
  }
}
```

Or with Claude Code:

```bash
claude mcp add comar -- /path/to/comar-mcp/target/release/comar-mcp
```

The first launch takes about a minute while it clones and verifies. Until that finishes, tools
reply that verification is still running.

### Shared or public server (streamable HTTP)

```bash
comar-mcp --transport http --bind 0.0.0.0:8000 --allowed-host comar.example.org
```

- MCP endpoint: `http://HOST:8000/mcp`. `GET /healthz` returns 200 once an edition has verified, 503 before that.
- `--allowed-host` is required for any non-loopback hostname. rmcp checks the `Host` header to block DNS rebinding.
- Put TLS and any rate limiting in a reverse proxy in front.
- Docker:

  ```bash
  docker build -t comar-mcp .
  docker run -p 8000:8000 -v comar-data:/data -e COMAR_MCP_ALLOWED_HOSTS=comar.example.org comar-mcp
  ```

### Options

| Flag | Env | Default |
|---|---|---|
| `--transport stdio\|http` | `COMAR_MCP_TRANSPORT` | `stdio` |
| `--bind` | `COMAR_MCP_BIND` | `127.0.0.1:8000` |
| `--allowed-host` (repeatable or comma-separated) | `COMAR_MCP_ALLOWED_HOSTS` | loopback only |
| `--data-dir` | `COMAR_MCP_DATA_DIR` | `~/.cache/comar-mcp` |
| `--expiration archival\|strict\|ignore` | `COMAR_MCP_EXPIRATION` | `archival` |
| `--refresh-secs` (0 = never) | `COMAR_MCP_REFRESH_SECS` | `3600` |
| `--offline` (serve existing mirrors, no network) | `COMAR_MCP_OFFLINE` | off |
| `--trusted-root` | `COMAR_MCP_TRUSTED_ROOT` | embedded Maryland root v1 |
| `--auth-repo`, `--auth-branch`, `--content-repo` | | Maryland defaults |

Logs go to stderr. Set the level with `RUST_LOG` (for example `RUST_LOG=comar_mcp=debug`).

## Licensing of the regulations

Maryland licenses this version of the COMAR text under **CC BY-NC-SA 4.0**, and dedicates it
to the public domain (CC0) 180 days after publication. Every response carries the attribution,
so keep it in place. Check the non-commercial term before running a public instance for a
commercial purpose. This code is MIT OR Apache-2.0. The vendored tough keeps its own MIT OR
Apache-2.0 license.

## Not yet covered

- The Maryland Register (`us/md/exec/register` in the same repository).
- Historical editions. The signed history makes "COMAR as of date X" possible: verify an older
  authentication-repository commit and serve its content commit.
- Persisting the search index. It is rebuilt in memory in about a second from the git mirror.
