# Find and connect to VirusTotal MCP

Connect to **`https://ai.virustotal.com/mcp`** with browser OAuth in a compatible
client; no static token or local Python package is needed. Alternatively, install
[`vt-mcp` 0.9.9 from PyPI](https://pypi.org/project/vt-mcp/0.9.9/) for local stdio.
The package and the public source repository,
[VirusTotal/virustotal-mcp](https://github.com/VirusTotal/virustotal-mcp), use
Apache-2.0. Installation from PyPI does not require a GitHub account. The historical
[0.8.0 release](https://github.com/king-tero/vt-mcp/releases/tag/v0.8.0) retains its
original MIT license and files.

Start with the setup for [Antigravity CLI (`agy`)](clients.md#antigravity-cli-agy),
[Claude Code](clients.md#claude-code), or [Codex](clients.md#codex-cli--remote-http).

## Google client distribution

The [Gemini CLI extension](google-clients.md#gemini-cli-extension) configures the
hosted OAuth endpoint from the root `gemini-extension.json`. Install from `main`
because older Python package archives do not include that manifest. The guide
also provides [Antigravity's native OAuth configuration](google-clients.md#antigravity-native-oauth)
and preserves the existing stdio setup.

Google's [extension gallery](https://geminicli.com/docs/extensions/releasing/)
discovers public repositories carrying `gemini-cli-extension` and validates their
root manifests during its periodic crawl. Configuration publication, gallery
listing and an actual authenticated tool workflow are distinct results; this
does not establish Antigravity Store placement.

## MCP Registry

Select
[`io.github.VirusTotal/virustotal-mcp`](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.VirusTotal%2Fvirustotal-mcp/versions/latest)
in a Registry catalogue. [`server.json`](../server.json) describes the hosted
Streamable HTTP endpoint, the version-pinned PyPI stdio package, and the official
public source repository. GitHub Actions OIDC establishes the corporate namespace;
publication is bound to repository ID `1361592455`. The package README carries the
matching `mcp-name` ownership marker.

Registry metadata **0.9.9** aligns its version with the existing **vt-mcp 0.9.9** package.
The description identifies this as the official VirusTotal MCP server: “official”
refers to VirusTotal ownership, not a Registry endorsement or compatibility badge.

Missing-report guidance keeps the result unknown and requests no upload. If the
user explicitly requests submission and the client cannot transmit file bytes,
the existing VirusTotal web upload can follow a confirmed missing hash report. That external upload
creates no VTAI receipt or registered analysis ID. Sharing guidance and permissions
still apply, and repeated queries still count toward existing quotas.
It retains URL submission, domain/IP reanalysis and caller-retained request IDs,
as well as the OAuth-capable endpoint, VirusTotal icon and public repository URL and ID.
Registry and package versions are independent: this metadata update points to an
existing Python release; it does not publish another package or deploy a hosted server.

The hosted option connects to `https://ai.virustotal.com/mcp`. In a client that
supports MCP OAuth, add this URL and follow its browser sign-in and consent flow;
you do not need to create or paste a static token first. The descriptor leaves
headers unset so the client can discover authorization from the endpoint's
`WWW-Authenticate` challenge. The endpoint still requires authentication. HTTP
connections require no local Python package.

For unattended setup or clients using configurable headers, static Agent Tokens
remain supported. Reuse your existing token or obtain one through
[free VTAI registration](https://ai.virustotal.com/connect/mcp). Configure
`Authorization: Bearer <your-agent-token>` in the host's protected credential
settings. The alternative `x-apikey` configuration is documented in the
[access guide](access.md). Send only one authentication header and do not combine
static headers with the client's OAuth connection. No token belongs in a manifest,
chat, source control or shared installation URL. Static tokens also remain the
credential for local stdio and direct REST access; MCP OAuth tokens are not REST
API keys. Reuse credentials rather than registering again after an error or quota
response.

The Registry stdio configuration uses `uvx --python 3.12` with `vt-mcp==0.9.9`,
so uv selects a supported interpreter. Set `VTAI_TOKEN_FILE` to the path of a protected
file containing only your VTAI token, for example `/home/user/.config/vt-mcp/token`.
The Registry input is the file path; the credential stays in that file. Restrict
file access to your user. Clients that do not import Registry configuration can
use the [manual setup](clients.md).

The ten common tools include file and URL submission, domain/IP reanalysis and
receipt recovery. Local stdio adds `submit_local_file`; a hosted backend can
separately enable `submit_attachment` through the
[client-neutral attachment contract](hosted-clients.md#attachment-downloads). Use the
connection's advertised tools to determine which adapter is available.
For a network operation explicitly requested by the user, retain a canonical
lowercase UUIDv4 `request_id`; after interruption recover the same receipt, without
automatically repeating POST. Standard sharing applies. OAuth network writes require
`vt:reports:read` plus `vt:network-analysis:write`; existing grants do not expand
automatically. See [analysis and recovery](analysis.md#network-analysis-and-recovery).

Registry discovery does not establish support in every client, approval by a model provider or directory, or a working
hosted-client connection. Consult the [client evidence](clients.md).

### Maintaining the entry

The `MCP Registry` workflow is bound to the corporate repository ID and main
branch. After metadata validation and that exact main commit's CI pass, dispatch
it with the full independently reviewed SHA in `reviewed_sha`.

The default `verify-identity` operation checks the GitHub Actions OIDC exchange
and corporate namespace permission, then removes the temporary credential. It
publishes nothing. The helper requires the source repository to be public and
inspects claims from the authenticated HTTPS exchange; it does not independently
verify the token's cryptographic signature locally.

Run `publish` with the reviewed metadata commit on main. Before requesting OIDC,
the helper checks PyPI's name, version and README ownership marker, and requires
exactly the wheel and source distribution, neither yanked. Their SHA-256 hashes
must match the corporate release's `SHA256SUMS` and GitHub asset digests. The
annotated `v0.9.9` tag object, package source commit and checksum manifest are
pinned independently of the metadata commit. This verifies existing published
bytes without rebuilding or uploading them. A moved tag, changed release,
partial upload or mismatched source blocks publication.

The helper uses the publisher fixed by version and SHA-256, reads the exact
published entry anonymously and compares its manifest and active status. No
permanent Registry secret or VTAI token is needed. CI validates the schema and
manifest contract without requiring an already-published PyPI package.

`retire` and `restore` change only current corporate metadata version **0.9.9**.
Retirement preserves its manifest and status message in the `include_deleted=true`
view; restoration reactivates the same entry and requires the matching PyPI release.
The personal **0.8.0** entry remains retired with its corporate migration message.
Corporate **0.9.0–0.9.3**, **0.9.5–0.9.6** and **0.9.8** retain their original
manifests and active status; differing
Registry/package version numbers in those historical entries are intentional pins,
not evidence of a broken package. The Registry may update its computed latest flag.

Corporate **0.8.2–0.8.7** remain deprecated with their previously published message
referring to **0.9.5**. This publication changes neither those messages nor their
manifests. The `deprecate-legacy` operation accepts one exact version in
`target_version` and the independently reviewed main SHA; its fixed message still
refers to **0.9.5**. A deprecated entry remains visible with unchanged package bytes.
There is no bulk operation, package deletion or automatic deprecation during publication.

Each run reads all pinned entries before changing exactly one version, records its
intent, and checks that every other entry is unchanged afterward. A failed or timed
out run is reconciled by reading the status and preserved intent before another
mutation; it is never automatically retried. To undo an accepted deprecation, use
`restore-legacy` with the same version and reviewed SHA. It restores `active`
without a status message. The allowlist excludes **0.9.x** and the personal namespace.

These operations use the Registry's official
[per-version status command](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md#mcp-publisher-status).
No PyPI release or hosted-service deployment is part of this metadata update.

Publication never overwrites an existing name/version or automatically retries a
mutation. After a failure or timeout, inspect every pinned version in both
namespaces with `include_deleted=true` before taking another action: publication
may have succeeded before a later check failed. An exact active entry establishes
publication despite a lost response. Retiring the current entry does not free
the endpoint while older corporate entries still occupy it. A namespace cutover
requires a separately reviewed operation. Release bytes and source history remain
unchanged.

See the official [remote server format](https://modelcontextprotocol.io/registry/remote-servers),
[PyPI package format](https://modelcontextprotocol.io/registry/package-types#pypi-packages),
[versioning rules](https://modelcontextprotocol.io/registry/versioning), and
[GitHub Actions publication guide](https://modelcontextprotocol.io/registry/github-actions).

## Glama

[`glama.json`](../glama.json) names GitHub account `bernardoquintero` as a maintainer
of the public corporate source, using Glama's documented schema. This identifies
a user account, not an organization or email address. A public repository and
metadata make it possible to submit the source to Glama; they do not prove
indexing, ownership verification, crawler refresh or managed hosting.

Use the setup links above for a working connection. Do not put a VTAI token in a
shareable inspector or installation URL. Directory listing and health labels are
distinct from availability of the authenticated MCP endpoint.

## Distribution maintenance

The [PyPI publishing guide](publishing.md) describes verification of existing
release assets and the separate Trusted Publisher setup. The
[hosted-client guide](hosted-clients.md) records account and authentication
requirements with their validation limits.
