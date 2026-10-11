# VirusTotal for Grok Build

Investigate file hashes, URLs, domains and IP addresses with VirusTotal reports.
This plugin bundles the remote VirusTotal MCP connection and a
`threat-intelligence` skill for report interpretation, explicitly requested
submissions and receipt recovery.

## What this plugin contains

| Component | Contents |
|---|---|
| MCP server | `virustotal` → `https://ai.virustotal.com/mcp` (Streamable HTTP) |
| Skill | `skills/threat-intelligence/SKILL.md` |
| Hooks | None |
| Commands, agents, LSP | None |
| Local code | None. The plugin runs no shell commands and reads no local files. |

## Network endpoints and credentials

The plugin only talks to `ai.virustotal.com`:

- `https://ai.virustotal.com/mcp`: MCP tools.
- `https://ai.virustotal.com/.well-known/oauth-protected-resource/mcp` and
  `https://ai.virustotal.com/.well-known/oauth-authorization-server`: OAuth discovery.
- `https://ai.virustotal.com/oauth/register`: dynamic client registration. Grok Build registers a public client.
- `https://ai.virustotal.com/oauth/authorize`, `/oauth/token` and `/oauth/revoke`: OAuth 2.1 with PKCE.
- Browser sign-in at `https://ai.virustotal.com/login`, using a Google account.

**Credentials:** Grok Build stores the OAuth tokens it obtains. The plugin
contains no API key, static token or secret. VTAI access is free and needs no
VirusTotal API key.

**Telemetry:** the plugin sends none. The VTAI service keeps the service logs
described in its privacy notice.

## Install from source

This package can be installed manually; these instructions do not require a
marketplace listing. Install [Grok Build](https://docs.x.ai/build) first, then
clone this repository and run the following from its root:

```sh
grok plugin validate ./plugins/grok-build
grok plugin install ./plugins/grok-build --trust
grok plugin list
```

Review the plugin first: `--trust` authorizes its MCP server and skill. For a
reproducible installation, check out the commit you intend to use before running
these commands. Restart Grok Build or reload its Plugins tab after installation.
See the [Grok plugin guide](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/09-plugins.md)
for client installation options.

To build a standalone ZIP from the same checkout, run:

```sh
python3 scripts/build_client_plugins.py --client grok-build
```

The output is `dist/client-plugins/virustotal-grok-build-0.1.0.zip` with its
checksum in `SHA256SUMS`. Extract it into an empty directory and install that
directory with the same `grok plugin validate` and `grok plugin install`
commands. The ZIP contains the manifest, MCP configuration, skill, README and
license notices; it contains no executable helper.

If you already have a `virustotal` MCP connection, keep one active connection
and preserve other servers.

## Connect and verify

1. Open `/mcps`, select `virustotal` and press `i` to authenticate.
2. Complete browser sign-in and consent at `ai.virustotal.com`.
3. Review the permissions requested by the client and approve the connection
   only if appropriate. Report access, file submission and network analysis are
   separate VTAI permissions; the consent page approves or cancels the requested
   set.

Never paste authorization codes or tokens into the conversation. Grok Build's
tool permission settings still apply; this plugin adds no approval rule.

Try a report-only request:

> Use VirusTotal to retrieve the existing report for example.com. Include the
> analysis date, source and coverage. Do not submit it or request a new analysis.

Inspect the actual tool result. A connected status alone does not prove a
successful query. Missing reports mean unknown; zero detections do not establish
safety.

## Tools and safety

Read-only tools:

- `get_file_report`, `get_url_report`, `get_domain_report`, `get_ip_report`
- `get_analysis`, `get_submission`

Submission and analysis tools, used only when the user explicitly asks:

- `submit_file`, `submit_attachment`, `submit_url`, `reanalyze_domain`, `reanalyze_ip`

The skill forbids submitting because a report is missing and asks before sharing
the user's own documents, internal code, credentials or personal data. The
server enforces separate OAuth permissions for submissions and network analysis,
quotas and idempotent recovery: network operations use a `request_id`, file
submissions a SHA-256.

## Files, sharing and costs

The remote server accepts original file bytes, not paths on your computer. This
plugin has no local upload hook. When the host cannot transfer the original bytes
programmatically, the skill uses the hash-first fallback described in the
[file workflow](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

`submit_file` requires original bytes encoded programmatically as base64 plus
their SHA-256; a local path or `file:<path>` is not a supported input here.
`submit_attachment` requires a public HTTPS `file.download_url` serving the
original bytes, supplied by the host or explicitly selected by the user. Never
publish a private file to obtain such a URL. Availability of this remote tool
does not establish that Grok Build provides a native attachment URL; native
attachment transfer is not claimed by this package.

**Sharing.** Standard submissions are shared with the VirusTotal community and
security partners. Submit only material you have the right and permission to
share. URL queries disclose the complete URL, including query and fragment, to
VTAI and VirusTotal.

**Quotas.** VTAI access is free subject to its quotas. Every report or analysis
read counts, including repeats and missing reports. Honor retry delays and never
create identities to evade limits. See the
[quota and recovery details](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

## Disconnect or remove

```sh
grok plugin uninstall virustotal
```

Verify that the grant is revoked in
[Your connections](https://ai.virustotal.com/oauth/connections), and revoke it
there if still present. Removing a local plugin is not evidence of server-side
revocation. Recover any uncertain submission with `get_submission` before
disconnecting.

## Documentation and support

- [Privacy notice](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a vulnerability privately](https://bughunters.google.com/)

Plugin code is licensed under [Apache-2.0](https://github.com/VirusTotal/virustotal-mcp/blob/main/LICENSE).
Service terms and sharing rules apply separately.
