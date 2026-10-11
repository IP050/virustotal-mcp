# VirusTotal for Kimi

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
| Commands, agents | None |
| Local code | None. The plugin runs no shell commands and reads no local files. |

## Network endpoints and credentials

The plugin only talks to `ai.virustotal.com`:

- `https://ai.virustotal.com/mcp`: MCP tools.
- `https://ai.virustotal.com/.well-known/oauth-protected-resource/mcp` and
  `https://ai.virustotal.com/.well-known/oauth-authorization-server`: OAuth discovery.
- `https://ai.virustotal.com/oauth/register`: dynamic client registration. Kimi Code registers a public client.
- `https://ai.virustotal.com/oauth/authorize`, `/oauth/token` and `/oauth/revoke`: OAuth 2.1 with PKCE.
- Browser sign-in at `https://ai.virustotal.com/login`, using a Google account.

**Credentials:** Kimi stores the OAuth tokens it obtains. The plugin
contains no API key, static token or secret. VTAI access is free and needs no
VirusTotal API key.

**Telemetry:** the plugin sends none. The VTAI service keeps the service logs
described in its privacy notice.

## Install in Kimi Code

This is a manually installable package, not a claim of marketplace availability.
Use a Kimi Code version that supports native `kimi.plugin.json` plugins. Review
the package, clone this repository and check out the commit you intend to use.
In Kimi Code, install the **absolute path** to its plugin directory:

```text
/plugins install /absolute/path/to/virustotal-mcp/plugins/kimi
/reload
/plugins info virustotal
```

Replace the example path with your checkout's actual path. Do not pass the
repository root or a GitHub `/tree/main/plugins/kimi` URL: Code's GitHub installer
does not select this monorepo subdirectory. It copies local installations, so
reinstall to pick up later changes to the source directory. See
[Kimi Code's plugin guide](https://www.kimi.com/en/help/kimi-code/cli-plugins).

To create a standalone ZIP, run this from the repository root:

```sh
python3 scripts/build_client_plugins.py --client kimi
```

The output is `dist/client-plugins/virustotal-kimi-0.1.0.zip` with its checksum
in `SHA256SUMS`. Extract it into an empty directory and install the absolute path
to that directory. Its `kimi.plugin.json` is at the archive root, alongside the
skill, README and license notices. A published URL to this ZIP can also be used
with `/plugins install`; an ordinary repository source archive has a different
layout.

## Kimi Work and web

Kimi Work's [Plugin Builder](https://www.kimi.com/en/help/plugins-and-skills/create)
can import a repository subdirectory into its Personal plugin tab. Specify this
repository and **only `plugins/kimi`**, review the generated plugin, then install
it from Personal. Builder conversion is separate from Code's installer; verify
the resulting MCP URL and skill before authorizing it.

Kimi web and Work have their own plugin availability and authorization flows.
A successful Code installation does not establish compatibility or publication
on either surface. No web marketplace installation is assumed here.

If you already have a `virustotal` MCP connection, keep one active connection
and preserve other servers.

## Connect and verify

1. Authorize the plugin when Kimi asks. In Kimi Code CLI, run
   `/mcp-config login plugin-virustotal:virustotal`, using the runtime server name
   shown by Kimi. You can also select the plugin in `/plugins` and press `M` to
   manage its MCP server. A separately configured manual server named
   `virustotal` has a different login target.
2. Complete browser sign-in and consent at `ai.virustotal.com`.
3. Review the permissions requested by the client and approve the connection
   only if appropriate. Report access, file submission and network analysis are
   separate VTAI permissions; the consent page approves or cancels the requested
   set.

For a manual Kimi Code connection with a VTAI Agent Token, use
`"bearerTokenEnvVar": "VTAI_AGENT_TOKEN"` on the server in your own MCP
configuration and supply the token outside the conversation. This is an
alternative to the bundled OAuth connection; disable its MCP server to avoid
duplicates. Do not put tokens in the plugin manifest or skill. See
[Kimi Code's MCP configuration](https://www.kimi.com/en/help/kimi-code/cli-mcp).

Never paste authorization codes or tokens into the conversation. Kimi's
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
does not establish native attachment transfer in Kimi Code, Work or web; this
package makes no such claim.

**Sharing.** Standard submissions are shared with the VirusTotal community and
security partners. Submit only material you have the right and permission to
share. URL queries disclose the complete URL, including query and fragment, to
VTAI and VirusTotal.

**Quotas.** VTAI access is free subject to its quotas. Every report or analysis
read counts, including repeats and missing reports. Honor retry delays and never
create identities to evade limits. See the
[quota and recovery details](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

## Disconnect or remove

In Code, use `/plugins remove virustotal` and reload. In Work or web, uninstall
through that surface's plugin manager. Kimi's
[web/Work documentation](https://www.kimi.com/en/help/plugins-and-skills/overview)
describes revocation of the related OAuth authorization on uninstall; do not
assume the same behavior for Code.

For either route, verify the grant in
[Your connections](https://ai.virustotal.com/oauth/connections) and revoke it
there if still present. Recover any uncertain submission with `get_submission`
before disconnecting.

## Documentation and support

- [Privacy notice](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a vulnerability privately](https://bughunters.google.com/)

Plugin code is licensed under [Apache-2.0](https://github.com/VirusTotal/virustotal-mcp/blob/main/LICENSE).
Service terms and sharing rules apply separately.
