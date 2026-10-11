# VirusTotal for Antigravity

Investigate file hashes, URLs, domains and IP addresses with VirusTotal reports.
This plugin bundles the remote MCP connection and a `threat-intelligence` skill
for report interpretation, authorized submissions and receipt recovery.

It complements the existing [Agy local stdio integration](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/clients.md#antigravity-cli-agy)
and [VT Sentinel extension for Antigravity IDE](https://open-vsx.org/extension/virustotal/vt-sentinel),
also available from [ai.virustotal.com](https://ai.virustotal.com/).
VT Sentinel provides its own editor protection workflow. This plugin supplies
tools and guidance to the agent; it does not intercept downloads or execution.

## Install from the official repository

Requires Git and an Antigravity installation with plugin support. From a directory
where you keep source checkouts:

```sh
git clone https://github.com/VirusTotal/virustotal-mcp.git
agy plugin validate ./virustotal-mcp/plugins/antigravity
agy plugin install ./virustotal-mcp/plugins/antigravity
agy plugin list
```

Review the plugin directory before installing. Agy 1.2.14 installs a local
directory; pass the `plugins/antigravity` subdirectory, not a GitHub URL or the
repository root. If you already have a checkout, use its local path instead.
The interactive `/plugin` manager also accepts **Install from local directory**.
See Google's [plugin guide](https://antigravity.google/docs/plugins/).

If you already use a `virustotal` MCP connection, keep one active connection and
preserve other servers. Recover uncertain submissions before changing a
connection, because receipts belong to the identity that submitted them. A
working local stdio or VT Sentinel installation does not need to be replaced.

## Connect and verify

The bundled server is `https://ai.virustotal.com/mcp`. It uses the host's OAuth
flow; the plugin contains no API key, static token or Google ADC configuration.
Start a new Agy session and open `/mcp`. Select `virustotal_virustotal`, choose
**Authenticate**, and complete browser sign-in and consent. Copy the code shown
by Google's callback page into Agy's authentication dialog, never into the
conversation. In Antigravity's graphical settings, use **Customizations →
Authenticate** and follow the callback step shown by that application.
Follow Google's [MCP authentication guide](https://antigravity.google/docs/mcp/).

Authorize only the operations your task needs. Report access, file submission
and network analysis have separate VTAI permissions. The host's tool permission
settings still apply; this plugin adds no blanket approval rule. A model login
does not grant access to VTAI. If the host cannot complete OAuth, use the existing
[Agy stdio setup](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/clients.md#antigravity-cli-agy).

Try a report-only request:

> Use VirusTotal to retrieve the existing report for example.com. Include the
> analysis date, source and coverage. Do not submit it or request a new analysis.

Inspect the actual tool result. Installation, validation and a connected status
alone do not prove a successful query. Missing reports mean unknown; zero
detections do not establish safety. Native browser sign-in and a report query
have been verified in Agy; token renewal, write operations and the graphical
applications have separate validation requirements. See [validation status](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/google-clients.md#validation-and-discovery).

## Files, sharing and costs

The remote server accepts original file bytes, not paths on your computer. This
plugin includes no local upload hook and does not expand `file:<path>`. Direct
`submit_file` use requires a host mechanism that transfers the original bytes
programmatically; do not ask the model to transcribe base64. The local stdio
integration offers `submit_local_file`. See the [file workflow](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md)
for the hash-first web-upload fallback when byte transfer is unavailable.

Standard submissions are shared with the VirusTotal community and security
partners. Submit only when the user explicitly requests it. Ask before sharing
your own documents, internal code, credentials or
personal data. Only submit material you have the right and permission to share.
Inline bytes also pass through MCP tool arguments, which the host or model
provider may retain. Removing this plugin does not withdraw submitted content.
URL queries disclose the complete URL, including query and fragment, to VTAI
and VirusTotal; use domain scope when sufficient and avoid secret URLs.

VTAI access is free subject to its quotas; Antigravity model access and credits
are separate. Every report or analysis read counts, including repeats and missing
reports. New-file contributions and owned receipt recovery use no report-query
quota; an existing file's returned report costs one query. Unknown-file
contributions have a separate allowance of 20 per fixed minute and 500 per UTC
day, shared by the signed-in VTAI account. Honor retry delays and reuse your
existing account. Never create identities to evade limits. Keep the hash or
request ID and recover uncertain submissions with `get_submission` instead of
repeating them. [Quota and recovery details](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

## Update, disable or remove

For a local installation, update your reviewed checkout and reinstall the plugin
directory using `/plugin`. Preserve the existing connection until any uncertain
submissions have been recovered. Manage the installation with:

```sh
agy plugin disable virustotal
agy plugin enable virustotal
agy plugin uninstall virustotal
```

For permanent disconnection, also revoke its access in
[Your connections](https://ai.virustotal.com/oauth/connections). Disabling or
uninstalling local files alone does not revoke the grant. Do not delete or copy
the host's credential files.

## Documentation and support

- [Google client connections](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/google-clients.md)
- [Privacy notice](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a vulnerability privately](https://bughunters.google.com/)

Plugin code is licensed under [Apache-2.0](https://github.com/VirusTotal/virustotal-mcp/blob/main/LICENSE). Service terms and
sharing rules apply separately. This directory is installable from source;
publication in Google's curated Marketplace is a separate review process.
