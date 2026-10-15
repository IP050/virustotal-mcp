# VirusTotal for DeepSeek Harness

Investigate file hashes, URLs, domains and IP addresses with VirusTotal reports.
This bundle adds the hosted VTAI MCP connection and a
`virustotal-threat-intelligence` skill that explains how to read a report,
when a submission is authorized, and how to recover an uncertain one.

It complements the repository's other client integrations. The
[Claude Code plugin](../claude-code/README.md), the
[Antigravity plugin](../antigravity/README.md) and this bundle provide the same
remote server; use one connection per client.

## What the bundle installs

Two rows are inserted into the profile:

| Row | Package | Role |
|---|---|---|
| `virustotal-mcp` | `@deepseek-ai/dsh-mcp-client` | The hosted `https://ai.virustotal.com/mcp` connection, exposed as `mcp__virustotal__*` tools |
| `virustotal-skill` | this package | Registers the bundled `virustotal-threat-intelligence` skill, and the `virustotal_submit_local_file` tool |

The bundle declares no dependencies. `@deepseek-ai/dsh-mcp-client` ships with
DeepSeek Harness and resolves from that installation.

## Submitting a local file

The hosted server accepts original file bytes rather than a path, and the DSH MCP
client cannot expand a local path by itself. This bundle therefore adds one tool:

```text
virustotal_submit_local_file(path)
```

It reads the named file, proves its lowercase SHA-256, and passes the original
bytes to the server's `submit_file` tool **without the content ever travelling
through the model as text**. Nothing needs to be base64-encoded by hand, and
`file:<path>` is not used anywhere.

It refuses, before reading a single byte:

| Refused | Why |
|---|---|
| A credential-like filename | Mirrors the filename pattern in `plugins/claude-code/client-contracts.json`; rename or re-encode a file is not a way around it |
| A symbolic link at the final path component | `lstat` rejects the link so it is never followed |
| A file larger than 24,000,000 bytes | The server's own decoded-content limit |
| An empty file, a directory, or a missing path | There is nothing to submit |

Containment is **not** re-implemented: the tool reads through DeepSeek Harness's
own filesystem service, so your configured file policy still fences it. Note that
`lstat` sees only the final path component, so a link in a *parent* directory is
not caught here.

The tool always runs as a nested tool call, so host permissions and guards still
decide whether a submission happens, and the server checks its own hash before
deciding to upload. When it reports `exists`, VirusTotal already knew the file and
**nothing new was published**.

## Authentication

The DSH MCP client supports `stdio` and `streamable-http` with static headers. It
has **no OAuth flow**, so this bundle cannot offer the browser sign-in that the
Claude Code, Antigravity and Gemini CLI integrations use. VTAI accepts a static
credential on its hosted HTTP endpoint, so the connection authenticates with an
`x-apikey` header instead.

That header does not contain the token. It reads the token at startup from a file
that only your user can read:

```
~/.config/vt-mcp/token          # POSIX
C:\Users\<you>\.config\vt-mcp\token   # Windows, the default here
```

No secret is therefore stored in the patch, in this repository, or in
conversation text. Set `VTAI_TOKEN_FILE` to use a different location.

**Prepare the credential:**

1. Create a VTAI Agent Token on the
   [Agent Token page](https://ai.virustotal.com/connect/mcp?client=other&transport=http&auth=token#access-heading).
   VTAI access is free within its published quotas and needs no VirusTotal API key.
2. Save **only the token** in that file — no `Bearer` prefix, no quotes, no dotenv
   syntax.
3. Restrict the file to your user. On Windows:

   ```powershell
   icacls "$env:USERPROFILE\.config\vt-mcp\token" /inheritance:r /grant:r "$($env:USERNAME):(R)"
   ```

   On POSIX, `chmod 600`.
4. Restart DeepSeek Harness so the header is re-read, then confirm the tools
   appeared (below).

Because the token is read at startup, editing the file requires a restart. The
expression reads `VTAI_TOKEN_FILE` first and falls back to the default path, so a
GUI launch that does not inherit your shell environment still works.

VTAI also accepts `Authorization: Bearer <token>` with the same token, rights and
quotas. Send **one** method per connection: replace the `x-apikey` header in
`cordis.patch.yml` rather than adding a second one.

To disconnect, remove the token file or the bundle, and revoke the token on the
Agent Token page. Only **HTTP 204** from the revocation endpoint confirms
revocation; clearing a file or deleting client settings does not.

## Install

Ask your DeepSeek Harness agent to install this directory as a bundle, naming its
absolute path — for example `plugins/dsh` inside a checkout:

> Install the bundle at `<absolute path>/plugins/dsh` in this profile.

The agent calls `install_bundle`, which performs package installation and bundle
selection. Do not hand-edit the profile's `package.json` or `cordis.patch.yml`.
Read the returned `application` field: it decides whether the change is live. An
`applied` result with no warnings means the rows activated.

Installing a new bundle can activate through HMR. Replacing the package afterwards
requires a restart to load a fresh module generation.

## Verify the connection

A connected status alone does not prove a successful query. Check both stages:

1. **Discovery.** The `mcp__virustotal__*` tools appear in the session. Without a
   valid token they do not appear at all — `failOnStartupError` is `false` so an
   unauthenticated connection reports missing tools instead of failing activation.
   Missing tools therefore mean a missing or unreadable token, not a broken plugin.
2. **One real report.** Ask:

   > Use VirusTotal to retrieve the existing report for `virustotal.com`. Show the
   > source, analysis date, coverage and report link. Do not request a new analysis.

   Inspect the actual tool result, not only the final answer. A missing report means
   unknown; zero detections do not establish safety.

For a file-hash regression check, use the SHA-256 of the empty file:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Files, sharing and costs

Use `virustotal_submit_local_file` for a file on this machine — see
[Submitting a local file](#submitting-a-local-file). It performs the byte transfer
itself, so no content has to be pasted through the model, and the server checks
its own hash before deciding to upload. Over HTTP there is no `submit_local_file`;
the stdio alternative below is the transport that provides one.

Standard submissions are shared with the VirusTotal community and security
partners. Submit only when the user explicitly requests it, and ask before sharing
anyone's own documents, internal code, credentials or personal data. Only submit
material you have the right and permission to share. Inline bytes pass through MCP
tool arguments, which the host or model provider may retain. Removing the bundle
does not withdraw submitted content.

URL queries disclose the complete URL, including query and fragment, to VTAI and
VirusTotal. Use domain scope when that answers the question, and avoid secret URLs.

Every report and analysis read consumes quota, including repeats, cache hits and
missing reports. New-file contributions and recovery of your own receipts use no
report-query quota. Honor the server's retry guidance and never create identities
to evade a limit — see the
[analysis and recovery guide](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md).

## Local stdio alternative

If you prefer `submit_local_file` and a local process, install the verified
package and replace the `virustotal-mcp` row's config with a stdio transport:

```bash
uv tool install --python 3.12 --default-index https://pypi.org/simple 'vt-mcp==0.9.9'
```

```yaml
        serverName: virustotal
        transport: stdio
        command: vt-mcp
        env:
          VTAI_TOKEN_FILE: C:\Users\<you>\.config\vt-mcp\token
        failOnStartupError: false
```

Keep exactly one `virustotal` row active. The server name must stay `virustotal`,
because the repository's documented tool names are `mcp__virustotal__*`. Local
stdio adds `submit_local_file` for eleven local tools; HTTP advertises
`submit_attachment` instead. Inline file submission accepts up to 24,000,000
decoded bytes; local file submission accepts up to 32,000,000 bytes.

## Update, disable or remove

Manage the bundle through Plugin Manager or the agent's `plugin_manager` tool:
`set_bundle` toggles it and `remove_bundle` removes it. Keep existing credentials
until any uncertain submission has been recovered, because a receipt belongs to
the identity that submitted it. Removing the bundle does not revoke the token.

## Validation status

Checked on **2026-10-15** on Windows with **DSH Desktop 2.0.17** and bundle
version 0.1.0.

| Observation | Result |
|---|---|
| Bundle install via `install_bundle` | `application: applied`, `enabled: true`, no warnings; pnpm exit 0 |
| `virustotal-mcp` row present in the live config | Confirmed |
| `virustotal-threat-intelligence` skill registered and listed | Confirmed, with its description from `SKILL.md` |
| Patch interpolation with a token file present | `x-apikey` resolved from the file |
| Missing token file | Empty header; **no** exception during interpolation, no activation failure |
| MCP tool discovery (`mcp__virustotal__*`) | Confirmed — 11 tools after the credential resolved; absent before it |
| A live report query through this connection | Confirmed — `get_domain_report("virustotal.com")` returned `found`, 92 engines, a real analysis date and report link |
| URL and file report lookups | Confirmed — `get_url_report` and `get_file_report` each returned `found` for the WICAR test indicators `http://malware.wicar.org/` and the SHA-256 of `YLILWin64.exe` |
| Skill body load | Confirmed — loaded from this bundle's own `SKILL.md`, resource base resolved |
| Bundle disable/enable cycle | Confirmed — rows and skill unregister and re-register cleanly |
| `virustotal_submit_local_file` against a real 650,752-byte Windows executable | Confirmed — produced the matching SHA-256 and transferred all 650,752 bytes with no truncation |
| Refusals before any byte is read | Confirmed — credential-like filename, absent path, directory, empty file, empty argument and final-component symlink |
| A file VirusTotal already knows | Confirmed — the server returned `exists` and uploaded nothing |
| Live registration of the tool in a *running* DSH session | **Not yet observed** — the running Harness had already imported 0.1.0, and a profile bundle caches its module, so the tool appears after a restart |
| A genuinely new upload, reanalysis and receipt recovery | **Not verified** — no new content was published |

The rows above are exact: the upload tool's logic, its refusal paths and a real
byte transfer were all exercised against the live server. What is unobserved is
the tool appearing in a *running* session, because loading a new module generation
needs a restart. Everything about other operating systems and other Harness
versions is likewise unverified, and a working local stdio or another client's
connection does not need to be replaced.

Verification cost four report lookups against the tested VTAI account. The single
submission attempted named a file VirusTotal already knew, so it published nothing
new.

## Documentation and support

- [Client connections](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/clients.md)
- [Access and credentials](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/access.md)
- [Analysis and recovery](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a vulnerability privately](https://github.com/VirusTotal/virustotal-mcp/blob/main/SECURITY.md)

Plugin code is licensed under
[Apache-2.0](https://github.com/VirusTotal/virustotal-mcp/blob/main/LICENSE).
Service terms and sharing rules apply separately.
