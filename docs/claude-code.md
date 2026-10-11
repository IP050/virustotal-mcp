# VirusTotal for Claude Code

The VirusTotal plugin connects Claude Code to the remote OAuth MCP server and
lets it submit a local file without copying its base64 through the model.
Install the plugin for reports, the threat-intelligence skill and local uploads.
The [manual HTTP alternative](#manual-http-alternative-without-nodejs) below works
without the plugin or Node.js.

## Install and connect

<!-- client-contract:claude-code:start -->
```sh
claude plugin marketplace add VirusTotal/virustotal-mcp
claude plugin install virustotal@virustotal
```

Requires Claude Code **2.1.283 or later** and **Node.js 22 or later** on its `PATH`. Node.js 22 and 24 are verified by the plugin CI. The plugin includes `https://ai.virustotal.com/mcp`.
<!-- client-contract:claude-code:end -->

If you previously used `claude mcp add virustotal`, recover any uncertain submission
through that original connection before removing a duplicate. Follow the
[migration and recovery details](#replace-an-existing-manual-connection) to inspect
its actual name and scope. A fresh installation needs no removal command.
No Python, npm dependencies, VirusTotal API key or copied OAuth token is needed.

Start a new Claude Code session or reload plugins with `/reload-plugins`. Use
`/mcp` to authenticate the VirusTotal connection in your browser when needed.
The plugin includes `https://ai.virustotal.com/mcp`; do not add a second manual
MCP server for file uploads. If your personal claude.ai connection is already
active under `VirusTotal` or `ai.virustotal.com`, the hook also supports that
imported connection. Alias spelling is case-insensitive.
Keep submission and receipt recovery on the same connection.

Ask Claude to investigate a hash, URL, domain or IP address, or to inspect an
unfamiliar local download. The plugin's threat-intelligence skill is also
available as `/virustotal:threat-intelligence`.

### Manual HTTP alternative without Node.js

For reports without the local file hook, configure the remote server directly:

```sh
claude mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

Open `/mcp` and complete browser sign-in. This is an alternative to the plugin;
do not add both as duplicate server entries. The direct connection cannot expand
`file:` paths. It can still submit original bytes if the client can transmit
them, or use the existing web-upload fallback described below.

## Local files

For a file that should be shared, Claude calculates its SHA256 and calls
`submit_file` with the usual `sha256` argument and a local reference:

```json
{
  "sha256": "<the original file's lowercase SHA256>",
  "content_base64": "file:/absolute/path/to/download.bin"
}
```

On Windows, use a local drive path, for example
`"file:C:\\Users\\you\\Downloads\\sample.bin"` in JSON. Paths containing spaces
are supported. The hook reads the original file, checks its hash and replaces
only `content_base64` with the bytes' base64. The server continues to receive the
existing API format; it cannot read your local path itself.

A valid expansion returns `permissionDecision: allow` automatically. The agent
chooses what to share using the policy below; the hook adds no confirmation for
each file. It does not obtain OAuth tokens or grant server permissions. Existing
VTAI scopes, quotas and receipt handling still apply. Inline base64 calls pass
through without a hook permission decision.

The server checks the verified hash before uploading. Contributing a confirmed
unknown file and recovering its receipt consume no query quota. Returning an
existing file report, or reading a report or analysis explicitly, consumes a
query each time. See [file workflow quota](analysis.md#query-quota-for-file-workflows).

The hook denies filenames commonly used for credentials before opening the
requested file. It asks for human review and supplies no bytes. The check uses only
the file's basename, without distinguishing letter case on any operating system:

- `.env*`; `*.pem`, `*.key`, `*.kdbx`, `*.p12`, `*.pfx`, `*.ppk`, `*.jks`, `*.keystore`.
- `id_rsa*`, `id_dsa*`, `id_ecdsa*`, `id_ed25519*`, `id_xmss*` and `ssh_host_*_key*`,
  including their public-key and backup variants.
- `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.pgpass`, `.htpasswd`,
  `credentials*` and `kubeconfig`.

This short list is a precaution, not a universal secret detector. It can block
public certificates and keys too; harmless names can still contain secrets.
Inline base64 has no filename and is unchanged by this check. If blocked, stop
for human review: do not rename, encode, use another tool or upload through the
website to bypass the block. There is no automatic override.

The local validation limit is **1 to 24,000,000 bytes**. This is a parser and file
limit, not a claim that every client/network supports a 24 MB upload. A missing
hook, unavailable Node executable or hook timeout leaves `file:` unexpanded;
that value is invalid base64 for the remote server. Do not retry an uncertain
upload: recover with `get_submission` and the same SHA256, then use its analysis
ID and polling delay with `get_analysis`.

## Permitted local scope

By enabling the plugin, you enable its local file reader for the session's
working directory. To also permit a downloads directory, set an explicit JSON
array before starting Claude Code:

```sh
export VTAI_UPLOAD_ROOTS='["/absolute/path/to/downloads"]'
claude
```

In PowerShell:

```powershell
$env:VTAI_UPLOAD_ROOTS = '["C:\\Users\\you\\Downloads"]'
claude
```

This setting adds at most 16 roots. Relative paths, symlinks below a permitted
root, nonregular files, Windows device paths/network shares, alternate data
streams and Windows components ending in a dot or space are rejected. A configured root itself may resolve through an existing
directory alias. File identity, length and timestamps are checked before and
after reading; changed files are rejected.

This is the hook's own filesystem scope. It does not reimplement Claude Code's
`Read` or `Bash` path-rule language and is not an operating-system sandbox.
Keep those host restrictions in place. Administrators can also disable plugin
hooks through Claude Code's managed policy. Hook errors contain no file bytes,
base64, credential values or local paths, and the hook writes no diagnostic logs.

The hook accepts only the plugin server's `plugin` provenance and exact identity,
or `claudeai` provenance with the imported name `claude.ai VirusTotal` or
`claude.ai ai.virustotal.com` and its corresponding `submit_file` tool. Only the
two alias spellings are case-insensitive. Project/user aliases with the same name and unknown
provenance are rejected before reading a file. The imported name is a configured
identity, not independent authentication of its endpoint: connect the official
`https://ai.virustotal.com/mcp` service and retain control of your client setup.

## Sharing and alternatives

Submit files or request URL, domain or IP analyses only when the user explicitly
requests that action. A missing report or unfamiliar file is not permission to submit.
Ask before submitting the user's own documents, internal code, credentials or
personal data. An attachment or executable extension does not establish consent
to share private content. Standard submissions are shared with the VirusTotal
community and security partners; only submit material you have the right and
permission to share.

If a client cannot transfer the original bytes and the plugin is unavailable,
first calculate the file's SHA-256 locally, or ask the user for it, and call
`get_file_report(hash)`. Use an existing report without uploading. Only an explicitly requested submission and a confirmed
missing report permit using the existing
[VirusTotal web uploader](https://www.virustotal.com/gui/home/upload), then reading
the same hash again. Permission, quota or service errors do not establish absence.
A web upload has no VTAI submission receipt. Every report query counts, including
missing reports and repeats; follow the [web fallback workflow](analysis.md#when-the-client-cannot-transmit-file-bytes).

### Replace an existing manual connection

Only if you previously added a manual VirusTotal entry, identify its exact name
and scope with `claude mcp list` and `claude mcp get <name>`. Recover any uncertain
submission on its original connection before removing that entry. Remove it
from the scope in which you configured it before using the plugin connection. For
example, for an entry named `virustotal` in the current project's local scope:

```sh
claude mcp remove --scope local virustotal
```

Use `--scope user` or `--scope project` only when that is the existing entry's
scope, and substitute its actual name. If the same manual entry exists in more
than one scope, review each one instead of removing an unrelated server.
[Removing a remote server](https://code.claude.com/docs/en/mcp#managing-your-servers)
also clears its locally stored OAuth tokens and client registration, so expect
to sign in again for the plugin. Do not manually delete credentials, revoke
server grants, delete submission receipts or disconnect the personal claude.ai
connection. Fresh installations need no removal command.

## Validation and removal

On 1 October 2026, plugin 0.1.3 was tested in Claude Code 2.1.284 on Linux with Node 22, starting
with a fresh OAuth login to the plugin's own connection. One inert 163-byte file
was uploaded, its original bytes verified after the hook, its receipt recovered
and its completed analysis read with the matching SHA-256. All ten general
VirusTotal tools were exercised, including once-only URL, domain and IP analysis
requests, receipt recovery and completed results. An invalid IP returned the
expected error. That session did not validate native attachment transfer. The current
`submit_attachment` descriptor requires a reachable public HTTPS URL for the
original file; it does not establish native Claude attachment support.

Earlier native Claude Code 2.1.283 tests used an imported OAuth connection for
100,000-byte, 1,000,000-byte and 24,000,000-byte public fixtures, with matching
receipts and completed analyses. A clean marketplace installation was verified
separately. These results do not certify authenticated uploads on Windows,
macOS, Cowork or Claude web chat. The CI workflow separately checks file
boundaries, provenance, races and the launcher on Linux, macOS and Windows with
Node 22 and 24; an offline pass does not prove a native authenticated upload.

```sh
claude plugin disable virustotal@virustotal
claude plugin uninstall virustotal@virustotal
```

Disabling or removing the plugin does not erase remote submissions or receipts.
See the official [plugin installation guide](https://code.claude.com/docs/en/discover-plugins),
[hook input and decision contract](https://code.claude.com/docs/en/hooks#pretooluse-input)
and [plugin manifest reference](https://code.claude.com/docs/en/plugins-reference).
