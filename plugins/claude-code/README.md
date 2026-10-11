# VirusTotal

Investigate file hashes, URLs, domains and IP addresses using VirusTotal threat
intelligence. Read existing reports, submit previously unknown files, request
network analyses and recover submission receipts through the authenticated
VirusTotal MCP connection. Reports include their analysis date and coverage;
zero detections do not establish that an item is safe.

## Install in Claude Code

<!-- client-contract:claude-code:start -->
```sh
claude plugin marketplace add VirusTotal/virustotal-mcp
claude plugin install virustotal@virustotal
```

Requires Claude Code **2.1.283 or later** and **Node.js 22 or later** on its `PATH`. Node.js 22 and 24 are verified by the plugin CI. The plugin includes `https://ai.virustotal.com/mcp`.
<!-- client-contract:claude-code:end -->

Start a new session or run `/reload-plugins`, then use `/mcp` to sign in to
VirusTotal in your browser. No VirusTotal API key is required. If you previously
used `claude mcp add virustotal`, recover any uncertain submission before
removing that manual connection with `claude mcp remove virustotal` in its
original scope. Fresh installations need no removal command.

For a connection without the local upload hook or Node.js, use this alternative:

```sh
claude mcp add --transport http virustotal https://ai.virustotal.com/mcp
```

## Use VirusTotal

- “Look up the VirusTotal report for 8.8.8.8. Include its analysis date and
  detection coverage. Do not request a reanalysis.”
- “Investigate this file hash. If there is no report, explain what is unknown.”
- In Claude Code: “Check this unfamiliar download without executing it. Submit
  it only if VirusTotal does not already know its hash.”

The `threat-intelligence` skill guides these workflows. In Claude web chat,
connect the remote server from the plugin's Connectors tab. Web chat does not
run the local file hook: a path on your computer is not an attachment, and this
plugin does not provide a native Claude web attachment transfer mechanism.
Cowork can load hooks, but authenticated uploads through this plugin have not
been validated there.

## Local file handling and permissions

In Claude Code, a `PreToolUse` hook runs the bundled
`scripts/expand-file.mjs` with Node.js. It reads an original file only for the
supported VirusTotal `submit_file` tool, verifies its SHA-256 and replaces the
`file:` argument with base64 bytes. It does not execute the sample, install
dependencies, obtain OAuth tokens or make its own network requests. Claude Code
sends the resulting tool input to `https://ai.virustotal.com/mcp`.

The reader accepts regular files of 1 to 24,000,000 bytes within the session's
working directory or explicitly configured `VTAI_UPLOAD_ROOTS`. It rejects
out-of-scope paths, symlinks below a permitted root, changing files and common
credential filenames. This filename check is not a content-based secret
detector. The reader has its own path scope; it does not implement Claude Code's
Read/Bash path rules or provide an operating-system sandbox.

A valid expansion returns `permissionDecision: allow` automatically. The agent
checks the user explicitly requested submission and authorized sharing; the hook does not add a confirmation for
each file. Ask before sharing the user's own documents, internal code,
credentials or personal data. If a credential filename is blocked, stop for
human review; do not rename, encode or switch upload methods to bypass it.

## Sharing, quota and recovery

Standard submissions are shared with the VirusTotal community and security
partners. Submit only when the user explicitly requests that action and has the
right and permission to share the material.
The server verifies the original bytes and checks the hash before uploading;
only a confirmed missing report permits a new contribution. New-file
contributions and receipt recovery use no report-query quota. Returning an
existing report and explicit report or analysis queries consume quota on every
call, including repeats. Separate contribution rate limits apply.

Keep the original SHA-256 or request ID and use `get_submission` to recover an
uncertain outcome on the same connection. Do not repeat an uncertain upload.
Respect the returned analysis polling and retry delays. Disabling the plugin
does not remove submissions from VirusTotal.

## Documentation and support

- [Setup, supported paths, credential checks and troubleshooting](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/claude-code.md)
- [Analysis and contribution workflow](https://github.com/VirusTotal/virustotal-mcp/blob/main/docs/analysis.md)
- [Privacy policy](https://cloud.google.com/terms/secops/privacy-notice)
- [Terms of Service](https://cloud.google.com/terms/secops)
- [Support](https://github.com/VirusTotal/virustotal-mcp/issues)
- [Report a security vulnerability privately](https://bughunters.google.com/)

The plugin code is licensed under Apache-2.0. VirusTotal's service terms and
data-sharing rules apply separately.
